// db.js — Couche base de données NUNI (Postgres / Neon, via le package "pg")
//
// Remplace la version SQLite (node:sqlite). Toutes les requêtes sont maintenant
// asynchrones (Promises). server.js et auth.js doivent utiliser await/async.
//
// Variable d'environnement requise sur Render : DATABASE_URL (fournie par Neon).

const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL manquante — ajoute-la dans Render (Environment) avec la chaîne de connexion Neon.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // requis par Neon
});

async function query(text, params = []) {
  const result = await pool.query(text, params);
  return result.rows;
}

async function get(text, params = []) {
  const rows = await query(text, params);
  return rows[0];
}

async function run(text, params = []) {
  const result = await pool.query(text, params);
  return { rowCount: result.rowCount, rows: result.rows };
}

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      account_type TEXT NOT NULL CHECK(account_type IN ('consumer','artist','label')),
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      age INTEGER,
      address TEXT,
      city TEXT,
      country TEXT,
      artist_name TEXT,
      label_or_manager TEXT,
      is_verified INTEGER DEFAULT 0,
      plan TEXT DEFAULT 'discovery' CHECK(plan IN ('discovery','consumer','artist')),
      subscription_status TEXT DEFAULT 'inactive' CHECK(subscription_status IN ('inactive','pending','active','expired')),
      subscription_started_at TIMESTAMPTZ,
      subscription_expires_at TIMESTAMPTZ,
      access_code TEXT,
      verification_status TEXT DEFAULT 'none',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tracks (
      id SERIAL PRIMARY KEY,
      artist_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      album TEXT,
      genre TEXT,
      release_type TEXT DEFAULT 'Single',
      cover_url TEXT,
      audio_url TEXT,
      lyrics TEXT,
      scheduled_release_at TIMESTAMPTZ,
      published INTEGER DEFAULT 1,
      streams INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS clips (
      id SERIAL PRIMARY KEY,
      artist_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      thumb_url TEXT,
      video_url TEXT,
      scheduled_release_at TIMESTAMPTZ,
      published INTEGER DEFAULT 1,
      views INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- ---------- Concerts (Phase 2) — publiés directement par l'artiste, aucune validation
    -- admin nécessaire. tour_name regroupe plusieurs dates d'une même tournée pour l'affichage
    -- en timeline côté recherche. places_restantes est saisi/mis à jour manuellement par
    -- l'artiste (pas de vraie billetterie intégrée à NUNI pour l'instant — honnête plutôt que
    -- de prétendre suivre les ventes en temps réel). purchase_link pointe vers le canal réel
    -- de vente (WhatsApp, plateforme de billetterie externe...).
    CREATE TABLE IF NOT EXISTS concerts (
      id SERIAL PRIMARY KEY,
      artist_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      description TEXT,
      flyer_url TEXT,
      event_date DATE NOT NULL,
      start_time TEXT,
      end_time TEXT,
      city TEXT NOT NULL,
      country TEXT NOT NULL,
      venue TEXT,
      address TEXT,
      gps_lat DOUBLE PRECISION,
      gps_lng DOUBLE PRECISION,
      ticket_price TEXT,
      ticket_type TEXT,
      capacity INTEGER,
      places_restantes INTEGER,
      purchase_link TEXT,
      tour_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- ---------- NUNI Événements (préparée pour la Phase 3) — gérés uniquement depuis
    -- l'admin, jamais par un artiste. Table créée dès maintenant pour éviter une migration
    -- séparée plus tard ; aucune route ne l'utilise encore.
    CREATE TABLE IF NOT EXISTS nuni_events (
      id SERIAL PRIMARY KEY,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      flyer_url TEXT,
      event_date DATE NOT NULL,
      start_time TEXT,
      venue TEXT,
      address TEXT,
      gps_lat DOUBLE PRECISION,
      gps_lng DOUBLE PRECISION,
      price TEXT,
      purchase_link TEXT,
      capacity INTEGER,
      places_restantes INTEGER,
      gallery_urls TEXT,
      promo_video_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- ============ PASS LABEL (Phase 1) ============
    -- Un Label a son propre compte de connexion (une ligne dans users, account_type='label')
    -- mais ses informations spécifiques (légales, logo, vérification...) vivent ici plutôt
    -- que de polluer la table users — même logique que artist_name/label_or_manager qui, eux,
    -- restent sur users car légers et communs à tous les comptes.
    CREATE TABLE IF NOT EXISTS labels (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
      label_name TEXT NOT NULL,
      logo_url TEXT,
      legal_name TEXT,
      country TEXT,
      city TEXT,
      address TEXT,
      professional_phone TEXT,
      professional_email TEXT,
      website TEXT,
      tax_id TEXT,
      description TEXT,
      social_links TEXT,
      responsible_name TEXT,
      responsible_id_doc_url TEXT,
      label_doc_url TEXT,
      plan TEXT NOT NULL DEFAULT 'start' CHECK(plan IN ('start','pro','premium','elite')),
      -- 'pending' = vient de s'inscrire, en file d'attente. 'verification' = en cours
      -- d'examen par l'équipe. 'validated' = actif. 'refused' = refusé (avec raison).
      verification_status TEXT NOT NULL DEFAULT 'pending' CHECK(verification_status IN ('pending','verification','validated','refused','suspended')),
      refusal_reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      validated_at TIMESTAMPTZ
    );

    -- ---------- Artistes gérés par un Label ----------
    -- IMPORTANT : un compte artiste reste 100% autonome et fonctionnel même sans Label — ceci
    -- est une AFFILIATION optionnelle, jamais une dépendance. Rien dans le flux de publication
    -- existant (tracks/clips/concerts, tous rattachés à artist_id) n'est modifié par cette table.
    CREATE TABLE IF NOT EXISTS label_artists (
      id SERIAL PRIMARY KEY,
      label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
      artist_id INTEGER NOT NULL REFERENCES users(id),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('invited','active','suspended','removed')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(label_id, artist_id)
    );

    -- ---------- Équipe / rôles du Label ----------
    CREATE TABLE IF NOT EXISTS label_team_members (
      id SERIAL PRIMARY KEY,
      label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id),
      email TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'assistant' CHECK(role IN ('owner','admin','manager','assistant')),
      status TEXT NOT NULL DEFAULT 'invited' CHECK(status IN ('invited','active')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS promo_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      discount_pct INTEGER NOT NULL,
      applies_to_plan TEXT,
      max_uses INTEGER DEFAULT 1,
      used_count INTEGER DEFAULT 0,
      expires_at TIMESTAMPTZ,
      active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS follows (
      id SERIAL PRIMARY KEY,
      follower_id INTEGER NOT NULL REFERENCES users(id),
      artist_id INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(follower_id, artist_id)
    );

    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      plan TEXT NOT NULL,
      duration_days INTEGER NOT NULL,
      amount_fcfa INTEGER NOT NULL,
      promo_code TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS plays (
      id SERIAL PRIMARY KEY,
      track_id INTEGER NOT NULL REFERENCES tracks(id),
      listener_id INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS clip_views (
      id SERIAL PRIMARY KEY,
      clip_id INTEGER NOT NULL REFERENCES clips(id),
      viewer_id INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS track_likes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      track_id INTEGER NOT NULL REFERENCES tracks(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, track_id)
    );

    CREATE TABLE IF NOT EXISTS clip_likes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      clip_id INTEGER NOT NULL REFERENCES clips(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, clip_id)
    );

    CREATE TABLE IF NOT EXISTS clip_dislikes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      clip_id INTEGER NOT NULL REFERENCES clips(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, clip_id)
    );
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_status TEXT DEFAULT 'none';`);
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS lyrics TEXT;`);

  // ---------- Concerts — type d'événement, tarifs par catégorie de ticket, et infos d'achat
  // enrichies (au-delà d'un simple lien : lieux physiques où se procurer un ticket, et/ou
  // numéros de téléphone à contacter) ----------
  await pool.query(`ALTER TABLE concerts ADD COLUMN IF NOT EXISTS event_type TEXT DEFAULT 'concert';`); // 'concert' ou 'showcase'
  await pool.query(`ALTER TABLE concerts ADD COLUMN IF NOT EXISTS ticket_price_vip TEXT;`);
  await pool.query(`ALTER TABLE concerts ADD COLUMN IF NOT EXISTS ticket_price_standard TEXT;`);
  await pool.query(`ALTER TABLE concerts ADD COLUMN IF NOT EXISTS purchase_locations TEXT;`); // lieux physiques, texte libre
  await pool.query(`ALTER TABLE concerts ADD COLUMN IF NOT EXISTS purchase_phone_numbers TEXT;`); // numéros séparés par une virgule
  await pool.query(`ALTER TABLE nuni_events ADD COLUMN IF NOT EXISTS purchase_locations TEXT;`);
  await pool.query(`ALTER TABLE nuni_events ADD COLUMN IF NOT EXISTS purchase_phone_numbers TEXT;`);
  // Artistes participants — noms séparés par une virgule (pas d'ID rigide, cohérent avec le
  // reste de l'app où les correspondances se font par nom, ex. le genre musical par artiste).
  // Sert à afficher "Événements auxquels il participe" sur la page profil de chaque artiste.
  await pool.query(`ALTER TABLE nuni_events ADD COLUMN IF NOT EXISTS featured_artist_names TEXT;`);

  // ---------- État réel du compte (distinct du Pass/abonnement) ----------
  // subscription_status = état du Pass payant (inactive/pending/active/expired).
  // account_status = état du COMPTE lui-même, décidé par l'admin :
  //   - 'active'    : compte normal, login autorisé (comportement selon son Pass ensuite)
  //   - 'suspended' : login TOTALEMENT bloqué par l'admin, quel que soit le Pass
  //   - 'deleted'   : filet de sécurité si une suppression partielle a eu lieu
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status TEXT DEFAULT 'active';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS momo_number TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_url TEXT;`);
  // ---------- Pass Label — migration de la contrainte account_type ----------
  // Le CREATE TABLE plus haut ne s'exécute qu'une fois (IF NOT EXISTS) — sur une base déjà
  // créée avant l'ajout du Pass Label, la contrainte doit être élargie explicitement.
  // DROP puis ADD à chaque démarrage est volontairement inconditionnel : ça reste sans danger
  // et idempotent (le nom de contrainte suit la convention Postgres par défaut pour un CHECK
  // inline sur une colonne), contrairement à un ADD seul qui échouerait au 2e redémarrage.
  await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_account_type_check;`);
  await pool.query(`ALTER TABLE users ADD CONSTRAINT users_account_type_check CHECK (account_type IN ('consumer','artist','label'));`);
  await pool.query(`ALTER TABLE labels DROP CONSTRAINT IF EXISTS labels_verification_status_check;`);
  await pool.query(`ALTER TABLE labels ADD CONSTRAINT labels_verification_status_check CHECK (verification_status IN ('pending','verification','validated','refused','suspended'));`);
  await pool.query(`UPDATE users SET account_status = 'active' WHERE account_status IS NULL;`);

  // ---------- Réinitialisation de mot de passe (code temporaire par email) ----------
  // reset_code : code à 6 chiffres envoyé par email, à usage unique.
  // reset_code_expires_at : le code n'est valide que 15 minutes.
  // reset_code_attempts : compteur d'essais incorrects, pour bloquer le brute-force sur un
  // code à 6 chiffres (1 million de combinaisons, cassable en boucle sans cette limite).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_code TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_code_expires_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_code_attempts INTEGER DEFAULT 0;`);

  // ---------- Biographie réelle de l'artiste ----------
  // Avant : la bio affichée (page artiste + lecteur plein écran) venait d'un dictionnaire
  // codé en dur avec 6 faux artistes de démo — n'importe quel vrai artiste tombait sur un
  // texte générique ("Découvrez l'univers de X sur NUNI."), jamais modifiable. Ici : un vrai
  // champ texte, rempli par l'artiste lui-même depuis son tableau de bord (voir
  // PUT /api/artist/bio dans server.js).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS has_seen_artist_contract INTEGER DEFAULT 0;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_history (
      id SERIAL PRIMARY KEY,
      artist_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount_fcfa INTEGER NOT NULL,
      streams_covered INTEGER NOT NULL,
      period_start TIMESTAMPTZ,
      period_end TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      method TEXT DEFAULT 'Manuel',
      reference TEXT,
      note TEXT,
      admin_key_used TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_payment_history_artist ON payment_history(artist_id);`);

  // ---------- Codes promo attribués personnellement à un utilisateur ----------
  // Avant : un code promo était forcément partagé (comme NUNI30, "les 100 premiers
  // inscrits"). Ici : un code peut être réservé à UNE seule personne — l'admin le crée pour
  // récompenser un consommateur actif dans les défis quotidiens, ou un artiste. Si cette
  // colonne est vide, le code reste un code partagé classique (comportement inchangé).
  await pool.query(`ALTER TABLE promo_codes ADD COLUMN IF NOT EXISTS assigned_to_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;`);
  await pool.query(`ALTER TABLE promo_codes ADD COLUMN IF NOT EXISTS note TEXT;`);

  // ---------- Progression réelle (XP, niveaux, série d'écoute) ----------
  // Fondation du système de gamification demandé : plus de badges/niveaux inventés,
  // tout est calculé à partir de vraies actions (écoutes, connexions, suivis, achats de Pass).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS xp INTEGER DEFAULT 0;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS streak_days INTEGER DEFAULT 0;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active_date DATE;`);

  // ---------- Crédits réels du morceau ----------
  // Avant : le formulaire de publication affichait des champs "Description", "Date de
  // sortie", "Compositeur / Auteur", "Featuring", "Studio d'enregistrement" — mais rien
  // n'était jamais envoyé au serveur ni sauvegardé. Les paroles étaient le seul champ
  // vraiment branché. Ces colonnes stockent enfin les vrais crédits renseignés par
  // l'artiste, affichés à la fois dans le lecteur (au lancement du son) et dans la
  // fenêtre "Crédits" accessible depuis la page artiste.
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS composer TEXT;`);
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS featuring TEXT;`);
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS studio TEXT;`);
  // Crédits / label — la mention type "℗ 2026 Nom du label" que l'artiste saisit lui-même
  // avant de publier, affichée en bas de la page album à côté du nombre de titres et de la
  // durée totale (calculés automatiquement, jamais saisis à la main).
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS credits TEXT;`);
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS description TEXT;`);
  await pool.query(`ALTER TABLE tracks ADD COLUMN IF NOT EXISTS release_date TIMESTAMPTZ;`);

  await pool.query(`ALTER TABLE clips ADD COLUMN IF NOT EXISTS dislikes INTEGER DEFAULT 0;`);

  // ---------- Contrainte d'unicité manquante sur plays/clip_views ----------
  // Avant : "déjà écouté/vu ?" était vérifié en code (SELECT puis INSERT), pas garanti par
  // la base — deux requêtes simultanées (double-clic, connexion lente qui retente) pouvaient
  // compter le même stream/vue deux fois, gonflant à tort les revenus réels de l'artiste.
  // Nettoie d'abord les doublons déjà présents (sinon la contrainte échouerait à la création),
  // recalcule honnêtement les compteurs à partir des vraies lignes dédupliquées, puis verrouille
  // au niveau base pour qu'un doublon devienne structurellement impossible désormais.
  await pool.query(`
    DELETE FROM plays a USING plays b
    WHERE a.id > b.id AND a.track_id = b.track_id AND a.listener_id = b.listener_id AND a.listener_id IS NOT NULL;
  `);
  await pool.query(`UPDATE tracks SET streams = (SELECT COUNT(*)::int FROM plays WHERE plays.track_id = tracks.id);`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_plays_unique_listener ON plays(track_id, listener_id) WHERE listener_id IS NOT NULL;`);

  await pool.query(`
    DELETE FROM clip_views a USING clip_views b
    WHERE a.id > b.id AND a.clip_id = b.clip_id AND a.viewer_id = b.viewer_id AND a.viewer_id IS NOT NULL;
  `);
  await pool.query(`UPDATE clips SET views = (SELECT COUNT(*)::int FROM clip_views WHERE clip_views.clip_id = clips.id);`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_clip_views_unique_viewer ON clip_views(clip_id, viewer_id) WHERE viewer_id IS NOT NULL;`);

  // ---------- Sons en vedette — sélectionnés par l'artiste pour sa biographie ----------
  // L'artiste choisit, parmi ses propres morceaux déjà publiés, jusqu'à 6 à mettre en avant
  // juste sous sa biographie, visibles par tout le monde sur sa page publique.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS featured_tracks (
      id SERIAL PRIMARY KEY,
      artist_id INTEGER NOT NULL REFERENCES users(id),
      track_id INTEGER NOT NULL REFERENCES tracks(id),
      position INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(artist_id, track_id)
    );
  `);

  // ---------- Défis quotidiens / hebdomadaires ----------
  // Progression par utilisateur, par défi, par période (jour ou semaine). completed_at posé
  // dès que la cible est atteinte, claimed_at posé quand l'XP a été récupérée (une seule fois).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS challenge_progress (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      challenge_key TEXT NOT NULL,
      period_key TEXT NOT NULL,
      progress INTEGER NOT NULL DEFAULT 0,
      completed_at TIMESTAMPTZ,
      claimed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, challenge_key, period_key)
    );
  `);

  // ---------- NUNI Points — monnaie virtuelle (étape 4 gamification) ----------
  // Gagnée par l'écoute, la connexion quotidienne et les défis complétés. Dépensée dans la
  // boutique contre des badges cosmétiques (aucune valeur réelle, jamais convertible en FCFA).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS nuni_points INTEGER DEFAULT 0;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shop_purchases (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      item_key TEXT NOT NULL,
      purchased_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, item_key)
    );
  `);

  // ---------- Cosmétiques équipés — personnalisation du profil (barre du haut) ----------
  // Un seul objet équipé par catégorie (couronne, casque, micro, cadre, badge, effet) —
  // garanti par la contrainte UNIQUE(user_id, category) + UPSERT atomique dans la route
  // d'équipement (même pattern que le reste : pas de check-then-write).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_equipped_cosmetics (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      category TEXT NOT NULL,
      item_key TEXT NOT NULL,
      equipped_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, category)
    );
  `);

  // ---------- NUNI Talent — vrais votes hebdomadaires ----------
  // Avant : classement 100% inventé (noms fictifs, streams aléatoires, votes jamais
  // enregistrés nulle part). Un seul vote par personne et par semaine, pour un vrai artiste.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS talent_votes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      artist_id INTEGER NOT NULL REFERENCES users(id),
      week_key TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, week_key)
    );
  `);

  // ---------- Bannières hero — gérées uniquement par l'admin ----------
  // Plusieurs photos possibles par section (accueil, top-congo...), tirée au hasard côté
  // client à chaque visite. Aucun utilisateur ne peut créer/modifier ces lignes — seul
  // admin.html (protégé par ADMIN_KEY) y a accès en écriture.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS hero_images (
      id SERIAL PRIMARY KEY,
      section TEXT NOT NULL,
      image_url TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // ---------- Notifications réelles ----------
  // Nouveau follower, nouvelle sortie d'un artiste suivi, palier de followers, rappel
  // d'absence — jamais de contenu inventé, uniquement de vrais événements déclenchés côté
  // serveur (voir createNotification dans server.js).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      link TEXT,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC);
  `);

  // ---------- Playlists NUNI — curées par l'équipe depuis admin.html ----------
  // Jamais de playlist générée automatiquement sans validation humaine (voir l'onglet
  // Playlists de admin.html, avec tirage aléatoire proposé comme point de départ seulement).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS playlists (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      cover_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS playlist_tracks (
      id SERIAL PRIMARY KEY,
      playlist_id INTEGER NOT NULL REFERENCES playlists(id) ON DELETE CASCADE,
      track_id INTEGER NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
      position INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_playlist_tracks_playlist ON playlist_tracks(playlist_id, position);
  `);

  // ---------- Signalements de morceaux — vrais, consultables côté admin ----------
  // Avant : le bouton "Signaler" affichait juste un message de confirmation, sans jamais
  // rien enregistrer nulle part. Maintenant : un vrai signalement, avec motif.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS track_reports (
      id SERIAL PRIMARY KEY,
      track_id INTEGER NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
      reporter_id INTEGER REFERENCES users(id),
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  // ---------- Notifications push réelles (Web Push, iOS Safari 16.4+ / Android Chrome) ----------
  // Un compte peut avoir plusieurs abonnements (plusieurs appareils/navigateurs). endpoint est
  // unique : un même appareil ne peut être enregistré deux fois pour le même compte.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      endpoint TEXT NOT NULL UNIQUE,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);
  `);
}

module.exports = { pool, query, get, run, initSchema };
