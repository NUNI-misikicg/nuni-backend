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
      account_type TEXT NOT NULL CHECK(account_type IN ('consumer','artist')),
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
