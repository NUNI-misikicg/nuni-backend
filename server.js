// server.js — Serveur NUNI (Express + node:sqlite)
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const {
  hashPassword, verifyPassword, signToken, verifyToken, generateAccessCode, authMiddleware,
} = require('./auth');
const { sendAccessCodeEmail } = require('./mailer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' })); // limite augmentée pour accepter les fichiers audio/pochette encodés
app.use(express.static(path.join(__dirname, 'public'))); // sert /admin.html

// ---------- Prepared statements ----------
const insertUser = db.prepare(`
  INSERT INTO users (account_type, first_name, last_name, email, phone, password_hash, age, address, city, country, artist_name, label_or_manager)
  VALUES (@account_type, @first_name, @last_name, @email, @phone, @password_hash, @age, @address, @city, @country, @artist_name, @label_or_manager)
`);
const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const setPendingSubscription = db.prepare(`
  UPDATE users SET plan = ?, subscription_status = 'pending' WHERE id = ?
`);
const activateSubscription = db.prepare(`
  UPDATE users
  SET subscription_status = 'active',
      plan = @plan,
      subscription_started_at = datetime('now'),
      subscription_expires_at = datetime('now', @duration),
      access_code = @access_code
  WHERE id = @id
`);
const insertTrack = db.prepare(`
  INSERT INTO tracks (artist_id, title, album, genre, release_type, cover_url, audio_url, lyrics, scheduled_release_at, published)
  VALUES (@artist_id, @title, @album, @genre, @release_type, @cover_url, @audio_url, @lyrics, @scheduled_release_at, @published)
`);
const insertClip = db.prepare(`
  INSERT INTO clips (artist_id, title, thumb_url, video_url, scheduled_release_at, published)
  VALUES (@artist_id, @title, @thumb_url, @video_url, @scheduled_release_at, @published)
`);
const findPromoCode = db.prepare('SELECT * FROM promo_codes WHERE code = ?');
const incrementPromoUsage = db.prepare('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = ?');
const insertPromoCode = db.prepare(`
  INSERT INTO promo_codes (code, discount_pct, applies_to_plan, max_uses, expires_at)
  VALUES (@code, @discount_pct, @applies_to_plan, @max_uses, @expires_at)
`);
const insertPayment = db.prepare(`
  INSERT INTO payments (user_id, plan, duration_days, amount_fcfa, promo_code)
  VALUES (@user_id, @plan, @duration_days, @amount_fcfa, @promo_code)
`);

// Prix de référence par Pass/durée (mêmes montants que ceux affichés sur le site).
// Pour une durée non listée exactement, le prix est calculé au prorata du tarif à 90 jours,
// pour ne jamais tomber sur un montant à 0 FCFA par erreur.
const PRICE_TABLE = {
  consumer: { 30: 650, 90: 650, 365: 1500 },
  artist:   { 90: 5000, 365: 10000 },
};
function basePriceFor(plan, durationDays) {
  const table = PRICE_TABLE[plan] || PRICE_TABLE.consumer;
  if (table[durationDays] != null) return table[durationDays];
  const refDays = table[90] ? 90 : 365;
  const ref = table[refDays] || Object.values(table)[0] || 0;
  return Math.round((ref / refDays) * durationDays);
}

// Vérifie un code promo : existe, actif, pas expiré, pas épuisé, compatible avec le Pass choisi.
function resolvePromoDiscount(code, plan) {
  if (!code) return { pct: 0, valid: true, code: null };
  const promo = findPromoCode.get(String(code).toUpperCase().trim());
  if (!promo) return { pct: 0, valid: false, error: 'Code promo introuvable.' };
  if (!promo.active) return { pct: 0, valid: false, error: 'Code promo désactivé.' };
  if (promo.expires_at && new Date(promo.expires_at) < new Date()) return { pct: 0, valid: false, error: 'Code promo expiré.' };
  if (promo.used_count >= promo.max_uses) return { pct: 0, valid: false, error: "Ce code a atteint sa limite d'utilisation." };
  if (promo.applies_to_plan && promo.applies_to_plan !== plan) return { pct: 0, valid: false, error: "Ce code ne s'applique pas à ce Pass." };
  return { pct: promo.discount_pct, valid: true, code: promo.code };
}

// Verrouillage automatique : si la date d'expiration est dépassée, on repasse le compte en "expired"
// tout seul — même si personne n'a eu le temps d'intervenir manuellement. Appelée avant chaque lecture
// de compte sensible (connexion, /api/me, listes admin), donc l'écart avec la vraie expiration ne peut
// jamais dépasser le temps entre deux consultations.
const expireOverdueSubscriptions = db.prepare(`
  UPDATE users SET subscription_status = 'expired'
  WHERE subscription_status = 'active'
    AND subscription_expires_at IS NOT NULL
    AND subscription_expires_at < datetime('now')
`);
function enforceSubscriptionExpiry() {
  try { expireOverdueSubscriptions.run(); } catch (e) { /* ne bloque jamais une requête si ça échoue */ }
}

// ---------- Validation helpers ----------
function isEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v || ''); }
function required(obj, fields) {
  return fields.filter((f) => !obj[f] || String(obj[f]).trim() === '');
}

// ================= AUTH =================

// Inscription — fiche de renseignement Consommateur ou Artiste
app.post('/api/register', async (req, res) => {
  const {
    accountType, firstName, lastName, email, phone, password,
    age, address, city, country, artistName, labelOrManager,
  } = req.body;

  if (!['consumer', 'artist'].includes(accountType)) {
    return res.status(400).json({ error: "Type de compte invalide (consumer ou artist)." });
  }

  const baseRequired = ['firstName', 'lastName', 'email', 'password', 'age', 'address', 'city', 'country'];
  const missing = required(req.body, accountType === 'artist' ? [...baseRequired, 'artistName'] : baseRequired);
  if (missing.length) {
    return res.status(400).json({ error: `Champs manquants : ${missing.join(', ')}` });
  }
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  if (Number(age) < 16) return res.status(400).json({ error: 'NUNI est réservé aux 16 ans et plus.' });

  if (findUserByEmail.get(email)) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }

  const password_hash = await hashPassword(password);
  const info = insertUser.run({
    account_type: accountType,
    first_name: firstName,
    last_name: lastName,
    email,
    phone: phone || null,
    password_hash,
    age: Number(age),
    address,
    city,
    country,
    artist_name: accountType === 'artist' ? artistName : null,
    label_or_manager: accountType === 'artist' ? (labelOrManager || null) : null,
  });

  const user = findUserById.get(info.lastInsertRowid);
  const token = signToken(user);
  res.status(201).json({
    message: 'Compte créé. Choisissez maintenant votre Pass pour continuer sur WhatsApp.',
    token,
    user: publicUser(withArtistStats(user)),
  });
});

// Connexion
app.post('/api/login', async (req, res) => {
  enforceSubscriptionExpiry();
  const { email, password } = req.body;
  const user = findUserByEmail.get(email || '');
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  const ok = await verifyPassword(password || '', user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  const token = signToken(user);
  res.json({ token, user: publicUser(withArtistStats(user)) });
});

// Profil courant
app.get('/api/me', authMiddleware, (req, res) => {
  enforceSubscriptionExpiry();
  const user = findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  res.json({ user: publicUser(withArtistStats(user)) });
});

// ================= ABONNEMENT =================

// Étape 1 : l'utilisateur choisit un Pass -> statut "pending", redirection WhatsApp côté front
app.post('/api/subscribe/request', authMiddleware, (req, res) => {
  const { plan } = req.body; // 'consumer' ou 'artist'
  if (!['consumer', 'artist'].includes(plan)) return res.status(400).json({ error: 'Pass invalide.' });
  setPendingSubscription.run(plan, req.user.id);
  res.json({
    message: 'Demande enregistrée. Finalisez le paiement sur WhatsApp, puis attendez votre code d\'accès.',
    whatsapp: 'https://wa.me/242068951600',
  });
});

// Fonction commune : génère le code, active l'abonnement, calcule le montant encaissé
// (avec code promo éventuel), l'enregistre, et envoie l'email à l'admin.
async function activateAndNotify(user, plan, durationDays, promoCode) {
  const access_code = generateAccessCode();
  activateSubscription.run({
    id: user.id,
    plan,
    duration: `+${durationDays} days`,
    access_code,
  });

  const promoResult = resolvePromoDiscount(promoCode, plan);
  const base = basePriceFor(plan, durationDays);
  const amount_fcfa = (promoResult.valid && promoResult.pct)
    ? Math.round(base * (1 - promoResult.pct / 100))
    : base;

  insertPayment.run({
    user_id: user.id, plan, duration_days: durationDays,
    amount_fcfa, promo_code: (promoResult.valid && promoResult.code) ? promoResult.code : null,
  });
  if (promoResult.valid && promoResult.code) incrementPromoUsage.run(promoResult.code);

  const mailResult = await sendAccessCodeEmail({
    user, plan, accessCode: access_code, durationDays,
  });
  return {
    access_code, emailSent: mailResult.sent, emailReason: mailResult.reason,
    amount_fcfa,
    promoApplied: (promoResult.valid && promoResult.code) ? promoResult.code : null,
    promoWarning: (!promoResult.valid && promoCode) ? promoResult.error : null,
  };
}

function checkAdminKey(req, res) {
  const adminKey = req.headers['x-admin-key'];
  if (!process.env.ADMIN_KEY || adminKey !== process.env.ADMIN_KEY) {
    res.status(403).json({ error: 'Clé admin invalide.' });
    return false;
  }
  return true;
}

// Étape 2 (par ID) : VOUS (admin) confirmez le paiement reçu sur WhatsApp -> génère le code, l'active
// et envoie automatiquement un email récapitulatif à EMAIL_USER (nunimisiki@gmail.com).
app.post('/api/admin/activate', async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { userId, plan, durationDays, promoCode } = req.body;
  const user = findUserById.get(userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  const result = await activateAndNotify(user, plan || user.plan || 'consumer', durationDays || 90, promoCode);
  res.json({
    message: 'Abonnement activé.',
    access_code: result.access_code,
    emailSent: result.emailSent,
    sentTo: process.env.EMAIL_USER,
    amount_fcfa: result.amount_fcfa,
    promoApplied: result.promoApplied,
    promoWarning: result.promoWarning,
  });
});

// Étape 2 (par EMAIL) : identique, mais plus simple à utiliser depuis /admin.html
// (pas besoin de connaître l'id interne du client, juste son email d'inscription).
app.post('/api/admin/activate-by-email', async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, plan, durationDays, promoCode } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });

  const user = findUserByEmail.get(email);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });

  const result = await activateAndNotify(user, plan || user.plan || 'consumer', durationDays || 90, promoCode);
  res.json({
    message: 'Abonnement activé.',
    access_code: result.access_code,
    emailSent: result.emailSent,
    sentTo: process.env.EMAIL_USER,
    amount_fcfa: result.amount_fcfa,
    promoApplied: result.promoApplied,
    promoWarning: result.promoWarning,
  });
});

// Étape 3 : l'utilisateur saisit le code reçu (transmis par vous sur WhatsApp) pour débloquer son accès
app.post('/api/subscribe/redeem', authMiddleware, (req, res) => {
  const { code } = req.body;
  const user = findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.subscription_status !== 'active') {
    return res.status(400).json({ error: "Aucun paiement confirmé pour ce compte pour l'instant." });
  }
  if (String(code).toUpperCase() !== user.access_code) {
    return res.status(400).json({ error: 'Code invalide.' });
  }
  res.json({ message: 'Accès débloqué — bienvenue sur NUNI en intégralité 🕊️', user: publicUser(withArtistStats(findUserById.get(user.id))) });
});

// ================= MUSIQUE & CLIPS (artiste) =================

app.post('/api/tracks', authMiddleware, (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { title, album, genre, releaseType, coverUrl, audioUrl, lyrics, scheduledReleaseAt } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();
  const info = insertTrack.run({
    artist_id: req.user.id, title, album: album || null, genre: genre || null,
    release_type: releaseType || 'Single', cover_url: coverUrl || null, audio_url: audioUrl || null,
    lyrics: lyrics || null,
    scheduled_release_at: scheduledReleaseAt || null, published: isFuture ? 0 : 1,
  });
  res.status(201).json({ id: info.lastInsertRowid, scheduled: isFuture });
});

app.post('/api/clips', authMiddleware, (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { title, thumbUrl, videoUrl, scheduledReleaseAt } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();
  const info = insertClip.run({
    artist_id: req.user.id, title, thumb_url: thumbUrl || null, video_url: videoUrl || null,
    scheduled_release_at: scheduledReleaseAt || null, published: isFuture ? 0 : 1,
  });
  res.status(201).json({ id: info.lastInsertRowid, scheduled: isFuture });
});

// Liste publique des morceaux publiés (tous artistes confondus)
app.get('/api/tracks', (req, res) => {
  const rows = db.prepare(`
    SELECT t.id, t.title, t.album, t.genre, t.release_type, t.cover_url, t.audio_url, t.lyrics,
           t.streams, t.likes, t.created_at, u.id as artist_id, u.artist_name, u.is_verified
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1 AND (t.scheduled_release_at IS NULL OR t.scheduled_release_at <= datetime('now'))
    ORDER BY t.created_at DESC
  `).all();
  res.json({ tracks: rows });
});

// Prix du système de streaming NUNI : chaque écoute réelle génère 2 FCFA,
// répartis 75% pour l'artiste et 25% pour NUNI (l'éditeur).
const NUNI_PRICE_PER_STREAM_FCFA = 2;
const NUNI_ARTIST_SHARE_PCT = 75;

const findExistingPlay = db.prepare('SELECT id FROM plays WHERE track_id = ? AND listener_id = ?');

// Enregistre une vraie écoute — mais compte UNE SEULE FOIS par auditeur et par morceau.
// Réécouter 10 ou 1000 fois ne fait jamais grimper le compteur au-delà de la première fois.
// Une écoute non connectée n'est jamais comptée (impossible de garantir l'unicité sans identité,
// et ça éviterait les abus faciles). L'artiste qui écoute son propre morceau n'est pas compté non plus.
app.post('/api/tracks/:id/play', (req, res) => {
  const trackId = Number(req.params.id);
  const track = db.prepare('SELECT id, artist_id, streams FROM tracks WHERE id = ?').get(trackId);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });

  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  const listenerId = payload ? payload.id : null;

  if (!listenerId) {
    return res.json({ counted: false, reason: 'Connectez-vous pour que votre écoute soit comptée.', streams: track.streams });
  }
  if (listenerId === track.artist_id) {
    return res.json({ counted: false, reason: "Une écoute de son propre morceau n'est pas comptée.", streams: track.streams });
  }
  if (findExistingPlay.get(trackId, listenerId)) {
    return res.json({ counted: false, reason: 'Déjà compté lors de votre première écoute de ce morceau.', streams: track.streams });
  }

  db.prepare('INSERT INTO plays (track_id, listener_id) VALUES (?, ?)').run(trackId, listenerId);
  db.prepare('UPDATE tracks SET streams = streams + 1 WHERE id = ?').run(trackId);
  res.json({ counted: true, streams: track.streams + 1 });
});

// Statistiques réelles de revenus pour le tableau de bord de l'artiste connecté
app.get('/api/artist/stats', authMiddleware, (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const row = db.prepare(`
    SELECT COALESCE(SUM(streams), 0) as total_streams
    FROM tracks WHERE artist_id = ?
  `).get(req.user.id);

  const totalStreams = row.total_streams;
  const grossFcfa = totalStreams * NUNI_PRICE_PER_STREAM_FCFA;
  const artistShareFcfa = Math.round(grossFcfa * NUNI_ARTIST_SHARE_PCT / 100);
  const platformShareFcfa = grossFcfa - artistShareFcfa;

  // Streams des 30 derniers jours, pour la tendance affichée sur le tableau de bord
  const recent = db.prepare(`
    SELECT COUNT(*) as n FROM plays p
    JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = ? AND p.created_at >= datetime('now', '-30 days')
  `).get(req.user.id);

  res.json({
    total_streams: totalStreams,
    streams_last_30_days: recent.n,
    gross_fcfa: grossFcfa,
    artist_share_fcfa: artistShareFcfa,
    platform_share_fcfa: platformShareFcfa,
    price_per_stream_fcfa: NUNI_PRICE_PER_STREAM_FCFA,
    artist_share_pct: NUNI_ARTIST_SHARE_PCT,
  });
});

// Suivre / ne plus suivre un vrai artiste (compte réel)
app.post('/api/follow', authMiddleware, (req, res) => {
  const { artistId } = req.body;
  const artist = findUserById.get(artistId);
  if (!artist || artist.account_type !== 'artist') return res.status(404).json({ error: 'Artiste introuvable.' });
  if (artist.id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas vous suivre vous-même.' });
  const existing = db.prepare(`SELECT * FROM follows WHERE follower_id = ? AND artist_id = ?`).get(req.user.id, artist.id);
  let following;
  if (existing) {
    db.prepare(`DELETE FROM follows WHERE follower_id = ? AND artist_id = ?`).run(req.user.id, artist.id);
    following = false;
  } else {
    db.prepare(`INSERT INTO follows (follower_id, artist_id) VALUES (?, ?)`).run(req.user.id, artist.id);
    following = true;
  }
  const followersCount = db.prepare(`SELECT COUNT(*) as c FROM follows WHERE artist_id = ?`).get(artist.id).c;
  res.json({ following, followersCount });
});

// Liste publique des clips publiés (aléatoire, tous artistes confondus)
app.get('/api/clips', (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.title, c.thumb_url, c.video_url, c.views, c.likes, u.artist_name
    FROM clips c JOIN users u ON u.id = c.artist_id
    WHERE c.published = 1 AND (c.scheduled_release_at IS NULL OR c.scheduled_release_at <= datetime('now'))
    ORDER BY RANDOM()
  `).all();
  res.json({ clips: rows });
});

const findExistingClipView = db.prepare('SELECT id FROM clip_views WHERE clip_id = ? AND viewer_id = ?');

// Enregistre une vraie vue de clip — même règle que les streams : une seule fois par spectateur,
// jamais pour l'artiste qui regarde son propre clip, jamais sans être connecté.
app.post('/api/clips/:id/view', (req, res) => {
  const clipId = Number(req.params.id);
  const clip = db.prepare('SELECT id, artist_id, views FROM clips WHERE id = ?').get(clipId);
  if (!clip) return res.status(404).json({ error: 'Clip introuvable.' });

  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  const viewerId = payload ? payload.id : null;

  if (!viewerId) {
    return res.json({ counted: false, reason: 'Connectez-vous pour que votre vue soit comptée.', views: clip.views });
  }
  if (viewerId === clip.artist_id) {
    return res.json({ counted: false, reason: "Une vue de son propre clip n'est pas comptée.", views: clip.views });
  }
  if (findExistingClipView.get(clipId, viewerId)) {
    return res.json({ counted: false, reason: 'Déjà compté lors de votre première vue de ce clip.', views: clip.views });
  }

  db.prepare('INSERT INTO clip_views (clip_id, viewer_id) VALUES (?, ?)').run(clipId, viewerId);
  db.prepare('UPDATE clips SET views = views + 1 WHERE id = ?').run(clipId);
  res.json({ counted: true, views: clip.views + 1 });
});

// ================= CERTIFICATION ARTISTE =================

// L'artiste demande sa certification (badge vérifié)
app.post('/api/verification/request', authMiddleware, (req, res) => {
  const user = findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.account_type !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  if (user.is_verified) return res.status(400).json({ error: 'Ce compte est déjà certifié.' });
  if (user.verification_status === 'pending') return res.status(400).json({ error: 'Une demande est déjà en attente.' });
  const stats = withArtistStats(user);
  const MIN_TRACKS = 50;
  const MIN_FOLLOWERS = 5000;
  if (stats.track_count < MIN_TRACKS || stats.follower_count < MIN_FOLLOWERS) {
    return res.status(403).json({
      error: `Conditions non remplies : ${stats.track_count}/${MIN_TRACKS} sons publiés, ${stats.follower_count}/${MIN_FOLLOWERS} abonnés.`,
    });
  }
  db.prepare(`UPDATE users SET verification_status = 'pending' WHERE id = ?`).run(user.id);
  res.json({ message: 'Demande de certification envoyée — en attente de validation NUNI.' });
});

// Liste des demandes en attente (admin)
// Liste de tous les utilisateurs inscrits (admin)
app.get('/api/admin/users', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  enforceSubscriptionExpiry();
  const rows = db.prepare(`
    SELECT u.id, u.account_type, u.first_name, u.last_name, u.email, u.artist_name,
           u.plan, u.subscription_status, u.is_verified, u.verification_status, u.created_at,
           (SELECT COUNT(*) FROM tracks t WHERE t.artist_id = u.id AND t.published = 1) as track_count,
           (SELECT COUNT(*) FROM follows f WHERE f.artist_id = u.id) as follower_count
    FROM users u
    ORDER BY u.created_at DESC
  `).all();
  res.json({ users: rows });
});

// Onglet "Argent à encaisser" : tous les Pass payants (actifs ou en attente), avec échéance d'expiration.
// Le verrouillage automatique (enforceSubscriptionExpiry) tourne juste avant, donc ce que l'admin voit
// ici est toujours à jour — un abonnement expiré n'apparaît plus jamais comme "actif" par erreur.
app.get('/api/admin/subscriptions', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  enforceSubscriptionExpiry();
  const rows = db.prepare(`
    SELECT u.id, u.first_name, u.last_name, u.email, u.account_type, u.artist_name, u.plan,
           u.subscription_status, u.subscription_started_at, u.subscription_expires_at,
           CAST((julianday(u.subscription_expires_at) - julianday('now')) AS INTEGER) as days_remaining,
           (SELECT p.amount_fcfa FROM payments p WHERE p.user_id = u.id ORDER BY p.created_at DESC LIMIT 1) as last_amount_fcfa
    FROM users u
    WHERE u.subscription_status IN ('active','pending','expired') AND u.plan != 'discovery'
    ORDER BY
      CASE u.subscription_status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,
      u.subscription_expires_at ASC
  `).all();
  const totalRow = db.prepare('SELECT COALESCE(SUM(amount_fcfa),0) as total FROM payments').get();
  res.json({ subscriptions: rows, total_collected_fcfa: totalRow.total });
});

// Codes promo — liste (admin)
app.get('/api/admin/promo-codes', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = db.prepare('SELECT * FROM promo_codes ORDER BY id DESC').all();
  res.json({ codes: rows });
});

// Codes promo — création (admin)
app.post('/api/admin/promo-codes', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { code, discount_pct, applies_to_plan, max_uses, expires_at } = req.body;
  if (!code || !discount_pct) return res.status(400).json({ error: 'Le code et le pourcentage de réduction sont obligatoires.' });
  try {
    insertPromoCode.run({
      code: String(code).toUpperCase().trim(),
      discount_pct: Number(discount_pct),
      applies_to_plan: applies_to_plan || null,
      max_uses: Number(max_uses) || 1,
      expires_at: expires_at || null,
    });
  } catch (e) {
    return res.status(400).json({ error: 'Ce code existe déjà.' });
  }
  res.json({ message: 'Code promo créé.' });
});

// Codes promo — activer/désactiver (admin)
app.post('/api/admin/promo-codes/toggle', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const promo = findPromoCode.get(String(req.body.code || '').toUpperCase().trim());
  if (!promo) return res.status(404).json({ error: 'Code introuvable.' });
  db.prepare('UPDATE promo_codes SET active = ? WHERE code = ?').run(promo.active ? 0 : 1, promo.code);
  res.json({ message: promo.active ? 'Code désactivé.' : 'Code réactivé.' });
});

// Codes promo — vérification publique (utilisée par l'écran des Pass sur le site)
app.post('/api/promo/validate', (req, res) => {
  const { code, plan } = req.body;
  const result = resolvePromoDiscount(code, plan);
  if (!result.valid) return res.status(400).json({ error: result.error || 'Code promo invalide.' });
  res.json({ discount_pct: result.pct, code: result.code });
});

app.get('/api/admin/verification/pending', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = db.prepare(`
    SELECT id, first_name, last_name, email, artist_name, created_at
    FROM users WHERE account_type = 'artist' AND verification_status = 'pending'
    ORDER BY created_at ASC
  `).all();
  res.json({ pending: rows });
});

// Approuve ou refuse une demande (admin)
app.post('/api/admin/verification/decide', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, approve } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  const user = findUserByEmail.get(email);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
  if (approve) {
    db.prepare(`UPDATE users SET verification_status = 'approved', is_verified = 1 WHERE id = ?`).run(user.id);
    res.json({ message: `${user.artist_name || user.first_name} est maintenant certifié(e). 🏅` });
  } else {
    db.prepare(`UPDATE users SET verification_status = 'rejected' WHERE id = ?`).run(user.id);
    res.json({ message: `Demande de ${user.artist_name || user.first_name} refusée.` });
  }
});

// Réinitialise la certification d'un compte (utile pour nettoyer les anciens comptes de test
// certifiés automatiquement avant la mise en place du vrai système de validation manuelle).
app.post('/api/admin/verification/reset', (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  const user = findUserByEmail.get(email);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
  db.prepare(`UPDATE users SET is_verified = 0, verification_status = 'none' WHERE id = ?`).run(user.id);
  res.json({ message: `Certification réinitialisée pour ${user.artist_name || user.first_name}.` });
});

// Ancienne page de certification — redirige vers le nouveau tableau de bord unique
app.get('/admin-verify.html', (req, res) => {
  res.redirect('/admin.html');
});

function publicUser(u) {
  const { password_hash, ...safe } = u;
  return safe;
}
function withArtistStats(u) {
  if (u.account_type !== 'artist') return u;
  const trackCount = db.prepare(`SELECT COUNT(*) as c FROM tracks WHERE artist_id = ? AND published = 1`).get(u.id).c;
  const followerCount = db.prepare(`SELECT COUNT(*) as c FROM follows WHERE artist_id = ?`).get(u.id).c;
  return { ...u, track_count: trackCount, follower_count: followerCount };
}

// ---------- Publication planifiée : job qui "sort" les titres/clips programmés ----------
setInterval(() => {
  db.prepare(`UPDATE tracks SET published = 1 WHERE published = 0 AND scheduled_release_at <= datetime('now')`).run();
  db.prepare(`UPDATE clips SET published = 1 WHERE published = 0 AND scheduled_release_at <= datetime('now')`).run();
}, 60 * 1000);

// ---------- Verrouillage automatique des abonnements expirés (en plus du contrôle à chaque connexion) ----------
// Couvre aussi les comptes que personne ne consulte activement pendant un moment.
enforceSubscriptionExpiry();
setInterval(enforceSubscriptionExpiry, 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NUNI backend en écoute sur http://localhost:${PORT}`));

module.exports = app;
