// server.js — Serveur NUNI (Express + node:sqlite)
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const {
  hashPassword, verifyPassword, signToken, generateAccessCode, authMiddleware,
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
      access_code = @access_code,
      is_verified = CASE WHEN account_type = 'artist' THEN 1 ELSE is_verified END
  WHERE id = @id
`);
const insertTrack = db.prepare(`
  INSERT INTO tracks (artist_id, title, album, genre, release_type, cover_url, audio_url, scheduled_release_at, published)
  VALUES (@artist_id, @title, @album, @genre, @release_type, @cover_url, @audio_url, @scheduled_release_at, @published)
`);
const insertClip = db.prepare(`
  INSERT INTO clips (artist_id, title, thumb_url, video_url, scheduled_release_at, published)
  VALUES (@artist_id, @title, @thumb_url, @video_url, @scheduled_release_at, @published)
`);

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
    user: publicUser(user),
  });
});

// Connexion
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail.get(email || '');
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  const ok = await verifyPassword(password || '', user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
});

// Profil courant
app.get('/api/me', authMiddleware, (req, res) => {
  const user = findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  res.json({ user: publicUser(user) });
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

// Fonction commune : génère le code, active l'abonnement et envoie l'email à l'admin.
async function activateAndNotify(user, plan, durationDays) {
  const access_code = generateAccessCode();
  activateSubscription.run({
    id: user.id,
    plan,
    duration: `+${durationDays} days`,
    access_code,
  });
  const mailResult = await sendAccessCodeEmail({
    user, plan, accessCode: access_code, durationDays,
  });
  return { access_code, emailSent: mailResult.sent, emailReason: mailResult.reason };
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
  const { userId, plan, durationDays } = req.body;
  const user = findUserById.get(userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  const result = await activateAndNotify(user, plan || user.plan || 'consumer', durationDays || 90);
  res.json({
    message: 'Abonnement activé.',
    access_code: result.access_code,
    emailSent: result.emailSent,
    sentTo: process.env.EMAIL_USER,
  });
});

// Étape 2 (par EMAIL) : identique, mais plus simple à utiliser depuis /admin.html
// (pas besoin de connaître l'id interne du client, juste son email d'inscription).
app.post('/api/admin/activate-by-email', async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, plan, durationDays } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });

  const user = findUserByEmail.get(email);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });

  const result = await activateAndNotify(user, plan || user.plan || 'consumer', durationDays || 90);
  res.json({
    message: 'Abonnement activé.',
    access_code: result.access_code,
    emailSent: result.emailSent,
    sentTo: process.env.EMAIL_USER,
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
  res.json({ message: 'Accès débloqué — bienvenue sur NUNI en intégralité 🕊️', user: publicUser(findUserById.get(user.id)) });
});

// ================= MUSIQUE & CLIPS (artiste) =================

app.post('/api/tracks', authMiddleware, (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { title, album, genre, releaseType, coverUrl, audioUrl, scheduledReleaseAt } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();
  const info = insertTrack.run({
    artist_id: req.user.id, title, album: album || null, genre: genre || null,
    release_type: releaseType || 'Single', cover_url: coverUrl || null, audio_url: audioUrl || null,
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
    SELECT t.id, t.title, t.album, t.genre, t.release_type, t.cover_url, t.audio_url,
           t.streams, t.likes, t.created_at, u.artist_name, u.is_verified
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1 AND (t.scheduled_release_at IS NULL OR t.scheduled_release_at <= datetime('now'))
    ORDER BY t.created_at DESC
  `).all();
  res.json({ tracks: rows });
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

function publicUser(u) {
  const { password_hash, ...safe } = u;
  return safe;
}

// ---------- Publication planifiée : job qui "sort" les titres/clips programmés ----------
setInterval(() => {
  db.prepare(`UPDATE tracks SET published = 1 WHERE published = 0 AND scheduled_release_at <= datetime('now')`).run();
  db.prepare(`UPDATE clips SET published = 1 WHERE published = 0 AND scheduled_release_at <= datetime('now')`).run();
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NUNI backend en écoute sur http://localhost:${PORT}`));

module.exports = app;
