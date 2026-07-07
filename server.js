// server.js — Serveur NUNI (Express + Postgres/Neon + Cloudinary)
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const db = require('./db');
const {
  initAuth, hashPassword, verifyPassword, signToken, verifyToken, generateAccessCode, authMiddleware,
} = require('./auth');
const { sendAccessCodeEmail } = require('./mailer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function h(fn) {
  return (req, res) => fn(req, res).catch((err) => {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  });
}

async function uploadIfDataUri(value, resourceType) {
  if (!value) return null;
  if (!String(value).startsWith('data:')) return value;
  const result = await cloudinary.uploader.upload(value, {
    resource_type: resourceType,
    folder: 'nuni',
  });
  return result.secure_url;
}

app.get('/api/upload-signature', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const timestamp = Math.round(Date.now() / 1000);
  const folder = 'nuni';
  const signature = cloudinary.utils.api_sign_request({ timestamp, folder }, cloudinary.config().api_secret);
  res.json({
    signature, timestamp, folder,
    apiKey: cloudinary.config().api_key,
    cloudName: cloudinary.config().cloud_name,
  });
}));

const PRICE_TABLE = {
  consumer: { 30: 650, 90: 650, 365: 1500 },
  artist: { 90: 5000, 365: 10000 },
};
function basePriceFor(plan, durationDays) {
  const table = PRICE_TABLE[plan] || PRICE_TABLE.consumer;
  if (table[durationDays] != null) return table[durationDays];
  const refDays = table[90] ? 90 : 365;
  const ref = table[refDays] || Object.values(table)[0] || 0;
  return Math.round((ref / refDays) * durationDays);
}

async function resolvePromoDiscount(code, plan) {
  if (!code) return { pct: 0, valid: true, code: null };
  const promo = await db.get('SELECT * FROM promo_codes WHERE code = $1', [String(code).toUpperCase().trim()]);
  if (!promo) return { pct: 0, valid: false, error: 'Code promo introuvable.' };
  if (!promo.active) return { pct: 0, valid: false, error: 'Code promo désactivé.' };
  if (promo.expires_at && new Date(promo.expires_at) < new Date()) return { pct: 0, valid: false, error: 'Code promo expiré.' };
  if (promo.used_count >= promo.max_uses) return { pct: 0, valid: false, error: "Ce code a atteint sa limite d'utilisation." };
  if (promo.applies_to_plan && promo.applies_to_plan !== plan) return { pct: 0, valid: false, error: "Ce code ne s'applique pas à ce Pass." };
  return { pct: promo.discount_pct, valid: true, code: promo.code };
}

async function enforceSubscriptionExpiry() {
  try {
    await db.run(`
      UPDATE users SET subscription_status = 'expired'
      WHERE subscription_status = 'active'
        AND subscription_expires_at IS NOT NULL
        AND subscription_expires_at < NOW()
    `);
  } catch (e) { /* ne bloque jamais une requête si ça échoue */ }
}

function isEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v || ''); }
function required(obj, fields) {
  return fields.filter((f) => !obj[f] || String(obj[f]).trim() === '');
}
function publicUser(u) {
  const { password_hash, ...safe } = u;
  return safe;
}
async function withArtistStats(u) {
  if (u.account_type !== 'artist') return u;
  const trackCount = (await db.get('SELECT COUNT(*)::int as c FROM tracks WHERE artist_id = $1 AND published = 1', [u.id])).c;
  const followerCount = (await db.get('SELECT COUNT(*)::int as c FROM follows WHERE artist_id = $1', [u.id])).c;
  return { ...u, track_count: trackCount, follower_count: followerCount };
}

// ================= AUTH =================

app.post('/api/register', h(async (req, res) => {
  const {
    accountType, firstName, lastName, email, phone, password,
    age, address, city, country, artistName, labelOrManager,
  } = req.body;

  if (!['consumer', 'artist'].includes(accountType)) {
    return res.status(400).json({ error: 'Type de compte invalide (consumer ou artist).' });
  }

  const baseRequired = ['firstName', 'lastName', 'email', 'password', 'age', 'address', 'city', 'country'];
  const missing = required(req.body, accountType === 'artist' ? [...baseRequired, 'artistName'] : baseRequired);
  if (missing.length) {
    return res.status(400).json({ error: `Champs manquants : ${missing.join(', ')}` });
  }
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  if (Number(age) < 16) return res.status(400).json({ error: 'NUNI est réservé aux 16 ans et plus.' });

  if (await db.get('SELECT id FROM users WHERE email = $1', [email])) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }

  const password_hash = await hashPassword(password);
  const inserted = await db.get(`
    INSERT INTO users (account_type, first_name, last_name, email, phone, password_hash, age, address, city, country, artist_name, label_or_manager)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    RETURNING id
  `, [
    accountType, firstName, lastName, email, phone || null, password_hash, Number(age), address, city, country,
    accountType === 'artist' ? artistName : null,
    accountType === 'artist' ? (labelOrManager || null) : null,
  ]);

  const user = await db.get('SELECT * FROM users WHERE id = $1', [inserted.id]);
  const token = signToken(user);
  res.status(201).json({
    message: 'Compte créé. Choisissez maintenant votre Pass pour continuer sur WhatsApp.',
    token,
    user: publicUser(await withArtistStats(user)),
  });
}));

// ---------- Connexion : VRAIE vérification de l'état du compte, à chaque tentative ----------
// Ordre volontaire : on ne révèle rien sur l'existence du compte tant que le mot de passe
// n'est pas confirmé exact. Ce n'est qu'APRÈS un mot de passe correct qu'on vérifie si le
// compte est suspendu/supprimé — sinon on donnerait à n'importe qui un moyen de deviner
// quels emails ont un compte suspendu, juste en essayant de se connecter avec.
app.post('/api/login', h(async (req, res) => {
  await enforceSubscriptionExpiry();
  const { email, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email || '']);
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });

  const ok = await verifyPassword(password || '', user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });

  if (user.account_status === 'deleted') {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }
  if (user.account_status === 'suspended') {
    return res.status(403).json({ error: 'Votre compte a été suspendu par l\'administration. Contactez le support.' });
  }

  const token = signToken(user);
  res.json({ token, user: publicUser(await withArtistStats(user)) });
}));

app.get('/api/me', authMiddleware, h(async (req, res) => {
  await enforceSubscriptionExpiry();
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  res.json({ user: publicUser(await withArtistStats(user)) });
}));

// ================= ABONNEMENT =================

app.post('/api/subscribe/request', authMiddleware, h(async (req, res) => {
  const { plan } = req.body;
  if (!['consumer', 'artist'].includes(plan)) return res.status(400).json({ error: 'Pass invalide.' });
  await db.run(`UPDATE users SET plan = $1, subscription_status = 'pending' WHERE id = $2`, [plan, req.user.id]);
  res.json({
    message: 'Demande enregistrée. Finalisez le paiement sur WhatsApp, puis attendez votre code d\'accès.',
    whatsapp: 'https://wa.me/242068951600',
  });
}));

async function activateAndNotify(user, plan, durationDays, promoCode) {
  const access_code = generateAccessCode();
  await db.run(`
    UPDATE users
    SET subscription_status = 'active',
        plan = $1,
        subscription_started_at = NOW(),
        subscription_expires_at = NOW() + ($2 || ' days')::interval,
        access_code = $3
    WHERE id = $4
  `, [plan, String(durationDays), access_code, user.id]);

  const promoResult = await resolvePromoDiscount(promoCode, plan);
  const base = basePriceFor(plan, durationDays);
  const amount_fcfa = (promoResult.valid && promoResult.pct)
    ? Math.round(base * (1 - promoResult.pct / 100))
    : base;

  await db.run(`
    INSERT INTO payments (user_id, plan, duration_days, amount_fcfa, promo_code)
    VALUES ($1,$2,$3,$4,$5)
  `, [user.id, plan, durationDays, amount_fcfa, (promoResult.valid && promoResult.code) ? promoResult.code : null]);

  if (promoResult.valid && promoResult.code) {
    await db.run('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1', [promoResult.code]);
  }

  const mailResult = await sendAccessCodeEmail({ user, plan, accessCode: access_code, durationDays });
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

app.post('/api/admin/activate', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { userId, plan, durationDays, promoCode } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = $1', [userId]);
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
}));

app.post('/api/admin/activate-by-email', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, plan, durationDays, promoCode } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });

  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
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
}));

app.post('/api/subscribe/redeem', authMiddleware, h(async (req, res) => {
  const { code } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.subscription_status !== 'active') {
    return res.status(400).json({ error: "Aucun paiement confirmé pour ce compte pour l'instant." });
  }
  if (String(code).toUpperCase() !== user.access_code) {
    return res.status(400).json({ error: 'Code invalide.' });
  }
  const fresh = await db.get('SELECT * FROM users WHERE id = $1', [user.id]);
  res.json({ message: 'Accès débloqué — bienvenue sur NUNI en intégralité 🕊️', user: publicUser(await withArtistStats(fresh)) });
}));

// ================= MUSIQUE & CLIPS (artiste) =================

// ---------- Soutien direct (Mobile Money) — don volontaire du fan vers l'artiste ----------
// NUNI ne traite jamais ce paiement et ne prend aucune commission dessus : c'est un simple
// transfert Mobile Money classique entre le fan et l'artiste, hors de la plateforme. NUNI se
// contente d'afficher le numéro que l'artiste a bien voulu renseigner (totalement facultatif).
app.put('/api/artist/momo', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { momoNumber } = req.body;
  const cleaned = (momoNumber || '').trim();
  if (cleaned && !/^[0-9+ ]{6,20}$/.test(cleaned)) {
    return res.status(400).json({ error: 'Numéro invalide — utilisez uniquement des chiffres, espaces et le signe +.' });
  }
  await db.run('UPDATE users SET momo_number = $1 WHERE id = $2', [cleaned || null, req.user.id]);
  res.json({ message: cleaned ? 'Numéro Mobile Money enregistré.' : 'Numéro Mobile Money retiré.', momo_number: cleaned || null });
}));

app.get('/api/artist/:id/support-info', h(async (req, res) => {
  const artist = await db.get(
    'SELECT id, account_type, artist_name, first_name, momo_number FROM users WHERE id = $1',
    [Number(req.params.id)],
  );
  if (!artist || artist.account_type !== 'artist') return res.status(404).json({ error: 'Artiste introuvable.' });
  res.json({
    artist_name: artist.artist_name || artist.first_name,
    momo_number: artist.momo_number || null,
  });
}));

// ---------- Historique des paiements — calculé en direct depuis les vraies écoutes ----------
// Avant : deux lignes ("Mai 2026", "Juin 2026") codées en dur, identiques pour tout le monde.
// Maintenant : regroupement réel des écoutes (table plays) par mois, pour les morceaux de
// CET artiste précis. Pas de fausse mention "Payé/En attente" inventée : les vrais versements
// se font manuellement par NUNI, donc on affiche seulement les vrais chiffres calculés.
app.get('/api/artist/payments-history', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const rows = await db.query(`
    SELECT to_char(date_trunc('month', p.created_at), 'YYYY-MM') as month, COUNT(*)::int as streams
    FROM plays p
    JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = $1
    GROUP BY date_trunc('month', p.created_at)
    ORDER BY date_trunc('month', p.created_at) DESC
    LIMIT 12
  `, [req.user.id]);

  const history = rows.map((r) => {
    const gross = r.streams * NUNI_PRICE_PER_STREAM_FCFA;
    const artistShare = Math.round(gross * NUNI_ARTIST_SHARE_PCT / 100);
    return { month: r.month, streams: r.streams, artist_share_fcfa: artistShare };
  });
  res.json({ history });
}));

app.post('/api/tracks', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { title, album, genre, releaseType, coverUrl, audioUrl, lyrics, scheduledReleaseAt } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();

  const [finalCoverUrl, finalAudioUrl] = await Promise.all([
    uploadIfDataUri(coverUrl, 'image'),
    uploadIfDataUri(audioUrl, 'video'),
  ]);

  const inserted = await db.get(`
    INSERT INTO tracks (artist_id, title, album, genre, release_type, cover_url, audio_url, lyrics, scheduled_release_at, published)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    RETURNING id
  `, [
    req.user.id, title, album || null, genre || null, releaseType || 'Single',
    finalCoverUrl || null, finalAudioUrl || null, lyrics || null,
    scheduledReleaseAt || null, isFuture ? 0 : 1,
  ]);
  res.status(201).json({ id: inserted.id, scheduled: isFuture });
}));

app.post('/api/clips', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { title, thumbUrl, videoUrl, scheduledReleaseAt } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();

  const [finalThumbUrl, finalVideoUrl] = await Promise.all([
    uploadIfDataUri(thumbUrl, 'image'),
    uploadIfDataUri(videoUrl, 'video'),
  ]);

  const inserted = await db.get(`
    INSERT INTO clips (artist_id, title, thumb_url, video_url, scheduled_release_at, published)
    VALUES ($1,$2,$3,$4,$5,$6)
    RETURNING id
  `, [req.user.id, title, finalThumbUrl || null, finalVideoUrl || null, scheduledReleaseAt || null, isFuture ? 0 : 1]);
  res.status(201).json({ id: inserted.id, scheduled: isFuture });
}));

// ---------- Statistique publique — vrai nombre de comptes avec un Pass actif ----------
// Remplace l'ancien compteur de démo qui s'incrémentait aléatoirement depuis un chiffre
// inventé. Ici c'est une vraie requête sur la base : nombre de comptes (Consommateur +
// Artiste confondus) dont le Pass est actuellement actif.
app.get('/api/stats/public', h(async (req, res) => {
  await enforceSubscriptionExpiry();
  const row = await db.get(`SELECT COUNT(*)::int as c FROM users WHERE subscription_status = 'active'`);
  res.json({ active_users: row.c });
}));

app.get('/api/tracks', h(async (req, res) => {
  const rows = await db.query(`
    SELECT t.id, t.title, t.album, t.genre, t.release_type, t.cover_url, t.audio_url, t.lyrics,
           t.streams, t.likes, t.created_at, u.id as artist_id, u.artist_name, u.is_verified
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1 AND (t.scheduled_release_at IS NULL OR t.scheduled_release_at <= NOW())
    ORDER BY t.created_at DESC
  `);
  res.json({ tracks: rows });
}));

const NUNI_PRICE_PER_STREAM_FCFA = 2;
const NUNI_ARTIST_SHARE_PCT = 75;

app.post('/api/tracks/:id/play', h(async (req, res) => {
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id, artist_id, streams FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });

  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  const listenerId = payload ? payload.id : null;

  if (!listenerId) {
    return res.json({ counted: false, reason: 'Connectez-vous pour que votre écoute soit comptée.', streams: track.streams });
  }
  if (payload.accountType !== 'consumer') {
    return res.json({ counted: false, reason: "Seules les écoutes via un Pass Consommateur génèrent un stream.", streams: track.streams });
  }
  if (await db.get('SELECT id FROM plays WHERE track_id = $1 AND listener_id = $2', [trackId, listenerId])) {
    return res.json({ counted: false, reason: 'Déjà compté lors de votre première écoute de ce morceau.', streams: track.streams });
  }

  await db.run('INSERT INTO plays (track_id, listener_id) VALUES ($1,$2)', [trackId, listenerId]);
  await db.run('UPDATE tracks SET streams = streams + 1 WHERE id = $1', [trackId]);
  res.json({ counted: true, streams: track.streams + 1 });
}));

// ---------- Likes réels sur les morceaux (persistés, un seul like par personne) ----------
app.post('/api/tracks/:id/like', authMiddleware, h(async (req, res) => {
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id, likes FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });

  const existing = await db.get('SELECT id FROM track_likes WHERE user_id = $1 AND track_id = $2', [req.user.id, trackId]);
  let liked;
  if (existing) {
    await db.run('DELETE FROM track_likes WHERE user_id = $1 AND track_id = $2', [req.user.id, trackId]);
    await db.run('UPDATE tracks SET likes = GREATEST(likes - 1, 0) WHERE id = $1', [trackId]);
    liked = false;
  } else {
    await db.run('INSERT INTO track_likes (user_id, track_id) VALUES ($1,$2)', [req.user.id, trackId]);
    await db.run('UPDATE tracks SET likes = likes + 1 WHERE id = $1', [trackId]);
    liked = true;
  }
  const fresh = await db.get('SELECT likes FROM tracks WHERE id = $1', [trackId]);
  res.json({ liked, likes: fresh.likes });
}));

// Liste des morceaux likés par l'utilisateur connecté — sert à resynchroniser les cœurs
// (Favoris) après une reconnexion ou sur un autre appareil, au lieu de repartir de zéro.
app.get('/api/me/liked-tracks', authMiddleware, h(async (req, res) => {
  const rows = await db.query('SELECT track_id FROM track_likes WHERE user_id = $1', [req.user.id]);
  res.json({ track_ids: rows.map((r) => r.track_id) });
}));

// ---------- Likes réels sur les clips ----------
app.post('/api/clips/:id/like', authMiddleware, h(async (req, res) => {
  const clipId = Number(req.params.id);
  const clip = await db.get('SELECT id, likes FROM clips WHERE id = $1', [clipId]);
  if (!clip) return res.status(404).json({ error: 'Clip introuvable.' });

  const existing = await db.get('SELECT id FROM clip_likes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
  let liked;
  if (existing) {
    await db.run('DELETE FROM clip_likes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
    await db.run('UPDATE clips SET likes = GREATEST(likes - 1, 0) WHERE id = $1', [clipId]);
    liked = false;
  } else {
    await db.run('INSERT INTO clip_likes (user_id, clip_id) VALUES ($1,$2)', [req.user.id, clipId]);
    await db.run('UPDATE clips SET likes = likes + 1 WHERE id = $1', [clipId]);
    liked = true;
  }
  const fresh = await db.get('SELECT likes FROM clips WHERE id = $1', [clipId]);
  res.json({ liked, likes: fresh.likes });
}));

// ---------- Statut de suivi réel — pour afficher "Suivre" / "Suivi ✓" au bon état à l'ouverture ----------
// Avant : le bouton affichait toujours "Suivre" par défaut, même si le compte connecté suivait déjà
// cet artiste — jamais vérifié contre la vraie base au moment d'ouvrir la page.
app.get('/api/follow/:artistId/status', authMiddleware, h(async (req, res) => {
  const artistId = Number(req.params.artistId);
  const existing = await db.get('SELECT id FROM follows WHERE follower_id = $1 AND artist_id = $2', [req.user.id, artistId]);
  res.json({ following: !!existing });
}));

app.get('/api/artist/stats', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const row = await db.get('SELECT COALESCE(SUM(streams), 0)::int as total_streams FROM tracks WHERE artist_id = $1', [req.user.id]);

  const totalStreams = row.total_streams;
  const grossFcfa = totalStreams * NUNI_PRICE_PER_STREAM_FCFA;
  const artistShareFcfa = Math.round(grossFcfa * NUNI_ARTIST_SHARE_PCT / 100);
  const platformShareFcfa = grossFcfa - artistShareFcfa;

  const recent = await db.get(`
    SELECT COUNT(*)::int as n FROM plays p
    JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = $1 AND p.created_at >= NOW() - INTERVAL '30 days'
  `, [req.user.id]);

  res.json({
    total_streams: totalStreams,
    streams_last_30_days: recent.n,
    gross_fcfa: grossFcfa,
    artist_share_fcfa: artistShareFcfa,
    platform_share_fcfa: platformShareFcfa,
    price_per_stream_fcfa: NUNI_PRICE_PER_STREAM_FCFA,
    artist_share_pct: NUNI_ARTIST_SHARE_PCT,
  });
}));

app.post('/api/follow', authMiddleware, h(async (req, res) => {
  const { artistId } = req.body;
  const artist = await db.get('SELECT * FROM users WHERE id = $1', [artistId]);
  if (!artist || artist.account_type !== 'artist') return res.status(404).json({ error: 'Artiste introuvable.' });
  if (artist.id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas vous suivre vous-même.' });
  const existing = await db.get('SELECT * FROM follows WHERE follower_id = $1 AND artist_id = $2', [req.user.id, artist.id]);
  let following;
  if (existing) {
    await db.run('DELETE FROM follows WHERE follower_id = $1 AND artist_id = $2', [req.user.id, artist.id]);
    following = false;
  } else {
    await db.run('INSERT INTO follows (follower_id, artist_id) VALUES ($1,$2)', [req.user.id, artist.id]);
    following = true;
  }
  const followersCount = (await db.get('SELECT COUNT(*)::int as c FROM follows WHERE artist_id = $1', [artist.id])).c;
  res.json({ following, followersCount });
}));

app.get('/api/clips', h(async (req, res) => {
  const rows = await db.query(`
    SELECT c.id, c.title, c.thumb_url, c.video_url, c.views, c.likes, u.artist_name
    FROM clips c JOIN users u ON u.id = c.artist_id
    WHERE c.published = 1 AND (c.scheduled_release_at IS NULL OR c.scheduled_release_at <= NOW())
    ORDER BY RANDOM()
  `);
  res.json({ clips: rows });
}));

app.post('/api/clips/:id/view', h(async (req, res) => {
  const clipId = Number(req.params.id);
  const clip = await db.get('SELECT id, artist_id, views FROM clips WHERE id = $1', [clipId]);
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
  if (await db.get('SELECT id FROM clip_views WHERE clip_id = $1 AND viewer_id = $2', [clipId, viewerId])) {
    return res.json({ counted: false, reason: 'Déjà compté lors de votre première vue de ce clip.', views: clip.views });
  }

  await db.run('INSERT INTO clip_views (clip_id, viewer_id) VALUES ($1,$2)', [clipId, viewerId]);
  await db.run('UPDATE clips SET views = views + 1 WHERE id = $1', [clipId]);
  res.json({ counted: true, views: clip.views + 1 });
}));

// ================= CERTIFICATION ARTISTE =================

app.post('/api/verification/request', authMiddleware, h(async (req, res) => {
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.account_type !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  if (user.is_verified) return res.status(400).json({ error: 'Ce compte est déjà certifié.' });
  if (user.verification_status === 'pending') return res.status(400).json({ error: 'Une demande est déjà en attente.' });
  const stats = await withArtistStats(user);
  const MIN_TRACKS = 50;
  const MIN_FOLLOWERS = 5000;
  if (stats.track_count < MIN_TRACKS || stats.follower_count < MIN_FOLLOWERS) {
    return res.status(403).json({
      error: `Conditions non remplies : ${stats.track_count}/${MIN_TRACKS} sons publiés, ${stats.follower_count}/${MIN_FOLLOWERS} abonnés.`,
    });
  }
  await db.run(`UPDATE users SET verification_status = 'pending' WHERE id = $1`, [user.id]);
  res.json({ message: 'Demande de certification envoyée — en attente de validation NUNI.' });
}));

app.get('/api/admin/users', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  await enforceSubscriptionExpiry();
  const rows = await db.query(`
    SELECT u.id, u.account_type, u.first_name, u.last_name, u.email, u.artist_name,
           u.plan, u.subscription_status, u.account_status, u.is_verified, u.verification_status, u.created_at,
           (SELECT COUNT(*) FROM tracks t WHERE t.artist_id = u.id AND t.published = 1) as track_count,
           (SELECT COUNT(*) FROM follows f WHERE f.artist_id = u.id) as follower_count
    FROM users u
    ORDER BY u.created_at DESC
  `);
  res.json({ users: rows });
}));

app.get('/api/admin/subscriptions', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  await enforceSubscriptionExpiry();
  const rows = await db.query(`
    SELECT u.id, u.first_name, u.last_name, u.email, u.account_type, u.artist_name, u.plan,
           u.subscription_status, u.account_status, u.subscription_started_at, u.subscription_expires_at,
           CEIL(EXTRACT(EPOCH FROM (u.subscription_expires_at - NOW())) / 86400)::int as days_remaining,
           (SELECT p.amount_fcfa FROM payments p WHERE p.user_id = u.id ORDER BY p.created_at DESC LIMIT 1) as last_amount_fcfa
    FROM users u
    WHERE u.subscription_status IN ('active','pending','expired') AND u.plan != 'discovery'
    ORDER BY
      CASE u.subscription_status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,
      u.subscription_expires_at ASC
  `);
  const totalRow = await db.get('SELECT COALESCE(SUM(amount_fcfa),0)::int as total FROM payments');
  res.json({ subscriptions: rows, total_collected_fcfa: totalRow.total });
}));

// ---------- Suspension d'un compte : coupe le Pass ET bloque totalement la connexion ----------
// Contrairement à avant, ceci fixe désormais account_status='suspended', qui est vérifié
// à CHAQUE connexion et à CHAQUE requête authentifiée — pas seulement l'abonnement.
app.post('/api/admin/subscription/deactivate', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
  await db.run(
    `UPDATE users SET subscription_status = 'inactive', account_status = 'suspended', access_code = NULL WHERE id = $1`,
    [user.id],
  );
  res.json({ message: `Compte suspendu pour ${user.artist_name || user.first_name} — connexion bloquée, compte et contenu conservés.` });
}));

// ---------- Réactivation d'un compte suspendu ----------
app.post('/api/admin/users/reactivate', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
  await db.run(`UPDATE users SET account_status = 'active' WHERE id = $1`, [user.id]);
  res.json({ message: `Connexion réactivée pour ${user.artist_name || user.first_name} — le Pass reste à réactiver séparément si besoin.` });
}));

// ---------- Suppression DÉFINITIVE d'un compte — cascade complète, aucun résidu ----------
app.post('/api/admin/users/delete', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, confirm } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  if (confirm !== 'SUPPRIMER') {
    return res.status(400).json({ error: 'Confirmation manquante ou incorrecte.' });
  }
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    // Vues/écoutes générées par ce compte en tant qu'auditeur
    await client.query('DELETE FROM clip_views WHERE viewer_id = $1', [user.id]);
    await client.query('DELETE FROM plays WHERE listener_id = $1', [user.id]);
    // Follows dans les deux sens (abonné à d'autres artistes / suivi par d'autres)
    await client.query('DELETE FROM follows WHERE follower_id = $1 OR artist_id = $1', [user.id]);
    // Paiements liés
    await client.query('DELETE FROM payments WHERE user_id = $1', [user.id]);
    // Si c'est un artiste : vues/écoutes reçues sur son contenu, puis le contenu lui-même
    const tracks = await client.query('SELECT id FROM tracks WHERE artist_id = $1', [user.id]);
    for (const t of tracks.rows) {
      await client.query('DELETE FROM plays WHERE track_id = $1', [t.id]);
    }
    await client.query('DELETE FROM tracks WHERE artist_id = $1', [user.id]);
    const clips = await client.query('SELECT id FROM clips WHERE artist_id = $1', [user.id]);
    for (const c of clips.rows) {
      await client.query('DELETE FROM clip_views WHERE clip_id = $1', [c.id]);
    }
    await client.query('DELETE FROM clips WHERE artist_id = $1', [user.id]);
    // Enfin le compte lui-même
    await client.query('DELETE FROM users WHERE id = $1', [user.id]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  res.json({ message: `Compte ${email} supprimé définitivement — aucune donnée résiduelle (morceaux, clips, abonnements, écoutes, follows).` });
}));

app.get('/api/admin/promo-codes', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query('SELECT * FROM promo_codes ORDER BY id DESC');
  res.json({ codes: rows });
}));

app.post('/api/admin/promo-codes', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { code, discount_pct, applies_to_plan, max_uses, expires_at } = req.body;
  if (!code || !discount_pct) return res.status(400).json({ error: 'Le code et le pourcentage de réduction sont obligatoires.' });
  try {
    await db.run(`
      INSERT INTO promo_codes (code, discount_pct, applies_to_plan, max_uses, expires_at)
      VALUES ($1,$2,$3,$4,$5)
    `, [
      String(code).toUpperCase().trim(), Number(discount_pct), applies_to_plan || null,
      Number(max_uses) || 1, expires_at || null,
    ]);
  } catch (e) {
    return res.status(400).json({ error: 'Ce code existe déjà.' });
  }
  res.json({ message: 'Code promo créé.' });
}));

app.post('/api/admin/promo-codes/toggle', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const promo = await db.get('SELECT * FROM promo_codes WHERE code = $1', [String(req.body.code || '').toUpperCase().trim()]);
  if (!promo) return res.status(404).json({ error: 'Code introuvable.' });
  await db.run('UPDATE promo_codes SET active = $1 WHERE code = $2', [promo.active ? 0 : 1, promo.code]);
  res.json({ message: promo.active ? 'Code désactivé.' : 'Code réactivé.' });
}));

app.post('/api/promo/validate', h(async (req, res) => {
  const { code, plan } = req.body;
  const result = await resolvePromoDiscount(code, plan);
  if (!result.valid) return res.status(400).json({ error: result.error || 'Code promo invalide.' });
  res.json({ discount_pct: result.pct, code: result.code });
}));

app.get('/api/admin/verification/pending', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query(`
    SELECT id, first_name, last_name, email, artist_name, created_at
    FROM users WHERE account_type = 'artist' AND verification_status = 'pending'
    ORDER BY created_at ASC
  `);
  res.json({ pending: rows });
}));

app.post('/api/admin/verification/decide', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, approve } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
  if (approve) {
    await db.run(`UPDATE users SET verification_status = 'approved', is_verified = 1 WHERE id = $1`, [user.id]);
    res.json({ message: `${user.artist_name || user.first_name} est maintenant certifié(e). 🏅` });
  } else {
    await db.run(`UPDATE users SET verification_status = 'rejected' WHERE id = $1`, [user.id]);
    res.json({ message: `Demande de ${user.artist_name || user.first_name} refusée.` });
  }
}));

app.post('/api/admin/verification/reset', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
  await db.run(`UPDATE users SET is_verified = 0, verification_status = 'none' WHERE id = $1`, [user.id]);
  res.json({ message: `Certification réinitialisée pour ${user.artist_name || user.first_name}.` });
}));

app.get('/admin-verify.html', (req, res) => {
  res.redirect('/admin.html');
});

setInterval(async () => {
  try {
    await db.run(`UPDATE tracks SET published = 1 WHERE published = 0 AND scheduled_release_at <= NOW()`);
    await db.run(`UPDATE clips SET published = 1 WHERE published = 0 AND scheduled_release_at <= NOW()`);
  } catch (e) { console.error('Erreur job publication planifiée:', e); }
}, 60 * 1000);

async function start() {
  await db.initSchema();
  await initAuth();

  enforceSubscriptionExpiry();
  setInterval(enforceSubscriptionExpiry, 60 * 1000);

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`NUNI backend en écoute sur http://localhost:${PORT}`));
}

start().catch((err) => {
  console.error('Échec du démarrage du serveur :', err);
  process.exit(1);
});

module.exports = app;
