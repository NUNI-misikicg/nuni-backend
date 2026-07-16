// server.js — Serveur NUNI (Express + Postgres/Neon + Cloudinary)
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const webpush = require('web-push');
const db = require('./db');
const {
  initAuth, hashPassword, verifyPassword, needsRehash, signToken, verifyToken, generateAccessCode, authMiddleware,
} = require('./auth');
const { sendAccessCodeEmail } = require('./mailer');

const app = express();
// ---------- CORS restreint (durcissement sécurité) ----------
// Avant : cors() sans configuration acceptait des requêtes depuis N'IMPORTE QUEL site web.
// NUNI n'utilise pas de cookies de session (juste un token Bearer attaché manuellement en JS),
// ce qui limite déjà fortement le risque CSRF classique — mais autoriser tous les domaines
// reste une porte ouverte inutile : un site tiers malveillant pourrait quand même appeler
// l'API si un token a fuité ailleurs (XSS sur un autre site, etc.). On restreint donc aux
// vrais domaines de NUNI. Les requêtes sans origine (Postman, curl, apps mobiles, appels
// serveur-à-serveur) restent autorisées — un navigateur ne les émet jamais sans origine.
const ALLOWED_ORIGINS = [
  'https://nuni-misikicg.github.io',
  'https://nuni-backend.onrender.com', // héberge admin.html directement (public/admin.html)
];
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('Origine non autorisée par la politique CORS de NUNI.'));
  },
}));
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

// ---------- Bannières hero — upload réservé à l'admin (admin.html, clé ADMIN_KEY) ----------
// Même principe de signature Cloudinary que l'upload artiste ci-dessus, mais protégé par
// checkAdminKey plutôt qu'un compte utilisateur : aucun utilisateur normal n'a accès à ces
// deux endpoints, qui ne sont appelés que depuis admin.html.
app.get('/api/admin/upload-signature', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const timestamp = Math.round(Date.now() / 1000);
  const folder = 'nuni/hero';
  const signature = cloudinary.utils.api_sign_request({ timestamp, folder }, cloudinary.config().api_secret);
  res.json({
    signature, timestamp, folder,
    apiKey: cloudinary.config().api_key,
    cloudName: cloudinary.config().cloud_name,
  });
}));

app.get('/api/admin/hero-images', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query('SELECT id, section, image_url, created_at FROM hero_images ORDER BY section, created_at DESC');
  res.json({ images: rows });
}));

app.post('/api/admin/hero-images', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { section, imageUrl } = req.body;
  if (!section || !imageUrl) return res.status(400).json({ error: 'Section et imageUrl requis.' });
  const row = await db.get('INSERT INTO hero_images (section, image_url) VALUES ($1,$2) RETURNING id', [section, imageUrl]);
  res.json({ message: 'Image ajoutée.', id: row.id });
}));

app.delete('/api/admin/hero-images/:id', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  await db.run('DELETE FROM hero_images WHERE id = $1', [req.params.id]);
  res.json({ message: 'Image supprimée.' });
}));

// Public, lecture seule : une image aléatoire par section (ou la liste complète en option),
// pour que le site affiche une bannière qui change à chaque visite sans jamais permettre
// à un visiteur de la modifier.
app.get('/api/hero-images/:section', h(async (req, res) => {
  const rows = await db.query('SELECT image_url FROM hero_images WHERE section = $1', [req.params.section]);
  res.json({ images: rows.map((r) => r.image_url) });
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

// ================= PROGRESSION (XP, niveaux, série d'écoute) =================
// Fondation du système de gamification : 10 niveaux, seuils d'XP croissants.
const NUNI_LEVELS = [
  { level: 1, name: 'Rookie', minXp: 0 },
  { level: 2, name: 'Explorer', minXp: 100 },
  { level: 3, name: 'Supporter', minXp: 300 },
  { level: 4, name: 'Auditeur Premium', minXp: 700 },
  { level: 5, name: 'Légende', minXp: 1500 },
  { level: 6, name: 'Elite', minXp: 3000 },
  { level: 7, name: 'Diamant', minXp: 6000 },
  { level: 8, name: 'Icône', minXp: 12000 },
  { level: 9, name: 'Ambassadeur', minXp: 25000 },
  { level: 10, name: 'NUNI GOD', minXp: 50000 },
];
function levelInfoForXp(xp) {
  let current = NUNI_LEVELS[0];
  for (const l of NUNI_LEVELS) { if (xp >= l.minXp) current = l; }
  const next = NUNI_LEVELS.find((l) => l.minXp > xp) || null;
  const progressPct = next ? Math.round(((xp - current.minXp) / (next.minXp - current.minXp)) * 100) : 100;
  return {
    level: current.level, name: current.name, xp,
    next_level_name: next ? next.name : null,
    xp_for_next: next ? next.minXp : null,
    progress_pct: progressPct,
  };
}
async function addXp(userId, amount) {
  try { await db.run('UPDATE users SET xp = COALESCE(xp,0) + $1 WHERE id = $2', [amount, userId]); } catch (e) { /* jamais bloquant */ }
}
// NUNI Points — monnaie virtuelle dépensée dans la boutique (badges cosmétiques uniquement,
// aucune conversion en FCFA, aucun lien avec la rémunération réelle des artistes).
async function addPoints(userId, amount) {
  try { await db.run('UPDATE users SET nuni_points = COALESCE(nuni_points,0) + $1 WHERE id = $2', [amount, userId]); } catch (e) { /* jamais bloquant */ }
}
// Connexion quotidienne : +15 XP et +5 NUNI Points la première fois du jour, et incrémente
// la vraie série (streak_days) si la dernière activité était bien hier — remise à zéro sinon.
async function touchDailyLogin(userId) {
  try {
    const user = await db.get('SELECT last_active_date, streak_days FROM users WHERE id = $1', [userId]);
    if (!user) return;
    const today = new Date().toISOString().slice(0, 10);
    if (user.last_active_date && new Date(user.last_active_date).toISOString().slice(0, 10) === today) return; // déjà compté aujourd'hui
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const wasYesterday = user.last_active_date && new Date(user.last_active_date).toISOString().slice(0, 10) === yesterday;
    const newStreak = wasYesterday ? (user.streak_days || 0) + 1 : 1;
    await db.run(
      'UPDATE users SET last_active_date = $1, streak_days = $2, xp = COALESCE(xp,0) + 15, nuni_points = COALESCE(nuni_points,0) + 5 WHERE id = $3',
      [today, newStreak, userId],
    );
  } catch (e) { /* jamais bloquant */ }
}

// ================= BOUTIQUE NUNI POINTS =================
// Étape 4 de la gamification. Articles purement cosmétiques : des badges collectionnables
// supplémentaires, achetés une seule fois, qui viennent s'ajouter à "Vos badges d'auditeur".
const SHOP_ITEMS = [
  { key: 'badge_gold_disc', name: '🥇 Disque d\'Or', description: 'Badge collector', cost: 100 },
  { key: 'badge_early_bird', name: '🌅 Lève-tôt NUNI', description: 'Badge collector', cost: 150 },
  { key: 'badge_flame_king', name: '👑 Roi du Streak', description: 'Badge collector', cost: 250 },
  { key: 'badge_legend', name: '⚡ Collectionneur', description: 'Badge collector', cost: 400 },
];

app.get('/api/shop/items', authMiddleware, h(async (req, res) => {
  const owned = await db.query('SELECT item_key FROM shop_purchases WHERE user_id = $1', [req.user.id]);
  const ownedSet = new Set(owned.map((o) => o.item_key));
  const user = await db.get('SELECT nuni_points FROM users WHERE id = $1', [req.user.id]);
  res.json({
    points: user.nuni_points || 0,
    items: SHOP_ITEMS.map((it) => ({ ...it, owned: ownedSet.has(it.key) })),
  });
}));

app.post('/api/shop/items/:key/buy', authMiddleware, rateLimit(15, 60000), h(async (req, res) => {
  const item = SHOP_ITEMS.find((i) => i.key === req.params.key);
  if (!item) return res.status(404).json({ error: 'Article introuvable.' });
  if (await db.get('SELECT id FROM shop_purchases WHERE user_id = $1 AND item_key = $2', [req.user.id, item.key])) {
    return res.status(400).json({ error: 'Déjà acheté.' });
  }
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    // Avant : le solde était vérifié AVANT la transaction, puis débité dedans — un
    // double-clic rapide ou deux onglets pouvaient passer la vérification en même temps
    // (tous deux liraient le même solde encore suffisant) et faire passer le solde en
    // négatif. Maintenant : la condition de solde suffisant fait partie de l'UPDATE
    // lui-même (atomique), donc une seule des deux requêtes concurrentes peut réussir.
    const updated = await client.query(
      'UPDATE users SET nuni_points = nuni_points - $1 WHERE id = $2 AND nuni_points >= $1 RETURNING nuni_points',
      [item.cost, req.user.id],
    );
    if (updated.rowCount === 0) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'Pas assez de NUNI Points.' });
    }
    await client.query('INSERT INTO shop_purchases (user_id, item_key) VALUES ($1,$2)', [req.user.id, item.key]);
    await client.query('COMMIT');
    res.json({ message: `${item.name} débloqué !`, points: updated.rows[0].nuni_points });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

// ================= DÉFIS QUOTIDIENS / HEBDOMADAIRES =================
// Étape 3 de la gamification. Récompense en XP direct (la monnaie NUNI Points arrive à
// l'étape 4, volontairement séparée). Les défis sont définis en code (comme NUNI_LEVELS) ;
// seule la progression par utilisateur/période est stockée en base (challenge_progress).
const CHALLENGES = [
  { key: 'daily_listen_3', period: 'daily', title: 'Écouter 3 morceaux différents', target: 3, xp: 20 },
  { key: 'daily_like_1', period: 'daily', title: 'Aimer un son ou un clip', target: 1, xp: 10 },
  { key: 'weekly_listen_15', period: 'weekly', title: 'Écouter 15 morceaux', target: 15, xp: 100 },
  { key: 'weekly_follow_2', period: 'weekly', title: 'Suivre 2 nouveaux artistes', target: 2, xp: 50 },
];

function dailyPeriodKey() {
  return new Date().toISOString().slice(0, 10); // ex: 2026-07-13
}
function weeklyPeriodKey() {
  const d = new Date();
  const dayIdx = (d.getUTCDay() + 6) % 7; // lundi = 0
  const monday = new Date(d);
  monday.setUTCDate(d.getUTCDate() - dayIdx);
  return `W${monday.toISOString().slice(0, 10)}`;
}
function periodKeyFor(period) {
  return period === 'weekly' ? weeklyPeriodKey() : dailyPeriodKey();
}

// Incrémente la progression d'un défi pour l'utilisateur, sur la période en cours.
// Idempotent une fois complété (n'est jamais recompté ni dépassé), jamais bloquant.
async function bumpChallenge(userId, challengeKey, amount = 1) {
  try {
    const def = CHALLENGES.find((c) => c.key === challengeKey);
    if (!def || !userId) return;
    const periodKey = periodKeyFor(def.period);
    const row = await db.get(
      'SELECT * FROM challenge_progress WHERE user_id = $1 AND challenge_key = $2 AND period_key = $3',
      [userId, challengeKey, periodKey],
    );
    if (row && row.completed_at) return; // déjà complété cette période
    const newProgress = Math.min((row ? row.progress : 0) + amount, def.target);
    const justCompleted = newProgress >= def.target;
    await db.run(`
      INSERT INTO challenge_progress (user_id, challenge_key, period_key, progress, completed_at)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (user_id, challenge_key, period_key)
      DO UPDATE SET progress = $4, completed_at = COALESCE(challenge_progress.completed_at, $5)
    `, [userId, challengeKey, periodKey, newProgress, justCompleted ? new Date() : null]);
  } catch (e) { /* jamais bloquant */ }
}

// Liste des défis en cours avec la progression réelle de l'utilisateur connecté.
app.get('/api/me/challenges', authMiddleware, h(async (req, res) => {
  const rows = await db.query(
    'SELECT challenge_key, period_key, progress, completed_at, claimed_at FROM challenge_progress WHERE user_id = $1',
    [req.user.id],
  );
  const byKey = {};
  rows.forEach((r) => { byKey[`${r.challenge_key}::${r.period_key}`] = r; });

  const challenges = CHALLENGES.map((def) => {
    const periodKey = periodKeyFor(def.period);
    const row = byKey[`${def.key}::${periodKey}`];
    return {
      key: def.key,
      period: def.period,
      title: def.title,
      target: def.target,
      xp: def.xp,
      progress: row ? row.progress : 0,
      completed: !!(row && row.completed_at),
      claimed: !!(row && row.claimed_at),
    };
  });
  res.json({ challenges });
}));

// Récupère l'XP d'un défi complété — une seule fois par période, vérifié côté serveur.
app.post('/api/me/challenges/:key/claim', authMiddleware, rateLimit(15, 60000), h(async (req, res) => {
  const def = CHALLENGES.find((c) => c.key === req.params.key);
  if (!def) return res.status(404).json({ error: 'Défi introuvable.' });
  const periodKey = periodKeyFor(def.period);
  const row = await db.get(
    'SELECT * FROM challenge_progress WHERE user_id = $1 AND challenge_key = $2 AND period_key = $3',
    [req.user.id, def.key, periodKey],
  );
  if (!row || !row.completed_at) return res.status(400).json({ error: 'Défi pas encore complété.' });
  // Avant : vérifier "pas déjà récupéré" puis mettre à jour dans deux requêtes séparées
  // permettait à deux clics rapides (ou deux onglets) de passer la vérification en même
  // temps et de récupérer la récompense deux fois. Maintenant : la condition fait partie de
  // l'UPDATE lui-même (atomique) — une seule requête concurrente peut réussir.
  const client = await db.pool.connect();
  let claimed;
  try {
    const result = await client.query(
      'UPDATE challenge_progress SET claimed_at = NOW() WHERE user_id = $1 AND challenge_key = $2 AND period_key = $3 AND claimed_at IS NULL RETURNING id',
      [req.user.id, def.key, periodKey],
    );
    claimed = result.rowCount > 0;
  } finally {
    client.release();
  }
  if (!claimed) {
    return res.status(400).json({ error: 'Récompense déjà récupérée.' });
  }
  await addXp(req.user.id, def.xp);
  const pointsAwarded = Math.round(def.xp / 2);
  await addPoints(req.user.id, pointsAwarded);
  res.json({ message: `+${def.xp} XP · +${pointsAwarded} NUNI Points !`, xp_awarded: def.xp, points_awarded: pointsAwarded });
}));

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

// ---------- Pass Découverte — vrai compte, vrai essai 24h suivi côté serveur ----------
// Avant : "démarrer la découverte" ne créait AUCUN compte, juste un compte à rebours en
// mémoire du navigateur — remis à zéro à chaque rechargement, et rien ne bloquait jamais
// vraiment l'accès à la fin. Ici : un vrai compte est créé, activé 24h immédiatement
// (subscription_expires_at réel, vérifié par enforceSubscriptionExpiry comme n'importe quel
// autre Pass). Après expiration, 2h de grâce pour valider un vrai Pass (voir
// enforceDiscoveryDeletion plus bas) avant suppression complète et définitive du compte.
app.post('/api/register-discovery', h(async (req, res) => {
  const {
    accountType, firstName, lastName, email, phone, password,
    age, address, city, country, artistName, labelOrManager,
  } = req.body;

  if (!['consumer', 'artist'].includes(accountType)) {
    return res.status(400).json({ error: 'Type de compte invalide (consumer ou artist).' });
  }
  const baseRequired = ['firstName', 'lastName', 'email', 'password', 'age', 'address', 'city', 'country'];
  const missing = required(req.body, accountType === 'artist' ? [...baseRequired, 'artistName'] : baseRequired);
  if (missing.length) return res.status(400).json({ error: `Champs manquants : ${missing.join(', ')}` });
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  if (Number(age) < 16) return res.status(400).json({ error: 'NUNI est réservé aux 16 ans et plus.' });
  if (await db.get('SELECT id FROM users WHERE email = $1', [email])) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }

  const password_hash = await hashPassword(password);
  const inserted = await db.get(`
    INSERT INTO users (
      account_type, first_name, last_name, email, phone, password_hash, age, address, city, country,
      artist_name, label_or_manager, plan, subscription_status, subscription_expires_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'discovery','active',NOW() + INTERVAL '24 hours')
    RETURNING id
  `, [
    accountType, firstName, lastName, email, phone || null, password_hash, Number(age), address, city, country,
    accountType === 'artist' ? artistName : null,
    accountType === 'artist' ? (labelOrManager || null) : null,
  ]);

  const user = await db.get('SELECT * FROM users WHERE id = $1', [inserted.id]);
  const token = signToken(user);
  res.status(201).json({
    message: 'Pass Découverte activé — 24h pour explorer NUNI en intégralité.',
    token,
    user: publicUser(await withArtistStats(user)),
  });
}));


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

  // Migration Argon2id transparente : si ce compte a encore un ancien hash bcrypt, on le
  // ré-hache maintenant qu'on connaît le mot de passe en clair (juste le temps de cette
  // requête, jamais stocké) — aucune action demandée à la personne, jamais bloquant.
  if (needsRehash(user.password_hash)) {
    hashPassword(password).then((newHash) => {
      db.run('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]).catch(() => {});
    }).catch(() => {});
  }

  if (user.account_status === 'deleted') {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }
  if (user.account_status === 'suspended') {
    return res.status(403).json({ error: 'Votre compte a été suspendu par l\'administration. Contactez le support.' });
  }

  const token = signToken(user);
  await touchDailyLogin(user.id);
  const fresh = await db.get('SELECT * FROM users WHERE id = $1', [user.id]);
  res.json({ token, user: publicUser(await withArtistStats(fresh)) });
}));

app.get('/api/me', authMiddleware, h(async (req, res) => {
  await enforceSubscriptionExpiry();
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  // Avant : seul /api/login vérifiait la suspension. Un compte déjà connecté (token valide)
  // au moment où l'admin le suspend continuait d'accéder normalement à l'application — la
  // vérification périodique côté client, qui interroge justement cet endpoint pour détecter
  // une suspension pendant une session déjà ouverte, ne pouvait donc jamais rien détecter.
  if (user.account_status === 'suspended') {
    return res.status(403).json({ error: 'Votre compte a été suspendu par l\'administration. Contactez le support.' });
  }
  res.json({ user: publicUser(await withArtistStats(user)) });
}));

// ---------- Progression réelle : niveau, XP, et les 6 badges calculés à partir de vraies actions ----------
// Avant : "Vos badges d'auditeur" était un tableau entièrement codé en dur (même le "62/100"
// était du texte fixe). Ici, chaque badge est calculé en direct depuis les vraies données
// (écoutes, genres, artistes suivis, classement mensuel réel).
app.get('/api/me/following', authMiddleware, h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.is_verified
    FROM follows f JOIN users u ON u.id = f.artist_id
    WHERE f.follower_id = $1
    ORDER BY f.id DESC
  `, [req.user.id]);
  res.json({ following: rows });
}));

app.get('/api/me/progress', authMiddleware, h(async (req, res) => {
  const user = await db.get('SELECT id, xp, streak_days, created_at FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  const distinctTracks = (await db.get(
    'SELECT COUNT(DISTINCT track_id)::int as c FROM plays WHERE listener_id = $1', [user.id],
  )).c;
  const distinctGenres = (await db.get(`
    SELECT COUNT(DISTINCT t.genre)::int as c FROM plays p
    JOIN tracks t ON t.id = p.track_id
    WHERE p.listener_id = $1 AND t.genre IS NOT NULL
  `, [user.id])).c;
  const followedArtists = (await db.get(
    'SELECT COUNT(*)::int as c FROM follows WHERE follower_id = $1', [user.id],
  )).c;
  const monthlyRank = await db.get(`
    WITH monthly AS (
      SELECT listener_id, COUNT(*) as c FROM plays
      WHERE created_at >= date_trunc('month', NOW()) AND listener_id IS NOT NULL
      GROUP BY listener_id
    )
    SELECT c, RANK() OVER (ORDER BY c DESC) as rnk FROM monthly WHERE listener_id = $1
  `, [user.id]);
  const isTopListener = !!(monthlyRank && Number(monthlyRank.rnk) <= 10);

  const badges = [
    { ic: '🕊️', n: 'Fan de la première heure', locked: false, d: 'Compte créé' },
    { ic: '🎧', n: '100 titres découverts', locked: distinctTracks < 100, d: `${distinctTracks}/100` },
    { ic: '🔥', n: `${user.streak_days || 0} jour(s) d'écoute d'affilée`, locked: (user.streak_days || 0) < 7, d: (user.streak_days || 0) >= 7 ? 'Débloqué' : 'Série en cours' },
    { ic: '🌍', n: '5 genres explorés', locked: distinctGenres < 5, d: `${distinctGenres}/5` },
    { ic: '💛', n: '10 artistes soutenus', locked: followedArtists < 10, d: `${followedArtists}/10` },
    { ic: '🏆', n: 'Top auditeur du mois', locked: !isTopListener, d: isTopListener ? `Rang #${monthlyRank.rnk}` : 'Verrouillé' },
  ];

  // Badges cosmétiques achetés dans la boutique NUNI Points — toujours débloqués une fois payés.
  const owned = await db.query('SELECT item_key FROM shop_purchases WHERE user_id = $1', [user.id]);
  const ownedSet = new Set(owned.map((o) => o.item_key));
  SHOP_ITEMS.forEach((it) => {
    if (ownedSet.has(it.key)) {
      badges.push({ ic: it.name.split(' ')[0], n: it.name.replace(/^\S+\s/, ''), locked: false, d: 'Boutique' });
    }
  });

  res.json({ ...levelInfoForXp(user.xp || 0), streak_days: user.streak_days || 0, nuni_points: (await db.get('SELECT nuni_points FROM users WHERE id = $1', [user.id])).nuni_points || 0, badges });
}));

// ---------- Classement public (XP) — étape 5 gamification ----------
// Top 20 auditeurs par XP, visible par n'importe qui (comme les stats publiques d'un artiste).
// Si la personne connectée n'est pas dans le top 20, son propre rang est renvoyé en plus,
// pour qu'elle se voie toujours quelque part même très loin dans le classement.
app.get('/api/leaderboard', h(async (req, res) => {
  const top = await db.query(`
    SELECT id, first_name, artist_name, account_type, avatar_url, xp,
      RANK() OVER (ORDER BY xp DESC) as rnk
    FROM users
    WHERE xp > 0
    ORDER BY xp DESC
    LIMIT 20
  `);

  let me = null;
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  if (payload) {
    const alreadyInTop = top.find((r) => r.id === payload.id);
    if (!alreadyInTop) {
      me = await db.get(`
        WITH ranked AS (SELECT id, xp, RANK() OVER (ORDER BY xp DESC) as rnk FROM users WHERE xp > 0)
        SELECT rnk, xp FROM ranked WHERE id = $1
      `, [payload.id]);
    }
  }

  res.json({
    top: top.map((r) => ({
      rank: Number(r.rnk), id: r.id, name: r.artist_name || r.first_name,
      account_type: r.account_type, avatar_url: r.avatar_url, xp: r.xp,
    })),
    my_rank: me ? { rank: Number(me.rnk), xp: me.xp } : null,
  });
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
  // Double protection : même si une ligne invalide existait déjà en base avant le garde-fou
  // à la création, on borne ici aussi et on ne laisse jamais un prix final négatif ou nul.
  const safePct = Math.min(100, Math.max(0, promoResult.pct || 0));
  const amount_fcfa = (promoResult.valid && safePct)
    ? Math.max(1, Math.round(base * (1 - safePct / 100)))
    : base;

  await db.run(`
    INSERT INTO payments (user_id, plan, duration_days, amount_fcfa, promo_code)
    VALUES ($1,$2,$3,$4,$5)
  `, [user.id, plan, durationDays, amount_fcfa, (promoResult.valid && promoResult.code) ? promoResult.code : null]);

  if (promoResult.valid && promoResult.code) {
    await db.run('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1', [promoResult.code]);
  }
  await addXp(user.id, 300);

  const mailResult = await sendAccessCodeEmail({ user, plan, accessCode: access_code, durationDays });
  return {
    access_code, emailSent: mailResult.sent, emailReason: mailResult.reason,
    amount_fcfa,
    promoApplied: (promoResult.valid && promoResult.code) ? promoResult.code : null,
    promoWarning: (!promoResult.valid && promoCode) ? promoResult.error : null,
  };
}

// ---------- Playlists NUNI — vraies playlists, curées par l'équipe depuis l'admin ----------
// Avant : la section "Playlists NUNI" du site n'était qu'une tranche arbitraire du
// catalogue (tracks.slice(2,7)), aucune vraie playlist n'existait. Ici : de vraies
// playlists en base, créées/éditées uniquement depuis admin.html (clé ADMIN_KEY), avec
// un tirage aléatoire de titres proposé comme point de départ (l'admin peut ensuite
// ajuster la sélection avant d'enregistrer — jamais publié sans validation humaine).
app.get('/api/admin/playlists', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const playlists = await db.query('SELECT id, title, description, cover_url, created_at FROM playlists ORDER BY created_at DESC');
  for (const p of playlists) {
    p.track_ids = (await db.query('SELECT track_id FROM playlist_tracks WHERE playlist_id = $1 ORDER BY position', [p.id])).map((r) => r.track_id);
  }
  res.json({ playlists });
}));

app.get('/api/admin/playlists/random-picks', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const count = Math.min(20, Math.max(1, parseInt(req.query.count, 10) || 6));
  const rows = await db.query(`
    SELECT t.id, t.title, u.artist_name, u.first_name
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1
    ORDER BY RANDOM() LIMIT $1
  `, [count]);
  res.json({ tracks: rows });
}));

app.post('/api/admin/playlists', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { title, description, coverUrl, trackIds } = req.body;
  if (!title || !Array.isArray(trackIds) || !trackIds.length) {
    return res.status(400).json({ error: 'Titre et au moins un morceau requis.' });
  }
  const row = await db.get(
    'INSERT INTO playlists (title, description, cover_url) VALUES ($1,$2,$3) RETURNING id',
    [title, description || null, coverUrl || null],
  );
  for (let i = 0; i < trackIds.length; i++) {
    await db.run('INSERT INTO playlist_tracks (playlist_id, track_id, position) VALUES ($1,$2,$3)', [row.id, trackIds[i], i]);
  }
  res.json({ message: 'Playlist créée.', id: row.id });
}));

app.put('/api/admin/playlists/:id', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { title, description, coverUrl, trackIds } = req.body;
  if (!title || !Array.isArray(trackIds) || !trackIds.length) {
    return res.status(400).json({ error: 'Titre et au moins un morceau requis.' });
  }
  await db.run('UPDATE playlists SET title = $1, description = $2, cover_url = $3 WHERE id = $4', [title, description || null, coverUrl || null, req.params.id]);
  await db.run('DELETE FROM playlist_tracks WHERE playlist_id = $1', [req.params.id]);
  for (let i = 0; i < trackIds.length; i++) {
    await db.run('INSERT INTO playlist_tracks (playlist_id, track_id, position) VALUES ($1,$2,$3)', [req.params.id, trackIds[i], i]);
  }
  res.json({ message: 'Playlist mise à jour.' });
}));

app.delete('/api/admin/playlists/:id', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  await db.run('DELETE FROM playlists WHERE id = $1', [req.params.id]);
  res.json({ message: 'Playlist supprimée.' });
}));

// Public, lecture seule — liste des playlists avec un aperçu (pochette du 1er morceau si
// aucune pochette dédiée n'a été choisie, et nombre réel de titres).
app.get('/api/playlists', h(async (req, res) => {
  const playlists = await db.query('SELECT id, title, description, cover_url FROM playlists ORDER BY created_at DESC');
  for (const p of playlists) {
    const countRow = await db.get('SELECT COUNT(*)::int as c FROM playlist_tracks WHERE playlist_id = $1', [p.id]);
    p.track_count = countRow.c;
    if (!p.cover_url) {
      const firstCover = await db.get(`
        SELECT t.cover_url FROM playlist_tracks pt JOIN tracks t ON t.id = pt.track_id
        WHERE pt.playlist_id = $1 ORDER BY pt.position LIMIT 1
      `, [p.id]);
      p.cover_url = firstCover ? firstCover.cover_url : null;
    }
  }
  res.json({ playlists });
}));

app.get('/api/playlists/:id', h(async (req, res) => {
  const playlist = await db.get('SELECT id, title, description, cover_url FROM playlists WHERE id = $1', [req.params.id]);
  if (!playlist) return res.status(404).json({ error: 'Playlist introuvable.' });
  const tracks = await db.query(`
    SELECT t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
      u.artist_name, u.first_name, u.is_verified, u.id as artist_id
    FROM playlist_tracks pt JOIN tracks t ON t.id = pt.track_id JOIN users u ON u.id = t.artist_id
    WHERE pt.playlist_id = $1 ORDER BY pt.position
  `, [req.params.id]);
  res.json({ playlist, tracks });
}));

function checkAdminKey(req, res) {
  const adminKey = req.headers['x-admin-key'];
  if (!process.env.ADMIN_KEY || adminKey !== process.env.ADMIN_KEY) {
    res.status(403).json({ error: 'Clé admin invalide.' });
    return false;
  }
  return true;
}

// ================= SÉCURITÉ ANTI-TRICHE (étape 6 gamification) =================
// Limiteur de débit léger en mémoire (sans dépendance externe) — identifie la personne par
// son compte si connectée (même via un token décodé manuellement sur les routes publiques),
// sinon par IP. Protège les routes qui rapportent de l'XP/des NUNI Points/des interactions
// contre un script qui les appellerait en boucle.
const rateLimitBuckets = new Map();
function rateLimitKeyFor(req) {
  if (req.user && req.user.id) return 'u' + req.user.id;
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  if (payload) return 'u' + payload.id;
  return 'ip' + req.ip;
}
function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const key = rateLimitKeyFor(req);
    const now = Date.now();
    let bucket = rateLimitBuckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      rateLimitBuckets.set(key, bucket);
    }
    bucket.count++;
    if (bucket.count > maxRequests) {
      return res.status(429).json({ error: 'Trop de requêtes en peu de temps — merci de ralentir un instant.' });
    }
    next();
  };
}
// Purge périodique pour ne pas laisser grossir la Map indéfiniment sur un serveur qui tourne longtemps.
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateLimitBuckets) { if (now > bucket.resetAt) rateLimitBuckets.delete(key); }
}, 5 * 60 * 1000);

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

// ---------- Statistiques publiques d'un artiste (visibles par n'importe quel visiteur) ----------
// Avant : le nombre de followers réel n'était affiché que sur SA PROPRE page (via /api/me).
// Un consommateur qui visitait la page d'un artiste voyait toujours "—", même si le vrai
// nombre existait déjà en base. Cette route publique corrige ça : n'importe qui peut voir
// le vrai nombre d'abonnés d'un artiste, comme sur n'importe quel réseau social.
// ---------- Vraie photo de profil artiste — persistée en base, visible par tout le monde ----------
// Avant : "Changer la photo de profil" ne faisait qu'un aperçu local dans le navigateur,
// jamais envoyé au serveur — perdu au rechargement, et jamais visible sur la vraie page
// artiste (qui affichait toujours les initiales, sans jamais vérifier une vraie photo).
app.put('/api/artist/avatar', authMiddleware, h(async (req, res) => {
  const { avatarUrl } = req.body;
  if (!avatarUrl || !String(avatarUrl).startsWith('http')) return res.status(400).json({ error: 'URL de photo invalide.' });
  await db.run('UPDATE users SET avatar_url = $1 WHERE id = $2', [avatarUrl, req.user.id]);
  res.json({ message: 'Photo de profil mise à jour.', avatar_url: avatarUrl });
}));

// ---------- Vraie photo de couverture (bannière) artiste — même principe que l'avatar ----------
// Avant : "Changer la photo de couverture" ne faisait qu'un aperçu local dans le navigateur,
// jamais envoyé au serveur — perdu au rechargement, jamais visible pour les autres visiteurs.
app.put('/api/artist/banner', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { bannerUrl } = req.body;
  if (!bannerUrl || !String(bannerUrl).startsWith('http')) return res.status(400).json({ error: 'URL de photo invalide.' });
  await db.run('UPDATE users SET banner_url = $1 WHERE id = $2', [bannerUrl, req.user.id]);
  res.json({ message: 'Photo de couverture mise à jour.', banner_url: bannerUrl });
}));

app.get('/api/artist/:id/public-stats', h(async (req, res) => {
  const artistId = Number(req.params.id);
  const artist = await db.get('SELECT id, account_type, avatar_url, banner_url FROM users WHERE id = $1', [artistId]);
  if (!artist || artist.account_type !== 'artist') return res.status(404).json({ error: 'Artiste introuvable.' });
  const followerCount = (await db.get('SELECT COUNT(*)::int as c FROM follows WHERE artist_id = $1', [artistId])).c;
  const trackCount = (await db.get('SELECT COUNT(*)::int as c FROM tracks WHERE artist_id = $1 AND published = 1', [artistId])).c;
  res.json({ follower_count: followerCount, track_count: trackCount, avatar_url: artist.avatar_url || null, banner_url: artist.banner_url || null });
}));

// "Mur des fans" — avant : 7 initiales codées en dur ("MK","PJ","TN"...), identiques pour
// n'importe quel artiste. Ici : les vrais derniers followers réels (table follows).
app.get('/api/artist/:id/recent-followers', h(async (req, res) => {
  const artistId = Number(req.params.id);
  const rows = await db.query(`
    SELECT u.first_name, u.avatar_url FROM follows f
    JOIN users u ON u.id = f.follower_id
    WHERE f.artist_id = $1
    ORDER BY f.id DESC LIMIT 8
  `, [artistId]);
  res.json({ followers: rows });
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

// ---------- Sons en vedette — sélectionnés par l'artiste pour sa biographie ----------
// L'artiste choisit, parmi ses propres morceaux déjà publiés sur la plateforme, jusqu'à 6
// à mettre en avant juste sous sa biographie. Visible par tout le monde sur sa page publique.
const MAX_FEATURED_TRACKS = 6;

app.put('/api/artist/featured-tracks', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { trackIds } = req.body;
  if (!Array.isArray(trackIds)) return res.status(400).json({ error: 'Liste de morceaux invalide.' });
  const ids = [...new Set(trackIds.map(Number).filter(Boolean))].slice(0, MAX_FEATURED_TRACKS);

  // Vérifie que chaque morceau appartient bien à cet artiste — impossible de mettre en
  // vedette le morceau de quelqu'un d'autre.
  if (ids.length) {
    const owned = await db.query('SELECT id FROM tracks WHERE id = ANY($1::int[]) AND artist_id = $2', [ids, req.user.id]);
    const ownedIds = new Set(owned.map((r) => r.id));
    if (ids.some((id) => !ownedIds.has(id))) {
      return res.status(403).json({ error: 'Vous ne pouvez mettre en vedette que vos propres morceaux.' });
    }
  }

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM featured_tracks WHERE artist_id = $1', [req.user.id]);
    for (let i = 0; i < ids.length; i++) {
      await client.query('INSERT INTO featured_tracks (artist_id, track_id, position) VALUES ($1,$2,$3)', [req.user.id, ids[i], i]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  res.json({ message: 'Sélection mise à jour.', count: ids.length });
}));

app.get('/api/artist/:id/featured-tracks', h(async (req, res) => {
  const artistId = Number(req.params.id);
  const rows = await db.query(`
    SELECT t.id, t.title, t.album, t.genre, t.release_type, t.cover_url, t.audio_url,
           t.streams, t.likes, u.artist_name, u.is_verified
    FROM featured_tracks f
    JOIN tracks t ON t.id = f.track_id
    JOIN users u ON u.id = t.artist_id
    WHERE f.artist_id = $1
    ORDER BY f.position ASC
  `, [artistId]);
  res.json({ tracks: rows });
}));

// ---------- Calendrier des sorties — vraies sorties programmées par l'artiste ----------
// Avant : "Calendrier des sorties" affichait 3 entrées codées en dur ("Nzela ya Sika",
// "Envol (Deluxe)", "Tournée Kinshasa"), identiques pour tout le monde, jamais reliées à
// aucune vraie programmation. Ici : les vrais morceaux/albums que CET artiste a importés
// avec une date de sortie future (published=0, en attente du job qui les publie
// automatiquement à l'heure dite — voir le setInterval plus bas dans ce fichier).
// ---------- Calendrier des sorties — page d'accueil, toute la plateforme ----------
// Avant : 4 sorties codées en dur ("Nzela ya Sika"...), identiques pour tout le monde,
// dates figées pour toujours. Ici : vraies sorties programmées de tous les artistes
// (Pass Artiste actif), triées par date réelle la plus proche.
app.get('/api/releases/upcoming', h(async (req, res) => {
  const rows = await db.query(`
    SELECT t.title, t.release_type, t.scheduled_release_at, u.artist_name, u.first_name
    FROM tracks t
    JOIN users u ON u.id = t.artist_id
    WHERE t.published = 0 AND t.scheduled_release_at IS NOT NULL AND t.scheduled_release_at > NOW()
      AND u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
    ORDER BY t.scheduled_release_at ASC
    LIMIT 8
  `);
  res.json({ releases: rows });
}));

app.get('/api/artist/:id/scheduled-releases', h(async (req, res) => {
  const artistId = Number(req.params.id);
  const rows = await db.query(`
    SELECT title, release_type, scheduled_release_at
    FROM tracks
    WHERE artist_id = $1 AND published = 0 AND scheduled_release_at IS NOT NULL AND scheduled_release_at > NOW()
    ORDER BY scheduled_release_at ASC
    LIMIT 10
  `, [artistId]);
  res.json({ releases: rows });
}));

// Version authentifiée — utilisée sur SA PROPRE page pour éviter toute dépendance à un ID
// recalculé côté client (currentArtistPageRealId), qui pouvait dans certains cas retomber
// sur un mauvais identifiant. Ici, req.user.id vient directement du token de connexion.
app.get('/api/artist/scheduled-releases', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const rows = await db.query(`
    SELECT id, title, release_type, scheduled_release_at
    FROM tracks
    WHERE artist_id = $1 AND published = 0 AND scheduled_release_at IS NOT NULL
    ORDER BY scheduled_release_at ASC
    LIMIT 20
  `, [req.user.id]);
  res.json({ releases: rows });
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

// ---------- Suppression d'un morceau — nécessaire pour corriger une publication en double ----------
app.delete('/api/tracks/:id', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id, artist_id FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });
  if (track.artist_id !== req.user.id) return res.status(403).json({ error: 'Vous ne pouvez supprimer que vos propres morceaux.' });
  await db.run('DELETE FROM plays WHERE track_id = $1', [trackId]);
  await db.run('DELETE FROM track_likes WHERE track_id = $1', [trackId]);
  await db.run('DELETE FROM featured_tracks WHERE track_id = $1', [trackId]);
  await db.run('DELETE FROM tracks WHERE id = $1', [trackId]);
  res.json({ message: 'Morceau supprimé.' });
}));

app.post('/api/tracks', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const {
    title, album, genre, releaseType, coverUrl, audioUrl, lyrics, scheduledReleaseAt,
    composer, featuring, studio, description, releaseDate,
  } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();

  const [finalCoverUrl, finalAudioUrl] = await Promise.all([
    uploadIfDataUri(coverUrl, 'image'),
    uploadIfDataUri(audioUrl, 'video'),
  ]);

  const inserted = await db.get(`
    INSERT INTO tracks (
      artist_id, title, album, genre, release_type, cover_url, audio_url, lyrics, scheduled_release_at, published,
      composer, featuring, studio, description, release_date
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
    RETURNING id
  `, [
    req.user.id, title, album || null, genre || null, releaseType || 'Single',
    finalCoverUrl || null, finalAudioUrl || null, lyrics || null,
    scheduledReleaseAt || null, isFuture ? 0 : 1,
    composer || null, featuring || null, studio || null, description || null, releaseDate || null,
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
           t.streams, t.likes, t.created_at, u.id as artist_id, u.artist_name, u.is_verified,
           t.composer, t.featuring, t.studio, t.description, t.release_date
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1 AND (t.scheduled_release_at IS NULL OR t.scheduled_release_at <= NOW())
    ORDER BY t.created_at DESC
  `);
  res.json({ tracks: rows });
}));

const NUNI_PRICE_PER_STREAM_FCFA = 2;
const NUNI_ARTIST_SHARE_PCT = 75;
const MONTH_LABELS_FR = ['Jan', 'Fév', 'Mar', 'Avr', 'Mai', 'Juin', 'Juil', 'Août', 'Sep', 'Oct', 'Nov', 'Déc'];

app.post('/api/tracks/:id/play', rateLimit(30, 60000), h(async (req, res) => {
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
  // Vérifié en base en direct (pas seulement dans le token, qui peut dater d'avant un
  // changement de Pass) — un compte Pass Découverte n'a payé pour rien : ses écoutes ne
  // doivent générer ni vrai stream ni rémunération pour l'artiste. Elles compteront
  // normalement dès que la personne valide un vrai Pass Consommateur payant.
  const listener = await db.get('SELECT account_type, plan FROM users WHERE id = $1', [listenerId]);
  if (!listener || listener.account_type !== 'consumer') {
    return res.json({ counted: false, reason: "Seules les écoutes via un Pass Consommateur génèrent un stream.", streams: track.streams });
  }
  if (listener.plan === 'discovery') {
    return res.json({ counted: false, reason: "Écoute en Pass Découverte — ne compte pas comme un vrai stream tant qu'aucun Pass payant n'est validé.", streams: track.streams });
  }
  // Insertion atomique (la base garantit maintenant l'unicité track_id+listener_id) — plus de
  // vérification séparée avant l'insertion, qui laissait une petite fenêtre pour compter deux
  // fois la même écoute en cas de requêtes simultanées.
  const inserted = await db.run(
    'INSERT INTO plays (track_id, listener_id) VALUES ($1,$2) ON CONFLICT (track_id, listener_id) WHERE listener_id IS NOT NULL DO NOTHING',
    [trackId, listenerId],
  );
  if (!inserted.rowCount) {
    return res.json({ counted: false, reason: 'Déjà compté lors de votre première écoute de ce morceau.', streams: track.streams });
  }
  await db.run('UPDATE tracks SET streams = streams + 1 WHERE id = $1', [trackId]);
  // Le vrai stream ci-dessus compte toujours pour la rémunération de l'artiste, sans plafond —
  // seule la RÉCOMPENSE de gamification (XP/points/défis) est limitée à 40 écoutes par jour,
  // pour empêcher un script d'enchaîner des écoutes en boucle uniquement pour farmer de l'XP.
  const DAILY_PLAY_REWARD_CAP = 40;
  const todayPlaysCount = (await db.get(
    "SELECT COUNT(*)::int as c FROM plays WHERE listener_id = $1 AND created_at >= CURRENT_DATE", [listenerId],
  )).c;
  if (todayPlaysCount <= DAILY_PLAY_REWARD_CAP) {
    await addXp(listenerId, 5);
    await addPoints(listenerId, 1);
    await bumpChallenge(listenerId, 'daily_listen_3', 1);
    await bumpChallenge(listenerId, 'weekly_listen_15', 1);
  }
  res.json({ counted: true, streams: track.streams + 1 });
}));

// ---------- Likes réels sur les morceaux (persistés, un seul like par personne) ----------
app.post('/api/tracks/:id/like', authMiddleware, rateLimit(30, 60000), h(async (req, res) => {
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id, likes FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });

  // Même faille de course que suivi/vote, corrigée pareillement : insertion atomique d'abord,
  // et si elle échoue (déjà liké), on bascule vers la suppression sans jamais planter.
  const inserted = await db.run(
    'INSERT INTO track_likes (user_id, track_id) VALUES ($1,$2) ON CONFLICT (user_id, track_id) DO NOTHING',
    [req.user.id, trackId],
  );
  let liked;
  if (inserted.rowCount > 0) {
    await db.run('UPDATE tracks SET likes = likes + 1 WHERE id = $1', [trackId]);
    liked = true;
    await bumpChallenge(req.user.id, 'daily_like_1', 1);
  } else {
    await db.run('DELETE FROM track_likes WHERE user_id = $1 AND track_id = $2', [req.user.id, trackId]);
    await db.run('UPDATE tracks SET likes = GREATEST(likes - 1, 0) WHERE id = $1', [trackId]);
    liked = false;
  }
  const fresh = await db.get('SELECT likes FROM tracks WHERE id = $1', [trackId]);
  res.json({ liked, likes: fresh.likes });
}));

// Signalement réel — avant, le bouton ne faisait qu'afficher un message, rien n'était
// jamais enregistré. Utilisable par un compte connecté OU un visiteur (reporter_id nullable),
// pour ne jamais bloquer un vrai signalement légitime derrière une exigence de connexion.
app.post('/api/tracks/:id/report', rateLimit(10, 60000), h(async (req, res) => {
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });
  const authHeader = req.headers.authorization;
  let reporterId = null;
  if (authHeader) {
    try { reporterId = verifyToken(authHeader.replace('Bearer ', '')).id; } catch (e) { /* visiteur non connecté : reporterId reste null */ }
  }
  const reason = (req.body && req.body.reason ? String(req.body.reason) : '').slice(0, 500) || null;
  await db.run('INSERT INTO track_reports (track_id, reporter_id, reason) VALUES ($1,$2,$3)', [trackId, reporterId, reason]);
  res.json({ message: 'Signalement enregistré — merci de votre vigilance, notre équipe va l\'examiner.' });
}));

// Liste des morceaux likés par l'utilisateur connecté — sert à resynchroniser les cœurs
// (Favoris) après une reconnexion ou sur un autre appareil, au lieu de repartir de zéro.
app.get('/api/me/liked-tracks', authMiddleware, h(async (req, res) => {
  const rows = await db.query('SELECT track_id FROM track_likes WHERE user_id = $1', [req.user.id]);
  res.json({ track_ids: rows.map((r) => r.track_id) });
}));

// ---------- Likes réels sur les clips ----------
app.post('/api/clips/:id/like', authMiddleware, rateLimit(30, 60000), h(async (req, res) => {
  const clipId = Number(req.params.id);
  const clip = await db.get('SELECT id, likes, dislikes FROM clips WHERE id = $1', [clipId]);
  if (!clip) return res.status(404).json({ error: 'Clip introuvable.' });

  // Même correction qu'ailleurs : insertion atomique d'abord.
  const inserted = await db.run(
    'INSERT INTO clip_likes (user_id, clip_id) VALUES ($1,$2) ON CONFLICT (user_id, clip_id) DO NOTHING',
    [req.user.id, clipId],
  );
  let liked;
  if (inserted.rowCount > 0) {
    await db.run('UPDATE clips SET likes = likes + 1 WHERE id = $1', [clipId]);
    liked = true;
    await bumpChallenge(req.user.id, 'daily_like_1', 1);
    // Exclusion mutuelle façon YouTube — un "j'aime" retire automatiquement un "je n'aime pas"
    // déjà posé par la même personne sur ce clip.
    const existingDislike = await db.get('SELECT id FROM clip_dislikes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
    if (existingDislike) {
      await db.run('DELETE FROM clip_dislikes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
      await db.run('UPDATE clips SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1', [clipId]);
    }
  } else {
    await db.run('DELETE FROM clip_likes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
    await db.run('UPDATE clips SET likes = GREATEST(likes - 1, 0) WHERE id = $1', [clipId]);
    liked = false;
  }
  const fresh = await db.get('SELECT likes, dislikes FROM clips WHERE id = $1', [clipId]);
  res.json({ liked, disliked: false, likes: fresh.likes, dislikes: fresh.dislikes });
}));

// ---------- "Je n'aime pas" — même principe que le like, avec exclusion mutuelle ----------
app.post('/api/clips/:id/dislike', authMiddleware, rateLimit(30, 60000), h(async (req, res) => {
  const clipId = Number(req.params.id);
  const clip = await db.get('SELECT id, likes, dislikes FROM clips WHERE id = $1', [clipId]);
  if (!clip) return res.status(404).json({ error: 'Clip introuvable.' });

  const insertedDislike = await db.run(
    'INSERT INTO clip_dislikes (user_id, clip_id) VALUES ($1,$2) ON CONFLICT (user_id, clip_id) DO NOTHING',
    [req.user.id, clipId],
  );
  let disliked;
  if (insertedDislike.rowCount > 0) {
    await db.run('UPDATE clips SET dislikes = dislikes + 1 WHERE id = $1', [clipId]);
    disliked = true;
    const existingLike = await db.get('SELECT id FROM clip_likes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
    if (existingLike) {
      await db.run('DELETE FROM clip_likes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
      await db.run('UPDATE clips SET likes = GREATEST(likes - 1, 0) WHERE id = $1', [clipId]);
    }
  } else {
    await db.run('DELETE FROM clip_dislikes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
    await db.run('UPDATE clips SET dislikes = GREATEST(dislikes - 1, 0) WHERE id = $1', [clipId]);
    disliked = false;
  }
  const fresh = await db.get('SELECT likes, dislikes FROM clips WHERE id = $1', [clipId]);
  res.json({ disliked, liked: false, likes: fresh.likes, dislikes: fresh.dislikes });
}));

// ---------- Statut like/dislike de la personne connectée sur un clip précis ----------
// Utile à l'ouverture du lecteur de clip, pour afficher les bons boutons déjà actifs.
app.get('/api/clips/:id/my-reaction', authMiddleware, h(async (req, res) => {
  const clipId = Number(req.params.id);
  const liked = await db.get('SELECT id FROM clip_likes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
  const disliked = await db.get('SELECT id FROM clip_dislikes WHERE user_id = $1 AND clip_id = $2', [req.user.id, clipId]);
  res.json({ liked: !!liked, disliked: !!disliked });
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

// ---------- Streams des 6 derniers mois — pour le graphique du Dashboard ----------
// Avant : const monthly = [{m:'Jan', v:31}, ...] codé en dur côté frontend, identique pour
// tout le monde, jamais branché sur les vraies données. Ici : vrai regroupement des écoutes
// (table plays) par mois pour les morceaux de CET artiste, sur les 6 derniers mois calendaires.
// Les mois sans aucune écoute sont bien renvoyés à 0 (et non absents), pour que le graphique
// affiche toujours 6 barres, dans l'ordre chronologique.
app.get('/api/artist/stats/monthly', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });

  const rows = await db.query(`
    SELECT to_char(date_trunc('month', p.created_at), 'YYYY-MM') as month, COUNT(*)::int as streams
    FROM plays p
    JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = $1
      AND p.created_at >= date_trunc('month', NOW()) - INTERVAL '5 months'
    GROUP BY date_trunc('month', p.created_at)
  `, [req.user.id]);

  const byMonth = {};
  rows.forEach((r) => { byMonth[r.month] = r.streams; });

  const now = new Date();
  const monthly = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    monthly.push({ m: MONTH_LABELS_FR[d.getMonth()], v: byMonth[key] || 0 });
  }

  res.json({ monthly });
}));

// ---------- Badges & progression réels — pour le panneau "Ton évolution" / "Badges exclusifs" ----------
// Avant : rang, barre de progression et badges tous codés en dur, identiques pour tout le monde.
// Ici : tout dérive de la table `plays` (un vrai stream = une ligne horodatée), sans nouvelle
// table. Pas de prédiction inventée ("X% de chances") : uniquement des faits mesurés.
// - roi_congo / rank : vrai classement par streams cumulés (tous artistes Pass actif)
// - tendance : top 3 plus forte progression sur les 7 derniers jours (vraies écoutes datées)
// - artiste_du_mois : #1 en streams depuis le 1er du mois calendaire en cours
// - revelation : compte créé il y a ≤60 jours ET déjà dans le top 50
// - legende : seuil de streams cumulés (1M, ajustable)
// - choix_public : même gagnant que le vote hebdomadaire NUNI Talent
app.get('/api/artist/badges', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const artistId = req.user.id;

  const allArtists = await db.query(`
    SELECT u.id, u.created_at,
      COALESCE((SELECT SUM(streams) FROM tracks WHERE artist_id = u.id), 0)::int as total_streams
    FROM users u
    WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
  `);
  const me = allArtists.find((a) => a.id === artistId);
  if (!me) return res.status(404).json({ error: 'Profil artiste introuvable ou Pass inactif.' });

  const sortedNow = [...allArtists].sort((a, b) => b.total_streams - a.total_streams);
  const rank = sortedNow.findIndex((a) => a.id === artistId) + 1;

  // Vraie progression sur 7 jours (table plays, horodatée) — pour "Tendance" et le delta de rang
  const growthRows = await db.query(`
    SELECT t.artist_id, COUNT(*)::int as streams_7d
    FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE p.created_at >= NOW() - INTERVAL '7 days'
    GROUP BY t.artist_id
  `);
  const growthMap = {};
  growthRows.forEach((r) => { growthMap[r.artist_id] = r.streams_7d; });
  const myWeeklyGrowth = growthMap[artistId] || 0;

  const tendanceTop3 = Object.entries(growthMap).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([id]) => Number(id));

  // Rang tel qu'il était il y a 7 jours (déduit : total actuel moins ce qui a été gagné depuis)
  const sorted7dAgo = [...allArtists]
    .map((a) => ({ id: a.id, total_7d_ago: a.total_streams - (growthMap[a.id] || 0) }))
    .sort((a, b) => b.total_7d_ago - a.total_7d_ago);
  const rank7dAgo = sorted7dAgo.findIndex((a) => a.id === artistId) + 1;
  const rankChange = rank7dAgo - rank; // positif = a gagné des places

  // Auditeurs distincts réels sur 7 jours (pas de fausse "croissance d'audience")
  const listenersRow = await db.get(`
    SELECT COUNT(DISTINCT p.listener_id)::int as n
    FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = $1 AND p.created_at >= NOW() - INTERVAL '7 days'
  `, [artistId]);

  // Streams du mois calendaire en cours, tous artistes — pour "Artiste du mois"
  const monthlyRows = await db.query(`
    SELECT t.artist_id, COUNT(*)::int as streams_month
    FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE p.created_at >= date_trunc('month', NOW())
    GROUP BY t.artist_id ORDER BY streams_month DESC LIMIT 1
  `);
  const artisteDuMoisId = monthlyRows[0] ? monthlyRows[0].artist_id : null;

  // Gagnant du vote NUNI Talent cette semaine (même règle que /api/talent/top100)
  const weekKey = weeklyPeriodKey();
  const voteWinner = await db.get(`
    SELECT artist_id FROM talent_votes WHERE week_key = $1
    GROUP BY artist_id ORDER BY COUNT(*) DESC LIMIT 1
  `, [weekKey]);

  const LEGENDE_THRESHOLD = 1000000;
  const daysSinceCreated = Math.floor((Date.now() - new Date(me.created_at).getTime()) / 86400000);

  const badges = {
    roi_congo: rank === 1,
    tendance: myWeeklyGrowth > 0 && tendanceTop3.includes(artistId),
    revelation: daysSinceCreated <= 60 && rank <= 50,
    legende: me.total_streams >= LEGENDE_THRESHOLD,
    choix_public: !!voteWinner && voteWinner.artist_id === artistId,
    artiste_du_mois: artisteDuMoisId === artistId,
  };

  // Palier suivant pour la barre de progression (prochain seuil rond au-dessus du total actuel)
  const milestones = [50000, 100000, 250000, 500000, 1000000, 2500000, 5000000, 10000000, 25000000];
  const nextMilestone = milestones.find((m) => m > me.total_streams) || me.total_streams * 2;
  const milestoneProgressPct = Math.min(100, Math.round((me.total_streams / nextMilestone) * 100));

  // Vraie courbe des 14 derniers jours (une ligne par jour, table plays)
  const dailySeries = await db.query(`
    SELECT to_char(d.day, 'YYYY-MM-DD') as day,
      COALESCE((SELECT COUNT(*)::int FROM plays p JOIN tracks t ON t.id = p.track_id
        WHERE t.artist_id = $1 AND p.created_at::date = d.day), 0) as streams
    FROM generate_series(CURRENT_DATE - INTERVAL '13 days', CURRENT_DATE, INTERVAL '1 day') as d(day)
  `, [artistId]);

  res.json({
    rank,
    rankChange,
    total_streams: me.total_streams,
    weekly_growth_streams: myWeeklyGrowth,
    weekly_new_listeners: listenersRow.n,
    nextMilestone,
    milestoneProgressPct,
    badges,
    daily_streams: dailySeries,
  });
}));


// Avant : 6 noms codés en dur ("Bibi Mwana", "Ndombe Junior"...), identiques pour tout le
// monde, indéfiniment. Ici : une vraie sélection aléatoire parmi les artistes ayant
// réellement payé leur Pass Artiste (donc de vrais comptes actifs à soutenir), qui change
// automatiquement toutes les 30 minutes — via un hash basé sur l'heure, pas de tâche
// planifiée nécessaire : la même fenêtre de 30 min donne le même ordre pour tout le monde,
// et l'ordre change tout seul dès qu'on passe à la fenêtre suivante.
app.get('/api/artists/featured', h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified,
      (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as top_genre
    FROM users u
    WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
    ORDER BY md5(u.id::text || floor(extract(epoch from now())/1800)::text)
    LIMIT 6
  `);
  res.json({ artists: rows });
}));

// ---------- Top 100 artistes — vrai classement par abonnés ----------
// Réservé aux comptes ayant réellement un Pass Artiste actif (même filtre que /featured),
// classés par leur vrai nombre d'abonnés (table follows), pas par XP ni popularité inventée.
app.get('/api/artists/top100', h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified,
      (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as top_genre,
      (SELECT COUNT(*)::int FROM follows f WHERE f.artist_id = u.id) as follower_count,
      RANK() OVER (ORDER BY (SELECT COUNT(*)::int FROM follows f WHERE f.artist_id = u.id) DESC) as rnk
    FROM users u
    WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
    ORDER BY follower_count DESC
    LIMIT 100
  `);
  res.json({ artists: rows });
}));

// ---------- Top artistes par streams — pour la pyramide Top Congo ----------
// Vrais streams cumulés (SUM sur tracks.streams), même filtre Pass Artiste actif
// que /top100 et /talent/top100. Pas de votes ici : uniquement l'écoute réelle.
app.get('/api/artists/top-streams', h(async (req, res) => {
  const genre = (req.query.genre || '').trim();
  const rows = genre
    ? await db.query(`
        SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified,
          $1::text as genre,
          COALESCE((SELECT SUM(streams) FROM tracks WHERE artist_id = u.id AND genre = $1), 0)::int as total_streams
        FROM users u
        WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
          AND EXISTS (SELECT 1 FROM tracks WHERE artist_id = u.id AND genre = $1)
        ORDER BY total_streams DESC
        LIMIT 11
      `, [genre])
    : await db.query(`
        SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified,
          (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as genre,
          COALESCE((SELECT SUM(streams) FROM tracks WHERE artist_id = u.id), 0)::int as total_streams
        FROM users u
        WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
        ORDER BY total_streams DESC
        LIMIT 11
      `);
  res.json({ artists: rows });
}));

// ---------- NUNI Talent — vrai classement (écoutes réelles + votes de la semaine) ----------
// Avant : noms fictifs, streams aléatoires générés côté client, votes jamais enregistrés.
// Score = vraies écoutes cumulées de l'artiste + un vrai poids par vote reçu cette semaine —
// un artiste avec peu de streams peut donc vraiment grimper grâce aux votes, sans que ça
// écrase complètement le poids des vraies écoutes.
const TALENT_VOTE_WEIGHT = 2000;
app.get('/api/talent/top100', h(async (req, res) => {
  const weekKey = weeklyPeriodKey();
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified,
      (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as genre,
      COALESCE((SELECT SUM(streams) FROM tracks WHERE artist_id = u.id), 0)::int as total_streams,
      (SELECT COUNT(*)::int FROM talent_votes tv WHERE tv.artist_id = u.id AND tv.week_key = $1) as votes_this_week
    FROM users u
    WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
  `, [weekKey]);

  const withScore = rows.map((r) => ({ ...r, score: r.total_streams + r.votes_this_week * TALENT_VOTE_WEIGHT }));
  withScore.sort((a, b) => b.score - a.score);
  withScore.forEach((r, i) => { r.rank = i + 1; });

  const weeklyWinner = [...withScore].sort((a, b) => b.votes_this_week - a.votes_this_week || b.score - a.score)[0] || null;

  let myVote = null;
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  if (payload) {
    const existing = await db.get('SELECT artist_id FROM talent_votes WHERE user_id = $1 AND week_key = $2', [payload.id, weekKey]);
    myVote = existing ? existing.artist_id : null;
  }

  res.json({ artists: withScore.slice(0, 100), weekly_winner: weeklyWinner, my_vote_artist_id: myVote });
}));

app.post('/api/talent/vote', authMiddleware, rateLimit(15, 60000), h(async (req, res) => {
  const { artistId } = req.body;
  const artist = await db.get(
    `SELECT id FROM users WHERE id = $1 AND account_type = 'artist' AND subscription_status = 'active' AND plan = 'artist'`,
    [artistId],
  );
  if (!artist) return res.status(404).json({ error: "Artiste introuvable ou sans Pass Artiste actif." });

  const weekKey = weeklyPeriodKey();
  // Avant : même faille de course que pour le suivi d'artiste — "déjà voté ?" vérifié puis
  // inséré en deux temps, plantait au lieu de refuser proprement en cas de double-clic rapide.
  const inserted = await db.run(
    'INSERT INTO talent_votes (user_id, artist_id, week_key) VALUES ($1,$2,$3) ON CONFLICT (user_id, week_key) DO NOTHING',
    [req.user.id, artistId, weekKey],
  );
  if (!inserted.rowCount) {
    return res.status(400).json({ error: 'Vous avez déjà voté cette semaine — revenez la semaine prochaine.' });
  }
  await addXp(req.user.id, 10);
  res.json({ message: 'Vote enregistré — merci de soutenir la scène congolaise 🕊️' });
}));

// ---------- Notifications push réelles (Web Push) ----------
// Fonctionne sur Android Chrome et iOS Safari 16.4+ (l'utilisateur doit avoir "ajouté à
// l'écran d'accueil" sur iPhone — restriction d'Apple, pas de NUNI). Les clés VAPID
// identifient NUNI auprès des services de push (Apple/Google) ; PRIVATE ne doit jamais
// être exposée côté client, seule PUBLIC_KEY l'est (via /api/push/public-key).
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || 'BIGK6eEnQwDEt8spBzCm4XrwIpX3YPpLETv7hBrYbnPxyJA-vqNRratwo2j1vV0GPL5MVV9RNqyeLRVKWa5a9iM';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '7kcTsfLMjsrhfIyfCSkuUwMshZHWchhCDSrSvHxPPAk';
webpush.setVapidDetails('mailto:nunimisiki@gmail.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

async function sendPushToUser(userId, { title, body, url }) {
  try {
    const subs = await db.query('SELECT * FROM push_subscriptions WHERE user_id = $1', [userId]);
    for (const sub of subs) {
      const pushSub = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
      const payload = JSON.stringify({ title, body, url: url || '/' });
      try {
        await webpush.sendNotification(pushSub, payload);
      } catch (e) {
        // Abonnement expiré/révoqué (l'utilisateur a désinstallé, changé de navigateur...) :
        // on le retire silencieusement, jamais bloquant pour le reste des envois.
        if (e.statusCode === 404 || e.statusCode === 410) {
          await db.run('DELETE FROM push_subscriptions WHERE id = $1', [sub.id]);
        } else {
          console.error('Erreur envoi push:', e.message);
        }
      }
    }
  } catch (e) { console.error('Erreur sendPushToUser:', e); }
}

app.get('/api/push/public-key', (req, res) => { res.json({ publicKey: VAPID_PUBLIC_KEY }); });

app.post('/api/push/subscribe', authMiddleware, h(async (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
    return res.status(400).json({ error: 'Abonnement push invalide.' });
  }
  await db.run(`
    INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth)
    VALUES ($1,$2,$3,$4)
    ON CONFLICT (endpoint) DO UPDATE SET user_id = $1, p256dh = $3, auth = $4
  `, [req.user.id, endpoint, keys.p256dh, keys.auth]);
  res.json({ message: 'Notifications push activées.' });
}));

app.post('/api/push/unsubscribe', authMiddleware, h(async (req, res) => {
  const { endpoint } = req.body;
  if (endpoint) await db.run('DELETE FROM push_subscriptions WHERE endpoint = $1 AND user_id = $2', [endpoint, req.user.id]);
  res.json({ message: 'Notifications push désactivées.' });
}));

// ---------- Notifications réelles ----------
// Avant : 3 notifications codées en dur dans le HTML, identiques pour tout le monde,
// badge toujours à "3". Ici : une vraie table, remplie uniquement à de vrais événements
// (nouveau follower, nouvelle sortie d'un artiste suivi) — pas de paiement fictif tant
// qu'il n'existe pas de vrai flux de versement aux artistes dans le backend.
async function createNotification(userId, type, title, body, link) {
  try {
    await db.run(
      'INSERT INTO notifications (user_id, type, title, body, link) VALUES ($1,$2,$3,$4,$5)',
      [userId, type, title, body, link || null],
    );
    // Chaque vraie notification devient aussi une vraie notification push, si la personne
    // en a activé au moins une (sinon push_subscriptions est vide pour elle, boucle no-op).
    sendPushToUser(userId, { title, body, url: link || '/' });
  } catch (e) { console.error('Erreur création notification:', e); }
}

app.get('/api/notifications', authMiddleware, h(async (req, res) => {
  const rows = await db.query(
    'SELECT id, type, title, body, link, is_read, created_at FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30',
    [req.user.id],
  );
  res.json({ notifications: rows });
}));

app.get('/api/notifications/unread-count', authMiddleware, h(async (req, res) => {
  const row = await db.get('SELECT COUNT(*)::int as c FROM notifications WHERE user_id = $1 AND is_read = 0', [req.user.id]);
  res.json({ count: row.c });
}));

app.post('/api/notifications/mark-read', authMiddleware, h(async (req, res) => {
  await db.run('UPDATE notifications SET is_read = 1 WHERE user_id = $1 AND is_read = 0', [req.user.id]);
  res.json({ ok: true });
}));

// Paliers de followers qui déclenchent une notification de félicitations — seuils réels,
// vérifiés à chaque nouveau follower (le compteur avance de 1 en 1, donc chaque seuil est
// forcément atteint exactement une fois, pas de risque de le "sauter").
const FOLLOWER_MILESTONES = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000];

app.post('/api/follow', authMiddleware, rateLimit(30, 60000), h(async (req, res) => {
  const { artistId } = req.body;
  const artist = await db.get('SELECT * FROM users WHERE id = $1', [artistId]);
  if (!artist || artist.account_type !== 'artist') return res.status(404).json({ error: 'Artiste introuvable.' });
  if (artist.id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas vous suivre vous-même.' });

  // Avant : vérifier "déjà suivi ?" puis insérer/supprimer dans deux requêtes séparées
  // laissait une fenêtre de course — un double-clic rapide (ou deux onglets) pouvait faire
  // planter la requête (violation de la contrainte d'unicité déjà en place sur follows,
  // jamais gérée gracieusement) au lieu de basculer proprement. Insertion atomique
  // (ON CONFLICT DO NOTHING) : si elle échoue vraiment à cause d'un doublon, c'est qu'on
  // suit déjà — on bascule alors proprement vers la suppression, sans jamais planter.
  const inserted = await db.run(
    'INSERT INTO follows (follower_id, artist_id) VALUES ($1,$2) ON CONFLICT (follower_id, artist_id) DO NOTHING',
    [req.user.id, artist.id],
  );
  let following;
  if (inserted.rowCount > 0) {
    following = true;
    await addXp(req.user.id, 20);
    await bumpChallenge(req.user.id, 'weekly_follow_2', 1);
    const follower = await db.get('SELECT first_name FROM users WHERE id = $1', [req.user.id]);
    const followerName = (follower && follower.first_name) || 'Un auditeur';
    await createNotification(artist.id, 'follower', 'Nouveau follower', `${followerName} vous suit désormais.`, null);
  } else {
    await db.run('DELETE FROM follows WHERE follower_id = $1 AND artist_id = $2', [req.user.id, artist.id]);
    following = false;
  }
  const followersCount = (await db.get('SELECT COUNT(*)::int as c FROM follows WHERE artist_id = $1', [artist.id])).c;
  if (following && FOLLOWER_MILESTONES.includes(followersCount)) {
    await createNotification(
      artist.id, 'follower_milestone', '🎉 Nouveau palier atteint',
      `Vous venez d'atteindre ${followersCount.toLocaleString('fr-FR')} followers. Votre musique touche de plus en plus de monde.`,
      null,
    );
  }
  res.json({ following, followersCount });
}));

app.get('/api/clips', h(async (req, res) => {
  const rows = await db.query(`
    SELECT c.id, c.title, c.thumb_url, c.video_url, c.views, c.likes, c.dislikes,
           u.id as artist_id, u.artist_name, u.avatar_url as artist_avatar_url
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
  // Même règle que pour les streams : un compte Pass Découverte n'a rien payé, ses vues ne
  // comptent pas tant qu'aucun vrai Pass n'est validé.
  const viewer = await db.get('SELECT plan FROM users WHERE id = $1', [viewerId]);
  if (viewer && viewer.plan === 'discovery') {
    return res.json({ counted: false, reason: "Vue en Pass Découverte — ne compte pas comme une vraie vue tant qu'aucun Pass payant n'est validé.", views: clip.views });
  }
  // Insertion atomique (la base garantit maintenant l'unicité clip_id+viewer_id) — même
  // correction que pour les streams, plus de fenêtre de course possible.
  const inserted = await db.run(
    'INSERT INTO clip_views (clip_id, viewer_id) VALUES ($1,$2) ON CONFLICT (clip_id, viewer_id) WHERE viewer_id IS NOT NULL DO NOTHING',
    [clipId, viewerId],
  );
  if (!inserted.rowCount) {
    return res.json({ counted: false, reason: 'Déjà compté lors de votre première vue de ce clip.', views: clip.views });
  }
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
// Suppression complète et réutilisable d'un compte (aucune donnée résiduelle) — utilisée à
// la fois par la suppression manuelle admin et par la purge automatique des comptes Pass
// Découverte qui n'ont validé aucun vrai Pass dans le délai de grâce.
async function fullyDeleteUser(userId) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM clip_views WHERE viewer_id = $1', [userId]);
    await client.query('DELETE FROM plays WHERE listener_id = $1', [userId]);
    await client.query('DELETE FROM track_likes WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM clip_likes WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM clip_dislikes WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM follows WHERE follower_id = $1 OR artist_id = $1', [userId]);
    await client.query('DELETE FROM payments WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM challenge_progress WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM shop_purchases WHERE user_id = $1', [userId]);
    // NUNI Talent : à la fois les votes DONNÉS par ce compte (user_id) et les votes REÇUS
    // s'il est artiste (artist_id) — oublié jusqu'ici, même bug qui avait déjà été corrigé
    // pour challenge_progress/shop_purchases (violation de clé étrangère → crash 500).
    await client.query('DELETE FROM talent_votes WHERE user_id = $1 OR artist_id = $1', [userId]);
    await client.query('DELETE FROM featured_tracks WHERE artist_id = $1', [userId]);
    // Notifications reçues (la table a bien ON DELETE CASCADE sur user_id, mais autant être
    // explicite ici plutôt que de dépendre uniquement du comportement du schéma).
    await client.query('DELETE FROM notifications WHERE user_id = $1', [userId]);
    const tracks = await client.query('SELECT id FROM tracks WHERE artist_id = $1', [userId]);
    for (const t of tracks.rows) {
      await client.query('DELETE FROM plays WHERE track_id = $1', [t.id]);
      await client.query('DELETE FROM track_likes WHERE track_id = $1', [t.id]);
      await client.query('DELETE FROM featured_tracks WHERE track_id = $1', [t.id]);
    }
    await client.query('DELETE FROM tracks WHERE artist_id = $1', [userId]);
    const clips = await client.query('SELECT id FROM clips WHERE artist_id = $1', [userId]);
    for (const c of clips.rows) {
      await client.query('DELETE FROM clip_views WHERE clip_id = $1', [c.id]);
      await client.query('DELETE FROM clip_likes WHERE clip_id = $1', [c.id]);
      await client.query('DELETE FROM clip_dislikes WHERE clip_id = $1', [c.id]);
    }
    await client.query('DELETE FROM clips WHERE artist_id = $1', [userId]);
    await client.query('DELETE FROM users WHERE id = $1', [userId]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

app.post('/api/admin/users/delete', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { email, confirm } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  if (confirm !== 'SUPPRIMER') {
    return res.status(400).json({ error: 'Confirmation manquante ou incorrecte.' });
  }
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });

  await fullyDeleteUser(user.id);

  res.json({ message: `Compte ${email} supprimé définitivement — aucune donnée résiduelle (morceaux, clips, abonnements, écoutes, follows).` });
}));

// Lecture publique, minimale : juste de quoi afficher honnêtement "X/Y déjà utilisés"
// sans jamais exposer les autres codes existants ni de données sensibles.
app.get('/api/promo/:code/status', h(async (req, res) => {
  const row = await db.get(
    'SELECT code, discount_pct, used_count, max_uses, active FROM promo_codes WHERE UPPER(code) = UPPER($1)',
    [req.params.code],
  );
  if (!row) return res.status(404).json({ error: 'Code introuvable.' });
  res.json(row);
}));

app.get('/api/admin/track-reports', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query(`
    SELECT tr.id, tr.reason, tr.created_at, t.title, t.id as track_id,
      u.artist_name, u.first_name as artist_first_name,
      rep.first_name as reporter_first_name, rep.email as reporter_email
    FROM track_reports tr
    JOIN tracks t ON t.id = tr.track_id
    JOIN users u ON u.id = t.artist_id
    LEFT JOIN users rep ON rep.id = tr.reporter_id
    ORDER BY tr.created_at DESC LIMIT 100
  `);
  res.json({ reports: rows });
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
  // Garde-fou contre une erreur de frappe (ex: "500" au lieu de "50") qui donnerait un prix
  // négatif une fois appliqué — aucune vraie utilité commerciale à un code >100% ou négatif.
  const pct = Number(discount_pct);
  if (!(pct > 0 && pct <= 100)) {
    return res.status(400).json({ error: 'Le pourcentage de réduction doit être compris entre 1 et 100.' });
  }
  try {
    await db.run(`
      INSERT INTO promo_codes (code, discount_pct, applies_to_plan, max_uses, expires_at)
      VALUES ($1,$2,$3,$4,$5)
    `, [
      String(code).toUpperCase().trim(), pct, applies_to_plan || null,
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
    // Repérer AVANT publication ce qui va sortir, pour notifier les vrais abonnés
    // (l'UPDATE seul ne permettrait pas de savoir quels morceaux viennent de changer).
    const newlyPublished = await db.query(`
      SELECT id, artist_id, title FROM tracks WHERE published = 0 AND scheduled_release_at <= NOW()
    `);
    await db.run(`UPDATE tracks SET published = 1 WHERE published = 0 AND scheduled_release_at <= NOW()`);
    await db.run(`UPDATE clips SET published = 1 WHERE published = 0 AND scheduled_release_at <= NOW()`);

    for (const track of newlyPublished) {
      const artist = await db.get('SELECT artist_name, first_name FROM users WHERE id = $1', [track.artist_id]);
      const artistName = (artist && (artist.artist_name || artist.first_name)) || 'Un artiste que vous suivez';
      const followers = await db.query('SELECT follower_id FROM follows WHERE artist_id = $1', [track.artist_id]);
      for (const f of followers) {
        await createNotification(
          f.follower_id, 'new_release', 'Nouvelle sortie suivie',
          `${artistName} vient de publier "${track.title}".`, null,
        );
      }
    }
  } catch (e) { console.error('Erreur job publication planifiée:', e); }
}, 60 * 1000);

// ---------- Rappels d'absence (3j / 7j) — vrai `last_active_date`, déjà mis à jour à
// chaque connexion (touchDailyLogin). Un seul envoi par seuil : on compare la date exacte,
// donc ça ne se déclenche qu'une fois pile à 3 jours et une fois pile à 7 jours d'absence,
// pas tous les jours en boucle. Passe une fois par jour, pas besoin de tourner plus souvent.
async function sendAbsenceReminders() {
  try {
    const staleAt = (days) => new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
    const threeDayUsers = await db.query(
      "SELECT id FROM users WHERE last_active_date IS NOT NULL AND last_active_date::date = $1::date AND account_type = 'consumer'",
      [staleAt(3)],
    );
    for (const u of threeDayUsers) {
      await createNotification(
        u.id, 'absence_reminder', '👋 On a remarqué votre absence',
        'De nouveaux morceaux vous attendent. Revenez découvrir ce qui fait vibrer le Congo.', null,
      );
    }
    const sevenDayUsers = await db.query(
      "SELECT id FROM users WHERE last_active_date IS NOT NULL AND last_active_date::date = $1::date AND account_type = 'consumer'",
      [staleAt(7)],
    );
    for (const u of sevenDayUsers) {
      await createNotification(
        u.id, 'absence_reminder', '✨ Votre bibliothèque a changé',
        'Plusieurs artistes que vous suivez ont publié de nouveaux titres depuis votre dernière visite.', null,
      );
    }
  } catch (e) { console.error('Erreur job rappels d\'absence:', e); }
}
setInterval(sendAbsenceReminders, 24 * 60 * 60 * 1000);
sendAbsenceReminders(); // premier passage au démarrage, pas besoin d'attendre 24h

// ---------- Purge des comptes Pass Découverte non validés (2h de grâce après expiration) ----------
// Ne touche QUE les comptes plan='discovery' encore au statut 'expired' — jamais un vrai
// Pass Consommateur/Artiste payé. Dès qu'un compte Découverte valide un vrai Pass (via
// activateAndNotify, redeem ou activation admin), son `plan` change et il sort
// définitivement de la portée de cette purge.
async function enforceDiscoveryDeletion() {
  try {
    const stale = await db.query(`
      SELECT id FROM users
      WHERE plan = 'discovery' AND subscription_status = 'expired'
        AND subscription_expires_at IS NOT NULL
        AND subscription_expires_at < NOW() - INTERVAL '2 hours'
    `);
    for (const u of stale) {
      try { await fullyDeleteUser(u.id); } catch (e) { console.error('Erreur purge Pass Découverte pour user', u.id, e); }
    }
  } catch (e) { console.error('Erreur job purge Pass Découverte:', e); }
}

async function start() {
  await db.initSchema();
  await initAuth();

  enforceSubscriptionExpiry();
  setInterval(enforceSubscriptionExpiry, 60 * 1000);
  enforceDiscoveryDeletion();
  setInterval(enforceDiscoveryDeletion, 5 * 60 * 1000);

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`NUNI backend en écoute sur http://localhost:${PORT}`));
}

start().catch((err) => {
  console.error('Échec du démarrage du serveur :', err);
  process.exit(1);
});

module.exports = app;
