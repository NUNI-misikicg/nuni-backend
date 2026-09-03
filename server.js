// server.js — Serveur NUNI (Express + Postgres/Neon + Cloudinary)
require('dotenv').config();
const path = require('path');
const dns = require('dns').promises;
const express = require('express');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const webpush = require('web-push');
const db = require('./db');
const {
  initAuth, hashPassword, verifyPassword, needsRehash, signToken, verifyToken, generateAccessCode,
  generateResetCode, hashResetCode, authMiddleware,
} = require('./auth');
const { sendAccessCodeEmail, sendPasswordResetEmail, sendAdRequestEmail, sendArtistPaymentEmail, sendVerificationEmail, sendAccessCodeToClient } = require('./mailer');

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

// Avant : toute valeur qui n'était pas une data-URI était renvoyée TELLE QUELLE, sans
// aucune vérification — utilisé par la création de morceaux (cover/audio), de clips
// (thumb/vidéo), la galerie "À propos", et les documents Label. N'importe quel champ pouvait
// donc recevoir une URL externe arbitraire au lieu d'un vrai fichier uploadé sur Cloudinary,
// stockée telle quelle et servie ensuite comme si c'était un vrai contenu NUNI (risque de
// contenu non modéré, de lien piégé, ou de traceur invisible). Maintenant : une valeur qui
// n'est ni une data-URI ni déjà une vraie URL Cloudinary est refusée (null) plutôt
// qu'acceptée aveuglément.
async function uploadIfDataUri(value, resourceType) {
  if (!value) return null;
  if (!String(value).startsWith('data:')) {
    return isCloudinaryUrl(value) ? value : null;
  }
  const result = await cloudinary.uploader.upload(value, {
    resource_type: resourceType,
    folder: 'nuni',
  });
  return result.secure_url;
}
function isCloudinaryUrl(url) {
  return typeof url === 'string' && /^https:\/\/res\.cloudinary\.com\//.test(url);
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
  consumer: { 30: 750, 90: 650, 365: 1250 },
  artist: { 90: 5000, 365: 10000 },
};
function basePriceFor(plan, durationDays) {
  const table = PRICE_TABLE[plan] || PRICE_TABLE.consumer;
  if (table[durationDays] != null) return table[durationDays];
  const refDays = table[90] ? 90 : 365;
  const ref = table[refDays] || Object.values(table)[0] || 0;
  return Math.round((ref / refDays) * durationDays);
}

async function resolvePromoDiscount(code, plan, userId) {
  if (!code) return { pct: 0, valid: true, code: null };
  const promo = await db.get('SELECT * FROM promo_codes WHERE code = $1', [String(code).toUpperCase().trim()]);
  if (!promo) return { pct: 0, valid: false, error: 'Code promo introuvable.' };
  if (!promo.active) return { pct: 0, valid: false, error: 'Code promo désactivé.' };
  if (promo.expires_at && new Date(promo.expires_at) < new Date()) return { pct: 0, valid: false, error: 'Code promo expiré.' };
  if (promo.used_count >= promo.max_uses) return { pct: 0, valid: false, error: "Ce code a atteint sa limite d'utilisation." };
  if (promo.applies_to_plan && promo.applies_to_plan !== plan) return { pct: 0, valid: false, error: "Ce code ne s'applique pas à ce Pass." };
  // Code personnel : réservé à un seul compte, personne d'autre ne peut l'utiliser même en
  // le devinant ou en le voyant passer quelque part.
  if (promo.assigned_to_user_id && promo.assigned_to_user_id !== userId) {
    return { pct: 0, valid: false, error: 'Ce code est réservé à un autre compte.' };
  }
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

// ---------- Vérification réelle qu'un domaine email peut recevoir des messages ----------
// Avant : seul le FORMAT de l'email était vérifié (présence d'un @, d'un point...) — une
// adresse avec un domaine bidon ou mal orthographié (ex. "jean@gmial.com") passait sans
// problème à l'inscription, désynchronisée de tout vrai utilisateur. Ici : une vraie requête
// DNS vérifie que le domaine a des enregistrements MX (serveurs de messagerie) — donc qu'il
// peut RÉELLEMENT recevoir un email, quel que soit le fournisseur (Gmail, Yahoo, Outlook...).
// N'utilise que le module dns natif de Node, aucun service tiers payant. Un cache mémoire de
// 10 minutes évite de refaire la même requête DNS à chaque frappe pour un domaine déjà vérifié.
const emailDomainCache = new Map(); // domaine -> { valid, checkedAt }
async function emailDomainCanReceiveMail(email) {
  if (!isEmail(email)) return false;
  const domain = email.split('@')[1].toLowerCase();
  const cached = emailDomainCache.get(domain);
  if (cached && Date.now() - cached.checkedAt < 10 * 60 * 1000) return cached.valid;
  let valid;
  try {
    const records = await dns.resolveMx(domain);
    valid = Array.isArray(records) && records.length > 0;
  } catch (e) {
    // ENOTFOUND / ENODATA = domaine sans serveur de messagerie, donc invalide. Toute autre
    // erreur (timeout DNS ponctuel, etc.) ne doit jamais bloquer une vraie personne à tort —
    // on laisse passer plutôt que de pénaliser un souci réseau temporaire de notre côté.
    valid = !['ENOTFOUND', 'ENODATA'].includes(e.code);
  }
  emailDomainCache.set(domain, { valid, checkedAt: Date.now() });
  return valid;
}
// ---------- Génère et envoie un nouveau code de vérification d'email ----------
// Réutilisé par /api/register, /api/register-discovery et /api/auth/resend-verification —
// un seul point qui génère le code, le hache avant stockage (jamais en clair, même
// logique que le mot de passe oublié), fixe l'expiration à 30 minutes, et remet le
// compteur de tentatives à zéro.
async function issueEmailVerification(user) {
  const code = generateResetCode(); // même générateur que le mot de passe oublié (6 chiffres)
  await db.run(
    `UPDATE users SET email_verify_code = $1, email_verify_expires_at = NOW() + INTERVAL '30 minutes', email_verify_attempts = 0 WHERE id = $2`,
    [hashResetCode(code), user.id],
  );
  return sendVerificationEmail({ user, code });
}
function required(obj, fields) {
  return fields.filter((f) => !obj[f] || String(obj[f]).trim() === '');
}
function publicUser(u) {
  // Avant : seul password_hash était retiré. reset_code et email_verify_code restaient
  // exposés dans la réponse API — ce sont des hachages de codes à 6 CHIFFRES SEULEMENT
  // (1 million de combinaisons), donc cassables hors-ligne en une fraction de seconde une
  // fois le hash connu, contrairement à un mot de passe. Toute donnée interne sensible est
  // désormais retirée, pas seulement le mot de passe.
  const {
    password_hash, reset_code, reset_code_expires_at, reset_code_attempts,
    email_verify_code, email_verify_expires_at, email_verify_attempts,
    ...safe
  } = u;
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
// Connexion quotidienne : +15 XP la première fois du jour, et incrémente la vraie série
// (streak_days) si la dernière activité était bien hier — remise à zéro sinon.
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
      'UPDATE users SET last_active_date = $1, streak_days = $2, xp = COALESCE(xp,0) + 15 WHERE id = $3',
      [today, newStreak, userId],
    );
  } catch (e) { /* jamais bloquant */ }
}

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
  res.json({ message: `+${def.xp} XP !`, xp_awarded: def.xp });
}));

// ================= AUTH =================

// ---------- Vérification en direct pendant la saisie de l'email (avant soumission du
// formulaire) — retour immédiat, la même vérification MX que celle appliquée à
// l'inscription elle-même (défense en profondeur : ce contrôle client n'est qu'un confort,
// jamais une garantie — la vraie vérification reste toujours refaite côté serveur ci-dessus). ----------
app.get('/api/auth/check-email-domain', rateLimit(30, 60000), h(async (req, res) => {
  const email = String(req.query.email || '');
  if (!isEmail(email)) return res.json({ valid: false, reason: 'format' });
  const valid = await emailDomainCanReceiveMail(email);
  res.json({ valid, reason: valid ? null : 'domain' });
}));

app.post('/api/register', rateLimit(10, 60 * 60000), h(async (req, res) => {
  const {
    accountType, firstName, lastName, email, phone, password,
    age, address, city, country, artistName, labelOrManager,
    // ---- Champs spécifiques au Pass Label ----
    labelName, logoUrl, legalName, professionalPhone, professionalEmail, website, taxId,
    labelDescription, socialLinks, responsibleName, responsibleIdDocUrl, labelDocUrl, labelPlan,
  } = req.body;

  if (!['consumer', 'artist', 'label'].includes(accountType)) {
    return res.status(400).json({ error: 'Type de compte invalide (consumer, artist ou label).' });
  }

  if (accountType === 'label') {
    // Un Label est une entreprise : pas de vérification d'âge (16 ans) comme pour une
    // personne physique, mais ses propres champs obligatoires (nom légal, contact pro...).
    const labelRequired = ['firstName', 'lastName', 'email', 'password', 'address', 'city', 'country', 'labelName', 'legalName', 'professionalPhone', 'professionalEmail'];
    const missingLabel = required(req.body, labelRequired);
    if (missingLabel.length) return res.status(400).json({ error: `Champs manquants : ${missingLabel.join(', ')}` });
    if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
    if (!isEmail(professionalEmail)) return res.status(400).json({ error: 'Email professionnel invalide.' });
    if (!(await emailDomainCanReceiveMail(email))) {
      return res.status(400).json({ error: "Cette adresse email n'existe pas — vérifiez l'orthographe." });
    }
    if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
    if (await db.get('SELECT id FROM users WHERE email = $1', [email])) {
      return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
    }
    const password_hash = await hashPassword(password);
    // plan='label' explicite — sans ça, la colonne retombe sur 'discovery' par défaut et
    // casse le routage post-connexion (voir /api/login côté client : il redirige vers la
    // page des tarifs pour tout compte dont subscription_status n'est pas 'active' ET dont
    // plan est 'discovery', ce qui décrivait alors n'importe quel compte Label par erreur).
    const insertedUser = await db.get(`
      INSERT INTO users (account_type, first_name, last_name, email, phone, password_hash, address, city, country, plan)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'label')
      RETURNING id
    `, [accountType, firstName, lastName, email, phone || null, password_hash, address, city, country]);
    const validPlan = ['start', 'pro', 'premium', 'elite'].includes(labelPlan) ? labelPlan : 'start';
    // Fichiers reçus en base64 (aucun jeton disponible avant que le compte existe, donc pas
    // d'upload direct signé possible) — le serveur les envoie lui-même à Cloudinary.
    const [finalLogoUrl, finalIdDocUrl, finalLabelDocUrl] = await Promise.all([
      uploadIfDataUri(logoUrl, 'image'),
      uploadIfDataUri(responsibleIdDocUrl, 'auto'),
      uploadIfDataUri(labelDocUrl, 'auto'),
    ]);
    await db.run(`
      INSERT INTO labels (
        user_id, label_name, logo_url, legal_name, country, city, address, professional_phone,
        professional_email, website, tax_id, description, social_links, responsible_name,
        responsible_id_doc_url, label_doc_url, plan
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
    `, [
      insertedUser.id, labelName, finalLogoUrl || null, legalName, country, city, address,
      professionalPhone, professionalEmail, website || null, taxId || null,
      labelDescription || null, socialLinks || null, responsibleName || null,
      finalIdDocUrl || null, finalLabelDocUrl || null, validPlan,
    ]);
    const labelUser = await db.get('SELECT * FROM users WHERE id = $1', [insertedUser.id]);
    const token = signToken(labelUser);
    const planSettingsForMsg = await getLabelPlanSettings();
    const planLabelsForMsg = { start: 'Label Start', pro: 'Label Pro', premium: 'Label Premium', elite: 'Label Elite' };
    return res.status(201).json({
      message: 'Demande envoyée — votre compte Label est en attente de vérification (sous 24h).',
      token,
      user: publicUser(labelUser),
      labelPlanName: planLabelsForMsg[validPlan],
      labelPlanPriceFcfa: planSettingsForMsg.prices[validPlan],
    });
  }

  const baseRequired = ['firstName', 'lastName', 'email', 'password', 'age', 'address', 'city', 'country'];
  const missing = required(req.body, accountType === 'artist' ? [...baseRequired, 'artistName'] : baseRequired);
  if (missing.length) {
    return res.status(400).json({ error: `Champs manquants : ${missing.join(', ')}` });
  }
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (!(await emailDomainCanReceiveMail(email))) {
    return res.status(400).json({ error: "Cette adresse email n'existe pas — vérifiez l'orthographe." });
  }
  if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  if (Number(age) < 16) return res.status(400).json({ error: 'NUNI est réservé aux 16 ans et plus.' });

  if (await db.get('SELECT id FROM users WHERE email = $1', [email])) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }

  const password_hash = await hashPassword(password);
  const inserted = await db.get(`
    INSERT INTO users (account_type, first_name, last_name, email, phone, password_hash, age, address, city, country, artist_name, label_or_manager, email_verified)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,FALSE)
    RETURNING id
  `, [
    accountType, firstName, lastName, email, phone || null, password_hash, Number(age), address, city, country,
    accountType === 'artist' ? artistName : null,
    accountType === 'artist' ? (labelOrManager || null) : null,
  ]);

  const user = await db.get('SELECT * FROM users WHERE id = $1', [inserted.id]);
  issueEmailVerification(user).catch((e) => console.error('[register] échec envoi vérification email :', e.message));
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
// autre Pass). Une fois expiré, le compte reste simplement "expiré" — il n'est PLUS jamais
// supprimé automatiquement (voir enforceDiscoveryDeletion plus bas : une suppression
// automatique aurait libéré l'email et permis des essais gratuits en série).
app.post('/api/register-discovery', rateLimit(10, 60 * 60000), h(async (req, res) => {
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
  if (!(await emailDomainCanReceiveMail(email))) {
    return res.status(400).json({ error: "Cette adresse email n'existe pas — vérifiez l'orthographe." });
  }
  if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  if (Number(age) < 16) return res.status(400).json({ error: 'NUNI est réservé aux 16 ans et plus.' });
  if (await db.get('SELECT id FROM users WHERE email = $1', [email])) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }

  const password_hash = await hashPassword(password);
  const inserted = await db.get(`
    INSERT INTO users (
      account_type, first_name, last_name, email, phone, password_hash, age, address, city, country,
      artist_name, label_or_manager, plan, subscription_status, subscription_expires_at, email_verified
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'discovery','active',NOW() + INTERVAL '24 hours', FALSE)
    RETURNING id
  `, [
    accountType, firstName, lastName, email, phone || null, password_hash, Number(age), address, city, country,
    accountType === 'artist' ? artistName : null,
    accountType === 'artist' ? (labelOrManager || null) : null,
  ]);

  const user = await db.get('SELECT * FROM users WHERE id = $1', [inserted.id]);
  // Le compte Découverte démarre bien immédiatement (aucune friction ajoutée à
  // l'inscription) — mais son accès réel au streaming reste bloqué tant que l'email n'est
  // pas confirmé (voir hasStreamingAccess plus bas). C'est cette vérification, pas un blocage
  // à l'inscription, qui ferme la porte aux essais gratuits en série avec des adresses
  // jetables ou variantes : il faut réellement recevoir et saisir un code pour écouter.
  issueEmailVerification(user).catch((e) => console.error('[register-discovery] échec envoi vérification email :', e.message));
  const token = signToken(user);
  res.status(201).json({
    message: 'Pass Découverte activé — confirmez votre email pour débloquer 24h d\'écoute NUNI en intégralité.',
    token,
    user: publicUser(await withArtistStats(user)),
  });
}));


// Ordre volontaire : on ne révèle rien sur l'existence du compte tant que le mot de passe
// n'est pas confirmé exact. Ce n'est qu'APRÈS un mot de passe correct qu'on vérifie si le
// compte est suspendu/supprimé — sinon on donnerait à n'importe qui un moyen de deviner
// quels emails ont un compte suspendu, juste en essayant de se connecter avec.
app.post('/api/login', rateLimit(10, 15 * 60000), h(async (req, res) => {
  await enforceSubscriptionExpiry();
  const { email, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE email = $1', [email || '']);
  // Avant : répondre "email inconnu" était quasi instantané, alors que "mauvais mot de
  // passe" prenait le temps du calcul Argon2id (volontairement lent) sur un vrai hash — la
  // différence de délai entre les deux permettait de deviner quels emails ont un compte
  // NUNI, juste en chronométrant les réponses (email enumeration par timing). Un compte
  // inexistant déclenche maintenant quand même une vraie vérification, contre un hash
  // factice fixe, pour un temps de réponse cohérent dans les deux cas.
  const DUMMY_HASH = '$argon2id$v=19$m=65536,p=4,t=3$FFEARNH0EaLUJ5yNEJYXeg$pzICrPiEaM5VBe02AHRDPmjPuqCNHhGG2AlvpQ87WPg';
  const ok = await verifyPassword(password || '', user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });

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

// ---------- Mot de passe oublié ----------
// Étape 1 : demande d'un code à 6 chiffres, envoyé par email au client (pas à la boîte NUNI,
// contrairement au code d'accès). On ne révèle JAMAIS si l'email correspond à un compte —
// même message de succès dans tous les cas, pour ne pas permettre de deviner quels emails
// sont inscrits sur NUNI.
app.post('/api/auth/forgot-password', rateLimit(5, 15 * 60000), h(async (req, res) => {
  const { email } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });

  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (user && user.account_status !== 'deleted') {
    const code = generateResetCode();
    await db.run(
      `UPDATE users SET reset_code = $1, reset_code_expires_at = NOW() + INTERVAL '15 minutes', reset_code_attempts = 0 WHERE id = $2`,
      [hashResetCode(code), user.id],
    );
    sendPasswordResetEmail({ user, resetCode: code }).catch((e) => {
      console.error('[forgot-password] échec envoi email :', e.message);
    });
  }
  res.json({ message: "Si un compte existe avec cet email, un code de réinitialisation vient d'être envoyé." });
}));

// Étape 2 : vérification du code + nouveau mot de passe. Code hashé (jamais stocké en clair),
// expire après 15 minutes, et bloqué après 5 tentatives incorrectes (protection brute-force
// sur un code à 6 chiffres).
app.post('/api/auth/reset-password', rateLimit(10, 15 * 60000), h(async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!isEmail(email) || !code || !newPassword) {
    return res.status(400).json({ error: 'Champs manquants.' });
  }
  if (String(newPassword).length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  }

  const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
  if (!user || !user.reset_code || !user.reset_code_expires_at) {
    return res.status(400).json({ error: 'Code invalide ou expiré.' });
  }
  if (new Date(user.reset_code_expires_at).getTime() < Date.now()) {
    return res.status(400).json({ error: "Ce code a expiré — merci d'en redemander un nouveau." });
  }
  if (user.reset_code_attempts >= 5) {
    await db.run('UPDATE users SET reset_code = NULL, reset_code_expires_at = NULL WHERE id = $1', [user.id]);
    return res.status(400).json({ error: 'Trop de tentatives incorrectes — merci de redemander un nouveau code.' });
  }
  if (hashResetCode(code) !== user.reset_code) {
    await db.run('UPDATE users SET reset_code_attempts = reset_code_attempts + 1 WHERE id = $1', [user.id]);
    return res.status(400).json({ error: 'Code incorrect.' });
  }

  const password_hash = await hashPassword(newPassword);
  await db.run(
    `UPDATE users SET password_hash = $1, reset_code = NULL, reset_code_expires_at = NULL, reset_code_attempts = 0 WHERE id = $2`,
    [password_hash, user.id],
  );
  res.json({ message: 'Mot de passe réinitialisé — vous pouvez maintenant vous connecter.' });
}));

// ---------- Vérification d'email — ferme la faille des essais Pass Découverte en série ----------
// Confirme que l'adresse saisie à l'inscription appartient vraiment à la personne, avant de
// débloquer son accès réel au streaming (voir hasStreamingAccess plus bas). Même protection
// anti-brute-force qu'un mot de passe oublié : code haché, expire après 30 minutes, bloqué
// après 5 tentatives incorrectes.
app.post('/api/auth/verify-email', authMiddleware, rateLimit(10, 15 * 60000), h(async (req, res) => {
  const { code } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.email_verified) return res.json({ message: 'Email déjà confirmé.', already_verified: true });
  if (!user.email_verify_code || !user.email_verify_expires_at) {
    return res.status(400).json({ error: "Aucun code en attente — demandez-en un nouveau." });
  }
  if (new Date(user.email_verify_expires_at).getTime() < Date.now()) {
    return res.status(400).json({ error: "Ce code a expiré — demandez-en un nouveau." });
  }
  if (user.email_verify_attempts >= 5) {
    await db.run('UPDATE users SET email_verify_code = NULL, email_verify_expires_at = NULL WHERE id = $1', [user.id]);
    return res.status(400).json({ error: 'Trop de tentatives incorrectes — demandez un nouveau code.' });
  }
  if (hashResetCode(code) !== user.email_verify_code) {
    await db.run('UPDATE users SET email_verify_attempts = email_verify_attempts + 1 WHERE id = $1', [user.id]);
    return res.status(400).json({ error: 'Code incorrect.' });
  }
  await db.run(
    `UPDATE users SET email_verified = TRUE, email_verify_code = NULL, email_verify_expires_at = NULL, email_verify_attempts = 0 WHERE id = $1`,
    [user.id],
  );
  const fresh = await db.get('SELECT * FROM users WHERE id = $1', [user.id]);
  res.json({ message: 'Email confirmé — bienvenue sur NUNI en intégralité !', user: publicUser(await withArtistStats(fresh)) });
}));

app.post('/api/auth/resend-verification', authMiddleware, rateLimit(5, 15 * 60000), h(async (req, res) => {
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.email_verified) return res.json({ message: 'Email déjà confirmé.', already_verified: true });
  const result = await issueEmailVerification(user);
  if (!result.sent) return res.status(502).json({ error: "L'envoi a échoué — réessayez dans un instant." });
  res.json({ message: 'Nouveau code envoyé à votre adresse email.' });
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

app.post('/api/me/mark-contract-seen', authMiddleware, h(async (req, res) => {
  await db.run('UPDATE users SET has_seen_artist_contract = 1 WHERE id = $1', [req.user.id]);
  res.json({ ok: true });
}));

// ================= PASS LABEL (Phase 1) =================
const LABEL_PLAN_MAX_ARTISTS = { start: 2, pro: 5, premium: 10, elite: null }; // valeurs par défaut, voir getLabelPlanSettings ci-dessous pour les vraies valeurs configurables
const LABEL_PLAN_DEFAULT_PRICES_FCFA = { start: 15000, pro: 30000, premium: 60000, elite: 120000 }; // par trimestre, valeurs par défaut

// ---------- Paliers Label configurables depuis l'admin (Phase 6) ----------
// Stockés dans app_settings (même mécanisme que les taux de reversement) — si rien n'a
// encore été configuré, les valeurs par défaut ci-dessus s'appliquent, jamais de crash.
async function getLabelPlanSettings() {
  const keys = [
    'label_plan_max_start', 'label_plan_max_pro', 'label_plan_max_premium', 'label_plan_max_elite',
    'label_plan_price_start', 'label_plan_price_pro', 'label_plan_price_premium', 'label_plan_price_elite',
  ];
  const rows = await db.query('SELECT key, value FROM app_settings WHERE key = ANY($1)', [keys]);
  const map = {};
  rows.forEach((r) => { map[r.key] = r.value; });
  const parseMax = (v, fallback) => (v === '' || v == null ? fallback : (v === 'null' ? null : Number(v)));
  return {
    maxArtists: {
      start: parseMax(map.label_plan_max_start, LABEL_PLAN_MAX_ARTISTS.start),
      pro: parseMax(map.label_plan_max_pro, LABEL_PLAN_MAX_ARTISTS.pro),
      premium: parseMax(map.label_plan_max_premium, LABEL_PLAN_MAX_ARTISTS.premium),
      elite: parseMax(map.label_plan_max_elite, LABEL_PLAN_MAX_ARTISTS.elite),
    },
    prices: {
      start: map.label_plan_price_start != null ? Number(map.label_plan_price_start) : LABEL_PLAN_DEFAULT_PRICES_FCFA.start,
      pro: map.label_plan_price_pro != null ? Number(map.label_plan_price_pro) : LABEL_PLAN_DEFAULT_PRICES_FCFA.pro,
      premium: map.label_plan_price_premium != null ? Number(map.label_plan_price_premium) : LABEL_PLAN_DEFAULT_PRICES_FCFA.premium,
      elite: map.label_plan_price_elite != null ? Number(map.label_plan_price_elite) : LABEL_PLAN_DEFAULT_PRICES_FCFA.elite,
    },
  };
}

// ---------- Publique — pour afficher les vrais prix/limites sur la page tarifs et le formulaire d'inscription ----------
app.get('/api/label-plan-settings', h(async (req, res) => {
  res.json(await getLabelPlanSettings());
}));

// ---------- Admin — modifier les limites et les prix ----------
app.post('/api/admin/label-plan-settings', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { maxArtists, prices } = req.body;
  const pairs = [];
  if (maxArtists) {
    ['start', 'pro', 'premium', 'elite'].forEach((p) => {
      if (maxArtists[p] !== undefined) pairs.push([`label_plan_max_${p}`, maxArtists[p] === null ? 'null' : String(maxArtists[p])]);
    });
  }
  if (prices) {
    ['start', 'pro', 'premium', 'elite'].forEach((p) => {
      if (prices[p] !== undefined) pairs.push([`label_plan_price_${p}`, String(prices[p])]);
    });
  }
  for (const [key, value] of pairs) {
    await db.run(
      `INSERT INTO app_settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, value],
    );
  }
  res.json({ message: 'Paliers Label mis à jour.', settings: await getLabelPlanSettings() });
}));

// ---------- Le Label consulte son propre profil + statut de vérification ----------
app.get('/api/label/me', authMiddleware, h(async (req, res) => {
  const user = await db.get('SELECT account_type FROM users WHERE id = $1', [req.user.id]);
  if (!user || user.account_type !== 'label') return res.status(403).json({ error: 'Réservé aux comptes Label.' });
  const label = await db.get('SELECT * FROM labels WHERE user_id = $1', [req.user.id]);
  if (!label) return res.status(404).json({ error: 'Profil Label introuvable.' });
  const artistCount = (await db.get(
    "SELECT COUNT(*)::int as c FROM label_artists WHERE label_id = $1 AND status = 'active'",
    [label.id],
  )).c;
  const planSettings1 = await getLabelPlanSettings();
  res.json({ label, artistCount, maxArtists: planSettings1.maxArtists[label.plan] });
}));

// ---------- Admin — liste des Labels (filtrable par statut de vérification) ----------
app.get('/api/admin/labels', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const status = req.query.status;
  const rows = status
    ? await db.query(
        `SELECT l.*, u.email, u.first_name, u.last_name, u.phone
         FROM labels l JOIN users u ON u.id = l.user_id
         WHERE l.verification_status = $1 ORDER BY l.created_at DESC`,
        [status],
      )
    : await db.query(
        `SELECT l.*, u.email, u.first_name, u.last_name, u.phone
         FROM labels l JOIN users u ON u.id = l.user_id ORDER BY l.created_at DESC`,
      );
  res.json({ labels: rows });
}));

// ---------- Admin — approuver un Label ----------
app.post('/api/admin/labels/:id/approve', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get('SELECT id FROM labels WHERE id = $1', [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  await db.run(
    `UPDATE labels SET verification_status = 'validated', validated_at = NOW(), refusal_reason = NULL,
      subscription_expires_at = NOW() + INTERVAL '1 year' WHERE id = $1`,
    [label.id],
  );
  res.json({ message: 'Label validé.' });
}));

// ---------- Admin — refuser un Label (avec raison) ----------
app.post('/api/admin/labels/:id/refuse', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get('SELECT id FROM labels WHERE id = $1', [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  const { reason } = req.body;
  await db.run(
    "UPDATE labels SET verification_status = 'refused', refusal_reason = $1 WHERE id = $2",
    [reason || null, label.id],
  );
  res.json({ message: 'Label refusé.' });
}));

// ---------- Admin — suspendre un Label déjà validé (accès Dashboard coupé, comptes
// artistes affiliés jamais touchés) ----------
app.post('/api/admin/labels/:id/suspend', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get('SELECT id FROM labels WHERE id = $1', [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  const { reason } = req.body;
  await db.run(
    "UPDATE labels SET verification_status = 'suspended', refusal_reason = $1 WHERE id = $2",
    [reason || null, label.id],
  );
  res.json({ message: 'Label suspendu.' });
}));
app.post('/api/admin/labels/:id/reactivate', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get('SELECT id FROM labels WHERE id = $1', [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  await db.run("UPDATE labels SET verification_status = 'validated', refusal_reason = NULL WHERE id = $1", [label.id]);
  res.json({ message: 'Label réactivé.' });
}));

// ---------- Admin — détail d'un Label : artistes liés + revenus, en un coup d'œil ----------
app.get('/api/admin/labels/:id/details', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get(`
    SELECT l.*, u.email, u.first_name, u.last_name, u.phone
    FROM labels l JOIN users u ON u.id = l.user_id WHERE l.id = $1
  `, [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  const artists = await db.query(`
    SELECT la.status as affiliation_status, u.id as artist_id, u.artist_name, u.email,
           COALESCE((SELECT SUM(t.streams)::bigint FROM tracks t WHERE t.artist_id = u.id AND t.published = 1), 0) as total_streams,
           COALESCE((SELECT SUM(ph.amount_fcfa)::bigint FROM payment_history ph WHERE ph.artist_id = u.id), 0) as total_paid_fcfa
    FROM label_artists la JOIN users u ON u.id = la.artist_id
    WHERE la.label_id = $1 AND la.status != 'removed'
    ORDER BY la.created_at DESC
  `, [label.id]);
  const totalStreams = artists.reduce((s, a) => s + Number(a.total_streams), 0);
  const totalPaidFcfa = artists.reduce((s, a) => s + Number(a.total_paid_fcfa), 0);
  res.json({ label, artists, totalStreams, totalPaidFcfa });
}));

// ---------- Admin — repasser un Label "en cours de vérification" (étape intermédiaire) ----------
app.post('/api/admin/labels/:id/mark-verification', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get('SELECT id FROM labels WHERE id = $1', [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  await db.run("UPDATE labels SET verification_status = 'verification' WHERE id = $1", [label.id]);
  res.json({ message: 'Marqué en cours de vérification.' });
}));

// ================= PASS LABEL — Phase 2 : gestion des artistes + vue d'ensemble =================
// Un Label validé peut gérer plusieurs artistes depuis son compte. IMPORTANT : "suspendre"
// ou "retirer" un artiste n'affecte QUE l'affiliation (label_artists) — jamais le compte
// artiste lui-même (account_status), qui reste sous le contrôle exclusif de l'artiste.
// Un Label ne peut jamais bloquer l'accès NUNI d'un artiste indépendant.
//
// ---------- Système de rôles (Phase 4) ----------
// Le compte de connexion du Label (labels.user_id) est toujours 'owner', rang le plus élevé.
// Les membres d'équipe (label_team_members) ont chacun un rôle propre, avec des permissions
// croissantes : assistant < manager < admin < owner. minRole fixe le rang minimum requis
// pour l'action demandée — par défaut 'assistant' (accès en lecture pour toute l'équipe).
const LABEL_ROLE_RANK = { assistant: 1, manager: 2, admin: 3, owner: 4 };
// Notifie le propriétaire du Label quand un artiste rejoint (création ou invitation
// acceptée), et signale en plus si le palier de son plan vient d'être atteint.
async function notifyLabelArtistAdded(label, artistName, newCount) {
  await createNotification(
    label.user_id, 'label_artist_added', 'Nouvel artiste',
    `${artistName} fait maintenant partie de ${label.label_name}.`, null,
  ).catch(() => {});
  const planSettings = await getLabelPlanSettings();
  const max = planSettings.maxArtists[label.plan];
  if (max !== null && newCount >= max) {
    await createNotification(
      label.user_id, 'label_plan_limit', 'Palier atteint',
      `${label.label_name} a atteint la limite de ${max} artiste(s) de son palier actuel. Passez à un palier supérieur pour continuer à ajouter des artistes.`, null,
    ).catch(() => {});
  }
}

// ---------- Activation atomique d'une affiliation Label <-> artiste — réutilisée par
// /accept ET /reactivate, jamais dupliquée. Corrige le contournement de maxArtists trouvé
// en audit : la vérification se faisait uniquement à l'invitation (/invite), jamais au
// moment réel où le statut passe à 'active'. Verrouille la ligne du Label (SELECT ... FOR
// UPDATE) pour la durée de la transaction : deux acceptations simultanées pour le MÊME
// Label se sérialisent — la deuxième ne voit la vraie limite qu'une fois la première
// entièrement validée et committée, jamais un compte simultané obsolète.
async function tryActivateLabelArtist(affiliationId, expectedArtistId) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const aff = await client.query(
      `SELECT la.id, la.label_id, la.artist_id, la.status
       FROM label_artists la WHERE la.id = $1 FOR UPDATE`,
      [affiliationId],
    );
    const row = aff.rows[0];
    if (!row || (expectedArtistId != null && row.artist_id !== expectedArtistId)) {
      await client.query('ROLLBACK');
      return { ok: false, status: 404, error: 'Affiliation introuvable.' };
    }
    if (row.status === 'active') {
      await client.query('ROLLBACK');
      return { ok: false, status: 409, error: 'Cette affiliation est déjà active.' };
    }
    // Verrou sur la ligne labels elle-même — c'est CE verrou, pas celui de l'affiliation,
    // qui sérialise réellement les tentatives concurrentes visant le même Label.
    const labelRow = await client.query('SELECT id, plan FROM labels WHERE id = $1 FOR UPDATE', [row.label_id]);
    const label = labelRow.rows[0];
    if (!label) { await client.query('ROLLBACK'); return { ok: false, status: 404, error: 'Label introuvable.' }; }
    const planSettings = await getLabelPlanSettings();
    const max = planSettings.maxArtists[label.plan];
    const currentActive = await client.query(
      "SELECT COUNT(*)::int AS c FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
    );
    if (max !== null && currentActive.rows[0].c >= max) {
      await client.query('ROLLBACK');
      return { ok: false, status: 403, error: `Palier (${label.plan}) déjà à sa limite de ${max} artiste(s) — impossible d'activer cette affiliation.` };
    }
    await client.query("UPDATE label_artists SET status = 'active' WHERE id = $1", [row.id]);
    await client.query('COMMIT');
    return { ok: true, labelId: label.id };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function requireValidatedLabel(req, res, minRole = 'assistant') {
  // Le compte est-il le compte de connexion du Label lui-même (toujours owner) ?
  const ownLabel = await db.get('SELECT * FROM labels WHERE user_id = $1', [req.user.id]);
  let label = ownLabel;
  let myRole = 'owner';
  if (!label) {
    // Sinon, est-ce un membre d'équipe actif d'un Label ?
    const membership = await db.get(
      "SELECT lt.role, lt.label_id FROM label_team_members lt WHERE lt.user_id = $1 AND lt.status = 'active' LIMIT 1",
      [req.user.id],
    );
    if (!membership) { res.status(403).json({ error: 'Réservé aux comptes Label.' }); return null; }
    label = await db.get('SELECT * FROM labels WHERE id = $1', [membership.label_id]);
    myRole = membership.role;
  }
  if (!label) { res.status(404).json({ error: 'Profil Label introuvable.' }); return null; }
  if (label.verification_status !== 'validated') {
    res.status(403).json({ error: 'Ce compte Label doit être validé par NUNI avant de gérer des artistes.' });
    return null;
  }
  if (label.subscription_expires_at && new Date(label.subscription_expires_at) < new Date()) {
    res.status(403).json({ error: 'Votre Pass Label a expiré (1 an révolu). Renouvelez-le depuis votre Dashboard pour continuer.' });
    return null;
  }
  if (LABEL_ROLE_RANK[myRole] < LABEL_ROLE_RANK[minRole]) {
    res.status(403).json({ error: `Action réservée aux rôles ${minRole} et supérieurs.` });
    return null;
  }
  return { ...label, myRole };
}

// ---------- Liste des artistes gérés par le Label, avec leurs vraies stats ----------
app.get('/api/label/artists', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'assistant');
  if (!label) return;
  const rows = await db.query(`
    SELECT la.id as affiliation_id, la.status as affiliation_status, la.created_at as joined_at,
           u.id as artist_id, u.artist_name, u.email, u.avatar_url, u.is_verified,
           COALESCE((SELECT COUNT(*)::int FROM tracks t WHERE t.artist_id = u.id AND t.published = 1), 0) as track_count,
           COALESCE((SELECT SUM(t.streams)::bigint FROM tracks t WHERE t.artist_id = u.id AND t.published = 1), 0) as total_streams
    FROM label_artists la JOIN users u ON u.id = la.artist_id
    WHERE la.label_id = $1 AND la.status != 'removed'
    ORDER BY la.created_at DESC
  `, [label.id]);
  const planSettings2 = await getLabelPlanSettings();
  res.json({ artists: rows, plan: label.plan, maxArtists: planSettings2.maxArtists[label.plan] });
}));

// ---------- Créer un nouvel artiste directement sous le Label ----------
app.post('/api/label/artists/create', authMiddleware, rateLimit(10, 60 * 60000), h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'manager');
  if (!label) return;
  const currentCount = (await db.get(
    "SELECT COUNT(*)::int as c FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
  )).c;
  const planSettings = await getLabelPlanSettings();
  const max = planSettings.maxArtists[label.plan];
  if (max !== null && currentCount >= max) {
    return res.status(403).json({ error: `Votre palier (${label.plan}) autorise au maximum ${max} artiste(s). Passez à un palier supérieur pour en gérer davantage.` });
  }
  const { artistName, email, password, firstName, lastName } = req.body;
  if (!artistName || !email || !password || !firstName || !lastName) {
    return res.status(400).json({ error: 'Nom d\'artiste, prénom, nom, email et mot de passe sont obligatoires.' });
  }
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  if (await db.get('SELECT id FROM users WHERE email = $1', [email])) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }
  const password_hash = await hashPassword(password);
  // Utilise les coordonnées du Label par défaut (l'artiste pourra les modifier lui-même
  // ensuite depuis son propre Dashboard, comme n'importe quel compte artiste).
  // IMPORTANT : plan doit être explicitement 'artist' — sans ça, la colonne retombe sur sa
  // valeur par défaut 'discovery', et l'interface affichait alors un faux compte à rebours
  // de ~100 ans (100 ans étant la durée choisie pour subscription_expires_at, interprétée à
  // tort comme un essai Découverte sur le point d'expirer).
  const insertedArtist = await db.get(`
    INSERT INTO users (account_type, first_name, last_name, email, password_hash, age, address, city, country, artist_name, label_or_manager, plan, subscription_status, subscription_expires_at)
    VALUES ('artist',$1,$2,$3,$4,18,$5,$6,$7,$8,$9,'artist','active', NOW() + INTERVAL '100 years')
    RETURNING id
  `, [firstName, lastName, email, password_hash, label.address, label.city, label.country, artistName, label.label_name]);
  // Compte créé directement par le Label et actif dès la création (statut 'active', pas
  // 'invited') — cohérent avec "Créer un artiste" dans le cahier des charges, distinct de
  // "Inviter un artiste" (un compte déjà existant, qui doit lui donner son accord).
  await db.run(
    "INSERT INTO label_artists (label_id, artist_id, status) VALUES ($1,$2,'active')",
    [label.id, insertedArtist.id],
  );
  await notifyLabelArtistAdded(label, artistName, currentCount + 1);
  res.status(201).json({ message: `${artistName} a été créé et rattaché à ${label.label_name}.`, artistId: insertedArtist.id });
}));

// ---------- Inviter un artiste EXISTANT (déjà inscrit sur NUNI) par email ----------
app.post('/api/label/artists/invite', authMiddleware, rateLimit(10, 60 * 60000), h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'manager');
  if (!label) return;
  const currentCount = (await db.get(
    "SELECT COUNT(*)::int as c FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
  )).c;
  const planSettings = await getLabelPlanSettings();
  const max = planSettings.maxArtists[label.plan];
  if (max !== null && currentCount >= max) {
    return res.status(403).json({ error: `Votre palier (${label.plan}) autorise au maximum ${max} artiste(s).` });
  }
  const { email } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  const artist = await db.get("SELECT id, artist_name FROM users WHERE email = $1 AND account_type = 'artist'", [email]);
  if (!artist) return res.status(404).json({ error: 'Aucun compte artiste NUNI ne correspond à cet email.' });
  if (await db.get('SELECT id FROM label_artists WHERE label_id = $1 AND artist_id = $2', [label.id, artist.id])) {
    return res.status(400).json({ error: 'Cet artiste est déjà affilié (ou l\'a déjà été) à votre Label.' });
  }
  // 'invited' : l'artiste doit accepter lui-même — voir /api/me/label-invites côté artiste.
  await db.run("INSERT INTO label_artists (label_id, artist_id, status) VALUES ($1,$2,'invited')", [label.id, artist.id]);
  res.status(201).json({ message: `Invitation envoyée à ${artist.artist_name}.` });
}));

// ---------- Retirer un artiste du Label (n'affecte jamais le compte artiste lui-même) ----------
app.delete('/api/label/artists/:id', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'admin');
  if (!label) return;
  const aff = await db.get('SELECT id FROM label_artists WHERE id = $1 AND label_id = $2', [Number(req.params.id), label.id]);
  if (!aff) return res.status(404).json({ error: 'Affiliation introuvable.' });
  await db.run("UPDATE label_artists SET status = 'removed' WHERE id = $1", [aff.id]);
  res.json({ message: 'Artiste retiré du Label.' });
}));

// ---------- Suspendre / réactiver l'affiliation (jamais le compte artiste lui-même) ----------
app.post('/api/label/artists/:id/suspend', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'manager');
  if (!label) return;
  const aff = await db.get('SELECT id FROM label_artists WHERE id = $1 AND label_id = $2', [Number(req.params.id), label.id]);
  if (!aff) return res.status(404).json({ error: 'Affiliation introuvable.' });
  await db.run("UPDATE label_artists SET status = 'suspended' WHERE id = $1", [aff.id]);
  res.json({ message: 'Affiliation suspendue — le compte artiste reste actif et indépendant sur NUNI.' });
}));
app.post('/api/label/artists/:id/reactivate', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'manager');
  if (!label) return;
  const aff = await db.get('SELECT id FROM label_artists WHERE id = $1 AND label_id = $2', [Number(req.params.id), label.id]);
  if (!aff) return res.status(404).json({ error: 'Affiliation introuvable.' });
  const result = await tryActivateLabelArtist(aff.id, null);
  if (!result.ok) return res.status(result.status).json({ error: result.error });
  res.json({ message: 'Affiliation réactivée.' });
}));

// ---------- Vue d'ensemble (accueil du Dashboard Label) ----------
app.get('/api/label/overview', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'assistant');
  if (!label) return;
  const artistIds = (await db.query(
    "SELECT artist_id FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
  )).map((r) => r.artist_id);
  if (!artistIds.length) {
    return res.json({ artistCount: 0, totalStreams: 0, estimatedRevenueFcfa: 0, collectedRevenueFcfa: 0, topArtist: null, topTrack: null });
  }
  const totalStreamsRow = await db.get(
    'SELECT COALESCE(SUM(streams),0)::bigint as total FROM tracks WHERE artist_id = ANY($1) AND published = 1', [artistIds],
  );
  const totalStreams = Number(totalStreamsRow.total);
  const priceRow = await db.get('SELECT value FROM app_settings WHERE key = $1', ['royalty_price_per_stream_fcfa']);
  const shareRow = await db.get('SELECT value FROM app_settings WHERE key = $1', ['royalty_artist_share_pct']);
  const pricePerStream = priceRow ? Number(priceRow.value) : 5;
  const artistShare = shareRow ? Number(shareRow.value) / 100 : 0.75;
  const estimatedRevenueFcfa = Math.round(totalStreams * pricePerStream * artistShare);
  const collectedRow = await db.get(
    'SELECT COALESCE(SUM(amount_fcfa),0)::bigint as total FROM payment_history WHERE artist_id = ANY($1)', [artistIds],
  ).catch(() => ({ total: 0 }));
  const topArtist = await db.get(`
    SELECT u.artist_name, COALESCE(SUM(t.streams),0)::bigint as streams
    FROM users u LEFT JOIN tracks t ON t.artist_id = u.id AND t.published = 1
    WHERE u.id = ANY($1) GROUP BY u.id, u.artist_name ORDER BY streams DESC LIMIT 1
  `, [artistIds]);
  const topTrack = await db.get(`
    SELECT t.title, u.artist_name, t.streams
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.artist_id = ANY($1) AND t.published = 1 ORDER BY t.streams DESC LIMIT 1
  `, [artistIds]);
  res.json({
    artistCount: artistIds.length,
    totalStreams,
    estimatedRevenueFcfa,
    collectedRevenueFcfa: Number(collectedRow.total || 0),
    topArtist: topArtist || null,
    topTrack: topTrack || null,
  });
}));

// ---------- Revenus & versements consolidés (Phase 3) ----------
// Vue de RAPPORT sur les vrais versements déjà enregistrés (table payment_history, celle que
// l'admin alimente depuis "Reversements artistes") — le Label ne reçoit ni ne redistribue
// d'argent lui-même via NUNI, il consulte simplement l'historique réel de ses artistes,
// consolidé. Rien n'est inventé ou simulé ici.
app.get('/api/label/payments', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'admin');
  if (!label) return;
  const artistIds = (await db.query(
    "SELECT artist_id FROM label_artists WHERE label_id = $1 AND status != 'removed'", [label.id],
  )).map((r) => r.artist_id);
  if (!artistIds.length) {
    return res.json({ totalPaidFcfa: 0, byArtist: [], history: [] });
  }
  const history = await db.query(`
    SELECT ph.id, ph.amount_fcfa, ph.streams_covered, ph.period_start, ph.period_end, ph.method, ph.created_at,
           u.artist_name
    FROM payment_history ph JOIN users u ON u.id = ph.artist_id
    WHERE ph.artist_id = ANY($1)
    ORDER BY ph.created_at DESC
  `, [artistIds]);
  const byArtist = await db.query(`
    SELECT u.id as artist_id, u.artist_name, COALESCE(SUM(ph.amount_fcfa),0)::bigint as total_paid_fcfa,
           COUNT(ph.id)::int as payment_count
    FROM users u LEFT JOIN payment_history ph ON ph.artist_id = u.id
    WHERE u.id = ANY($1) GROUP BY u.id, u.artist_name ORDER BY total_paid_fcfa DESC
  `, [artistIds]);
  const totalPaidFcfa = byArtist.reduce((sum, a) => sum + Number(a.total_paid_fcfa), 0);
  res.json({ totalPaidFcfa, byArtist, history });
}));

// ================= ANALYTICS + CATALOGUE (Phase 5) =================
// Important, par honnêteté : NUNI ne suit pas encore la plateforme de lecture (mobile/web/
// desktop) ni un vrai système de "brouillon" distinct d'une simple publication — ces deux
// éléments demandés dans le cahier des charges ne sont donc pas inclus ici plutôt que
// d'afficher des chiffres inventés. Tout le reste (streams, auditeurs, pays, villes,
// croissance, rétention) vient de vraies données déjà en base (table plays).
// ---------- "Afrique en direct" — vraie géographie des écoutes, plateforme entière ----------
// Basé sur le pays/ville renseigné par l'auditeur à son inscription, croisé avec ses vraies
// écoutes (table plays) — même principe honnête que les analytics Label, mais sans filtre
// sur un artiste ou un label précis : toute la plateforme.
// Regroupement pays → région — volontairement centré sur les pays les plus probables pour
// l'audience de NUNI (Afrique + diaspora). Un pays non reconnu tombe dans "Autres régions"
// plutôt que d'être ignoré ou classé au hasard.
const COUNTRY_TO_REGION = {
  'congo':'Afrique centrale', 'republique du congo':'Afrique centrale', 'rdc':'Afrique centrale',
  'republique democratique du congo':'Afrique centrale', 'rd congo':'Afrique centrale',
  'gabon':'Afrique centrale', 'cameroun':'Afrique centrale', 'tchad':'Afrique centrale',
  'centrafrique':'Afrique centrale', 'guinee equatoriale':'Afrique centrale', 'sao tome':'Afrique centrale',
  'senegal':'Afrique de l\'Ouest', 'cote d\'ivoire':'Afrique de l\'Ouest', 'ivoire':'Afrique de l\'Ouest',
  'mali':'Afrique de l\'Ouest', 'burkina faso':'Afrique de l\'Ouest', 'guinee':'Afrique de l\'Ouest',
  'benin':'Afrique de l\'Ouest', 'togo':'Afrique de l\'Ouest', 'niger':'Afrique de l\'Ouest',
  'nigeria':'Afrique de l\'Ouest', 'ghana':'Afrique de l\'Ouest', 'sierra leone':'Afrique de l\'Ouest',
  'liberia':'Afrique de l\'Ouest', 'gambie':'Afrique de l\'Ouest', 'mauritanie':'Afrique de l\'Ouest',
  'cap-vert':'Afrique de l\'Ouest', 'guinee-bissau':'Afrique de l\'Ouest',
  'kenya':'Afrique de l\'Est', 'tanzanie':'Afrique de l\'Est', 'ouganda':'Afrique de l\'Est',
  'ethiopie':'Afrique de l\'Est', 'rwanda':'Afrique de l\'Est', 'burundi':'Afrique de l\'Est',
  'somalie':'Afrique de l\'Est', 'djibouti':'Afrique de l\'Est', 'soudan':'Afrique de l\'Est',
  'afrique du sud':'Afrique australe', 'zimbabwe':'Afrique australe', 'zambie':'Afrique australe',
  'namibie':'Afrique australe', 'botswana':'Afrique australe', 'mozambique':'Afrique australe',
  'angola':'Afrique australe', 'malawi':'Afrique australe', 'lesotho':'Afrique australe', 'eswatini':'Afrique australe',
  'maroc':'Afrique du Nord', 'algerie':'Afrique du Nord', 'tunisie':'Afrique du Nord',
  'egypte':'Afrique du Nord', 'libye':'Afrique du Nord',
  'france':'Europe', 'belgique':'Europe', 'allemagne':'Europe', 'royaume-uni':'Europe', 'angleterre':'Europe',
  'suisse':'Europe', 'italie':'Europe', 'espagne':'Europe', 'portugal':'Europe', 'pays-bas':'Europe',
  'suede':'Europe', 'norvege':'Europe',
  'etats-unis':'Amérique du Nord', 'usa':'Amérique du Nord', 'canada':'Amérique du Nord', 'mexique':'Amérique du Nord',
  'bresil':'Amérique du Sud', 'argentine':'Amérique du Sud',
  'jamaique':'Caraïbes', 'haiti':'Caraïbes', 'cuba':'Caraïbes', 'republique dominicaine':'Caraïbes',
  'chine':'Asie', 'inde':'Asie', 'japon':'Asie', 'coree du sud':'Asie', 'emirats arabes unis':'Moyen-Orient',
  'arabie saoudite':'Moyen-Orient', 'liban':'Moyen-Orient', 'qatar':'Moyen-Orient',
  'australie':'Océanie', 'nouvelle-zelande':'Océanie',
};
function normalizeCountryKey(name) {
  return (name || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
}
function regionForCountry(name) {
  return COUNTRY_TO_REGION[normalizeCountryKey(name)] || 'Autres régions';
}

// ---------- Récap personnel mensuel — vrais top artistes/morceaux, par vrai nombre
// d'écoutes (pas de minutes : ni tracks ni plays ne stockent de durée aujourd'hui). ----------
app.get('/api/me/recap', authMiddleware, h(async (req, res) => {
  // Liste des mois où ce compte a réellement écouté quelque chose, du plus récent au plus ancien.
  const months = await db.query(`
    SELECT DISTINCT date_trunc('month', p.created_at) as month
    FROM plays p WHERE p.listener_id = $1
    ORDER BY month DESC LIMIT 12
  `, [req.user.id]);
  const requestedMonth = req.query.month; // format 'YYYY-MM-01', optionnel — sinon le plus récent
  const targetMonth = requestedMonth || (months[0] ? months[0].month : null);
  if (!targetMonth) { res.json({ months: [], totalPlays: 0, topArtists: [], topTracks: [] }); return; }

  const totalPlays = (await db.get(`
    SELECT COUNT(*)::int as c FROM plays p
    WHERE p.listener_id = $1 AND date_trunc('month', p.created_at) = $2::timestamptz
  `, [req.user.id, targetMonth])).c;

  const topArtists = await db.query(`
    SELECT u.id, u.artist_name, u.avatar_url, COUNT(*)::int as plays
    FROM plays p JOIN tracks t ON t.id = p.track_id JOIN users u ON u.id = t.artist_id
    WHERE p.listener_id = $1 AND date_trunc('month', p.created_at) = $2::timestamptz
    GROUP BY u.id, u.artist_name, u.avatar_url ORDER BY plays DESC LIMIT 3
  `, [req.user.id, targetMonth]);

  const topTracks = await db.query(`
    SELECT t.id, t.title, t.cover_url, u.artist_name, COUNT(*)::int as plays
    FROM plays p JOIN tracks t ON t.id = p.track_id JOIN users u ON u.id = t.artist_id
    WHERE p.listener_id = $1 AND date_trunc('month', p.created_at) = $2::timestamptz
    GROUP BY t.id, t.title, t.cover_url, u.artist_name ORDER BY plays DESC LIMIT 5
  `, [req.user.id, targetMonth]);

  res.json({ months: months.map((m) => m.month), targetMonth, totalPlays, topArtists, topTracks });
}));

// ---------- "Écoutés récemment" — vrai historique d'écoute, un morceau une seule fois
// (regroupé par morceau, daté par sa toute dernière écoute) — jamais une liste brute de
// lignes "plays" qui répéterait le même morceau plusieurs fois s'il a été relancé souvent.
app.get('/api/me/recently-played', authMiddleware, h(async (req, res) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 15));
  const rows = await db.query(`
    SELECT t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
           u.id as artist_id, u.artist_name, u.first_name, u.is_verified, u.avatar_url as artist_avatar_url,
           MAX(p.created_at) as last_played_at
    FROM plays p
    JOIN tracks t ON t.id = p.track_id
    JOIN users u ON u.id = t.artist_id
    WHERE p.listener_id = $1
    GROUP BY t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
             u.id, u.artist_name, u.first_name, u.is_verified, u.avatar_url
    ORDER BY last_played_at DESC
    LIMIT $2
  `, [req.user.id, limit]);
  const meRow = await db.get('SELECT subscription_status, plan, email_verified FROM users WHERE id = $1', [req.user.id]);
  res.json({ tracks: stripAudioIfNoAccess(rows, hasStreamingAccess(meRow)) });
}));

// ---------- "Reprendre l'écoute" — vraie position de lecture par morceau ----------
// Sauvegarde périodique pendant la lecture (voir app.js, appelée toutes les ~10s pendant
// qu'un vrai morceau audio joue). Une position trop proche du début ne vaut pas la peine
// d'être retenue (reprendrait pratiquement du début de toute façon).
app.post('/api/me/playback-position', authMiddleware, h(async (req, res) => {
  const trackId = Number(req.body.trackId);
  const positionSeconds = Math.max(0, Math.round(Number(req.body.positionSeconds) || 0));
  if (!trackId) return res.status(400).json({ error: 'trackId requis.' });
  if (positionSeconds < 15) {
    await db.run('DELETE FROM playback_positions WHERE user_id = $1 AND track_id = $2', [req.user.id, trackId]);
    return res.json({ ok: true, cleared: true });
  }
  await db.run(`
    INSERT INTO playback_positions (user_id, track_id, position_seconds, updated_at)
    VALUES ($1,$2,$3,NOW())
    ON CONFLICT (user_id, track_id) DO UPDATE SET position_seconds = $3, updated_at = NOW()
  `, [req.user.id, trackId, positionSeconds]);
  res.json({ ok: true });
}));

// Efface une position précise — morceau terminé naturellement, ou relancé depuis le début.
app.delete('/api/me/playback-position/:trackId', authMiddleware, h(async (req, res) => {
  await db.run('DELETE FROM playback_positions WHERE user_id = $1 AND track_id = $2', [req.user.id, Number(req.params.trackId)]);
  res.json({ ok: true });
}));

// Morceaux à reprendre — les plus récemment laissés en cours d'abord, jusqu'à 5.
app.get('/api/me/resume', authMiddleware, h(async (req, res) => {
  const rows = await db.query(`
    SELECT pp.track_id, pp.position_seconds, pp.updated_at,
           t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
           u.id as artist_id, u.artist_name, u.first_name, u.is_verified, u.avatar_url as artist_avatar_url
    FROM playback_positions pp
    JOIN tracks t ON t.id = pp.track_id
    JOIN users u ON u.id = t.artist_id
    WHERE pp.user_id = $1
    ORDER BY pp.updated_at DESC
    LIMIT 5
  `, [req.user.id]);
  const meRow = await db.get('SELECT subscription_status, plan, email_verified FROM users WHERE id = $1', [req.user.id]);
  res.json({ resumes: stripAudioIfNoAccess(rows, hasStreamingAccess(meRow)) });
}));

// ---------- "Votre sélection NUNI" — vraie sélection basée sur les genres que ce compte
// écoute le plus (table plays), jamais un algorithme flou ou des chiffres inventés. Sans
// historique d'écoute, la sélection est simplement absente (pas de repli aléatoire déguisé
// en "personnalisé") — le frontend masque alors la section entière.
app.get('/api/me/selection', authMiddleware, h(async (req, res) => {
  const topGenres = await db.query(`
    SELECT t.genre, COUNT(*)::int as plays
    FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE p.listener_id = $1 AND t.genre IS NOT NULL
    GROUP BY t.genre ORDER BY plays DESC LIMIT 3
  `, [req.user.id]);
  if (!topGenres.length) return res.json({ genres: [], tracks: [] });
  const genreNames = topGenres.map((g) => g.genre);
  // Morceaux réels de ces genres, en excluant ceux déjà beaucoup écoutés par cette même
  // personne (on veut prolonger ses goûts, pas juste lui rejouer ce qu'elle connaît déjà).
  const rows = await db.query(`
    SELECT t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
           u.id as artist_id, u.artist_name, u.first_name, u.is_verified, u.avatar_url as artist_avatar_url,
           COALESCE((SELECT COUNT(*)::int FROM plays p2 WHERE p2.track_id = t.id AND p2.listener_id = $1), 0) as my_plays
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1 AND t.genre = ANY($2::text[])
    ORDER BY my_plays ASC, t.streams DESC
    LIMIT 20
  `, [req.user.id, genreNames]);
  const meRow = await db.get('SELECT subscription_status, plan, email_verified FROM users WHERE id = $1', [req.user.id]);
  res.json({ genres: genreNames, tracks: stripAudioIfNoAccess(rows, hasStreamingAccess(meRow)) });
}));

app.get('/api/stats/geo', h(async (req, res) => {
  const topCountries = await db.query(`
    SELECT u.country, COUNT(*)::int as plays
    FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.country IS NOT NULL AND u.country != ''
    GROUP BY u.country ORDER BY plays DESC LIMIT 10
  `);
  const topCities = await db.query(`
    SELECT u.city, u.country, COUNT(*)::int as plays
    FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.city IS NOT NULL AND u.city != ''
    GROUP BY u.city, u.country ORDER BY plays DESC LIMIT 10
  `);
  // TOUS les pays (pas seulement le top 10) — nécessaire pour un vrai regroupement par
  // région, sinon les petits pays d'une région seraient ignorés et fausseraient le total.
  const allCountries = await db.query(`
    SELECT u.country, COUNT(*)::int as plays
    FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.country IS NOT NULL AND u.country != ''
    GROUP BY u.country
  `);
  const regionTotals = {};
  allCountries.forEach((c) => {
    const region = regionForCountry(c.country);
    regionTotals[region] = (regionTotals[region] || 0) + c.plays;
  });
  const topRegions = Object.entries(regionTotals)
    .map(([region, plays]) => ({ region, plays }))
    .sort((a, b) => b.plays - a.plays)
    .slice(0, 10);

  // ---- Vraies tendances : écoutes des 7 derniers jours vs les 7 jours précédents.
  // Jamais un pourcentage inventé — et surtout, jamais un pourcentage TROMPEUR : avec très
  // peu de données (ex: 1 écoute avant, 19 après), un calcul brut donnerait des variations
  // énormes et illisibles. En dessous d'un seuil minimum sur les deux périodes, la tendance
  // est marquée "pas assez de recul" plutôt qu'un chiffre qui donne une fausse impression de
  // précision statistique.
  const MIN_SAMPLE_FOR_TREND = 5;
  function computeTrends(lastRows, prevRows, key) {
    const prevMap = {}; prevRows.forEach((r) => { prevMap[r[key]] = r.plays; });
    const lastMap = {}; lastRows.forEach((r) => { lastMap[r[key]] = r.plays; });
    const trends = {};
    new Set([...lastRows.map((r) => r[key]), ...prevRows.map((r) => r[key])]).forEach((k) => {
      const now = lastMap[k] || 0;
      const before = prevMap[k] || 0;
      if (before === 0 && now === 0) return;
      if (before === 0) { trends[k] = { direction: 'new' }; return; }
      if (before < MIN_SAMPLE_FOR_TREND && now < MIN_SAMPLE_FOR_TREND) { trends[k] = { direction: 'low_sample' }; return; }
      const pct = Math.round(((now - before) / before) * 100);
      trends[k] = { direction: pct > 3 ? 'up' : pct < -3 ? 'down' : 'flat', pct };
    });
    return trends;
  }
  const last7Countries = await db.query(`
    SELECT u.country, COUNT(*)::int as plays FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.country IS NOT NULL AND u.country != '' AND p.created_at >= NOW() - INTERVAL '7 days' GROUP BY u.country
  `);
  const prev7Countries = await db.query(`
    SELECT u.country, COUNT(*)::int as plays FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.country IS NOT NULL AND u.country != '' AND p.created_at >= NOW() - INTERVAL '14 days' AND p.created_at < NOW() - INTERVAL '7 days' GROUP BY u.country
  `);
  const last7Cities = await db.query(`
    SELECT u.city, COUNT(*)::int as plays FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.city IS NOT NULL AND u.city != '' AND p.created_at >= NOW() - INTERVAL '7 days' GROUP BY u.city
  `);
  const prev7Cities = await db.query(`
    SELECT u.city, COUNT(*)::int as plays FROM plays p JOIN users u ON u.id = p.listener_id
    WHERE u.city IS NOT NULL AND u.city != '' AND p.created_at >= NOW() - INTERVAL '14 days' AND p.created_at < NOW() - INTERVAL '7 days' GROUP BY u.city
  `);
  const trends = computeTrends(last7Countries, prev7Countries, 'country');
  const cityTrends = computeTrends(last7Cities, prev7Cities, 'city');
  // Régions : recalculées à partir des mêmes lignes pays, regroupées — cohérent avec le
  // regroupement du total ci-dessus, jamais une seconde source de vérité qui pourrait diverger.
  function regionize(rows) {
    const totals = {};
    rows.forEach((r) => { const region = regionForCountry(r.country); totals[region] = (totals[region] || 0) + r.plays; });
    return Object.entries(totals).map(([region, plays]) => ({ region, plays }));
  }
  const regionTrends = computeTrends(regionize(last7Countries), regionize(prev7Countries), 'region');

  // ---- Tendance réelle du total de la plateforme : ce mois-ci vs le mois précédent.
  const totalThisMonth = (await db.get(
    "SELECT COUNT(*)::int as c FROM plays WHERE created_at >= date_trunc('month', NOW())",
  )).c;
  const totalLastMonth = (await db.get(
    "SELECT COUNT(*)::int as c FROM plays WHERE created_at >= date_trunc('month', NOW() - INTERVAL '1 month') AND created_at < date_trunc('month', NOW())",
  )).c;
  let totalTrend = { direction: 'flat', pct: 0 };
  if (totalLastMonth === 0) { totalTrend = totalThisMonth > 0 ? { direction: 'new' } : { direction: 'flat', pct: 0 }; }
  else {
    const pct = Math.round(((totalThisMonth - totalLastMonth) / totalLastMonth) * 100);
    totalTrend = { direction: pct > 3 ? 'up' : pct < -3 ? 'down' : 'flat', pct };
  }

  const totalPlays = (await db.get('SELECT COUNT(*)::int as c FROM plays')).c;
  const totalCountries = allCountries.length;
  res.json({ topCountries, topCities, topRegions, trends, cityTrends, regionTrends, totalTrend, totalPlays, totalCountries });
}));

app.get('/api/label/analytics', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'assistant');
  if (!label) return;
  const artistIds = (await db.query(
    "SELECT artist_id FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
  )).map((r) => r.artist_id);
  if (!artistIds.length) {
    return res.json({ streamsByMonth: [], topCountries: [], topCities: [], growthPct: null, retentionPct: null });
  }

  const streamsByMonth = await db.query(`
    SELECT to_char(date_trunc('month', p.created_at), 'Mon YYYY') as month,
           COUNT(*)::int as streams, COUNT(DISTINCT p.listener_id)::int as listeners
    FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = ANY($1) AND p.created_at >= NOW() - INTERVAL '6 months'
    GROUP BY date_trunc('month', p.created_at)
    ORDER BY date_trunc('month', p.created_at) ASC
  `, [artistIds]);

  const topCountries = await db.query(`
    SELECT u.country, COUNT(*)::int as plays
    FROM plays p JOIN tracks t ON t.id = p.track_id JOIN users u ON u.id = p.listener_id
    WHERE t.artist_id = ANY($1) AND u.country IS NOT NULL AND u.country != ''
    GROUP BY u.country ORDER BY plays DESC LIMIT 6
  `, [artistIds]);

  const topCities = await db.query(`
    SELECT u.city, COUNT(*)::int as plays
    FROM plays p JOIN tracks t ON t.id = p.track_id JOIN users u ON u.id = p.listener_id
    WHERE t.artist_id = ANY($1) AND u.city IS NOT NULL AND u.city != ''
    GROUP BY u.city ORDER BY plays DESC LIMIT 6
  `, [artistIds]);

  // Croissance : variation des streams entre les deux derniers mois complets.
  let growthPct = null;
  if (streamsByMonth.length >= 2) {
    const prev = streamsByMonth[streamsByMonth.length - 2].streams;
    const curr = streamsByMonth[streamsByMonth.length - 1].streams;
    growthPct = prev > 0 ? Math.round(((curr - prev) / prev) * 1000) / 10 : null;
  }

  // Rétention : parmi les auditeurs distincts du mois précédent, quelle proportion a
  // réécouté au moins une fois ce mois-ci.
  const prevListeners = await db.query(`
    SELECT DISTINCT p.listener_id FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = ANY($1)
      AND p.created_at >= date_trunc('month', NOW() - INTERVAL '1 month')
      AND p.created_at < date_trunc('month', NOW())
  `, [artistIds]);
  let retentionPct = null;
  if (prevListeners.length) {
    const prevIds = prevListeners.map((r) => r.listener_id);
    const retained = await db.get(`
      SELECT COUNT(DISTINCT p.listener_id)::int as c FROM plays p JOIN tracks t ON t.id = p.track_id
      WHERE t.artist_id = ANY($1) AND p.listener_id = ANY($2) AND p.created_at >= date_trunc('month', NOW())
    `, [artistIds, prevIds]);
    retentionPct = Math.round((retained.c / prevIds.length) * 1000) / 10;
  }

  res.json({ streamsByMonth, topCountries, topCities, growthPct, retentionPct });
}));

// ---------- Catalogue consolidé (tous les artistes du Label) ----------
app.get('/api/label/catalog', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'assistant');
  if (!label) return;
  const artistIds = (await db.query(
    "SELECT artist_id FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
  )).map((r) => r.artist_id);
  if (!artistIds.length) {
    return res.json({ tracks: [], clips: [], scheduled: [] });
  }
  const tracks = await db.query(`
    SELECT t.id, t.title, t.album, t.release_type, t.cover_url, t.streams, t.created_at,
           u.artist_name
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.artist_id = ANY($1) AND t.published = 1
    ORDER BY t.created_at DESC
  `, [artistIds]);
  const clips = await db.query(`
    SELECT c.id, c.title, c.thumb_url, c.views, c.created_at, u.artist_name
    FROM clips c JOIN users u ON u.id = c.artist_id
    WHERE c.artist_id = ANY($1) AND c.published = 1
    ORDER BY c.created_at DESC
  `, [artistIds]);
  const scheduled = await db.query(`
    SELECT t.id, t.title, t.album, t.release_type, t.cover_url, t.scheduled_release_at, u.artist_name
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.artist_id = ANY($1) AND t.published = 0 AND t.scheduled_release_at IS NOT NULL
    ORDER BY t.scheduled_release_at ASC
  `, [artistIds]);
  res.json({ tracks, clips, scheduled });
}));

// ---------- Équipe & rôles (Phase 4) ----------
// PROPRIÉTAIRE (le compte de connexion du Label lui-même) > ADMIN > MANAGER > ASSISTANT.
// ---------- Changer de palier — calcule le vrai prix (avec 25% de réduction si c'est le
// tout premier changement), puis renvoie vers WhatsApp pour finaliser le paiement, comme le
// reste des Pass NUNI. Le changement réel de palier est appliqué par l'admin une fois le
// paiement confirmé (voir /api/admin/labels/:id/set-plan) — jamais avant, pour ne jamais
// accorder plus de capacité (plus d'artistes) sans paiement vérifié. ----------
app.post('/api/label/change-plan-request', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'owner');
  if (!label) return;
  const { newPlan } = req.body;
  if (!['start', 'pro', 'premium', 'elite'].includes(newPlan)) {
    return res.status(400).json({ error: 'Palier invalide.' });
  }
  if (newPlan === label.plan) return res.status(400).json({ error: 'Vous êtes déjà sur ce palier.' });
  const settings = await getLabelPlanSettings();
  const fullPrice = settings.prices[newPlan];
  const discounted = !label.has_changed_plan_once;
  const finalPrice = discounted ? Math.round(fullPrice * 0.75) : fullPrice;
  const planLabels = { start: 'Label Start', pro: 'Label Pro', premium: 'Label Premium', elite: 'Label Elite' };
  res.json({
    fullPrice,
    finalPrice,
    discounted,
    whatsapp: 'https://wa.me/242068951600',
    whatsappMessage: `Bonjour NUNI, je souhaite passer ${label.label_name} au palier ${planLabels[newPlan]}` +
      (discounted ? ` (${finalPrice.toLocaleString('fr-FR')} FCFA au lieu de ${fullPrice.toLocaleString('fr-FR')} FCFA — réduction de 25% pour mon premier changement de palier).` : ` (${finalPrice.toLocaleString('fr-FR')} FCFA).`),
  });
}));

// ---------- Admin — applique réellement le changement de palier, une fois le paiement
// confirmé (jamais automatique, comme tout paiement NUNI) ----------
app.post('/api/admin/labels/:id/set-plan', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const label = await db.get('SELECT * FROM labels WHERE id = $1', [Number(req.params.id)]);
  if (!label) return res.status(404).json({ error: 'Label introuvable.' });
  const { newPlan } = req.body;
  if (!['start', 'pro', 'premium', 'elite'].includes(newPlan)) {
    return res.status(400).json({ error: 'Palier invalide.' });
  }
  const settings = await getLabelPlanSettings();
  const newMax = settings.maxArtists[newPlan];
  if (newMax !== null) {
    const currentCount = (await db.get(
      "SELECT COUNT(*)::int as c FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
    )).c;
    if (currentCount > newMax) {
      return res.status(400).json({ error: `Impossible : ce Label gère déjà ${currentCount} artiste(s), au-delà de la limite de ${newMax} du palier ${newPlan}.` });
    }
  }
  await db.run(
    'UPDATE labels SET plan = $1, has_changed_plan_once = TRUE WHERE id = $2',
    [newPlan, label.id],
  );
  res.json({ message: `Palier changé pour ${newPlan}.` });
}));

app.get('/api/label/team', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'assistant');
  if (!label) return;
  const rows = await db.query(`
    SELECT lt.id, lt.role, lt.status, lt.email, lt.created_at, u.first_name, u.last_name
    FROM label_team_members lt LEFT JOIN users u ON u.id = lt.user_id
    WHERE lt.label_id = $1 ORDER BY lt.created_at ASC
  `, [label.id]);
  const owner = await db.get('SELECT first_name, last_name, email FROM users WHERE id = $1', [label.user_id]);
  res.json({ members: rows, owner, myRole: label.myRole });
}));

app.post('/api/label/team/invite', authMiddleware, rateLimit(15, 60 * 60000), h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'admin');
  if (!label) return;
  const { email, role } = req.body;
  if (!isEmail(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (!['admin', 'manager', 'assistant'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide (admin, manager ou assistant).' });
  }
  const invitedUser = await db.get('SELECT id FROM users WHERE email = $1', [email]);
  if (!invitedUser) return res.status(404).json({ error: 'Aucun compte NUNI ne correspond à cet email — la personne doit d\'abord créer un compte NUNI.' });
  if (invitedUser.id === label.user_id) return res.status(400).json({ error: 'Cette personne est déjà propriétaire du Label.' });
  if (await db.get('SELECT id FROM label_team_members WHERE label_id = $1 AND user_id = $2', [label.id, invitedUser.id])) {
    return res.status(400).json({ error: 'Cette personne fait déjà partie de votre équipe (ou en a déjà fait partie).' });
  }
  await db.run(
    "INSERT INTO label_team_members (label_id, user_id, email, role, status) VALUES ($1,$2,$3,$4,'invited')",
    [label.id, invitedUser.id, email, role],
  );
  await createNotification(invitedUser.id, 'label_team_invite', 'Invitation à rejoindre un Label', `${label.label_name} vous invite à rejoindre son équipe NUNI en tant que ${role}.`, null).catch(() => {});
  res.status(201).json({ message: 'Invitation envoyée.' });
}));

app.delete('/api/label/team/:id', authMiddleware, h(async (req, res) => {
  const label = await requireValidatedLabel(req, res, 'admin');
  if (!label) return;
  const member = await db.get('SELECT id FROM label_team_members WHERE id = $1 AND label_id = $2', [Number(req.params.id), label.id]);
  if (!member) return res.status(404).json({ error: 'Membre introuvable.' });
  await db.run('DELETE FROM label_team_members WHERE id = $1', [member.id]);
  res.json({ message: 'Membre retiré de l\'équipe.' });
}));

app.put('/api/label/team/:id/role', authMiddleware, h(async (req, res) => {
  // Changer le rôle d'un membre est réservé au propriétaire — évite qu'un admin ne se
  // promeuve lui-même ou ne rétrograde un autre admin par rivalité interne.
  const label = await requireValidatedLabel(req, res, 'owner');
  if (!label) return;
  const { role } = req.body;
  if (!['admin', 'manager', 'assistant'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide (admin, manager ou assistant).' });
  }
  const member = await db.get('SELECT id FROM label_team_members WHERE id = $1 AND label_id = $2', [Number(req.params.id), label.id]);
  if (!member) return res.status(404).json({ error: 'Membre introuvable.' });
  await db.run('UPDATE label_team_members SET role = $1 WHERE id = $2', [role, member.id]);
  res.json({ message: 'Rôle mis à jour.' });
}));

// ---------- Côté UTILISATEUR : invitations d'équipe reçues ----------
app.get('/api/me/label-team-invites', authMiddleware, h(async (req, res) => {
  const rows = await db.query(`
    SELECT lt.id, lt.role, l.label_name, l.logo_url
    FROM label_team_members lt JOIN labels l ON l.id = lt.label_id
    WHERE lt.user_id = $1 AND lt.status = 'invited'
  `, [req.user.id]);
  res.json({ invites: rows });
}));
app.post('/api/me/label-team-invites/:id/accept', authMiddleware, h(async (req, res) => {
  const invite = await db.get(
    "SELECT id FROM label_team_members WHERE id = $1 AND user_id = $2 AND status = 'invited'",
    [Number(req.params.id), req.user.id],
  );
  if (!invite) return res.status(404).json({ error: 'Invitation introuvable.' });
  await db.run("UPDATE label_team_members SET status = 'active' WHERE id = $1", [invite.id]);
  res.json({ message: 'Invitation acceptée.' });
}));
app.post('/api/me/label-team-invites/:id/decline', authMiddleware, h(async (req, res) => {
  const invite = await db.get(
    "SELECT id FROM label_team_members WHERE id = $1 AND user_id = $2 AND status = 'invited'",
    [Number(req.params.id), req.user.id],
  );
  if (!invite) return res.status(404).json({ error: 'Invitation introuvable.' });
  await db.run('DELETE FROM label_team_members WHERE id = $1', [invite.id]);
  res.json({ message: 'Invitation refusée.' });
}));

// ---------- Côté ARTISTE : voir/accepter/refuser une invitation reçue d'un Label ----------
app.get('/api/me/label-invites', authMiddleware, h(async (req, res) => {
  const rows = await db.query(`
    SELECT la.id, l.label_name, l.logo_url
    FROM label_artists la JOIN labels l ON l.id = la.label_id
    WHERE la.artist_id = $1 AND la.status = 'invited'
  `, [req.user.id]);
  res.json({ invites: rows });
}));
app.post('/api/me/label-invites/:id/accept', authMiddleware, h(async (req, res) => {
  const invite = await db.get(
    "SELECT id, label_id FROM label_artists WHERE id = $1 AND artist_id = $2 AND status = 'invited'",
    [Number(req.params.id), req.user.id],
  );
  if (!invite) return res.status(404).json({ error: 'Invitation introuvable.' });
  const result = await tryActivateLabelArtist(invite.id, req.user.id);
  if (!result.ok) return res.status(result.status).json({ error: result.error });
  const label = await db.get('SELECT * FROM labels WHERE id = $1', [invite.label_id]);
  const artist = await db.get('SELECT artist_name FROM users WHERE id = $1', [req.user.id]);
  if (label && artist) {
    const newCount = (await db.get(
      "SELECT COUNT(*)::int as c FROM label_artists WHERE label_id = $1 AND status = 'active'", [label.id],
    )).c;
    await notifyLabelArtistAdded(label, artist.artist_name, newCount);
  }
  res.json({ message: 'Invitation acceptée.' });
}));
app.post('/api/me/label-invites/:id/decline', authMiddleware, h(async (req, res) => {
  const invite = await db.get(
    "SELECT id FROM label_artists WHERE id = $1 AND artist_id = $2 AND status = 'invited'",
    [Number(req.params.id), req.user.id],
  );
  if (!invite) return res.status(404).json({ error: 'Invitation introuvable.' });
  await db.run("UPDATE label_artists SET status = 'removed' WHERE id = $1", [invite.id]);
  res.json({ message: 'Invitation refusée.' });
}));

app.post('/api/ads/request', rateLimit(5, 15 * 60000), h(async (req, res) => {
  const { name, desc, link, contact, duration } = req.body;
  if (!name || !link || !contact) {
    return res.status(400).json({ error: 'Merci de renseigner au minimum le nom du produit, un lien et un contact.' });
  }
  const result = await sendAdRequestEmail({ name, desc, link, contact, duration });
  if (!result.sent) {
    return res.status(502).json({ error: "La demande n'a pas pu être envoyée pour l'instant — réessayez plus tard." });
  }
  res.json({ message: 'Votre demande a bien été envoyée — NUNI vous recontactera bientôt.' });
}));

// ---------- Progression réelle : niveau, XP, et les 6 badges calculés à partir de vraies actions ----------
// Avant : "Vos badges d'auditeur" était un tableau entièrement codé en dur (même le "62/100"
// était du texte fixe). Ici, chaque badge est calculé en direct depuis les vraies données
// (écoutes, genres, artistes suivis, classement mensuel réel).
app.get('/api/me/following', authMiddleware, h(async (req, res) => {
  // Avant : ni l'avatar ni la date de suivi n'étaient renvoyés — la Bibliothèque ne pouvait
  // ni afficher les vraies photos des artistes suivis, ni trier "Ajouts récents" par date
  // réelle (f.created_at existe en base depuis le début, juste jamais exposée ici).
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.is_verified, u.avatar_url, f.created_at as followed_at
    FROM follows f JOIN users u ON u.id = f.artist_id
    WHERE f.follower_id = $1
    ORDER BY f.created_at DESC
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
    { icon: 'star', n: 'Fan de la première heure', locked: false, d: 'Compte créé' },
    { icon: 'headphones', n: '100 titres découverts', locked: distinctTracks < 100, d: `${distinctTracks}/100` },
    { icon: 'flame', n: `${user.streak_days || 0} jour(s) d'écoute d'affilée`, locked: (user.streak_days || 0) < 7, d: (user.streak_days || 0) >= 7 ? 'Débloqué' : 'Série en cours' },
    { icon: 'globe', n: '5 genres explorés', locked: distinctGenres < 5, d: `${distinctGenres}/5` },
    { icon: 'heart', n: '10 artistes soutenus', locked: followedArtists < 10, d: `${followedArtists}/10` },
    { icon: 'trophy', n: 'Top auditeur du mois', locked: !isTopListener, d: isTopListener ? `Rang #${monthlyRank.rnk}` : 'Verrouillé' },
  ];

  res.json({ ...levelInfoForXp(user.xp || 0), streak_days: user.streak_days || 0, badges });
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

app.post('/api/subscribe/request', authMiddleware, rateLimit(15, 60000), h(async (req, res) => {
  const { plan, durationDays } = req.body;
  if (!['consumer', 'artist'].includes(plan)) return res.status(400).json({ error: 'Pass invalide.' });
  // Liste blanche stricte — jamais une valeur arbitraire envoyée par le client, uniquement
  // les vraies durées proposées (voir RR_DURATION_OPTIONS côté frontend et PRICE_TABLE
  // ci-dessus). Une valeur hors-liste est simplement ignorée (NULL), jamais une erreur qui
  // bloquerait l'inscription pour ça.
  const validDuration = [30, 90, 365].includes(Number(durationDays)) ? Number(durationDays) : null;
  await db.run(
    `UPDATE users SET plan = $1, subscription_status = 'pending', requested_duration_days = $2 WHERE id = $3`,
    [plan, validDuration, req.user.id],
  );
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

  const promoResult = await resolvePromoDiscount(promoCode, plan, user.id);
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
    // Avant : "vérifier la limite" (resolvePromoDiscount) puis "incrémenter" étaient deux
    // requêtes séparées — une fenêtre de course entre les deux pouvait, en cas d'appels
    // simultanés, laisser le compteur dépasser max_uses. Une seule requête conditionnelle
    // (WHERE used_count < max_uses) rend l'opération atomique : impossible de dépasser la
    // limite quel que soit le nombre de tentatives simultanées.
    await db.run('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1 AND used_count < max_uses', [promoResult.code]);
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
  if(!playlists.length){ return res.json({ playlists }); }
  const ids = playlists.map(p=>p.id);

  // ---- Optimisation réelle — avant : jusqu'à 3 requêtes SQL par playlist (comptage,
  // pochette de repli, genre dominant), donc jusqu'à 3N allers-retours base pour N
  // playlists. Remplacé par 3 vraies requêtes groupées au total, peu importe le nombre de
  // playlists — même résultat, juste calculé une seule fois pour tout le monde. ----
  const countRows = await db.query(`SELECT playlist_id, COUNT(*)::int as c FROM playlist_tracks WHERE playlist_id = ANY($1) GROUP BY playlist_id`, [ids]);
  const countByPlaylist = new Map(countRows.map(r=>[r.playlist_id, r.c]));

  const coverRows = await db.query(`
    SELECT DISTINCT ON (pt.playlist_id) pt.playlist_id, t.cover_url
    FROM playlist_tracks pt JOIN tracks t ON t.id = pt.track_id
    WHERE pt.playlist_id = ANY($1) ORDER BY pt.playlist_id, pt.position
  `, [ids]);
  const coverByPlaylist = new Map(coverRows.map(r=>[r.playlist_id, r.cover_url]));

  const genreRows = await db.query(`
    SELECT DISTINCT ON (pt.playlist_id) pt.playlist_id, t.genre, COUNT(*) as c
    FROM playlist_tracks pt JOIN tracks t ON t.id = pt.track_id
    WHERE pt.playlist_id = ANY($1) AND t.genre IS NOT NULL
    GROUP BY pt.playlist_id, t.genre ORDER BY pt.playlist_id, c DESC
  `, [ids]);
  const genreByPlaylist = new Map(genreRows.map(r=>[r.playlist_id, r.genre]));

  for (const p of playlists) {
    p.track_count = countByPlaylist.get(p.id) || 0;
    if (!p.cover_url) p.cover_url = coverByPlaylist.get(p.id) || null;
    // Genre dominant réel — le genre le plus fréquent parmi les vrais morceaux de cette
    // playlist. Sert uniquement à personnaliser l'ordre d'affichage côté client, jamais
    // affiché comme une catégorisation officielle inventée pour la playlist elle-même.
    p.dominant_genre = genreByPlaylist.get(p.id) || null;
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
  const authUser = await optionalAuthUser(req);
  res.json({ playlist, tracks: stripAudioIfNoAccess(tracks, hasStreamingAccess(authUser)) });
}));

// ---------- Playlists PERSONNELLES — créées par chaque utilisateur, jamais mélangées avec
// les playlists officielles NUNI ci-dessus (même esprit, mais rattachées à un compte précis
// via user_id, avec vérification systématique du propriétaire avant toute modification). ----------
app.get('/api/me/playlists', authMiddleware, h(async (req, res) => {
  const playlists = await db.query('SELECT id, title, created_at FROM user_playlists WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
  for (const p of playlists) {
    const countRow = await db.get('SELECT COUNT(*)::int as c FROM user_playlist_tracks WHERE playlist_id = $1', [p.id]);
    p.track_count = countRow.c;
    const firstCover = await db.get(`
      SELECT t.cover_url FROM user_playlist_tracks upt JOIN tracks t ON t.id = upt.track_id
      WHERE upt.playlist_id = $1 ORDER BY upt.added_at LIMIT 1
    `, [p.id]);
    p.cover_url = firstCover ? firstCover.cover_url : null;
  }
  res.json({ playlists });
}));

app.post('/api/me/playlists', authMiddleware, rateLimit(20, 60000), h(async (req, res) => {
  const title = (req.body && req.body.title ? String(req.body.title) : '').trim().slice(0, 100);
  if (!title) return res.status(400).json({ error: 'Un nom de playlist est requis.' });
  const row = await db.get(
    'INSERT INTO user_playlists (user_id, title) VALUES ($1, $2) RETURNING id, title, created_at',
    [req.user.id, title],
  );
  res.json({ playlist: { ...row, track_count: 0, cover_url: null } });
}));

app.delete('/api/me/playlists/:id', authMiddleware, h(async (req, res) => {
  const playlist = await db.get('SELECT id FROM user_playlists WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (!playlist) return res.status(404).json({ error: 'Playlist introuvable.' });
  await db.run('DELETE FROM user_playlists WHERE id = $1', [req.params.id]);
  res.json({ deleted: true });
}));

app.get('/api/me/playlists/:id', authMiddleware, h(async (req, res) => {
  const playlist = await db.get('SELECT id, title, created_at FROM user_playlists WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (!playlist) return res.status(404).json({ error: 'Playlist introuvable.' });
  const tracks = await db.query(`
    SELECT t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
      u.artist_name, u.first_name, u.is_verified, u.id as artist_id
    FROM user_playlist_tracks upt JOIN tracks t ON t.id = upt.track_id JOIN users u ON u.id = t.artist_id
    WHERE upt.playlist_id = $1 ORDER BY upt.added_at DESC
  `, [req.params.id]);
  const meRow = await db.get('SELECT subscription_status, plan, email_verified FROM users WHERE id = $1', [req.user.id]);
  res.json({ playlist, tracks: stripAudioIfNoAccess(tracks, hasStreamingAccess(meRow)) });
}));

app.post('/api/me/playlists/:id/tracks', authMiddleware, rateLimit(30, 60000), h(async (req, res) => {
  const playlist = await db.get('SELECT id FROM user_playlists WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (!playlist) return res.status(404).json({ error: 'Playlist introuvable.' });
  const trackId = Number(req.body && req.body.trackId);
  const track = await db.get('SELECT id FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });
  // Insertion atomique — même pattern que les likes/suivis : jamais d'erreur si le morceau
  // est déjà dans la playlist, on ignore simplement en silence.
  await db.run(
    'INSERT INTO user_playlist_tracks (playlist_id, track_id) VALUES ($1,$2) ON CONFLICT (playlist_id, track_id) DO NOTHING',
    [req.params.id, trackId],
  );
  res.json({ added: true });
}));

app.delete('/api/me/playlists/:id/tracks/:trackId', authMiddleware, h(async (req, res) => {
  const playlist = await db.get('SELECT id FROM user_playlists WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (!playlist) return res.status(404).json({ error: 'Playlist introuvable.' });
  await db.run('DELETE FROM user_playlist_tracks WHERE playlist_id = $1 AND track_id = $2', [req.params.id, req.params.trackId]);
  res.json({ removed: true });
}));

function checkAdminKey(req, res) {
  const adminKey = (req.headers['x-admin-key'] || '').trim();
  const expectedKey = (process.env.ADMIN_KEY || '').trim();
  if (!expectedKey || adminKey !== expectedKey) {
    res.status(403).json({ error: 'Clé admin invalide.' });
    return false;
  }
  return true;
}

// ---------- Accès réel au streaming (correctif sécurité) ----------
// Avant : GET /api/tracks et GET /api/playlists/:id étaient entièrement publics et
// renvoyaient audio_url (le vrai lien Cloudinary du morceau) à N'IMPORTE QUELLE requête —
// même sans compte, sans connexion, sans Pass payé. N'importe qui pouvait donc récupérer la
// liste des morceaux et écouter/télécharger toute la musique NUNI gratuitement, en
// contournant entièrement le Pass Consommateur payant.
// Maintenant : le catalogue (titres, pochettes, streams, likes...) reste public — la
// découverte du catalogue ne doit jamais être bloquée, elle donne envie de s'inscrire.
// Seul le vrai lien audio est retenu, sauf pour un compte authentifié dont l'abonnement est
// réellement actif (Pass Consommateur/Artiste payé OU essai Pass Découverte de 24h en
// cours — jamais un accès anonyme, jamais un compte expiré).
async function optionalAuthUser(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  try {
    const user = await db.get('SELECT id, account_status, subscription_status, plan, email_verified FROM users WHERE id = $1', [payload.id]);
    if (!user || user.account_status === 'suspended' || user.account_status === 'deleted') return null;
    return user;
  } catch (e) { return null; }
}
function hasStreamingAccess(user) {
  if (!user || user.subscription_status !== 'active') return false;
  // Un essai Pass Découverte n'ouvre l'accès réel qu'une fois l'email confirmé — c'est ce
  // qui ferme la porte aux essais gratuits en série avec une adresse jetable ou variante
  // (voir issueEmailVerification et /api/register-discovery). Un Pass Consommateur/Artiste
  // payé, lui, est déjà vérifié humainement via le circuit WhatsApp/admin — pas concerné.
  if (user.plan === 'discovery' && !user.email_verified) return false;
  return true;
}
// Retire audio_url des morceaux si l'accès n'est pas réellement actif — jamais de morceau
// silencieusement modifié pour tout le monde, seulement le champ audio masqué au cas par cas.
function stripAudioIfNoAccess(rows, canStream) {
  if (canStream) return rows;
  return rows.map((r) => ({ ...r, audio_url: null }));
}

// ---------- Diagnostic de la clé admin — attendu par showAdminKeyDiagnostic dans
// admin.html (affiché automatiquement dès qu'une clé est rejetée), mais jamais construit
// côté serveur : la page appelait une route inexistante et retombait systématiquement sur
// "Diagnostic impossible à charger", cachant la vraie cause de "Clé admin invalide" (clé
// vide côté Render, mauvais service ciblé, espace en trop copié/collé, etc.).
// Ne révèle jamais la clé complète, ni côté tapé ni côté attendu — seulement la longueur et
// le premier/dernier caractère de chacune, largement suffisant pour repérer un espace, un
// guillemet ou une troncature accidentelle sans exposer le secret lui-même.
app.get('/api/admin/debug-key-check', h(async (req, res) => {
  const provided = (req.headers['x-admin-key'] || '').trim();
  const expected = (process.env.ADMIN_KEY || '').trim();
  res.json({
    match: !!expected && provided === expected,
    providedLength: provided.length,
    expectedLength: expected.length,
    providedFirstChar: provided ? provided[0] : '(vide)',
    providedLastChar: provided ? provided[provided.length - 1] : '(vide)',
    expectedFirstChar: expected ? expected[0] : '(vide — ADMIN_KEY absente ou vide sur Render)',
    expectedLastChar: expected ? expected[expected.length - 1] : '(vide — ADMIN_KEY absente ou vide sur Render)',
  });
}));

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
    // Avant : la clé ne comportait que l'identité (IP ou compte), donc TOUTES les routes
    // protégées (jouer un morceau, liker, suivre, se connecter, créer un compte...) partageaient
    // le même compteur. Une personne qui écoutait plusieurs morceaux pouvait ainsi se retrouver
    // bloquée pour créer un compte, sans aucun rapport entre les deux actions. On inclut
    // maintenant la route elle-même dans la clé : chaque endpoint a son propre compteur, comme prévu.
    const routePart = (req.route && req.route.path) || req.path;
    const key = routePart + '|' + rateLimitKeyFor(req);
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
    userId: user.id,
  });
}));

// ---------- Envoyer le code d'accès DIRECTEMENT au client par email, depuis le panneau
// admin — pour l'admin qui préfère envoyer lui-même le code une fois le paiement confirmé
// par l'équipe WhatsApp, plutôt que de repasser par le circuit habituel (boîte NUNI →
// retransmission WhatsApp). Relit toujours le vrai code ACTUEL en base (jamais un code
// fourni par la requête) — impossible d'envoyer un code périmé, déjà changé, ou trafiqué.
app.post('/api/admin/send-access-code-to-client', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { userId } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = $1', [userId]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (!user.access_code) return res.status(400).json({ error: "Ce compte n'a pas encore de code d'accès généré — activez d'abord son Pass." });
  const durationDays = user.subscription_started_at && user.subscription_expires_at
    ? Math.round((new Date(user.subscription_expires_at) - new Date(user.subscription_started_at)) / 86400000)
    : null;
  const result = await sendAccessCodeToClient({ user, plan: user.plan, accessCode: user.access_code, durationDays: durationDays || '—' });
  if (!result.sent) return res.status(502).json({ error: "L'envoi a échoué — " + (result.reason || 'réessayez.') });
  res.json({ message: `Code envoyé directement à ${user.email}.` });
}));

app.post('/api/subscribe/redeem', authMiddleware, rateLimit(10, 60000), h(async (req, res) => {
  const { code } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (user.subscription_status !== 'active') {
    return res.status(400).json({ error: "Aucun paiement confirmé pour ce compte pour l'instant." });
  }
  // Avant : le code n'était jamais nettoyé des espaces avant comparaison côté serveur — ça
  // ne fonctionnait que parce que le frontend le faisait déjà (trim + majuscules). Le
  // serveur ne doit jamais dépendre uniquement du client pour ça : un espace collé par
  // erreur (copier-coller depuis un email, appel direct à l'API...) ferait échouer un vrai
  // code correct.
  if (String(code || '').trim().toUpperCase() !== user.access_code) {
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
// Avant : avatarUrl/bannerUrl acceptaient n'importe quelle URL commençant par "http" — un
// compte aurait pu y mettre un lien externe arbitraire (traceur invisible qui logue les
// visiteurs du profil, contenu inapproprié jamais passé par la modération Cloudinary, etc.).
// Maintenant : uniquement une vraie URL Cloudinary (isCloudinaryUrl, définie plus haut avec
// uploadIfDataUri), cohérente avec le seul vrai chemin d'upload de l'app.

app.put('/api/artist/avatar', authMiddleware, h(async (req, res) => {
  const { avatarUrl } = req.body;
  if (!isCloudinaryUrl(avatarUrl)) return res.status(400).json({ error: 'URL de photo invalide.' });
  await db.run('UPDATE users SET avatar_url = $1 WHERE id = $2', [avatarUrl, req.user.id]);
  res.json({ message: 'Photo de profil mise à jour.', avatar_url: avatarUrl });
}));

// ---------- Vraie photo de couverture (bannière) artiste — même principe que l'avatar ----------
// Avant : "Changer la photo de couverture" ne faisait qu'un aperçu local dans le navigateur,
// jamais envoyé au serveur — perdu au rechargement, jamais visible pour les autres visiteurs.
app.put('/api/artist/banner', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { bannerUrl } = req.body;
  if (!isCloudinaryUrl(bannerUrl)) return res.status(400).json({ error: 'URL de photo invalide.' });
  await db.run('UPDATE users SET banner_url = $1 WHERE id = $2', [bannerUrl, req.user.id]);
  res.json({ message: 'Photo de couverture mise à jour.', banner_url: bannerUrl });
}));

// ---------- Vraie biographie artiste — remplie par l'artiste lui-même ----------
// Avant : texte générique codé en dur, jamais modifiable, affiché pour tout artiste réel
// (page artiste + lecteur plein écran). Ici : un vrai champ, visible par tout le monde une
// fois enregistré.
app.put('/api/artist/bio', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { bio } = req.body;
  const cleaned = String(bio || '').trim().slice(0, 600);
  await db.run('UPDATE users SET bio = $1 WHERE id = $2', [cleaned || null, req.user.id]);
  res.json({ message: 'Biographie mise à jour.', bio: cleaned || null });
}));

// ---------- Artistes suivis par CET artiste — vraie suggestion pour les auditeurs de sa
// page, basée sur qui il suit réellement (même mécanisme de suivi que tout le monde). ----------
app.get('/api/artist/:id/follows', h(async (req, res) => {
  const artistId = Number(req.params.id);
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.avatar_url, u.is_verified,
      (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as top_genre
    FROM follows f JOIN users u ON u.id = f.artist_id
    WHERE f.follower_id = $1 AND u.account_type = 'artist' AND u.id != $1
    ORDER BY f.created_at DESC LIMIT 12
  `, [artistId]);
  res.json({ artists: rows });
}));

app.get('/api/artist/:id/public-stats', h(async (req, res) => {
  const artistId = Number(req.params.id);
  const artist = await db.get('SELECT id, account_type, avatar_url, banner_url, bio, about_gallery_urls FROM users WHERE id = $1', [artistId]);
  if (!artist || artist.account_type !== 'artist') return res.status(404).json({ error: 'Artiste introuvable.' });
  const followerCount = (await db.get('SELECT COUNT(*)::int as c FROM follows WHERE artist_id = $1', [artistId])).c;
  const trackCount = (await db.get('SELECT COUNT(*)::int as c FROM tracks WHERE artist_id = $1 AND published = 1', [artistId])).c;
  // Auditeurs par mois — le frontend l'attendait depuis longtemps, jamais calculé côté
  // serveur jusqu'ici. Vrai nombre de comptes distincts ayant réellement écouté un morceau
  // de cet artiste depuis le 1er du mois calendaire en cours (table plays, horodatée).
  const monthlyListeners = (await db.get(`
    SELECT COUNT(DISTINCT p.listener_id)::int as c
    FROM plays p JOIN tracks t ON t.id = p.track_id
    WHERE t.artist_id = $1 AND p.created_at >= date_trunc('month', NOW())
  `, [artistId])).c;
  res.json({
    follower_count: followerCount, track_count: trackCount,
    avatar_url: artist.avatar_url || null, banner_url: artist.banner_url || null,
    bio: artist.bio || null, monthly_listeners: monthlyListeners,
    about_gallery_urls: artist.about_gallery_urls ? artist.about_gallery_urls.split(',').filter(Boolean) : [],
  });
}));

// ---------- L'artiste gère sa propre galerie "À propos" (jusqu'à 5 photos) ----------
app.put('/api/artist/about-gallery', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const { images } = req.body; // tableau de data-URI (nouvelle photo) ou d'URL déjà en ligne (inchangée), max 5
  if (!Array.isArray(images) || images.length > 5) {
    return res.status(400).json({ error: 'Maximum 5 photos.' });
  }
  const finalUrls = await Promise.all(images.filter(Boolean).map((img) => uploadIfDataUri(img, 'image')));
  await db.run('UPDATE users SET about_gallery_urls = $1 WHERE id = $2', [finalUrls.join(','), req.user.id]);
  res.json({ gallery: finalUrls });
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
  const authUser = await optionalAuthUser(req);
  const rows = await db.query(`
    SELECT t.id, t.title, t.release_type, t.scheduled_release_at, t.cover_url, u.artist_name, u.first_name,
      EXISTS(SELECT 1 FROM release_notify_requests rnr WHERE rnr.track_id = t.id AND rnr.user_id = $1) AS notify_requested
    FROM tracks t
    JOIN users u ON u.id = t.artist_id
    WHERE t.published = 0 AND t.scheduled_release_at IS NOT NULL AND t.scheduled_release_at > NOW()
      AND u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
    ORDER BY t.scheduled_release_at ASC
    LIMIT 8
  `, [authUser ? authUser.id : null]);
  res.json({ releases: rows });
}));

// "Me prévenir" sur une sortie à venir — inscrit une vraie demande, jamais une confirmation
// simulée. L'envoi réel de la notification push a lieu séparément (job qui vérifie les
// sorties arrivées à échéance), pas au moment de l'inscription.
app.post('/api/releases/:trackId/notify-me', authMiddleware, h(async (req, res) => {
  const trackId = Number(req.params.trackId);
  const track = await db.get('SELECT id FROM tracks WHERE id = $1 AND published = 0', [trackId]);
  if (!track) return res.status(404).json({ error: 'Sortie introuvable ou déjà publiée.' });
  await db.run(
    'INSERT INTO release_notify_requests (user_id, track_id) VALUES ($1, $2) ON CONFLICT (user_id, track_id) DO NOTHING',
    [req.user.id, trackId],
  );
  res.json({ ok: true });
}));
app.delete('/api/releases/:trackId/notify-me', authMiddleware, h(async (req, res) => {
  await db.run('DELETE FROM release_notify_requests WHERE user_id = $1 AND track_id = $2', [req.user.id, Number(req.params.trackId)]);
  res.json({ ok: true });
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
  // Avant : seul le TYPE de compte était vérifié — choisi librement par n'importe qui à
  // l'inscription (voir /api/register, accountType vient du client sans validation de
  // paiement). N'importe qui pouvait donc créer un compte "artiste" gratuit et publier de la
  // musique sans jamais passer par le circuit Pass Artiste payant. On vérifie maintenant le
  // vrai abonnement en base (jamais le JWT seul, qui peut dater de 30 jours et ne plus
  // refléter la réalité si un Pass a expiré depuis).
  const meArtist = await db.get('SELECT subscription_status, plan FROM users WHERE id = $1', [req.user.id]);
  if (!meArtist || meArtist.subscription_status !== 'active' || meArtist.plan !== 'artist') {
    return res.status(403).json({ error: 'Un Pass Artiste actif est requis pour publier un morceau — voir WhatsApp NUNI pour l\'activer.' });
  }
  const {
    title, album, genre, releaseType, coverUrl, audioUrl, lyrics, scheduledReleaseAt,
    composer, featuring, studio, description, releaseDate, credits, moodKeys, collaborators,
  } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis.' });
  // Limite de 3 ambiances maximum — vérifiée ici, jamais seulement côté client (qui peut
  // être contourné par n'importe quel appel direct à l'API).
  if (Array.isArray(moodKeys) && moodKeys.length > 3) {
    return res.status(400).json({ error: 'Maximum 3 ambiances par morceau.' });
  }
  const isFuture = scheduledReleaseAt && new Date(scheduledReleaseAt) > new Date();

  const [finalCoverUrl, finalAudioUrl] = await Promise.all([
    uploadIfDataUri(coverUrl, 'image'),
    uploadIfDataUri(audioUrl, 'video'),
  ]);

  const inserted = await db.get(`
    INSERT INTO tracks (
      artist_id, title, album, genre, release_type, cover_url, audio_url, lyrics, scheduled_release_at, published,
      composer, featuring, studio, description, release_date, credits
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
    RETURNING id
  `, [
    req.user.id, title, album || null, genre || null, releaseType || 'Single',
    finalCoverUrl || null, finalAudioUrl || null, lyrics || null,
    scheduledReleaseAt || null, isFuture ? 0 : 1,
    composer || null, featuring || null, studio || null, description || null, releaseDate || null, credits || null,
  ]);
  // Ambiances — entièrement optionnel, ne bloque jamais la publication si absent ou si une
  // clé envoyée ne correspond à aucune ambiance réelle du vocabulaire NUNI.
  if (Array.isArray(moodKeys) && moodKeys.length) {
    try {
      await db.run(
        `INSERT INTO track_moods (track_id, mood_id)
         SELECT $1, m.id FROM moods m WHERE m.key = ANY($2)
         ON CONFLICT DO NOTHING`,
        [inserted.id, moodKeys],
      );
    } catch (e) { console.error('Erreur enregistrement ambiances:', e); }
  }
  // Collaboration "primary" — créée automatiquement pour tout nouveau morceau, miroir
  // exact de artist_id (jamais une modification de tracks elle-même). Garantit que le
  // rétro-remplissage fait au démarrage du serveur (pour les morceaux déjà existants) et
  // le comportement des morceaux publiés APRÈS ce démarrage restent cohérents entre eux.
  try {
    const primaryCollab = await db.get(
      `INSERT INTO track_collaborators (track_id, artist_id, role, added_by) VALUES ($1,$2,'primary',$2) RETURNING id`,
      [inserted.id, req.user.id],
    );
    await db.run(
      `INSERT INTO collaboration_terms (collaborator_id, rights_type, payment_type, share_pct, status, created_by)
       VALUES ($1,'both','aucun_paiement',100,'accepted',$2)`,
      [primaryCollab.id, req.user.id],
    );
  } catch (e) { console.error('Erreur création collaboration primary:', e); }

  // Collaborateurs déclarés dans le formulaire de publication (avant que le morceau
  // n'existe) — réutilise exactement la même validation que l'endpoint dédié, jamais
  // dupliquée. Une déclaration invalide n'empêche jamais la publication elle-même.
  if (Array.isArray(collaborators) && collaborators.length) {
    for (const c of collaborators) {
      try {
        const result = await addCollaboratorToTrack({ id: inserted.id, title }, req.user.id, c);
        if (result.status >= 400) console.error('Collaborateur déclaré ignoré (validation) :', result.error);
      } catch (e) { console.error('Erreur ajout collaborateur à la publication:', e); }
    }
  }
  res.status(201).json({ id: inserted.id, scheduled: isFuture });
  if (!isFuture) {
    // Notification "nouvelle sortie" pour le Label — jamais bloquante pour la réponse déjà envoyée.
    db.get(
      "SELECT l.user_id, l.label_name, u.artist_name FROM label_artists la JOIN labels l ON l.id = la.label_id JOIN users u ON u.id = la.artist_id WHERE la.artist_id = $1 AND la.status = 'active' LIMIT 1",
      [req.user.id],
    ).then((row) => {
      if (row) createNotification(row.user_id, 'label_new_release', 'Nouvelle sortie', `${row.artist_name} vient de publier « ${title} » sur NUNI.`, null).catch(() => {});
    }).catch(() => {});
  }
}));

app.post('/api/clips', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const meArtistClip = await db.get('SELECT subscription_status, plan FROM users WHERE id = $1', [req.user.id]);
  if (!meArtistClip || meArtistClip.subscription_status !== 'active' || meArtistClip.plan !== 'artist') {
    return res.status(403).json({ error: 'Un Pass Artiste actif est requis pour publier un clip — voir WhatsApp NUNI pour l\'activer.' });
  }
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
           u.avatar_url as artist_avatar_url,
           t.composer, t.featuring, t.studio, t.description, t.release_date, t.credits
    FROM tracks t JOIN users u ON u.id = t.artist_id
    WHERE t.published = 1 AND (t.scheduled_release_at IS NULL OR t.scheduled_release_at <= NOW())
    ORDER BY t.created_at DESC
  `);
  const authUser = await optionalAuthUser(req);
  res.json({ tracks: stripAudioIfNoAccess(rows, hasStreamingAccess(authUser)) });
}));

const NUNI_PRICE_PER_STREAM_FCFA = 2;
const NUNI_ARTIST_SHARE_PCT = 75;
const MONTH_LABELS_FR = ['Jan', 'Fév', 'Mar', 'Avr', 'Mai', 'Juin', 'Juil', 'Août', 'Sep', 'Oct', 'Nov', 'Déc'];

// ---------- Taux de reversement configurables (module Reversements artistes) ----------
// Stockés dans app_settings (déjà utilisée pour le secret JWT) — pas de nouvelle table
// pour deux valeurs. Si jamais rien n'a été configuré, on retombe sur les constantes
// historiques ci-dessus (celles déjà utilisées par le Dashboard artiste classique).
async function getRoyaltySettings() {
  const priceRow = await db.get('SELECT value FROM app_settings WHERE key = $1', ['royalty_price_per_stream_fcfa']);
  const shareRow = await db.get('SELECT value FROM app_settings WHERE key = $1', ['royalty_artist_share_pct']);
  return {
    price_per_stream_fcfa: priceRow ? Number(priceRow.value) : NUNI_PRICE_PER_STREAM_FCFA,
    artist_share_pct: shareRow ? Number(shareRow.value) : NUNI_ARTIST_SHARE_PCT,
  };
}
async function setRoyaltySetting(key, value) {
  await db.run(
    `INSERT INTO app_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, String(value)],
  );
}

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
    await bumpChallenge(listenerId, 'daily_listen_3', 1);
    await bumpChallenge(listenerId, 'weekly_listen_15', 1);
  }
  res.json({ counted: true, streams: track.streams + 1 });
}));

// ---------- Likes réels sur les morceaux (persistés, un seul like par personne) ----------
app.post('/api/tracks/:id/like', authMiddleware, rateLimit(30, 60000), h(async (req, res) => {
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id, likes, artist_id FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });
  // Un artiste ne peut pas liker son propre morceau — évite de gonfler artificiellement
  // son propre compteur (même logique déjà appliquée au suivi d'artiste ci-dessus).
  if (track.artist_id === req.user.id) {
    return res.status(400).json({ error: 'Vous ne pouvez pas aimer votre propre morceau.' });
  }

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
  // Avant : seul le track_id était renvoyé — impossible de savoir QUAND un morceau avait été
  // liké, donc impossible de le faire apparaître au bon endroit dans un vrai "Ajouts récents"
  // trié chronologiquement. created_at existe en base depuis le début (track_likes), juste
  // jamais exposé. On garde track_ids pour compatibilité et on ajoute "likes" avec la date.
  const rows = await db.query('SELECT track_id, created_at as liked_at FROM track_likes WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
  res.json({ track_ids: rows.map((r) => r.track_id), likes: rows });
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
// automatiquement chaque semaine — via un hash basé sur la semaine calendaire, pas de
// tâche planifiée nécessaire : la même semaine donne le même ordre pour tout le monde,
// et l'ordre change tout seul dès qu'on passe à la fenêtre suivante.
// (Une route dupliquée /api/artist/:id/follows existait juste ici — identique à celle
// définie plus haut vers la ligne 2046, jamais atteinte par Express puisque la première
// déclaration répondait déjà systématiquement. Supprimée.)
app.get('/api/artists/featured', h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified,
      (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as top_genre
    FROM users u
    WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
    ORDER BY md5(u.id::text || floor(extract(epoch from now())/604800)::text)
    LIMIT 6
  `);
  res.json({ artists: rows });
}));

// ---------- Top 100 artistes — vrai classement par abonnés ----------
// Réservé aux comptes ayant réellement un Pass Artiste actif (même filtre que /featured),
// classés par leur vrai nombre d'abonnés (table follows), pas par XP ni popularité inventée.
// ---------- Recherche d'artiste — pour le sélecteur de collaborateur (A2). Vraie recherche
// en base, jamais limitée aux morceaux déjà chargés côté client. ----------
app.get('/api/artists/search', authMiddleware, h(async (req, res) => {
  const query = ((req.query.q || '') + '').trim();
  if (query.length < 2) return res.json({ artists: [] });
  const rows = await db.query(
    `SELECT id, artist_name, first_name, avatar_url FROM users
     WHERE account_type = 'artist' AND id != $1
       AND (LOWER(artist_name) LIKE LOWER($2) OR LOWER(first_name) LIKE LOWER($2))
     LIMIT 8`,
    [req.user.id, `%${query}%`],
  );
  res.json({ artists: rows });
}));

// ---------- A3 — "Mes collaborations" : toutes les collaborations où je suis l'artiste
// principal (celui qui publie), groupées par morceau, avec le vrai statut de chacune. ----------
app.get('/api/me/collaborations-given', authMiddleware, h(async (req, res) => {
  const rows = await db.query(`
    SELECT t.id AS track_id, t.title AS track_title,
      tc.id AS collaborator_id, tc.role, tc.external_name,
      u.id AS collaborator_artist_id, u.artist_name, u.first_name,
      ct.id AS terms_id, ct.rights_type, ct.share_pct, ct.status, ct.payment_type,
      cd.reason AS dispute_reason,
      COALESCE((SELECT SUM(cp.gross_share_fcfa) FROM collaborator_payouts cp
                WHERE cp.collaboration_terms_id = ct.id AND cp.status IN ('held_dispute','held_pending')), 0) AS frozen_amount_fcfa
    FROM tracks t
    JOIN track_collaborators tc ON tc.track_id = t.id AND tc.role != 'primary'
    JOIN collaboration_terms ct ON ct.collaborator_id = tc.id AND ct.effective_until IS NULL
    LEFT JOIN users u ON u.id = tc.artist_id
    LEFT JOIN collaboration_disputes cd ON cd.collaboration_terms_id = ct.id AND cd.status = 'open'
    WHERE t.artist_id = $1
    ORDER BY t.created_at DESC
  `, [req.user.id]);
  res.json({ items: rows });
}));

// ---------- C4 — "Mes collaborations" côté collaborateur : accords où JE suis le
// collaborateur (jamais l'artiste principal), sur des morceaux d'autres artistes. ----------
app.get('/api/me/collaborations-received', authMiddleware, h(async (req, res) => {
  const rows = await db.query(`
    SELECT t.id AS track_id, t.title AS track_title, t.cover_url,
      tc.id AS collaborator_id, tc.role,
      pu.artist_name AS primary_artist_name, pu.first_name AS primary_first_name,
      ct.id AS terms_id, ct.rights_type, ct.share_pct, ct.status, ct.payment_type,
      cd.reason AS dispute_reason,
      COALESCE((SELECT SUM(cp.gross_share_fcfa) FROM collaborator_payouts cp
                WHERE cp.collaboration_terms_id = ct.id AND cp.status IN ('held_dispute','held_pending')), 0) AS frozen_amount_fcfa
    FROM track_collaborators tc
    JOIN tracks t ON t.id = tc.track_id
    JOIN users pu ON pu.id = t.artist_id
    JOIN collaboration_terms ct ON ct.collaborator_id = tc.id AND ct.effective_until IS NULL
    LEFT JOIN collaboration_disputes cd ON cd.collaboration_terms_id = ct.id AND cd.status = 'open'
    WHERE tc.artist_id = $1
    ORDER BY tc.created_at DESC
  `, [req.user.id]);
  // Normaliser le nom d'affichage de l'artiste principal, jamais recalculé côté client.
  rows.forEach(r => { r.primary_artist_name = r.primary_artist_name || r.primary_first_name || 'Artiste NUNI'; });
  res.json({ items: rows });
}));

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

// ---------- "À surveiller" — vrais artistes récemment inscrits ayant déjà au moins un vrai
// morceau publié. Jamais un statut "émergent"/"à surveiller" affiché sans activité réelle
// derrière — le filtre sur un vrai morceau publié écarte les comptes créés mais inactifs. ----------
app.get('/api/artists/emerging', h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url, u.is_verified, u.city, u.created_at,
      (SELECT genre FROM tracks WHERE artist_id = u.id AND genre IS NOT NULL ORDER BY created_at DESC LIMIT 1) as top_genre,
      (SELECT COUNT(*)::int FROM tracks WHERE artist_id = u.id AND published = 1) as track_count
    FROM users u
    WHERE u.account_type = 'artist' AND u.subscription_status = 'active' AND u.plan = 'artist'
      AND EXISTS (SELECT 1 FROM tracks t WHERE t.artist_id = u.id AND t.published = 1)
    ORDER BY u.created_at DESC
    LIMIT 4
  `);
  res.json({ artists: rows });
}));

// ---------- "Les titres qui montent" — vraie progression semaine sur semaine, calculée en
// direct sur les vraies écoutes horodatées (table plays), jamais un pourcentage inventé ou
// un historique de rang fictif. Seuil minimum de 5 écoutes la semaine précédente pour éviter
// qu'un morceau passé de 1 à 2 écoutes affiche une fausse "progression de 100%".
app.get('/api/tracks/rising', h(async (req, res) => {
  const rows = await db.query(`
    WITH weekly AS (
      SELECT track_id,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') AS this_week,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '14 days' AND created_at < NOW() - INTERVAL '7 days') AS last_week
      FROM plays
      GROUP BY track_id
    )
    SELECT t.id, t.title, u.artist_name, u.first_name, w.this_week, w.last_week,
      ROUND(((w.this_week - w.last_week)::numeric / NULLIF(w.last_week,0)) * 100) AS growth_pct
    FROM weekly w
    JOIN tracks t ON t.id = w.track_id AND t.published = 1
    JOIN users u ON u.id = t.artist_id
    WHERE w.last_week >= 5 AND w.this_week > w.last_week
    ORDER BY growth_pct DESC
    LIMIT 5
  `);
  res.json({ tracks: rows });
}));

// ---------- "En ce moment" — vrais nouveaux auditeurs des dernières 24h, par artiste.
// NUNI ne garde aucune notion de lecture "en cours" (plays.created_at correspond à la
// PREMIÈRE écoute d'un morceau par un auditeur, jamais réécrit ensuite) — donc jamais de
// faux compteur "en direct" affiché. Un artiste n'apparaît que s'il a réellement de
// nouveaux auditeurs aujourd'hui.
app.get('/api/activity/today', h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url,
      COUNT(DISTINCT p.listener_id)::int AS new_listeners_today
    FROM plays p
    JOIN tracks t ON t.id = p.track_id
    JOIN users u ON u.id = t.artist_id
    WHERE p.created_at >= NOW() - INTERVAL '24 hours' AND p.listener_id IS NOT NULL
    GROUP BY u.id, u.artist_name, u.first_name, u.avatar_url
    ORDER BY new_listeners_today DESC
    LIMIT 5
  `);
  res.json({ activity: rows });
}));

// ---------- Ambiances NUNI — vraies ambiances taguées par les artistes (jamais de mood
// déduit automatiquement). Une ambiance n'est renvoyée que si elle a réellement au moins 3
// morceaux publiés — sinon, mieux vaut ne pas l'afficher plutôt que de remplir la section
// artificiellement avec 1 ou 2 morceaux.
// Vocabulaire complet des ambiances — pour le sélecteur du formulaire de publication
// artiste. Distinct de GET /api/moods (qui ne renvoie que les ambiances déjà assez
// peuplées pour l'accueil) : un artiste doit pouvoir taguer une ambiance même si elle n'a
// encore aucun morceau.
app.get('/api/moods/available', h(async (req, res) => {
  const rows = await db.query('SELECT key, label FROM moods ORDER BY sort_order');
  res.json({ moods: rows });
}));

app.get('/api/moods', h(async (req, res) => {
  const rows = await db.query(`
    SELECT m.key, m.label,
      json_agg(json_build_object('id', t.id, 'title', t.title, 'cover_url', t.cover_url, 'artist_name', u.artist_name, 'first_name', u.first_name) ORDER BY t.created_at DESC) AS tracks
    FROM moods m
    JOIN track_moods tm ON tm.mood_id = m.id
    JOIN tracks t ON t.id = tm.track_id AND t.published = 1
    JOIN users u ON u.id = t.artist_id
    GROUP BY m.id, m.key, m.label, m.sort_order
    HAVING COUNT(t.id) >= 3
    ORDER BY m.sort_order
  `);
  // On ne garde que les 8 morceaux les plus récents par ambiance côté réponse — la requête
  // ci-dessus les a déjà triés du plus récent au plus ancien.
  rows.forEach(r => { r.tracks = r.tracks.slice(0, 8); });
  res.json({ moods: rows });
}));

// Ambiances d'un morceau précis — prévu pour être affiché sur sa page, dans l'album, la
// recherche et les futures recommandations. Tableau vide si aucune ambiance taguée, jamais
// une valeur par défaut inventée.
app.get('/api/tracks/:id/moods', h(async (req, res) => {
  const rows = await db.query(
    `SELECT m.key, m.label FROM track_moods tm JOIN moods m ON m.id = tm.mood_id WHERE tm.track_id = $1 ORDER BY m.sort_order`,
    [Number(req.params.id)],
  );
  res.json({ moods: rows });
}));

// ---------- "En ce moment" — vrais nouveaux auditeurs uniques du jour, par morceau. NUNI ne
// garde qu'une ligne par (morceau, auditeur) au tout premier passage (plays), donc aucune
// notion réelle d'écoute "en direct" n'existe — ceci reste honnête : "X personnes ont
// découvert ce morceau aujourd'hui", jamais un faux compteur de lecteurs simultanés.
// Seuil minimum de 2 pour éviter d'afficher un chiffre dérisoire comme s'il était notable.
app.get('/api/tracks/discovered-today', h(async (req, res) => {
  const rows = await db.query(`
    SELECT t.id, t.title, u.artist_name, u.first_name, COUNT(*)::int AS listener_count
    FROM plays p
    JOIN tracks t ON t.id = p.track_id AND t.published = 1
    JOIN users u ON u.id = t.artist_id
    WHERE p.created_at >= CURRENT_DATE
    GROUP BY t.id, t.title, u.artist_name, u.first_name
    HAVING COUNT(*) >= 2
    ORDER BY listener_count DESC
    LIMIT 4
  `);
  res.json({ tracks: rows });
}));

// ---------- "En ce moment" — vrais NOUVEAUX auditeurs uniques aujourd'hui, par artiste.
// NUNI ne garde aucune notion d'écoute "en direct" (plays = une ligne par auditeur/morceau,
// jamais mise à jour ensuite) : jamais de compteur "X personnes écoutent maintenant" simulé
// à la place. Version honnête : "X personnes ont découvert cet artiste aujourd'hui".
app.get('/api/artists/discovered-today', h(async (req, res) => {
  const rows = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.avatar_url,
      COUNT(DISTINCT p.listener_id)::int AS new_listeners_today
    FROM plays p
    JOIN tracks t ON t.id = p.track_id
    JOIN users u ON u.id = t.artist_id
    WHERE p.created_at >= CURRENT_DATE AND p.listener_id IS NOT NULL
    GROUP BY u.id, u.artist_name, u.first_name, u.avatar_url
    HAVING COUNT(DISTINCT p.listener_id) > 0
    ORDER BY new_listeners_today DESC
    LIMIT 4
  `);
  res.json({ artists: rows });
}));

// ---------- Top artistes par streams — pour la pyramide Top Congo ----------
// Vrais streams cumulés (SUM sur tracks.streams), même filtre Pass Artiste actif
// que /top100 et /talent/top100. Pas de votes ici : uniquement l'écoute réelle.
// ---------- Tendance régionale — vraies écoutes de vrais auditeurs du même pays ----------
// Avant : "Top Congo" était la seule tendance disponible, toujours calculée sur TOUTES les
// écoutes de la plateforme sans distinction de pays — ce qui n'a d'importance que le jour où
// NUNI aura de vrais auditeurs hors Congo. Cette route prépare cette évolution : les 30
// derniers jours d'écoutes (plays.created_at), filtrées sur les VRAIS auditeurs (listener_id
// → users.country) du même pays que la personne qui consulte l'accueil — jamais un contenu
// générique ou inventé, juste un vrai classement scopé sur de vraies données déjà en base.
app.get('/api/tracks/trending-region', h(async (req, res) => {
  const country = (req.query.country || '').trim();
  if (!country) return res.json({ tracks: [], scoped: false });
  const rows = await db.query(`
    SELECT t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type,
      u.artist_name, u.first_name, u.is_verified, u.id as artist_id,
      COUNT(p.id)::int as region_plays
    FROM plays p
    JOIN tracks t ON t.id = p.track_id
    JOIN users u ON u.id = t.artist_id
    JOIN users listener ON listener.id = p.listener_id
    WHERE listener.country = $1 AND p.created_at > NOW() - INTERVAL '30 days' AND t.published = 1
    GROUP BY t.id, t.title, t.cover_url, t.audio_url, t.genre, t.streams, t.likes, t.release_type, u.artist_name, u.first_name, u.is_verified, u.id
    ORDER BY region_plays DESC
    LIMIT 12
  `, [country]);
  const authUser = await optionalAuthUser(req);
  res.json({ tracks: stripAudioIfNoAccess(rows, hasStreamingAccess(authUser)), scoped: true, country });
}));

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

// ---------- NUNI Tendance — vraie vitesse de progression des streams, basée sur
// track_streams_history. Compare le vrai total actuel au vrai instantané le plus ancien
// disponible datant d'un jour précédent. Si aucun instantané d'un jour antérieur n'existe
// encore (plateforme trop récente), retourne une liste vide — jamais une progression
// inventée à partir du seul total cumulé. ----------
// ---------- "Classement de la semaine" — vraie progression depuis le lundi de cette
// semaine (même définition que weeklyPeriodKey, déjà utilisée pour les votes Talent),
// jamais le total cumulé (c'est déjà Top Congo). Si aucun instantané datant d'avant ce
// lundi n'existe encore, retourne une liste vide — jamais un classement inventé. ----------
app.get('/api/tracks/weekly-ranking', h(async (req, res) => {
  const d = new Date();
  const dayIdx = (d.getUTCDay() + 6) % 7;
  const monday = new Date(d);
  monday.setUTCDate(d.getUTCDate() - dayIdx);
  const mondayStr = monday.toISOString().slice(0, 10);

  const baselineRows = await db.query(`
    SELECT DISTINCT ON (track_id) track_id, streams_snapshot
    FROM track_streams_history
    WHERE recorded_date <= $1
    ORDER BY track_id, recorded_date DESC
  `, [mondayStr]);
  if (!baselineRows.length) { return res.json({ tracks: [], reason: 'Historique insuffisant (pas encore de donnée avant ce lundi).' }); }
  const baselineByTrack = new Map(baselineRows.map(r => [r.track_id, r.streams_snapshot]));

  const allTracks = await db.query(`SELECT id, streams FROM tracks`);
  const ranked = allTracks
    .map(t => ({ id: t.id, weeklyStreams: t.streams - (baselineByTrack.get(t.id) ?? t.streams) }))
    .filter(t => t.weeklyStreams > 0)
    .sort((a, b) => b.weeklyStreams - a.weeklyStreams)
    .slice(0, 100);
  res.json({ tracks: ranked });
}));

app.get('/api/tracks/trending', h(async (req, res) => {
  const oldestRow = await db.get(`SELECT MIN(recorded_date) as d FROM track_streams_history WHERE recorded_date < CURRENT_DATE`);
  if (!oldestRow || !oldestRow.d) { return res.json({ tracks: [], reason: 'Historique insuffisant (moins de 2 jours de données réelles).' }); }
  const rows = await db.query(`
    SELECT t.id, (t.streams - COALESCE(h.streams_snapshot, 0)) as velocity, h.streams_snapshot as old_streams
    FROM tracks t
    JOIN track_streams_history h ON h.track_id = t.id AND h.recorded_date = $1
    WHERE t.streams > COALESCE(h.streams_snapshot, 0)
    ORDER BY velocity DESC
    LIMIT 15
  `, [oldestRow.d]);
  res.json({ tracks: rows.map(r => ({
    id: r.id, velocity: r.velocity,
    // Vrai pourcentage — si le point de départ était à 0, la progression est "nouvelle"
    // (jamais un pourcentage divisé par zéro, jamais un chiffre absurde ou inventé).
    percent: r.old_streams > 0 ? Math.round((r.velocity / r.old_streams) * 100) : null,
  })) });
}));

// ---------- Artistes à surveiller — même principe que NUNI Tendance, agrégé par artiste
// (vraie somme de la progression de tous ses morceaux). Même garde-fou : liste vide tant
// qu'il n'y a pas au moins un jour d'historique réel antérieur. ----------
app.get('/api/artists/rising', h(async (req, res) => {
  const oldestRow = await db.get(`SELECT MIN(recorded_date) as d FROM track_streams_history WHERE recorded_date < CURRENT_DATE`);
  if (!oldestRow || !oldestRow.d) { return res.json({ artists: [], reason: 'Historique insuffisant (moins de 2 jours de données réelles).' }); }
  const rows = await db.query(`
    SELECT t.artist_id, SUM(t.streams - COALESCE(h.streams_snapshot, 0)) as velocity
    FROM tracks t
    JOIN track_streams_history h ON h.track_id = t.id AND h.recorded_date = $1
    GROUP BY t.artist_id
    HAVING SUM(t.streams - COALESCE(h.streams_snapshot, 0)) > 0
    ORDER BY velocity DESC
    LIMIT 15
  `, [oldestRow.d]);
  res.json({ artists: rows.map(r => ({ artistId: r.artist_id, velocity: r.velocity })) });
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
// Avant : une clé de repli en dur existait pour les deux variables — si jamais les vraies
// variables d'environnement n'étaient pas définies sur Render, la vraie clé PRIVÉE se
// retrouvait alors directement dans le code source, donc sur GitHub. Maintenant : aucun
// repli — sans les deux variables d'environnement, les notifications push se désactivent
// simplement proprement (avertissement au démarrage), plutôt que d'exposer un secret.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_CONFIGURED = !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);
if (VAPID_CONFIGURED) {
  webpush.setVapidDetails('mailto:nunimisiki@gmail.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} else {
  console.warn('VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY absentes des variables d\'environnement — notifications push désactivées.');
}

async function sendPushToUser(userId, { title, body, url }) {
  if (!VAPID_CONFIGURED) return; // notifications désactivées proprement, voir avertissement au démarrage
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
  // Rappel régulier pour consulter "Opportunités" — pas un vrai cron (aucun scheduler dans
  // ce projet), mais un déclenchement naturel : à chaque fois que la personne consulte ses
  // notifications, on vérifie si son dernier rappel Opportunités date de plus de 7 jours ;
  // si oui, on en recrée un tout de suite. Résultat : un rappel qui revient vraiment
  // régulièrement, sans jamais spammer (au plus un par semaine et par personne).
  const lastReminder = await db.get(
    "SELECT created_at FROM notifications WHERE user_id = $1 AND type = 'opportunites_reminder' ORDER BY created_at DESC LIMIT 1",
    [req.user.id],
  );
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  if (!lastReminder || new Date(lastReminder.created_at).getTime() < sevenDaysAgo) {
    await createNotification(
      req.user.id, 'opportunites_reminder', 'De nouvelles opportunités vous attendent',
      "Sponsors, mises en avant, collaborations — jetez un œil à la section Opportunités, ça bouge régulièrement.", '/opportunites',
    );
  }
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

// ================= CONCERTS (Phase 2) =================
// Publication directe par l'artiste, aucune validation admin nécessaire — dès qu'il publie,
// le concert apparaît dans l'onglet Concerts de la recherche (voir GET /api/concerts).

// ---------- Publique — tous les concerts à venir, pour la page Concerts de la recherche ----------
app.get('/api/concerts', h(async (req, res) => {
  const rows = await db.query(`
    SELECT co.*, u.artist_name, u.avatar_url as artist_avatar_url, u.is_verified
    FROM concerts co JOIN users u ON u.id = co.artist_id
    WHERE co.event_date >= CURRENT_DATE
    ORDER BY co.event_date ASC
  `);
  res.json({ concerts: rows });
}));

// ---------- Publique — concerts à venir d'un artiste précis (page profil artiste) ----------
app.get('/api/artists/:id/concerts', h(async (req, res) => {
  const rows = await db.query(`
    SELECT * FROM concerts WHERE artist_id = $1 AND event_date >= CURRENT_DATE ORDER BY event_date ASC
  `, [Number(req.params.id)]);
  res.json({ concerts: rows });
}));

// ---------- Gestion — les concerts de l'artiste connecté (Dashboard), passés et à venir ----------
app.get('/api/dashboard/concerts', authMiddleware, h(async (req, res) => {
  const user = await db.get('SELECT account_type FROM users WHERE id = $1', [req.user.id]);
  if (!user || user.account_type !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes artiste.' });
  const rows = await db.query('SELECT * FROM concerts WHERE artist_id = $1 ORDER BY event_date DESC', [req.user.id]);
  res.json({ concerts: rows });
}));

// ---------- Créer un concert ----------
app.post('/api/dashboard/concerts', authMiddleware, rateLimit(10, 60000), h(async (req, res) => {
  const user = await db.get('SELECT account_type FROM users WHERE id = $1', [req.user.id]);
  if (!user || user.account_type !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes artiste.' });
  const {
    title, description, flyerUrl, eventDate, startTime, endTime, city, country, venue, address,
    gpsLat, gpsLng, ticketPrice, ticketType, capacity, placesRestantes, purchaseLink, tourName,
    eventType, ticketPriceVip, ticketPriceStandard, purchaseLocations, purchasePhoneNumbers,
  } = req.body;
  if (!title || !eventDate || !city || !country) {
    return res.status(400).json({ error: 'Titre, date, ville et pays sont obligatoires.' });
  }
  const row = await db.get(
    `INSERT INTO concerts (
      artist_id, title, description, flyer_url, event_date, start_time, end_time, city, country,
      venue, address, gps_lat, gps_lng, ticket_price, ticket_type, capacity, places_restantes,
      purchase_link, tour_name, event_type, ticket_price_vip, ticket_price_standard,
      purchase_locations, purchase_phone_numbers
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) RETURNING *`,
    [
      req.user.id, title, description || null, flyerUrl || null, eventDate, startTime || null, endTime || null,
      city, country, venue || null, address || null, gpsLat || null, gpsLng || null,
      ticketPrice || null, ticketType || null, capacity || null, placesRestantes || capacity || null,
      purchaseLink || null, tourName || null, eventType === 'showcase' ? 'showcase' : 'concert',
      ticketPriceVip || null, ticketPriceStandard || null, purchaseLocations || null, purchasePhoneNumbers || null,
    ],
  );
  res.json({ concert: row, message: 'Publié — visible immédiatement dans la recherche.' });
}));

// ---------- Modifier (ex: mettre à jour les places restantes) ----------
app.put('/api/dashboard/concerts/:id', authMiddleware, h(async (req, res) => {
  const concert = await db.get('SELECT id FROM concerts WHERE id = $1 AND artist_id = $2', [Number(req.params.id), req.user.id]);
  if (!concert) return res.status(404).json({ error: 'Concert introuvable.' });
  const { placesRestantes } = req.body;
  if (typeof placesRestantes === 'number') {
    await db.run('UPDATE concerts SET places_restantes = $1 WHERE id = $2', [placesRestantes, concert.id]);
  }
  res.json({ message: 'Concert mis à jour.' });
}));

// ---------- Supprimer ----------
app.delete('/api/dashboard/concerts/:id', authMiddleware, h(async (req, res) => {
  const concert = await db.get('SELECT id FROM concerts WHERE id = $1 AND artist_id = $2', [Number(req.params.id), req.user.id]);
  if (!concert) return res.status(404).json({ error: 'Concert introuvable.' });
  await db.run('DELETE FROM concerts WHERE id = $1', [concert.id]);
  res.json({ message: 'Concert supprimé.' });
}));

// ================= NUNI ÉVÉNEMENTS (Phase 3) =================
// Entièrement administrés par NUNI — aucun artiste ne peut y publier, uniquement l'équipe
// admin via admin.html (protégé par x-admin-key, même mécanisme que le reste de l'admin).

// ---------- Publique — pour la page NUNI Événements de la recherche ----------
app.get('/api/nuni-events', h(async (req, res) => {
  const rows = await db.query(`
    SELECT * FROM nuni_events WHERE event_date >= CURRENT_DATE ORDER BY event_date ASC
  `);
  res.json({ events: rows });
}));

// ---------- Admin — liste complète (passés compris, pour la gestion) ----------
app.get('/api/admin/nuni-events', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query('SELECT * FROM nuni_events ORDER BY event_date DESC');
  res.json({ events: rows });
}));

// ---------- Admin — créer ----------
app.post('/api/admin/nuni-events', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const {
    category, title, description, flyerUrl, eventDate, startTime, venue, address,
    gpsLat, gpsLng, price, purchaseLink, capacity, placesRestantes, galleryUrls, promoVideoUrl,
    purchaseLocations, purchasePhoneNumbers, featuredArtistNames,
  } = req.body;
  if (!category || !title || !eventDate) {
    return res.status(400).json({ error: 'Catégorie, titre et date sont obligatoires.' });
  }
  const row = await db.get(
    `INSERT INTO nuni_events (
      category, title, description, flyer_url, event_date, start_time, venue, address,
      gps_lat, gps_lng, price, purchase_link, capacity, places_restantes, gallery_urls, promo_video_url,
      purchase_locations, purchase_phone_numbers, featured_artist_names
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *`,
    [
      category, title, description || null, flyerUrl || null, eventDate, startTime || null, venue || null, address || null,
      gpsLat || null, gpsLng || null, price || null, purchaseLink || null, capacity || null,
      placesRestantes || capacity || null, galleryUrls || null, promoVideoUrl || null,
      purchaseLocations || null, purchasePhoneNumbers || null, featuredArtistNames || null,
    ],
  );
  res.json({ event: row, message: 'Événement publié — visible immédiatement dans la recherche.' });
}));

// ---------- Admin — modifier (ex: ajouter points de vente/numéros après coup) ----------
app.put('/api/admin/nuni-events/:id', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const event = await db.get('SELECT id FROM nuni_events WHERE id = $1', [Number(req.params.id)]);
  if (!event) return res.status(404).json({ error: 'Événement introuvable.' });
  const { purchaseLocations, purchasePhoneNumbers, purchaseLink, placesRestantes, featuredArtistNames } = req.body;
  await db.run(
    `UPDATE nuni_events SET
      purchase_locations = COALESCE($1, purchase_locations),
      purchase_phone_numbers = COALESCE($2, purchase_phone_numbers),
      purchase_link = COALESCE($3, purchase_link),
      places_restantes = COALESCE($4, places_restantes),
      featured_artist_names = COALESCE($5, featured_artist_names)
     WHERE id = $6`,
    [purchaseLocations || null, purchasePhoneNumbers || null, purchaseLink || null, placesRestantes ?? null, featuredArtistNames || null, event.id],
  );
  res.json({ message: 'Événement mis à jour.' });
}));

// ---------- Admin — supprimer ----------
app.delete('/api/admin/nuni-events/:id', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const event = await db.get('SELECT id FROM nuni_events WHERE id = $1', [Number(req.params.id)]);
  if (!event) return res.status(404).json({ error: 'Événement introuvable.' });
  await db.run('DELETE FROM nuni_events WHERE id = $1', [event.id]);
  res.json({ message: 'Événement supprimé.' });
}));

// ---------- Informations officielles NUNI (locaux, service client) ----------
// Affichées à la place d'un lien d'achat pour les événements NUNI Événements qui n'en ont
// pas — contrairement aux concerts d'artistes, un événement NUNI appartient à la plateforme
// elle-même, donc ce sont les vraies coordonnées NUNI qui ont du sens ici, pas "bientôt
// disponible". Stocké dans app_settings, même mécanisme que les taux de reversement.
const NUNI_INFO_KEYS = ['nuni_info_locations', 'nuni_info_phone', 'nuni_info_email'];
app.get('/api/nuni-info', h(async (req, res) => {
  const rows = await db.query('SELECT key, value FROM app_settings WHERE key = ANY($1)', [NUNI_INFO_KEYS]);
  const map = {};
  rows.forEach((r) => { map[r.key] = r.value; });
  res.json({
    locations: map.nuni_info_locations || null,
    phone: map.nuni_info_phone || null,
    email: map.nuni_info_email || null,
  });
}));
app.post('/api/admin/nuni-info', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { locations, phone, email } = req.body;
  const pairs = [
    ['nuni_info_locations', locations || ''],
    ['nuni_info_phone', phone || ''],
    ['nuni_info_email', email || ''],
  ];
  for (const [key, value] of pairs) {
    await db.run(
      `INSERT INTO app_settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, value],
    );
  }
  res.json({ message: 'Informations NUNI enregistrées.' });
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
           u.requested_duration_days,
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

// ================= REVERSEMENTS ARTISTES (royalties) =================
// Principe central, jamais dévié : tracks.streams (les streams publics — profil, classements,
// pages morceaux) n'est JAMAIS modifié par ce module, nulle part. Le "compteur de période"
// n'est pas une valeur stockée à réinitialiser (risque de désync) : c'est un calcul dérivé —
// total_streams actuel moins la somme des streams déjà couverts par un paiement passé
// (payment_history.streams_covered). Payer un artiste ne fait qu'ajouter une ligne à
// l'historique ; les vrais streams publics ne bougent jamais.

app.get('/api/admin/royalty-settings', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  res.json(await getRoyaltySettings());
}));

app.put('/api/admin/royalty-settings', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { price_per_stream_fcfa, artist_share_pct } = req.body;
  if (price_per_stream_fcfa != null) {
    const p = Number(price_per_stream_fcfa);
    if (!(p > 0)) return res.status(400).json({ error: 'Le prix par stream doit être positif.' });
    await setRoyaltySetting('royalty_price_per_stream_fcfa', p);
  }
  if (artist_share_pct != null) {
    const pct = Number(artist_share_pct);
    if (!(pct > 0 && pct <= 100)) return res.status(400).json({ error: 'Le pourcentage artiste doit être entre 1 et 100.' });
    await setRoyaltySetting('royalty_artist_share_pct', pct);
  }
  res.json({ message: 'Taux de reversement mis à jour.', settings: await getRoyaltySettings() });
}));

// ============================================================
// MOTEUR DE COLLABORATIONS — couche strictement additive au-dessus du paiement
// existant. N'appelle JAMAIS computeArtistPayout() en interne et n'en modifie
// jamais le résultat — elle se contente de calculer une déduction à appliquer
// à côté, dans la même transaction que le paiement de l'artiste principal.
// ============================================================
class CollaborationValidationError extends Error {}

// Petit helper d'audit — utilisé par tous les endpoints sensibles de ce système.
async function logCollabAudit(entityType, entityId, action, actorId, beforeObj, afterObj) {
  try {
    await db.run(
      `INSERT INTO collab_audit_log (entity_type, entity_id, action, actor_id, before_json, after_json)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [entityType, entityId, action, actorId || null, beforeObj ? JSON.stringify(beforeObj) : null, afterObj ? JSON.stringify(afterObj) : null],
    );
  } catch (e) { console.error('[collab_audit_log] échec (non bloquant) :', e.message); }
}

// ---------- Ajouter un collaborateur sur un morceau — réservé à l'artiste principal
// (tracks.artist_id) uniquement. Crée toujours un accord en 'pending' : aucune part
// n'est jamais considérée acceptée sur simple déclaration. ----------
// Fonction partagée — réutilisée par POST /api/tracks/:id/collaborators ET par la
// publication elle-même (POST /api/tracks, qui accepte un tableau `collaborators`).
// Ne jamais dupliquer cette logique de validation à deux endroits différents.
async function addCollaboratorToTrack(track, requesterId, body) {
  const {
    collaboratorArtistId, externalName, externalContact, role,
    paymentType, upfrontAmountFcfa, masterPct, publishingPct, agreementNotes,
  } = body || {};

  if (!collaboratorArtistId && !externalName) {
    return { error: 'Indiquez soit un compte NUNI existant, soit un nom externe.', status: 400 };
  }
  if (!['featured', 'co-artist', 'producer', 'composer', 'label'].includes(role)) {
    return { error: 'Rôle invalide.', status: 400 };
  }
  if (!['forfait', 'avance_recoupable', 'royalties', 'forfait_et_royalties', 'aucun_paiement', 'autre'].includes(paymentType)) {
    return { error: "Type d'accord invalide.", status: 400 };
  }
  const hasMaster = masterPct !== null && masterPct !== undefined && masterPct !== '';
  const hasPublishing = publishingPct !== null && publishingPct !== undefined && publishingPct !== '';
  if (!hasMaster && !hasPublishing) {
    return { error: 'Indiquez au moins une part (master ou publishing), même 0%.', status: 400 };
  }
  for (const [label, val] of [['master', masterPct], ['publishing', publishingPct]]) {
    if (val === null || val === undefined || val === '') continue;
    const n = Number(val);
    if (Number.isNaN(n) || n < 0) return { error: `Le pourcentage ${label} ne peut pas être négatif.`, status: 400 };
    if (n > 100) return { error: `Le pourcentage ${label} ne peut pas dépasser 100%.`, status: 400 };
  }
  if (upfrontAmountFcfa !== null && upfrontAmountFcfa !== undefined && upfrontAmountFcfa !== '' && Number(upfrontAmountFcfa) < 0) {
    return { error: 'Le montant ne peut pas être négatif.', status: 400 };
  }
  if ((paymentType === 'avance_recoupable') && (!upfrontAmountFcfa || Number(upfrontAmountFcfa) <= 0)) {
    return { error: 'Une avance recoupable exige un montant supérieur à 0.', status: 400 };
  }
  if ((paymentType === 'royalties' || paymentType === 'forfait_et_royalties')
    && (!hasMaster || Number(masterPct) <= 0) && (!hasPublishing || Number(publishingPct) <= 0)) {
    return { error: 'Un accord en royalties exige au moins une part (master ou publishing) supérieure à 0%.', status: 400 };
  }
  if (collaboratorArtistId) {
    const exists = await db.get('SELECT id FROM users WHERE id = $1', [Number(collaboratorArtistId)]);
    if (!exists) return { error: 'Compte artiste introuvable.', status: 404 };
  }
  for (const [rightsType, pct] of [['master', masterPct], ['publishing', publishingPct]]) {
    if (pct === null || pct === undefined || pct === '') continue;
    const existingRow = await db.get(
      `SELECT COALESCE(SUM(ct.share_pct),0) AS total
       FROM collaboration_terms ct
       JOIN track_collaborators tc ON tc.id = ct.collaborator_id
       WHERE tc.track_id = $1 AND tc.role != 'primary' AND ct.rights_type = $2
         AND ct.status = 'accepted' AND ct.effective_until IS NULL`,
      [track.id, rightsType],
    );
    const projectedTotal = Number(existingRow.total) + Number(pct);
    if (projectedTotal > 100) {
      return { error: `Total des parts ${rightsType} incohérent : ${existingRow.total}% déjà accepté(s) + ${pct}% proposé(s) = ${projectedTotal}% (> 100%).`, status: 409 };
    }
  }

  const collab = await db.get(
    `INSERT INTO track_collaborators (track_id, artist_id, external_name, external_contact, role, added_by)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [track.id, collaboratorArtistId || null, externalName || null, externalContact || null, role, requesterId],
  );
  const createdTermsIds = [];
  for (const [rightsType, pct] of [['master', masterPct], ['publishing', publishingPct]]) {
    if (pct === null || pct === undefined || pct === '') continue;
    const terms = await db.get(
      `INSERT INTO collaboration_terms
         (collaborator_id, rights_type, payment_type, upfront_amount_fcfa, share_pct, agreement_notes, status, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,'pending',$7) RETURNING id`,
      [collab.id, rightsType, paymentType, upfrontAmountFcfa || null, Number(pct), agreementNotes || null, requesterId],
    );
    createdTermsIds.push(terms.id);
    await logCollabAudit('collaboration_terms', terms.id, 'created', requesterId, null, {
      trackId: track.id, role, rightsType, paymentType, upfrontAmountFcfa, sharePct: Number(pct),
    });
  }

  if (collaboratorArtistId) {
    const requester = await db.get('SELECT artist_name, first_name FROM users WHERE id = $1', [requesterId]);
    const requesterName = requester.artist_name || requester.first_name || 'Un artiste';
    createNotification(
      Number(collaboratorArtistId), 'collaboration_request', 'Demande de collaboration',
      `${requesterName} vous propose une collaboration (${role}) sur "${track.title}" — votre confirmation est requise.`,
      `/collab:${collab.id}`,
    ).catch(() => {});
  }
  return { collaboratorId: collab.id, termsIds: createdTermsIds, status: 201 };
}

app.post('/api/tracks/:id/collaborators', authMiddleware, h(async (req, res) => {
  const trackId = Number(req.params.id);
  const track = await db.get('SELECT id, artist_id, title FROM tracks WHERE id = $1', [trackId]);
  if (!track) return res.status(404).json({ error: 'Morceau introuvable.' });
  if (track.artist_id !== req.user.id) {
    return res.status(403).json({ error: "Seul l'artiste principal de ce morceau peut y ajouter un collaborateur." });
  }
  const result = await addCollaboratorToTrack(track, req.user.id, req.body);
  const { status, ...body } = result;
  res.status(status).json(body);
}));

// ---------- Le collaborateur répond à une proposition — accepted / disputed / rejected.
// Seul le vrai compte concerné (track_collaborators.artist_id) peut répondre, jamais
// l'artiste principal à sa place. ----------
app.post('/api/collaboration-terms/:id/respond', authMiddleware, h(async (req, res) => {
  const termsId = Number(req.params.id);
  const { status, disputeReason } = req.body || {};
  if (!['accepted', 'disputed', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Statut invalide.' });
  }
  if (status === 'disputed' && !disputeReason) {
    return res.status(400).json({ error: 'Un motif est requis pour contester un accord.' });
  }
  const row = await db.get(
    `SELECT ct.*, tc.artist_id AS collaborator_artist_id
     FROM collaboration_terms ct JOIN track_collaborators tc ON tc.id = ct.collaborator_id
     WHERE ct.id = $1`,
    [termsId],
  );
  if (!row) return res.status(404).json({ error: 'Accord introuvable.' });
  if (row.collaborator_artist_id !== req.user.id) {
    return res.status(403).json({ error: "Vous n'êtes pas le collaborateur concerné par cet accord." });
  }
  if (row.effective_until) {
    return res.status(409).json({ error: 'Cette version de l\'accord n\'est plus active.' });
  }
  // Une fois accepté ou refusé, la décision est définitive via cet endpoint — jamais une
  // deuxième acceptation, jamais un refus retourné en acceptation. Seule une contestation
  // reste modifiable (peut être levée après discussion, voir le workflow C3).
  if (row.status === 'accepted') {
    return res.status(409).json({ error: 'Vous avez déjà accepté cet accord.' });
  }
  if (row.status === 'rejected') {
    return res.status(409).json({ error: 'Cet accord a déjà été refusé — impossible de revenir en arrière ici.' });
  }
  const before = { status: row.status };
  await db.run('UPDATE collaboration_terms SET status = $1 WHERE id = $2', [status, termsId]);
  await logCollabAudit('collaboration_terms', termsId, 'status_changed', req.user.id, before, { status });

  if (status === 'disputed') {
    await db.run(
      `INSERT INTO collaboration_disputes (collaboration_terms_id, raised_by, reason) VALUES ($1,$2,$3)`,
      [termsId, req.user.id, disputeReason],
    );
  }
  res.json({ ok: true, status });
}));

// ---------- Liste des collaborateurs d'un morceau — pour affichage crédits/catalogue.
// Renvoie les vraies données, jamais une part supposée pour un accord non confirmé. ----------
app.get('/api/tracks/:id/collaborators', h(async (req, res) => {
  const rows = await db.query(`
    SELECT tc.id AS collaborator_id, tc.role, tc.external_name,
      u.id AS artist_id, u.artist_name, u.first_name,
      ct.id AS terms_id, ct.rights_type, ct.payment_type, ct.share_pct, ct.status
    FROM track_collaborators tc
    LEFT JOIN users u ON u.id = tc.artist_id
    LEFT JOIN collaboration_terms ct ON ct.collaborator_id = tc.id AND ct.effective_until IS NULL
    WHERE tc.track_id = $1
    ORDER BY (tc.role = 'primary') DESC, tc.created_at ASC
  `, [Number(req.params.id)]);
  res.json({ collaborators: rows });
}));

// ---------- C2 — détail complet d'une proposition de collaboration. Réservé au vrai
// collaborateur concerné (jamais un tiers, jamais l'artiste principal qui pourrait vouloir
// vérifier). Regroupe master + publishing pour la même personne, jamais deux écrans
// séparés pour un même accord. ----------
app.get('/api/track-collaborators/:id/detail', authMiddleware, h(async (req, res) => {
  const collaboratorId = Number(req.params.id);
  const tc = await db.get(
    `SELECT tc.*, t.title AS track_title, t.cover_url, t.artist_id AS primary_artist_id,
       pu.artist_name AS primary_artist_name, pu.first_name AS primary_first_name
     FROM track_collaborators tc
     JOIN tracks t ON t.id = tc.track_id
     JOIN users pu ON pu.id = t.artist_id
     WHERE tc.id = $1`,
    [collaboratorId],
  );
  if (!tc) return res.status(404).json({ error: 'Proposition introuvable.' });
  if (tc.artist_id !== req.user.id) {
    return res.status(403).json({ error: "Cette proposition ne vous est pas destinée." });
  }
  const terms = await db.query(
    `SELECT id, rights_type, payment_type, upfront_amount_fcfa, share_pct, agreement_notes, status, effective_from
     FROM collaboration_terms WHERE collaborator_id = $1 AND effective_until IS NULL`,
    [collaboratorId],
  );
  const documents = await db.query(
    `SELECT id, file_url, note, is_legally_binding, uploaded_at FROM collaboration_documents WHERE collaborator_id = $1`,
    [collaboratorId],
  );
  const disputes = await db.query(
    `SELECT cd.reason, cd.status, cd.opened_at FROM collaboration_disputes cd
     WHERE cd.collaboration_terms_id = ANY($1::int[]) ORDER BY cd.opened_at DESC`,
    [terms.map(t => t.id)],
  );
  res.json({
    collaboratorId, role: tc.role,
    track: { id: tc.track_id, title: tc.track_title, coverUrl: tc.cover_url },
    primaryArtist: { id: tc.primary_artist_id, name: tc.primary_artist_name || tc.primary_first_name },
    terms, documents, disputes,
  });
}));

// ============================================================
// ADMIN — écrans N1 (file d'attente) / N2 (résolution) du système de
// collaborations. Réservés à l'équipe NUNI (checkAdminKey, comme le
// reste de l'admin existant). NUNI utilise une clé admin partagée (pas
// de comptes admin individuels) — actor_id reste donc NULL dans l'audit
// pour ces actions, jamais une valeur inventée dans une colonne qui
// référence de vrais utilisateurs.
// ============================================================

// ---- N1 — file des payouts en attente/litige, avec tout le contexte nécessaire pour
// décider (gross_share_fcfa, période, morceau, motif) sans jamais recalculer quoi que ce soit.
app.get('/api/admin/collaboration-disputes', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query(`
    SELECT cp.id AS payout_id, cp.status, cp.gross_share_fcfa, cp.recoupment_applied_fcfa, cp.net_payable_fcfa, cp.held_reason,
      trp.track_id, trp.period_start, trp.period_end,
      ct.id AS terms_id, ct.rights_type, ct.payment_type, ct.share_pct, ct.status AS terms_status,
      t.title AS track_title,
      collabU.id AS collaborator_artist_id, collabU.artist_name AS collaborator_artist_name, collabU.first_name AS collaborator_first_name,
      tc.external_name,
      cd.reason AS dispute_reason, cd.opened_at AS dispute_opened_at
    FROM collaborator_payouts cp
    JOIN track_revenue_periods trp ON trp.id = cp.revenue_period_id
    JOIN collaboration_terms ct ON ct.id = cp.collaboration_terms_id
    JOIN track_collaborators tc ON tc.id = cp.collaborator_id
    JOIN tracks t ON t.id = trp.track_id
    LEFT JOIN users collabU ON collabU.id = tc.artist_id
    LEFT JOIN collaboration_disputes cd ON cd.collaboration_terms_id = ct.id AND cd.status = 'open'
    WHERE cp.status IN ('held_dispute', 'held_pending')
    ORDER BY cp.created_at ASC
  `);
  res.json({ items: rows });
}));

// ---- N2a — Libérer : le montant gross_share_fcfa déjà enregistré n'est jamais recalculé,
// seul le statut change (-> payable).
app.post('/api/admin/collaborator-payouts/:id/release', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const payoutId = Number(req.params.id);
  const { note } = req.body || {};
  const payout = await db.get('SELECT * FROM collaborator_payouts WHERE id = $1', [payoutId]);
  if (!payout) return res.status(404).json({ error: 'Payout introuvable.' });
  if (payout.status === 'paid') return res.status(409).json({ error: 'Ce payout a déjà été payé — irréversible.' });
  await db.run(`UPDATE collaborator_payouts SET status = 'payable', held_reason = NULL WHERE id = $1`, [payoutId]);
  await logCollabAudit('collaborator_payouts', payoutId, 'released', null, { status: payout.status }, { status: 'payable', note: note || null });
  res.json({ ok: true });
}));

// ---- N2b — Ajuster : ne modifie JAMAIS le montant original. Crée une ligne
// payout_adjustments append-only, motif obligatoire, document optionnel.
app.post('/api/admin/collaborator-payouts/:id/adjust', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const payoutId = Number(req.params.id);
  const { amountFcfa, reason, documentUrl } = req.body || {};
  if (!reason || !reason.trim()) return res.status(400).json({ error: 'Un motif est obligatoire pour tout ajustement.' });
  if (amountFcfa === undefined || amountFcfa === null || Number.isNaN(Number(amountFcfa))) {
    return res.status(400).json({ error: 'Montant d\'ajustement invalide.' });
  }
  const payout = await db.get('SELECT * FROM collaborator_payouts WHERE id = $1', [payoutId]);
  if (!payout) return res.status(404).json({ error: 'Payout introuvable.' });

  const adjustment = await db.get(
    `INSERT INTO payout_adjustments (original_payout_id, amount_fcfa, reason, document_url, created_by)
     VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [payoutId, Number(amountFcfa), reason.trim(), documentUrl || null, req.user ? req.user.id : null],
  );
  await logCollabAudit('payout_adjustments', adjustment.id, 'created', null, null, {
    originalPayoutId: payoutId,
    originalAmountFcfa: Number(payout.net_payable_fcfa),
    adjustmentAmountFcfa: Number(amountFcfa),
    newAmountFcfa: Number(payout.net_payable_fcfa) + Number(amountFcfa),
    reason: reason.trim(),
  });
  res.json({
    ok: true,
    adjustmentId: adjustment.id,
    originalAmountFcfa: Number(payout.net_payable_fcfa),
    adjustmentAmountFcfa: Number(amountFcfa),
    newAmountFcfa: Number(payout.net_payable_fcfa) + Number(amountFcfa),
  });
}));

// ---- N2c — Rejet définitif : la contestation est tranchée en défaveur du collaborateur,
// son accord passe à rejected — plus aucun droit actif, jamais de suppression de l'historique.
app.post('/api/admin/collaboration-terms/:id/final-reject', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const termsId = Number(req.params.id);
  const { reason } = req.body || {};
  if (!reason || !reason.trim()) return res.status(400).json({ error: 'Un motif est obligatoire pour un rejet définitif.' });
  const terms = await db.get('SELECT * FROM collaboration_terms WHERE id = $1', [termsId]);
  if (!terms) return res.status(404).json({ error: 'Accord introuvable.' });
  await db.run(`UPDATE collaboration_terms SET status = 'rejected' WHERE id = $1`, [termsId]);
  await db.run(
    `UPDATE collaboration_disputes SET status = 'resolved', resolution_note = $1, resolved_at = NOW()
     WHERE collaboration_terms_id = $2 AND status = 'open'`,
    [reason.trim(), termsId],
  );
  await logCollabAudit('collaboration_terms', termsId, 'final_rejected', null, { status: terms.status }, { status: 'rejected', reason: reason.trim() });
  res.json({ ok: true });
}));

// ---- N2d — Résoudre le litige : distinct de "release" (qui ne débloque qu'une période
// précise sans jamais rien dire sur le litige lui-même) et de "final-reject" (qui tranche en
// défaveur du collaborateur). Ici, le litige est tranché EN FAVEUR de l'accord original :
// l'accord redevient accepted, le litige est officiellement refermé, et — pour éviter d'avoir
// à libérer chaque période une par une après coup — toutes les périodes déjà gelées par CE
// litige précis (held_dispute) sont libérées en une fois. gross_share_fcfa n'est jamais
// modifié, seul le statut change, exactement comme le fait "release" pour une période isolée.
app.post('/api/admin/collaboration-terms/:id/resolve-dispute', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const termsId = Number(req.params.id);
  const { resolutionNote } = req.body || {};
  if (!resolutionNote || !resolutionNote.trim()) return res.status(400).json({ error: 'Un motif de résolution est obligatoire.' });
  const terms = await db.get('SELECT * FROM collaboration_terms WHERE id = $1', [termsId]);
  if (!terms) return res.status(404).json({ error: 'Accord introuvable.' });
  // Bloque nativement une double résolution : une fois status='accepted', un deuxième appel
  // échoue ici — jamais besoin d'un verrou supplémentaire pour ce cas précis.
  if (terms.status !== 'disputed') {
    return res.status(409).json({ error: "Cet accord n'est pas actuellement en litige." });
  }
  await db.run(`UPDATE collaboration_terms SET status = 'accepted' WHERE id = $1`, [termsId]);
  const releasedRows = await db.query(
    `UPDATE collaborator_payouts SET status = 'payable', held_reason = NULL
     WHERE collaboration_terms_id = $1 AND status = 'held_dispute' RETURNING id, gross_share_fcfa`,
    [termsId],
  );
  await db.run(
    `UPDATE collaboration_disputes SET status = 'resolved', resolution_note = $1, resolved_at = NOW()
     WHERE collaboration_terms_id = $2 AND status = 'open'`,
    [resolutionNote.trim(), termsId],
  );
  await logCollabAudit('collaboration_terms', termsId, 'dispute_resolved', null, { status: 'disputed' }, {
    status: 'accepted', resolutionNote: resolutionNote.trim(), releasedPayoutIds: releasedRows.map(r => r.id),
  });
  res.json({ ok: true, releasedPayoutsCount: releasedRows.length });
}));

async function applyCollaborationSplits(client, artistId, settings) {
  const tracksWithCollab = await client.query(`
    SELECT DISTINCT t.id AS track_id
    FROM tracks t
    JOIN track_collaborators tc ON tc.track_id = t.id
    JOIN collaboration_terms ct ON ct.collaborator_id = tc.id AND ct.effective_until IS NULL
    WHERE t.artist_id = $1 AND tc.role != 'primary'
      AND ct.rights_type IN ('master','both')
  `, [artistId]);

  let totalDeductionFcfa = 0;
  const createdPayoutIds = [];

  for (const row of tracksWithCollab.rows) {
    const trackId = row.track_id;

    const terms = (await client.query(`
      SELECT ct.*, tc.id AS collaborator_id
      FROM collaboration_terms ct
      JOIN track_collaborators tc ON tc.id = ct.collaborator_id
      WHERE tc.track_id = $1 AND ct.effective_until IS NULL
        AND tc.role != 'primary' AND ct.rights_type IN ('master','both')
    `, [trackId])).rows;
    if (!terms.length) continue;

    // Garde-fou absolu : jamais plus de 100% de parts acceptées sur un même morceau.
    const acceptedPctSum = terms
      .filter(t => t.status === 'accepted')
      .reduce((sum, t) => sum + Number(t.share_pct || 0), 0);
    if (acceptedPctSum > 100) {
      throw new CollaborationValidationError(
        `Morceau #${trackId} : parts acceptées totalisant ${acceptedPctSum}% (> 100%). Paiement bloqué — à corriger avant tout versement.`,
      );
    }

    const lastPeriod = await client.query(
      `SELECT period_end FROM track_revenue_periods WHERE track_id = $1 ORDER BY period_end DESC LIMIT 1`,
      [trackId],
    );
    const lastPeriodEnd = lastPeriod.rows[0] ? lastPeriod.rows[0].period_end : null;

    for (const term of terms) {
      const windowStart = (lastPeriodEnd && lastPeriodEnd > term.effective_from) ? lastPeriodEnd : term.effective_from;

      const streamsRow = await client.query(
        `SELECT COUNT(*)::int AS c FROM plays WHERE track_id = $1 AND created_at >= $2 AND created_at < NOW()`,
        [trackId, windowStart],
      );
      const streamsInWindow = streamsRow.rows[0].c;
      if (streamsInWindow <= 0) continue;

      const revenuePeriodFcfa = Math.round(streamsInWindow * settings.price_per_stream_fcfa);

      const periodRow = await client.query(
        `INSERT INTO track_revenue_periods (track_id, period_start, period_end, streams_in_period, revenue_fcfa_total)
         VALUES ($1, $2, NOW(), $3, $4) RETURNING id`,
        [trackId, windowStart, streamsInWindow, revenuePeriodFcfa],
      );
      const revenuePeriodId = periodRow.rows[0].id;

      if (term.status === 'rejected') continue;
      if (term.payment_type === 'forfait' || term.payment_type === 'aucun_paiement') continue;

      const grossShareFcfa = Math.round(revenuePeriodFcfa * Number(term.share_pct || 0) / 100);
      if (grossShareFcfa <= 0) continue;

      let recoupmentAppliedFcfa = 0;
      let netPayableFcfa = grossShareFcfa;
      if (term.payment_type === 'avance_recoupable') {
        const recoupedSoFar = await client.query(
          `SELECT COALESCE(SUM(recoupment_applied_fcfa),0)::numeric AS s FROM collaborator_payouts WHERE collaboration_terms_id = $1`,
          [term.id],
        );
        const remainingBalance = Math.max(0, Number(term.upfront_amount_fcfa || 0) - Number(recoupedSoFar.rows[0].s));
        recoupmentAppliedFcfa = Math.min(grossShareFcfa, remainingBalance);
        netPayableFcfa = grossShareFcfa - recoupmentAppliedFcfa;
      }

      totalDeductionFcfa += grossShareFcfa;

      let payoutStatus = 'payable';
      let heldReason = null;
      if (term.status === 'disputed') { payoutStatus = 'held_dispute'; heldReason = 'Accord contesté par le collaborateur.'; }
      else if (term.status === 'pending') { payoutStatus = 'held_pending'; heldReason = 'En attente de confirmation du collaborateur.'; }

      const payoutRow = await client.query(
        `INSERT INTO collaborator_payouts
           (revenue_period_id, collaborator_id, collaboration_terms_id, gross_share_fcfa, recoupment_applied_fcfa, net_payable_fcfa, status, held_reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (revenue_period_id, collaboration_terms_id) DO NOTHING
         RETURNING id`,
        [revenuePeriodId, term.collaborator_id, term.id, grossShareFcfa, recoupmentAppliedFcfa, netPayableFcfa, payoutStatus, heldReason],
      );
      if (payoutRow.rows[0]) createdPayoutIds.push(payoutRow.rows[0].id);
    }
  }

  return { totalDeductionFcfa, createdPayoutIds };
}

// Calcule pour un artiste : streams déjà payés (somme de l'historique), streams de la
// période en cours (dérivé, jamais stocké), montant dû, date du dernier paiement.
async function computeArtistPayout(artistId, settings) {
  const totalStreamsRow = await db.get(
    'SELECT COALESCE(SUM(streams), 0)::int as c FROM tracks WHERE artist_id = $1', [artistId],
  );
  const paidRow = await db.get(
    'SELECT COALESCE(SUM(streams_covered), 0)::int as c, MAX(paid_at)::text as last_paid FROM (SELECT streams_covered, period_end as paid_at FROM payment_history WHERE artist_id = $1) x',
    [artistId],
  );
  const totalStreams = totalStreamsRow.c;
  const alreadyPaidStreams = paidRow.c;
  const currentPeriodStreams = Math.max(0, totalStreams - alreadyPaidStreams);
  const amountDueFcfa = Math.round(currentPeriodStreams * settings.price_per_stream_fcfa * settings.artist_share_pct / 100);
  return {
    total_streams: totalStreams,
    current_period_streams: currentPeriodStreams,
    amount_due_fcfa: amountDueFcfa,
    last_payment_at: paidRow.last_paid || null,
    status: currentPeriodStreams === 0 ? 'à jour' : (amountDueFcfa > 0 ? 'prêt à payer' : 'en attente'),
  };
}

app.get('/api/admin/artist-payouts', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const settings = await getRoyaltySettings();
  const artists = await db.query(`
    SELECT u.id, u.artist_name, u.first_name, u.email, u.account_status
    FROM users u WHERE u.account_type = 'artist'
    ORDER BY u.artist_name ASC NULLS LAST, u.first_name ASC
  `);
  const payouts = [];
  for (const a of artists) {
    const p = await computeArtistPayout(a.id, settings);
    payouts.push({
      id: a.id, pseudo: a.artist_name || a.first_name, real_name: `${a.first_name}`, email: a.email,
      account_status: a.account_status, ...p,
    });
  }
  payouts.sort((x, y) => y.amount_due_fcfa - x.amount_due_fcfa);
  const totalDueFcfa = payouts.reduce((sum, p) => sum + p.amount_due_fcfa, 0);
  res.json({ payouts, total_due_fcfa: totalDueFcfa, ...settings });
}));

app.get('/api/admin/artist-payouts/:artistId/history', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query(
    'SELECT id, amount_fcfa, streams_covered, period_start, period_end, method, reference, note, created_at FROM payment_history WHERE artist_id = $1 ORDER BY created_at DESC',
    [Number(req.params.artistId)],
  );
  res.json({ history: rows });
}));

// Enregistre un vrai versement — ne touche jamais tracks.streams. Envoie un email à
// l'artiste pour trace écrite, jamais bloquant si l'email échoue.
//
// Depuis l'ajout du système de collaborations : toute la logique de paiement (principal
// + collaborateurs) tourne dans UNE SEULE transaction avec verrou — soit tout est
// enregistré ensemble, soit rien ne l'est. computeArtistPayout() reste appelée telle
// quelle et n'est jamais modifiée ; la déduction des parts collaborateurs est appliquée
// séparément, juste avant l'écriture de payment_history.
app.post('/api/admin/artist-payouts/:artistId/pay', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const artistId = Number(req.params.artistId);
  const artist = await db.get('SELECT * FROM users WHERE id = $1 AND account_type = $2', [artistId, 'artist']);
  if (!artist) return res.status(404).json({ error: 'Artiste introuvable.' });

  const settings = await getRoyaltySettings();
  const { method, reference, note } = req.body || {};

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    // Verrou : empêche deux admins (ou un double clic) de payer cet artiste en même temps.
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [artistId]);

    const p = await computeArtistPayout(artistId, settings); // INCHANGÉE, appelée telle quelle
    if (p.current_period_streams <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: "Aucun stream en attente de paiement pour cet artiste." });
    }

    let collabResult;
    try {
      collabResult = await applyCollaborationSplits(client, artistId, settings);
    } catch (e) {
      await client.query('ROLLBACK');
      if (e instanceof CollaborationValidationError) {
        return res.status(409).json({ error: e.message });
      }
      throw e;
    }

    const netAmountFcfa = Math.max(0, p.amount_due_fcfa - collabResult.totalDeductionFcfa);

    const lastPaymentRow = await client.query(
      'SELECT period_end FROM payment_history WHERE artist_id = $1 ORDER BY created_at DESC LIMIT 1', [artistId],
    );
    const lastPayment = lastPaymentRow.rows[0];
    const insertedRow = await client.query(
      `INSERT INTO payment_history (artist_id, amount_fcfa, streams_covered, period_start, period_end, method, reference, note)
       VALUES ($1,$2,$3,$4,NOW(),$5,$6,$7) RETURNING id`,
      [artistId, netAmountFcfa, p.current_period_streams, lastPayment ? lastPayment.period_end : artist.created_at,
        method || 'Manuel', reference || null, note || null],
    );
    const inserted = insertedRow.rows[0];

    await client.query('COMMIT');

    sendArtistPaymentEmail({
      user: artist, amountFcfa: netAmountFcfa, streamsCovered: p.current_period_streams,
      periodStart: lastPayment ? lastPayment.period_end : artist.created_at, periodEnd: new Date(),
    }).catch((e) => console.error('[artist-payouts] échec envoi email de versement :', e.message));

    // Notification "paiement reçu" pour le Label, si cet artiste lui est affilié.
    db.get(
      "SELECT l.user_id, l.label_name FROM label_artists la JOIN labels l ON l.id = la.label_id WHERE la.artist_id = $1 AND la.status = 'active' LIMIT 1",
      [artistId],
    ).then((row) => {
      if (row) createNotification(row.user_id, 'label_payment_received', 'Paiement reçu', `${artist.artist_name || artist.first_name} a reçu un versement de ${netAmountFcfa.toLocaleString('fr-FR')} FCFA.`, null).catch(() => {});
    }).catch(() => {});

    res.json({
      message: `Versement de ${netAmountFcfa.toLocaleString('fr-FR')} FCFA enregistré pour ${artist.artist_name || artist.first_name}.`,
      payment_id: inserted.id,
      gross_amount_fcfa: p.amount_due_fcfa,
      collaborators_deduction_fcfa: collabResult.totalDeductionFcfa,
      net_amount_fcfa: netAmountFcfa,
      collaborator_payouts_created: collabResult.createdPayoutIds.length,
    });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) { /* déjà annulée ou connexion perdue */ }
    console.error('[artist-payouts/pay] erreur, transaction annulée :', e.message);
    res.status(500).json({ error: "Erreur lors de l'enregistrement du paiement — aucune donnée n'a été modifiée." });
  } finally {
    client.release(); // toujours libérer la connexion, succès comme échec
  }
}));

// ---------- Côté artiste : son propre statut de paiement et son propre historique ----------
app.get('/api/artist/payment-status', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const settings = await getRoyaltySettings();
  const p = await computeArtistPayout(req.user.id, settings);
  res.json({ ...p, price_per_stream_fcfa: settings.price_per_stream_fcfa, artist_share_pct: settings.artist_share_pct });
}));

app.get('/api/artist/payment-history', authMiddleware, h(async (req, res) => {
  if (req.user.accountType !== 'artist') return res.status(403).json({ error: 'Réservé aux comptes Artiste.' });
  const rows = await db.query(
    'SELECT amount_fcfa, streams_covered, period_start, period_end, method, created_at FROM payment_history WHERE artist_id = $1 ORDER BY created_at DESC',
    [req.user.id],
  );
  res.json({ history: rows });
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
    await client.query('DELETE FROM payment_history WHERE artist_id = $1', [userId]);
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
    // Concerts créés par cet artiste, et cosmétiques de gamification équipés par ce compte —
    // même souci d'absence de CASCADE, oubliés jusqu'ici.
    await client.query('DELETE FROM concerts WHERE artist_id = $1', [userId]);
    await client.query('DELETE FROM user_equipped_cosmetics WHERE user_id = $1', [userId]);
    // Notifications reçues (la table a bien ON DELETE CASCADE sur user_id, mais autant être
    // explicite ici plutôt que de dépendre uniquement du comportement du schéma).
    await client.query('DELETE FROM notifications WHERE user_id = $1', [userId]);
    // Signalements faits PAR ce compte — oublié jusqu'ici, même bug déjà corrigé pour
    // talent_votes/challenge_progress/shop_purchases (violation de clé étrangère → crash 500).
    // Note : ceux REÇUS sur les morceaux de ce compte sont déjà couverts par le CASCADE de
    // track_reports.track_id quand ses morceaux sont supprimés juste après.
    await client.query('DELETE FROM track_reports WHERE reporter_id = $1', [userId]);
    // Rattachements Label — un artiste affilié à un Label, ou un membre de l'équipe d'un
    // Label, faisait planter la suppression faute de nettoyage de ces deux tables (aucune
    // des deux n'a de ON DELETE CASCADE vers users, contrairement à label_id → labels).
    await client.query('DELETE FROM label_artists WHERE artist_id = $1', [userId]);
    await client.query('DELETE FROM label_team_members WHERE user_id = $1', [userId]);
    // Si ce compte est lui-même un Label (labels.user_id), sa fiche Label doit être
    // supprimée avant lui — même souci d'absence de CASCADE. label_artists/label_team_members
    // de CE label sont déjà nettoyés par leur propre ON DELETE CASCADE vers labels.id.
    await client.query('DELETE FROM labels WHERE user_id = $1', [userId]);
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
  const { code, discount_pct, applies_to_plan, max_uses, expires_at, assigned_to_email, note, notify } = req.body;
  if (!code || !discount_pct) return res.status(400).json({ error: 'Le code et le pourcentage de réduction sont obligatoires.' });
  // Garde-fou contre une erreur de frappe (ex: "500" au lieu de "50") qui donnerait un prix
  // négatif une fois appliqué — aucune vraie utilité commerciale à un code >100% ou négatif.
  const pct = Number(discount_pct);
  if (!(pct > 0 && pct <= 100)) {
    return res.status(400).json({ error: 'Le pourcentage de réduction doit être compris entre 1 et 100.' });
  }
  // Code personnel : réservé à un seul compte (récompense pour un consommateur actif dans
  // les défis, ou un artiste) — on résout l'email en vrai ID utilisateur tout de suite,
  // jamais stocké comme simple texte libre (garantit que le compte existe vraiment).
  let assignedUserId = null;
  if (assigned_to_email) {
    const targetUser = await db.get('SELECT id, first_name, email FROM users WHERE LOWER(email) = LOWER($1)', [String(assigned_to_email).trim()]);
    if (!targetUser) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
    assignedUserId = targetUser.id;
  }
  const cleanCode = String(code).toUpperCase().trim();
  try {
    await db.run(`
      INSERT INTO promo_codes (code, discount_pct, applies_to_plan, max_uses, expires_at, assigned_to_user_id, note)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
    `, [
      cleanCode, pct, applies_to_plan || null,
      Number(max_uses) || 1, expires_at || null, assignedUserId, note || null,
    ]);
  } catch (e) {
    return res.status(400).json({ error: 'Ce code existe déjà.' });
  }

  // ---------- Notification automatique du/des bénéficiaire(s) (brique Communication) ----------
  // notify est vrai par défaut côté formulaire admin.html, mais reste désactivable (ex: import
  // en masse de codes de test). Réutilise le même chemin que les notifications manuelles :
  // createNotification pour chaque destinataire réel, plus une ligne dans admin_broadcasts
  // pour que ça remonte aussi dans l'historique des envois.
  let recipientCount = 0;
  if (notify !== false) {
    const title = `🎁 Nouveau code promo : ${cleanCode}`;
    const body = `Profitez de ${pct}% de réduction${note ? ' — ' + note : ''}.`;
    let targetIds = [];
    let audienceLabel;
    if (assignedUserId) {
      targetIds = [assignedUserId];
      audienceLabel = assigned_to_email;
    } else {
      const planTypes = applies_to_plan ? [applies_to_plan] : ['artist', 'consumer'];
      const rows = await db.query('SELECT id FROM users WHERE account_type = ANY($1)', [planTypes]);
      targetIds = rows.map((r) => r.id);
      audienceLabel = applies_to_plan || 'artist+consumer';
    }
    for (const userId of targetIds) {
      await createNotification(userId, 'promo_code', title, body, '/pass');
    }
    recipientCount = targetIds.length;
    if (recipientCount > 0) {
      await db.run(
        `INSERT INTO admin_broadcasts (title, body, link, audience, recipient_count) VALUES ($1,$2,$3,$4,$5)`,
        [title, body, '/pass', audienceLabel, recipientCount],
      );
    }
  }

  res.json({
    message: assignedUserId ? 'Code promo personnel créé et attribué.' : 'Code promo créé.',
    notified_count: recipientCount,
  });
}));

// ---------- Codes promo personnels — vus par l'utilisateur lui-même ----------
app.get('/api/me/promo-codes', authMiddleware, h(async (req, res) => {
  const rows = await db.query(
    `SELECT code, discount_pct, applies_to_plan, expires_at, note FROM promo_codes
     WHERE assigned_to_user_id = $1 AND active = 1 AND used_count < max_uses
       AND (expires_at IS NULL OR expires_at > NOW())
     ORDER BY id DESC`,
    [req.user.id],
  );
  res.json({ codes: rows });
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

// ================= CENTRE DE NOTIFICATIONS ADMIN (cloche) =================
// Agrège de VRAIS événements déjà présents en base — jamais de contenu inventé :
// certifications artiste en attente, Labels à valider, signalements de morceaux (ces deux
// premiers restent tant qu'ils ne sont pas traités, exactement comme dans le Tableau de bord),
// et paiements / inscriptions récents (fenêtre de 14 jours, sinon la cloche resterait polluée
// indéfiniment par de très vieilles inscriptions). Chaque item a un id stable ("cert-12",
// "payment-88"...) construit à partir du vrai id de la ligne source, pour que admin.html
// puisse retenir localement ce qui a déjà été vu (la clé admin est partagée par l'équipe,
// donc l'état "lu" est géré par navigateur, pas par compte individuel).
// ================= COMMUNICATION — notifications manuelles vers une audience =================
// Réutilise createNotification (donc aussi le vrai push web) pour chaque destinataire réel —
// aucune notification de masse "magique" à part : on boucle simplement sur de vrais comptes.
// Le type 'admin_broadcast' permet de les distinguer des notifications automatiques (follower,
// nouvelle sortie...) si besoin plus tard côté app utilisateur.
app.post('/api/admin/notifications/send', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const { title, body, link, audience, specific_email } = req.body;
  if (!title || !String(title).trim() || !body || !String(body).trim()) {
    return res.status(400).json({ error: 'Le titre et le message sont obligatoires.' });
  }
  const validAudiences = ['all', 'artist', 'label', 'consumer', 'specific'];
  if (!validAudiences.includes(audience)) {
    return res.status(400).json({ error: 'Audience invalide.' });
  }

  let targetIds = [];
  let audienceLabel = audience;
  if (audience === 'specific') {
    if (!isEmail(specific_email)) return res.status(400).json({ error: 'Email invalide.' });
    const user = await db.get('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [String(specific_email).trim()]);
    if (!user) return res.status(404).json({ error: "Aucun compte NUNI n'existe avec cet email." });
    targetIds = [user.id];
    audienceLabel = specific_email.trim();
  } else if (audience === 'all') {
    const rows = await db.query('SELECT id FROM users');
    targetIds = rows.map(r => r.id);
  } else {
    const rows = await db.query('SELECT id FROM users WHERE account_type = $1', [audience]);
    targetIds = rows.map(r => r.id);
  }

  if (!targetIds.length) {
    return res.status(400).json({ error: 'Aucun compte ne correspond à cette audience.' });
  }

  const cleanTitle = String(title).trim();
  const cleanBody = String(body).trim();
  const cleanLink = link ? String(link).trim() : null;

  for (const userId of targetIds) {
    await createNotification(userId, 'admin_broadcast', cleanTitle, cleanBody, cleanLink);
  }

  await db.run(
    `INSERT INTO admin_broadcasts (title, body, link, audience, recipient_count) VALUES ($1,$2,$3,$4,$5)`,
    [cleanTitle, cleanBody, cleanLink, audienceLabel, targetIds.length],
  );

  res.json({ message: `Notification envoyée à ${targetIds.length} compte(s).`, recipient_count: targetIds.length });
}));

app.get('/api/admin/notifications/history', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;
  const rows = await db.query(
    'SELECT id, title, body, link, audience, recipient_count, created_at FROM admin_broadcasts ORDER BY created_at DESC LIMIT 100',
  );
  res.json({ broadcasts: rows });
}));

app.get('/api/admin/notifications', h(async (req, res) => {
  if (!checkAdminKey(req, res)) return;

  const [pendingCerts, pendingLabels, reports, recentPayments, recentSignups] = await Promise.all([
    db.query(`
      SELECT id, first_name, artist_name, created_at FROM users
      WHERE account_type = 'artist' AND verification_status = 'pending'
      ORDER BY created_at DESC LIMIT 20
    `),
    db.query(`
      SELECT id, label_name, created_at FROM labels
      WHERE verification_status IN ('pending','verification')
      ORDER BY created_at DESC LIMIT 20
    `),
    db.query(`
      SELECT tr.id, tr.created_at, t.title, u.artist_name, u.first_name as artist_first_name
      FROM track_reports tr
      JOIN tracks t ON t.id = tr.track_id
      JOIN users u ON u.id = t.artist_id
      ORDER BY tr.created_at DESC LIMIT 20
    `),
    db.query(`
      SELECT p.id, p.amount_fcfa, p.created_at, u.first_name, u.last_name, u.artist_name
      FROM payments p JOIN users u ON u.id = p.user_id
      WHERE p.created_at > NOW() - INTERVAL '14 days'
      ORDER BY p.created_at DESC LIMIT 20
    `),
    db.query(`
      SELECT id, first_name, last_name, account_type, artist_name, created_at
      FROM users
      WHERE created_at > NOW() - INTERVAL '14 days'
      ORDER BY created_at DESC LIMIT 20
    `),
  ]);

  const items = [];
  for (const c of pendingCerts) {
    items.push({
      id: 'cert-' + c.id, dot: 'red',
      text: `🏅 Certification en attente : ${c.artist_name || c.first_name}`,
      tab: 'cert', created_at: c.created_at,
    });
  }
  for (const l of pendingLabels) {
    items.push({
      id: 'label-' + l.id, dot: 'orange',
      text: `🏢 Nouveau Label à valider : ${l.label_name}`,
      tab: 'labels', created_at: l.created_at,
    });
  }
  for (const r of reports) {
    items.push({
      id: 'report-' + r.id, dot: 'red',
      text: `🚩 Signalement : « ${r.title} » (${r.artist_name || r.artist_first_name})`,
      tab: 'tracks', created_at: r.created_at,
    });
  }
  for (const p of recentPayments) {
    items.push({
      id: 'payment-' + p.id, dot: 'green',
      text: `💰 Paiement reçu : ${Number(p.amount_fcfa).toLocaleString('fr-FR')} FCFA (${p.artist_name || (p.first_name + ' ' + p.last_name)})`,
      tab: 'subs', created_at: p.created_at,
    });
  }
  for (const u of recentSignups) {
    items.push({
      id: 'signup-' + u.id, dot: 'green',
      text: `✨ Nouvelle inscription : ${u.artist_name || (u.first_name + ' ' + u.last_name)} (${u.account_type})`,
      tab: 'users', created_at: u.created_at,
    });
  }

  items.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ notifications: items.slice(0, 40) });
}));

async function snapshotTrackStreams() {
  try {
    // Un seul instantané par vrai morceau et par jour (contrainte unique en base) —
    // idempotent même si cette tâche se relance plusieurs fois le même jour après un
    // redémarrage à froid (plan gratuit Render).
    await db.query(`
      INSERT INTO track_streams_history (track_id, streams_snapshot, recorded_date)
      SELECT id, streams, CURRENT_DATE FROM tracks
      ON CONFLICT (track_id, recorded_date) DO UPDATE SET streams_snapshot = EXCLUDED.streams_snapshot, recorded_at = NOW()
    `);
  } catch (e) { console.error('[streams-history snapshot]', e.message); }
}
setInterval(snapshotTrackStreams, 60 * 60 * 1000); // vérifié toutes les heures ; premier vrai instantané déclenché dans start(), une fois le schéma prêt

app.get('/admin-verify.html', (req, res) => {
  res.redirect('/admin.html');
});

setInterval(async () => {
  try {
    // Repérer AVANT publication ce qui va sortir, pour notifier les vrais abonnés
    // (l'UPDATE seul ne permettrait pas de savoir quels morceaux/clips viennent de changer).
    const newlyPublished = await db.query(`
      SELECT id, artist_id, title FROM tracks WHERE published = 0 AND scheduled_release_at <= NOW()
    `);
    // Avant : les clips programmés se publiaient bien automatiquement (UPDATE plus bas),
    // mais contrairement aux morceaux, aucune notification n'était jamais envoyée aux
    // abonnés — oubli, corrigé en reprenant exactement la même logique.
    const newlyPublishedClips = await db.query(`
      SELECT id, artist_id, title FROM clips WHERE published = 0 AND scheduled_release_at <= NOW()
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
    for (const clip of newlyPublishedClips) {
      const artist = await db.get('SELECT artist_name, first_name FROM users WHERE id = $1', [clip.artist_id]);
      const artistName = (artist && (artist.artist_name || artist.first_name)) || 'Un artiste que vous suivez';
      const followers = await db.query('SELECT follower_id FROM follows WHERE artist_id = $1', [clip.artist_id]);
      for (const f of followers) {
        await createNotification(
          f.follower_id, 'new_release', 'Nouveau clip suivi',
          `${artistName} vient de publier le clip "${clip.title}".`, null,
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

// ---------- "Me prévenir" — envoi réel des notifications quand une sortie suivie devient
// disponible. Ne marque jamais notified_at avant un vrai envoi (ou une vraie tentative si
// VAPID n'est pas configuré, pour ne pas re-tenter indéfiniment un envoi impossible). ----------
async function sendReleaseNotifications() {
  try {
    const due = await db.query(`
      SELECT rnr.id AS req_id, rnr.user_id, t.id AS track_id, t.title, u.artist_name, u.first_name
      FROM release_notify_requests rnr
      JOIN tracks t ON t.id = rnr.track_id
      JOIN users u ON u.id = t.artist_id
      WHERE rnr.notified_at IS NULL AND t.published = 1
    `);
    for (const r of due) {
      const artist = r.artist_name || r.first_name || 'Un artiste NUNI';
      await sendPushToUser(r.user_id, {
        title: '🎵 Nouvelle sortie disponible',
        body: `« ${r.title} » de ${artist} est maintenant sur NUNI.`,
        url: '/',
      });
      await db.run('UPDATE release_notify_requests SET notified_at = NOW() WHERE id = $1', [r.req_id]);
    }
  } catch (e) { console.error('Erreur job notifications de sortie:', e); }
}
setInterval(sendReleaseNotifications, 10 * 60 * 1000); // toutes les 10 minutes, pas besoin de plus réactif pour une sortie
sendReleaseNotifications();

// ---------- Purge des comptes Pass Découverte non validés — DÉSACTIVÉE (faille de sécurité) ----------
// Avant : un compte Pass Découverte expiré était supprimé automatiquement après 2h de
// grâce — ce qui libérait son email dans la base. N'importe qui pouvait alors se réinscrire
// avec EXACTEMENT LE MÊME email pour obtenir un nouvel essai gratuit de 24h, indéfiniment,
// sans jamais payer un vrai Pass. Maintenant : un compte Découverte expiré reste simplement
// "expiré" en base, comme n'importe quel autre Pass — il est bloqué côté interface (écran
// plein écran "Pass expiré") mais son email reste engagé, fermant la porte aux essais en
// série. La fonction est conservée pour référence mais n'est plus jamais planifiée.
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
  snapshotTrackStreams(); // premier vrai instantané, schéma désormais garanti prêt

  enforceSubscriptionExpiry();
  setInterval(enforceSubscriptionExpiry, 60 * 1000);
  // enforceDiscoveryDeletion volontairement plus jamais planifiée — voir le commentaire sur
  // sa définition plus haut (faille de sécurité : permettait des essais Découverte en série).

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`NUNI backend en écoute sur http://localhost:${PORT}`));
}

start().catch((err) => {
  console.error('Échec du démarrage du serveur :', err);
  process.exit(1);
});

module.exports = app;
