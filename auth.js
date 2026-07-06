// auth.js — Utilitaires d'authentification NUNI (adapté Postgres / async)
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

// La clé JWT doit maintenant être chargée de façon ASYNCHRONE (requête Postgres),
// donc on ne peut plus faire `const JWT_SECRET = getOrCreateJwtSecret()` au chargement
// du module comme avant. À la place : initAuth() est appelée UNE FOIS au démarrage du
// serveur (dans server.js, avant app.listen), et remplit JWT_SECRET en mémoire.
let JWT_SECRET = null;

async function initAuth() {
  if (process.env.JWT_SECRET) {
    JWT_SECRET = process.env.JWT_SECRET;
    return;
  }
  const row = await db.get('SELECT value FROM app_settings WHERE key = $1', ['jwt_secret']);
  if (row && row.value) {
    JWT_SECRET = row.value;
    return;
  }
  const generated = crypto.randomBytes(48).toString('hex');
  await db.run(
    `INSERT INTO app_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    ['jwt_secret', generated]
  );
  JWT_SECRET = generated;
}

async function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function signToken(user) {
  if (!JWT_SECRET) throw new Error('initAuth() doit être appelée avant signToken().');
  return jwt.sign(
    { id: user.id, accountType: user.account_type, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function verifyToken(token) {
  if (!JWT_SECRET) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Génère un code d'accès à 6 caractères (lettres majuscules + chiffres), unique et lisible
function generateAccessCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // exclut 0/O/1/I pour éviter la confusion
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentification requise.' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Session invalide ou expirée.' });
  req.user = payload;
  next();
}

module.exports = { initAuth, hashPassword, verifyPassword, signToken, verifyToken, generateAccessCode, authMiddleware };
