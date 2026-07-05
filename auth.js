// auth.js — Utilitaires d'authentification NUNI
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

// Clé secrète stable : utilise la variable d'environnement JWT_SECRET si elle est configurée
// (meilleure pratique), sinon en génère une seule fois et la conserve en base — pour ne
// jamais déconnecter tout le monde silencieusement à chaque redémarrage du serveur.
function getOrCreateJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get('jwt_secret');
  if (row && row.value) return row.value;
  const generated = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)').run('jwt_secret', generated);
  return generated;
}
const JWT_SECRET = getOrCreateJwtSecret();

async function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, accountType: user.account_type, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function verifyToken(token) {
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

module.exports = { hashPassword, verifyPassword, signToken, verifyToken, generateAccessCode, authMiddleware };
