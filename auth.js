// auth.js — Utilitaires d'authentification NUNI (adapté Postgres / async)
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

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

function generateAccessCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

// ---------- Middleware d'authentification — RE-VÉRIFIE le compte en base à CHAQUE requête ----------
// Avant : ce middleware faisait uniquement confiance au JWT (signature valide = accès autorisé),
// sans jamais revérifier l'état réel du compte. Un compte suspendu ou supprimé APRÈS l'émission
// du token continuait donc de fonctionner normalement jusqu'à l'expiration du token (30 jours !).
// Maintenant : chaque requête authentifiée fait une vraie vérification en base. Si l'admin suspend
// ou supprime un compte, l'utilisateur perd l'accès dès sa PROCHAINE requête — pas dans 30 jours.
async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentification requise.' });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Session invalide ou expirée.' });

  try {
    const user = await db.get('SELECT id, account_status FROM users WHERE id = $1', [payload.id]);
    if (!user) {
      return res.status(401).json({ error: 'Ce compte n\'existe plus.' });
    }
    if (user.account_status === 'suspended') {
      return res.status(403).json({ error: 'Votre compte a été suspendu par l\'administration. Contactez le support.' });
    }
    if (user.account_status === 'deleted') {
      return res.status(401).json({ error: 'Ce compte n\'existe plus.' });
    }
  } catch (e) {
    console.error('Erreur de vérification du compte dans authMiddleware:', e);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }

  req.user = payload;
  next();
}

module.exports = { initAuth, hashPassword, verifyPassword, signToken, verifyToken, generateAccessCode, authMiddleware };
