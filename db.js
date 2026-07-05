// db.js — Couche base de données NUNI (SQLite intégré à Node.js)
const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'nuni.db'));

db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    -- champs spécifiques artiste
    artist_name TEXT,
    label_or_manager TEXT,
    is_verified INTEGER DEFAULT 0,
    -- abonnement
    plan TEXT DEFAULT 'discovery' CHECK(plan IN ('discovery','consumer','artist')),
    subscription_status TEXT DEFAULT 'inactive' CHECK(subscription_status IN ('inactive','pending','active','expired')),
    subscription_started_at TEXT,
    subscription_expires_at TEXT,
    access_code TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS tracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artist_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    album TEXT,
    genre TEXT,
    release_type TEXT DEFAULT 'Single',
    cover_url TEXT,
    audio_url TEXT,
    lyrics TEXT,
    scheduled_release_at TEXT,
    published INTEGER DEFAULT 1,
    streams INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS clips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artist_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    thumb_url TEXT,
    video_url TEXT,
    scheduled_release_at TEXT,
    published INTEGER DEFAULT 1,
    views INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS promo_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    discount_pct INTEGER NOT NULL,
    applies_to_plan TEXT,
    max_uses INTEGER DEFAULT 1,
    used_count INTEGER DEFAULT 0,
    expires_at TEXT,
    active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER NOT NULL REFERENCES users(id),
    artist_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(follower_id, artist_id)
  );

  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    plan TEXT NOT NULL,
    duration_days INTEGER NOT NULL,
    amount_fcfa INTEGER NOT NULL,
    promo_code TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Migration : ajoute la colonne de statut de certification si elle n'existe pas encore
try {
  db.exec(`ALTER TABLE users ADD COLUMN verification_status TEXT DEFAULT 'none'`);
} catch (e) {
  // La colonne existe déjà — rien à faire.
}

// Migration : ajoute la colonne paroles aux morceaux déjà existants en base
try {
  db.exec(`ALTER TABLE tracks ADD COLUMN lyrics TEXT`);
} catch (e) {
  // La colonne existe déjà — rien à faire.
}

module.exports = db;
