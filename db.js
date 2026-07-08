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
  await pool.query(`UPDATE users SET account_status = 'active' WHERE account_status IS NULL;`);
}

module.exports = { pool, query, get, run, initSchema };
