import pg from 'pg';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { promisify } from 'node:util';

const { Pool } = pg;
const scrypt = promisify(scryptCallback);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL is required. Add the PostgreSQL connection string in Railway Variables.');
}

export const pool = new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: Number(process.env.DB_POOL_MAX || 10),
});

export async function migrate() {
  const schema = await fs.readFile(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  await pool.query("DELETE FROM sessions WHERE expires_at < NOW()");
  console.log('PostgreSQL schema is ready.');
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${Buffer.from(derived).toString('hex')}`;
}

export async function ensureAdminFromEnv() {
  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (!email || !password) return;
  if (password.length < 8) throw new Error('ADMIN_PASSWORD must be at least 8 characters');
  await query(
    `INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin')
     ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash, role='admin'`,
    [email, await hashPassword(password)]
  );
  console.log(`Administrator account is ready for ${email}.`);
}

export async function query(text, params) {
  const startedAt = performance.now();
  try {
    return await pool.query(text, params);
  } finally {
    const durationMs = performance.now() - startedAt;
    const thresholdMs = Number(process.env.QUERY_SLOW_MS || 500);
    if (durationMs >= thresholdMs) {
      const sql = String(text).replace(/\s+/g, ' ').trim().slice(0, 240);
      console.warn(JSON.stringify({ event: 'slow_query', durationMs: Math.round(durationMs), thresholdMs, sql }));
    }
  }
}
