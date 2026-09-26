import 'dotenv/config';
import express from 'express';
import compression from 'compression';
import apiHandler from './api-handler.js';
import { migrate, ensureAdminFromEnv, pool } from './db.js';

const app = express();
const port = Number(process.env.PORT || 8080);
const origins = (process.env.FRONTEND_ORIGIN || '*').split(',').map((x) => x.trim()).filter(Boolean);
app.use(express.json({ limit: '4mb' }));
app.use(compression());
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origins.includes('*')) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (origin && origins.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Bootstrap-Secret');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
app.get('/health', async (_req, res) => { try { await pool.query('SELECT 1'); res.json({ status: 'ok', service: 'invoice-api', database: 'postgresql' }); } catch { res.status(503).json({ status: 'error', service: 'invoice-api', database: 'unavailable' }); } });
app.use((req, res) => apiHandler(req, res));
migrate().then(ensureAdminFromEnv).then(() => app.listen(port, '0.0.0.0', () => console.log(`Invoice PostgreSQL API listening on ${port}`))).catch((error) => { console.error('Database migration or admin provisioning failed:', error); process.exit(1); });
process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
