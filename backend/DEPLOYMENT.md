# Railway backend deployment

This directory is the complete server package for Aqua Ledger.

## What it contains

- `server.js`: starts Express only after PostgreSQL migrations complete.
- `db.js`: PostgreSQL connection pool and migration runner.
- `schema.sql`: creates all application tables and indexes automatically.
- `api-handler.js`: server-side authentication, contacts, invoices, vendor invoices, settings, ledger, cash expenses, public invoice lookup, contact documents, and Google Sheets proxy operations.

At startup, `schema.sql` runs first. If `ADMIN_EMAIL` and `ADMIN_PASSWORD` are present, the server then creates or updates that administrator account before opening the HTTP port.

## Railway variables

```env
DATABASE_URL=${{Postgres.DATABASE_URL}}
FRONTEND_ORIGIN=https://your-frontend.vercel.app
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=use-a-strong-password
ADMIN_BOOTSTRAP_SECRET=use-a-random-secret
```

## Start command

```bash
npm start
```

Railway installs dependencies from `package.json`. Do not include `node_modules` in the ZIP.
