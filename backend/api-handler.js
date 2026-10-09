import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { pool, query } from './db.js';

const scrypt = promisify(scryptCallback);
const SESSION_DAYS = 30;
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || 15 * 60 * 1000);
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);
const loginAttempts = new Map();
const json = (res, status, value) => res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate').status(status).json(value);
const emailOf = (value) => String(value || '').trim().toLowerCase();
const hashToken = (value) => createHash('sha256').update(value).digest('hex');
const roundCurrency = (value) => {
  const rounded = Math.round(Number(value) || 0);
  return Object.is(rounded, -0) ? 0 : rounded;
};

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${Buffer.from(derived).toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const [salt, hex] = String(stored || '').split(':');
  if (!salt || !hex) return false;
  const derived = await scrypt(password, salt, 64);
  const expected = Buffer.from(hex, 'hex');
  return expected.length === derived.length && timingSafeEqual(expected, derived);
}
async function createSession(userId) {
  const token = randomBytes(32).toString('hex');
  await query('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+$3::interval)', [hashToken(token), userId, `${SESSION_DAYS} days`]);
  return token;
}
async function currentUser(req) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const { rows } = await query(`SELECT u.id,u.email,u.role,u.contact_id,c.type,c.full_name,c.phone,c.company_name,c.location,c.address,c.area,c.tax_rate,c.cnic_front_url,c.cnic_back_url,c.cheque_url,c.temp_password,c.created_at AS contact_created_at FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN contacts c ON c.id=u.contact_id WHERE s.token_hash=$1 AND s.expires_at>NOW()`, [hashToken(token)]);
  return rows[0] || null;
}
function sessionView(user, token) {
  return { token, user: { uid: user.id, id: user.id, email: user.email }, role: user.role, contact: user.contact_id ? {
    id: user.contact_id, type: user.type, fullName: user.full_name, phone: user.phone, email: user.email,
    companyName: user.company_name, location: user.location, address: user.address, area: user.area,
    taxRate: Number(user.tax_rate || 0), cnicFrontUrl: user.cnic_front_url || '', cnicBackUrl: user.cnic_back_url || '',
    chequeUrl: user.cheque_url || '', tempPassword: user.temp_password || '', createdAt: user.contact_created_at,
  } : null, accessToken: null };
}
function invoiceView(row, type) {
  const totalAmount = roundCurrency(row.total_amount);
  const payments = Array.isArray(row.payments) ? row.payments : [];
  const paymentHistoryTotal = payments.reduce((sum, payment) => sum + Number(payment.amount || 0), 0);
  const amountPaid = roundCurrency(Math.max(Number(row.amount_paid || 0), paymentHistoryTotal));
  const balance = roundCurrency(totalAmount - amountPaid);
  return { rowIndex: 0, id: row.id, date: row.date, customerName: row.customer_name || '', customerId: row.customer_id || '', customerEmail: row.customer_email || '', customerPhone: row.customer_phone || '', totalAmount, taxRate: Number(row.tax_rate || 0), taxAmount: roundCurrency(row.tax_amount), expenses: { baraf: Number(row.baraf || 0), rickshawRent: Number(row.rickshaw_rent || 0), workerExpense: Number(row.worker_expense || 0) }, expenseTotal: roundCurrency(row.expense_total), amountPaid, paymentDate: row.payment_date || '', balance, status: balance <= 0 ? 'Paid' : row.status || 'Pending', notes: row.notes || '', items: row.items || [], payments, rawRow: [], invoiceType: type || row.invoice_type || 'customer' };
}
const invoiceColumns = 'id,date,customer_name,customer_email,customer_phone,customer_id,total_amount,tax_rate,tax_amount,baraf,rickshaw_rent,worker_expense,expense_total,amount_paid,payment_date,balance,status,notes,items,payments,invoice_type';
function normalizeInvoice(inv) {
  const items = Array.isArray(inv.items) ? inv.items : [];
  const subtotal = items.length ? items.reduce((sum, item) => sum + Number(item.total || (Number(item.quantity || 0) * Number(item.price || 0))), 0) : Number(inv.subtotal ?? inv.totalAmount ?? 0);
  const taxRate = Number(inv.taxRate || 0);
  const expenses = inv.invoiceType === 'customer' ? { baraf: 0, rickshawRent: 0, workerExpense: 0 } : {
    baraf: Number(inv.expenses?.baraf || 0), rickshawRent: Number(inv.expenses?.rickshawRent || 0), workerExpense: Number(inv.expenses?.workerExpense || 0),
  };
  const expenseTotal = roundCurrency(expenses.baraf + expenses.rickshawRent + expenses.workerExpense);
  const commissionBase = inv.invoiceType === 'vendor' ? Math.max(0, subtotal - expenseTotal) : subtotal;
  const calculatedTaxAmount = commissionBase * taxRate / 100;
  const suppliedTaxAmount = inv.taxAmount ?? inv.tax_amount;
  const taxAmount = suppliedTaxAmount === undefined || suppliedTaxAmount === null
    ? roundCurrency(calculatedTaxAmount)
    : roundCurrency(Number(suppliedTaxAmount));
  const totalAmount = roundCurrency(subtotal + taxAmount - expenseTotal);
  const payments = (Array.isArray(inv.payments) ? inv.payments : []).filter((payment) => Number(payment.amount || 0) > 0);
  // The editor's current amountPaid is authoritative. Payment history can
  // contain legacy appliedAmount metadata from an earlier allocation, so only
  // use it when the caller does not provide an explicit current total.
  const paymentHistoryTotal = payments.reduce((sum, payment) => sum + Number(payment.appliedAmount ?? payment.amount ?? 0), 0);
  const amountPaidInput = inv.amountPaid ?? inv.amount_paid;
  const amountPaid = roundCurrency(amountPaidInput ?? (payments.length ? paymentHistoryTotal : 0));
  const balance = roundCurrency(totalAmount - amountPaid);
  const status = balance <= 0 ? 'Paid' : inv.status === 'Overdue' ? 'Overdue' : inv.status === 'Unpaid' ? 'Unpaid' : 'Due';
  return { ...inv, totalAmount, taxRate, taxAmount, expenses, expenseTotal, amountPaid, balance, status, items, payments, paymentDate: payments.at(-1)?.date || inv.paymentDate || '' };
}
function invoiceParams(inv) { const normalized = normalizeInvoice(inv); return [normalized.id, normalized.date || '', normalized.customerName || '', normalized.customerEmail || '', normalized.customerPhone || '', normalized.customerId || '', normalized.totalAmount, normalized.taxRate, normalized.taxAmount, normalized.expenses.baraf, normalized.expenses.rickshawRent, normalized.expenses.workerExpense, normalized.expenseTotal, normalized.amountPaid, normalized.paymentDate, normalized.balance, normalized.status, normalized.notes || '', JSON.stringify(normalized.items), JSON.stringify(normalized.payments), normalized.invoiceType === 'vendor' ? 'vendor' : 'customer']; }
function consumeUnappliedCredit(payments, amount) {
  let remaining = amount;
  const nextPayments = payments.map((payment) => ({ ...payment }));
  for (let index = nextPayments.length - 1; index >= 0 && remaining > 0; index -= 1) {
    const payment = nextPayments[index];
    const paymentAmount = Number(payment.amount || 0);
    if (paymentAmount <= 0) continue;
    const consumed = Math.min(remaining, paymentAmount);
    payment.amount = roundCurrency(paymentAmount - consumed);
    if (payment.appliedAmount !== undefined) {
      payment.appliedAmount = roundCurrency(Math.min(Number(payment.appliedAmount || 0), payment.amount));
    }
    remaining -= consumed;
  }
  return nextPayments.filter((payment) => Number(payment.amount || 0) > 0);
}
function contactView(c) { return { id: c.id, type: c.type, fullName: c.full_name, phone: c.phone, email: c.email, companyName: c.company_name, location: c.location, address: c.address, area: c.area, taxRate: Number(c.tax_rate || 0), cnicFrontUrl: c.cnic_front_data || c.cnic_front_url || '', cnicBackUrl: c.cnic_back_data || c.cnic_back_url || '', chequeUrl: c.cheque_data || c.cheque_url || '', tempPassword: c.temp_password || '', createdAt: c.created_at }; }
async function applyInvoiceCredit(client, normalized) {
  let newAmountPaid = normalized.amountPaid;
  let newBalance = normalized.balance;
  let newPayments = [...normalized.payments];
  if (!normalized.customerId || newBalance <= 0) return { amountPaid: newAmountPaid, balance: newBalance, payments: newPayments, applied: 0 };
  const table = normalized.invoiceType === 'vendor' ? 'vendor_invoices' : 'invoices';
  const creditResult = await client.query(
    `SELECT id,total_amount,amount_paid,balance,payments FROM ${table} WHERE customer_id=$1 AND id<>$2 AND (balance<0 OR total_amount<amount_paid OR total_amount<(SELECT COALESCE(SUM(COALESCE(NULLIF(payment->>'amount','')::numeric,0)),0) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(${table}.payments)='array' THEN ${table}.payments ELSE '[]'::jsonb END) payment)) ORDER BY date ASC,id ASC FOR UPDATE`,
    [normalized.customerId, normalized.id]
  );
  for (const creditInvoice of creditResult.rows) {
    if (newBalance <= 0) break;
    const paymentHistoryTotal = (Array.isArray(creditInvoice.payments) ? creditInvoice.payments : []).reduce((sum, payment) => sum + Number(payment.amount || 0), 0);
    const oldPaidTotal = Math.max(Number(creditInvoice.amount_paid || 0), paymentHistoryTotal);
    const adjustment = Math.min(Math.max(0, oldPaidTotal - Number(creditInvoice.total_amount || 0)), newBalance);
    if (adjustment <= 0) continue;
    const updatedOldPayments = consumeUnappliedCredit(Array.isArray(creditInvoice.payments) ? creditInvoice.payments : [], adjustment);
    const oldAmountPaid = roundCurrency(oldPaidTotal - adjustment);
    const oldBalance = roundCurrency(Number(creditInvoice.total_amount || 0) - oldAmountPaid);
    await client.query(`UPDATE ${table} SET amount_paid=$1,balance=$2,status=$3,payments=$4 WHERE id=$5`, [oldAmountPaid, oldBalance, oldBalance <= 0 ? 'Paid' : 'Due', JSON.stringify(updatedOldPayments), creditInvoice.id]);
    newAmountPaid = roundCurrency(newAmountPaid + adjustment);
    newBalance = roundCurrency(newBalance - adjustment);
    newPayments.push({ amount: adjustment, appliedAmount: adjustment, date: normalized.date, paymentId: `credit-${creditInvoice.id}-${normalized.id}`, contactName: normalized.customerName || '', contactPhone: normalized.customerPhone || '' });
  }
  return { amountPaid: newAmountPaid, balance: newBalance, payments: newPayments, applied: roundCurrency(newAmountPaid - normalized.amountPaid) };
}
function adminOnly(user) { return user && user.role === 'admin'; }
function loginKey(req, email) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return `${forwarded || req.ip || req.socket?.remoteAddress || 'unknown'}:${email}`;
}
function loginThrottleState(key) {
  const now = Date.now();
  if (loginAttempts.size > 10000) {
    for (const [storedKey, storedState] of loginAttempts) {
      if (now - storedState.startedAt >= LOGIN_WINDOW_MS && storedState.blockedUntil <= now) loginAttempts.delete(storedKey);
    }
  }
  const state = loginAttempts.get(key);
  if (!state || now - state.startedAt >= LOGIN_WINDOW_MS) {
    const next = { startedAt: now, attempts: 0, blockedUntil: 0 };
    loginAttempts.set(key, next);
    return next;
  }
  return state;
}
function recordLoginFailure(key) {
  const state = loginThrottleState(key);
  state.attempts += 1;
  if (state.attempts >= LOGIN_MAX_ATTEMPTS) state.blockedUntil = Date.now() + LOGIN_WINDOW_MS;
}
function clearLoginFailures(key) { loginAttempts.delete(key); }
function paymentJsonSql(column = 'payments') { return `CASE WHEN jsonb_typeof(${column}) = 'array' THEN ${column} ELSE '[]'::jsonb END`; }
async function applyPayment(contactId, amount, paymentDate, paymentId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const contactResult = await client.query('SELECT id,type,full_name,phone FROM contacts WHERE id=$1 LIMIT 1', [contactId]);
    const contact = contactResult.rows[0];
    if (!contact) throw new Error('Contact not found');
    const table = contact.type === 'vendor' ? 'vendor_invoices' : 'invoices';
    const invoiceResult = await client.query(
      `SELECT id,date,customer_name,customer_phone,total_amount,amount_paid,balance,payments
       FROM ${table} WHERE customer_id=$1 AND balance>0 ORDER BY date ASC, id ASC FOR UPDATE`,
      [contactId]
    );
    const invoices = invoiceResult.rows;
    const outstanding = invoices.reduce((sum, invoice) => sum + Math.max(0, Number(invoice.balance) || 0), 0);
    const allocated = Math.min(amount, outstanding);
    if (allocated <= 0) throw new Error('This contact has no unpaid invoices.');
    let remaining = allocated;
    let firstAllocation = true;
    for (const invoice of invoices) {
      if (remaining <= 0) break;
      const currentBalance = Math.max(0, Number(invoice.balance) || 0);
      const applied = Math.min(remaining, currentBalance);
      remaining -= applied;
      const payments = Array.isArray(invoice.payments) ? invoice.payments : [];
      payments.push({
        amount: applied,
        appliedAmount: applied,
        date: paymentDate,
        paymentId,
        contactName: contact.full_name || invoice.customer_name || '',
        contactPhone: contact.phone || invoice.customer_phone || '',
      });
      if (firstAllocation && amount > allocated) {
        payments.push({
          amount: amount - allocated,
          appliedAmount: 0,
          date: paymentDate,
          paymentId,
          contactName: contact.full_name || invoice.customer_name || '',
          contactPhone: contact.phone || invoice.customer_phone || '',
        });
      }
      const excessCredit = firstAllocation ? Math.max(0, amount - allocated) : 0;
      const amountPaid = roundCurrency(Number(invoice.amount_paid || 0) + applied + excessCredit);
      const balance = roundCurrency(currentBalance - applied - excessCredit);
      await client.query(
        `UPDATE ${table} SET amount_paid=$1,payment_date=$2,balance=$3,status=$4,payments=$5 WHERE id=$6`,
        [amountPaid, paymentDate, balance, balance <= 0 ? 'Paid' : 'Due', JSON.stringify(payments), invoice.id]
      );
      firstAllocation = false;
    }
    await client.query(
      `INSERT INTO payment_logs(payment_id,contact_id,contact_name,contact_phone,amount,payment_date)
       VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(payment_id) DO NOTHING`,
      [paymentId, contact.id, contact.full_name || '', contact.phone || '', amount, paymentDate]
    );
    await client.query('COMMIT');
    return { allocated: roundCurrency(allocated), outstanding: roundCurrency(outstanding), invoiceCount: invoices.length };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
async function dashboardSummary(user, today, mode = 'customer') {
  const scoped = user?.role === 'vendor' || user?.role === 'customer';
  const args = scoped ? [user.contact_id, today] : [today];
  const where = scoped ? 'WHERE customer_id=$1' : '';
  const todayParam = scoped ? '$2' : '$1';
  const { rows } = await query(`
    WITH combined AS (
      SELECT total_amount,amount_paid,balance,status,payments,payment_date,date FROM ${mode === 'vendor' ? 'vendor_invoices' : 'invoices'} ${where}
    )
    SELECT COUNT(*)::int AS total_invoices,
      COALESCE(SUM(total_amount),0) AS total_revenue,
      COALESCE(SUM(GREATEST(amount_paid,0)),0) AS total_paid,
      COALESCE(SUM(GREATEST(amount_paid-total_amount,0)),0) AS total_overpaid,
      COALESCE(SUM(GREATEST(balance,0)),0) AS total_pending,
      COUNT(*) FILTER (WHERE status='Paid')::int AS paid_count,
      COUNT(*) FILTER (WHERE status IN ('Pending','Due'))::int AS pending_count,
      COUNT(*) FILTER (WHERE status='Overdue')::int AS overdue_count,
      COALESCE(SUM(GREATEST(balance,0)) FILTER (WHERE status='Overdue'),0) AS overdue_amount,
      COALESCE(SUM(GREATEST(balance,0)) FILTER (WHERE status IN ('Pending','Due')),0) AS due_amount,
      COALESCE(AVG(total_amount),0) AS average_invoice,
      COALESCE(SUM((SELECT SUM(COALESCE(NULLIF(p->>'appliedAmount','')::numeric,NULLIF(p->>'amount','')::numeric,0)) FROM jsonb_array_elements(${paymentJsonSql()}) p WHERE p->>'date'=${todayParam})),0) AS today_collection,
      COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(${paymentJsonSql()}) p WHERE p->>'date'=${todayParam}))::int AS today_paid_count,
      COUNT(*) FILTER (WHERE status='Pending' AND date=${todayParam})::int AS today_pending_count
    FROM combined`, args);
  const r = rows[0] || {};
  return { totalInvoices: Number(r.total_invoices || 0), totalRevenue: Number(r.total_revenue || 0), totalPaid: Number(r.total_paid || 0), totalOverpaid: Number(r.total_overpaid || 0), totalPending: Number(r.total_pending || 0), paidCount: Number(r.paid_count || 0), pendingCount: Number(r.pending_count || 0), overdueCount: Number(r.overdue_count || 0), overdueAmount: Number(r.overdue_amount || 0), dueAmount: Number(r.due_amount || 0), averageInvoice: Number(r.average_invoice || 0), todayCollection: Number(r.today_collection || 0), todayPaidCount: Number(r.today_paid_count || 0), todayPendingCount: Number(r.today_pending_count || 0) };
}

async function nextInvoiceId() {
  const yearPrefix = String(new Date().getFullYear()).slice(-2);
  const prefix = `INV-${yearPrefix}`;
  const { rows } = await query(
    `SELECT id FROM (
       SELECT id FROM invoices WHERE id LIKE $1
       UNION ALL
       SELECT id FROM vendor_invoices WHERE id LIKE $1
     ) all_invoices
     WHERE id ~ $2
     ORDER BY substring(id FROM 5)::bigint DESC
     LIMIT 1`,
    [`${prefix}%`, `^${prefix}[0-9]+$`]
  );
  const highest = rows[0]?.id ? Number(String(rows[0].id).slice(prefix.length)) : 0;
  return `${prefix}${String((Number.isFinite(highest) ? highest : 0) + 1).padStart(3, '0')}`;
}

export default async function apiHandler(req, res) {
  const path = req.url.split('?')[0]; const method = req.method;
  try {
    if (path === '/api/auth/session' && method === 'GET') { const user = await currentUser(req); return user ? json(res, 200, sessionView(user, String(req.headers.authorization).replace(/^Bearer\s+/i, '').trim())) : json(res, 401, { error: 'Not authenticated' }); }
    if (path === '/api/auth/logout' && method === 'POST') { const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim(); if (token) await query('DELETE FROM sessions WHERE token_hash=$1', [hashToken(token)]); return json(res, 200, { success: true }); }
    if (path === '/api/auth/login' && method === 'POST') {
      const email = emailOf(req.body?.email); const password = String(req.body?.password || '');
      const attemptKey = loginKey(req, email);
      const attemptState = loginThrottleState(attemptKey);
      if (attemptState.blockedUntil > Date.now()) {
        const retryAfter = Math.max(1, Math.ceil((attemptState.blockedUntil - Date.now()) / 1000));
        res.set('Retry-After', String(retryAfter));
        return json(res, 429, { error: 'Too many failed login attempts. Try again later.' });
      }
      const { rows } = await query(`SELECT u.*,c.type,c.full_name,c.phone,c.company_name,c.location,c.address,c.area,c.tax_rate,c.cnic_front_url,c.cnic_back_url,c.cheque_url,c.temp_password,c.created_at AS contact_created_at FROM users u LEFT JOIN contacts c ON c.id=u.contact_id WHERE u.email=$1`, [email]);
      if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) {
        recordLoginFailure(attemptKey);
        return json(res, 401, { error: 'Invalid email or password' });
      }
      clearLoginFailures(attemptKey);
      return json(res, 200, sessionView(rows[0], await createSession(rows[0].id)));
    }
    if (path === '/api/auth/bootstrap-admin' && method === 'POST') {
      if (process.env.ADMIN_BOOTSTRAP_SECRET && req.headers['x-bootstrap-secret'] !== process.env.ADMIN_BOOTSTRAP_SECRET) return json(res, 403, { error: 'Forbidden' });
      const email = emailOf(req.body?.email || process.env.ADMIN_EMAIL); const password = String(req.body?.password || process.env.ADMIN_PASSWORD || '');
      if (!email || password.length < 8) return json(res, 400, { error: 'Admin email and an 8+ character password are required' });
      await query(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin') ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash,role='admin'`, [email, await hashPassword(password)]); return json(res, 201, { success: true });
    }

    if (path === '/api/public-invoice-template' && method === 'GET') {
      const { rows } = await query(`SELECT invoice_template FROM user_settings WHERE invoice_template IS NOT NULL AND invoice_template <> '{}'::jsonb ORDER BY updated_at DESC LIMIT 1`);
      return json(res, 200, { template: rows[0]?.invoice_template || null });
    }

    const user = await currentUser(req);
    if (path === '/api/invoices/next-id' && method === 'GET') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      return json(res, 200, { id: await nextInvoiceId() });
    }
    if (path === '/api/dashboard/summary' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const params = new URL(req.url, 'http://localhost').searchParams;
      const today = params.get('date') || new Date().toISOString().slice(0, 10);
      const mode = user.role === 'vendor' ? 'vendor' : user.role === 'customer' ? 'customer' : params.get('mode') === 'vendor' ? 'vendor' : 'customer';
      return json(res, 200, await dashboardSummary(user, today, mode));
    }
    if (path === '/api/payment-logs' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const url = new URL(req.url, 'http://localhost');
      const page = Math.max(1, Number(url.searchParams.get('page') || 1));
      const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
      const offset = (page - 1) * limit;
      const args = [limit, offset];
      const { rows } = await query(
        `SELECT payment_id, payment_date, contact_name, contact_phone, amount
         FROM payment_logs
         ORDER BY created_at DESC, payment_id DESC
         LIMIT $1 OFFSET $2`,
        args
      );
      const logs = rows.map((row) => ({ paymentId: row.payment_id, date: row.payment_date || '', name: row.contact_name || '', phone: row.contact_phone || '', amount: Number(row.amount || 0) }));
      return json(res, 200, { page, limit, logs, hasMore: logs.length === limit });
    }
    if (path === '/api/payment-preview' && method === 'GET') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const contactId = new URL(req.url, 'http://localhost').searchParams.get('contactId');
      const contactResult = await query('SELECT type FROM contacts WHERE id=$1 LIMIT 1', [contactId]);
      if (!contactResult.rows[0]) return json(res, 404, { error: 'Contact not found' });
      const table = contactResult.rows[0].type === 'vendor' ? 'vendor_invoices' : 'invoices';
      const { rows } = await query(`SELECT COUNT(*)::int AS invoice_count, COALESCE(SUM(GREATEST(balance,0)),0) AS outstanding FROM ${table} WHERE customer_id=$1 AND balance>0`, [contactId]);
      return json(res, 200, { invoiceCount: Number(rows[0]?.invoice_count || 0), outstanding: Number(rows[0]?.outstanding || 0) });
    }
    if (path === '/api/payments' && method === 'POST') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const contactId = String(req.body?.contactId || '').trim();
      const amount = Number(req.body?.amount || 0);
      if (!contactId || amount <= 0) return json(res, 400, { error: 'A contact and payment amount greater than zero are required' });
      try {
        const paymentDate = String(req.body?.paymentDate || new Date().toISOString().slice(0, 10));
        const result = await applyPayment(contactId, amount, paymentDate, String(req.body?.paymentId || randomBytes(16).toString('hex')));
        return json(res, 200, result);
      } catch (error) {
        return json(res, 400, { error: error.message || 'Could not apply payment' });
      }
    }
    if (path === '/api/invoices/history' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const url = new URL(req.url, 'http://localhost');
      const contactId = url.searchParams.get('customerId')?.trim();
      const invoiceType = url.searchParams.get('invoiceType') === 'vendor' ? 'vendor' : 'customer';
      if (!contactId) return json(res, 400, { error: 'customerId is required' });
      if (!adminOnly(user)) {
        const expectedType = user.role === 'vendor' ? 'vendor' : 'customer';
        if (user.contact_id !== contactId || expectedType !== invoiceType) {
          return json(res, 403, { error: 'You may only access your own invoice history' });
        }
      }
      const table = invoiceType === 'vendor' ? 'vendor_invoices' : 'invoices';
      const args = [contactId];
      const conditions = ['customer_id=$1'];
      const addParam = (value) => { args.push(value); return `$${args.length}`; };
      const status = url.searchParams.get('status');
      if (status && status !== 'all' && status !== 'All') conditions.push(status === 'Paid' ? 'balance <= 0' : `status=${addParam(status)}`);
      const fromDate = url.searchParams.get('fromDate');
      if (fromDate) conditions.push(`date >= ${addParam(fromDate)}`);
      const toDate = url.searchParams.get('toDate');
      if (toDate) conditions.push(`date <= ${addParam(toDate)}`);
      const search = url.searchParams.get('search')?.trim();
      if (search) { const param = addParam(`%${search}%`); conditions.push(`id ILIKE ${param}`); }
      const { rows } = await query(`SELECT ${invoiceColumns}, created_at FROM ${table} WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC, id DESC`, args);
      const invoices = rows.map((row) => invoiceView(row, invoiceType));
      const summary = invoices.reduce((result, invoice) => ({
        billed: result.billed + invoice.totalAmount,
        paid: result.paid + Math.max(invoice.amountPaid, 0),
        overpaid: result.overpaid + Math.max(-invoice.balance, 0),
        outstanding: result.outstanding + Math.max(invoice.balance, 0),
        settled: result.settled + (invoice.balance <= 0 ? 1 : 0),
        overdue: result.overdue + (invoice.balance > 0 && invoice.status === 'Overdue' ? 1 : 0),
      }), { billed: 0, paid: 0, overpaid: 0, outstanding: 0, settled: 0, overdue: 0 });
      return json(res, 200, { invoices, total: invoices.length, summary });
    }
    if (path === '/api/contact-summary' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const params = new URL(req.url, 'http://localhost').searchParams;
      const contactId = params.get('customerId')?.trim();
      const invoiceType = params.get('invoiceType') === 'vendor' ? 'vendor' : 'customer';
      if (!contactId) return json(res, 400, { error: 'customerId is required' });
      if (!adminOnly(user)) {
        const expectedType = user.role === 'vendor' ? 'vendor' : 'customer';
        if (user.contact_id !== contactId || expectedType !== invoiceType) {
          return json(res, 403, { error: 'You may only access your own invoice summary' });
        }
      }
      const table = invoiceType === 'vendor' ? 'vendor_invoices' : 'invoices';
      const { rows } = await query(`
        SELECT COUNT(*)::int AS invoice_count,
          COALESCE(SUM(total_amount),0) AS total_billed,
          COALESCE(SUM(GREATEST(amount_paid,0)),0) AS total_paid,
          COALESCE(SUM(GREATEST(amount_paid-total_amount,0)),0) AS total_overpaid,
          COALESCE(SUM(GREATEST(balance,0)),0) AS outstanding,
          COUNT(*) FILTER (WHERE balance <= 0)::int AS settled,
          COUNT(*) FILTER (WHERE balance > 0 AND status='Overdue')::int AS overdue
        FROM ${table} WHERE customer_id=$1`, [contactId]);
      const row = rows[0] || {};
      return json(res, 200, { billed: Number(row.total_billed || 0), paid: Number(row.total_paid || 0), overpaid: Number(row.total_overpaid || 0), outstanding: Number(row.outstanding || 0), settled: Number(row.settled || 0), overdue: Number(row.overdue || 0), invoiceCount: Number(row.invoice_count || 0) });
    }
    if (path === '/api/invoices/expenses' && method === 'GET') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const url = new URL(req.url, 'http://localhost');
      const fromDate = url.searchParams.get('fromDate')?.trim();
      const toDate = url.searchParams.get('toDate')?.trim();
      const expenseFields = { baraf: 'baraf', rickshawRent: 'rickshaw_rent', workerExpense: 'worker_expense' };
      const expense = url.searchParams.get('expense') || 'baraf';
      const expenseField = expenseFields[expense];
      if (!fromDate || !toDate || !expenseField) return json(res, 400, { error: 'Valid fromDate, toDate and expense are required' });
      const { rows } = await query(
        `SELECT ${invoiceColumns} FROM vendor_invoices WHERE date >= $1 AND date <= $2 AND ${expenseField} > 0 ORDER BY date DESC, id DESC`,
        [fromDate, toDate]
      );
      const invoices = rows.map((row) => invoiceView(row, 'vendor'));
      const totalExpense = invoices.reduce((sum, invoice) => sum + Number(invoice.expenses?.[expense] || 0), 0);
      const totalInvoiceAmount = invoices.reduce((sum, invoice) => sum + Number(invoice.totalAmount || 0), 0);
      return json(res, 200, {
        invoices,
        summary: { totalExpense: roundCurrency(totalExpense), invoiceCount: invoices.length, totalInvoiceAmount: roundCurrency(totalInvoiceAmount) },
      });
    }
    if (path === '/api/invoices/ledger-date' && method === 'GET') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const date = new URL(req.url, 'http://localhost').searchParams.get('date')?.trim();
      if (!date) return json(res, 400, { error: 'date is required' });
      const paymentDateCondition = `EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(payments)='array' THEN payments ELSE '[]'::jsonb END) payment WHERE payment->>'date'=$1 AND COALESCE(NULLIF(payment->>'appliedAmount','')::numeric,NULLIF(payment->>'amount','')::numeric,0)>0)`;
      const [customerResult, vendorResult] = await Promise.all([
        query(`SELECT ${invoiceColumns}, created_at FROM invoices WHERE ${paymentDateCondition}`, [date]),
        query(`SELECT ${invoiceColumns}, created_at FROM vendor_invoices WHERE ${paymentDateCondition}`, [date]),
      ]);
      const rows = [
        ...customerResult.rows.map((row) => invoiceView(row, 'customer')),
        ...vendorResult.rows.map((row) => invoiceView(row, 'vendor')),
      ].map((invoice) => {
        const paymentsForDate = invoice.payments.filter((payment) => payment.date === date);
        return paymentsForDate.length > 0
          ? { ...invoice, totalAmount: roundCurrency(paymentsForDate.reduce((sum, payment) => sum + Number(payment.appliedAmount ?? payment.amount ?? 0), 0)) }
          : invoice;
      }).sort((a, b) => (parseInt(a.id.replace(/\D/g, ''), 10) || 0) - (parseInt(b.id.replace(/\D/g, ''), 10) || 0));
      return json(res, 200, { invoices: rows, total: rows.length });
    }
    if (path === '/api/contacts' && method === 'GET') { if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' }); const { rows } = await query('SELECT * FROM contacts ORDER BY created_at DESC'); return json(res, 200, rows.map(contactView)); }
    if (path === '/api/contacts' && method === 'POST') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' }); const d = req.body || {}; const email = emailOf(d.email); const password = String(d.password || randomBytes(9).toString('base64url'));
      if (!d.fullName || !email || password.length < 6) return json(res, 400, { error: 'Full name, email and a 6+ character password are required' });
      const { rows } = await query(`INSERT INTO contacts(type,full_name,phone,email,company_name,location,address,area,tax_rate,temp_password,cnic_front_data,cnic_back_data,cheque_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`, [d.type === 'vendor' ? 'vendor' : 'customer', d.fullName.trim(), d.phone || '', email, d.companyName || '', d.location || '', d.address || '', d.area || '', Number(d.taxRate || 0), password, d.cnicFrontData || '', d.cnicBackData || '', d.chequeData || '']);
      const c = rows[0]; await query('INSERT INTO users(email,password_hash,role,contact_id) VALUES($1,$2,$3,$4)', [email, await hashPassword(password), c.type, c.id]); return json(res, 201, { contact: contactView(c), password });
    }
    const contactMatch = path.match(/^\/api\/contacts\/([^/]+)$/);
    if (contactMatch && method === 'PUT') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const d = req.body || {};
      const email = emailOf(d.email);
      if (!d.fullName || !email) return json(res, 400, { error: 'Full name and email are required' });
      if (d.password && String(d.password).length < 6) return json(res, 400, { error: 'Password must be at least 6 characters' });
      const { rows } = await query(`UPDATE contacts SET type=$1,full_name=$2,phone=$3,email=$4,company_name=$5,location=$6,address=$7,area=$8,tax_rate=$9,temp_password=CASE WHEN NULLIF($10,'') IS NULL THEN temp_password ELSE $10 END,cnic_front_data=COALESCE(NULLIF($11,''),cnic_front_data),cnic_back_data=COALESCE(NULLIF($12,''),cnic_back_data),cheque_data=COALESCE(NULLIF($13,''),cheque_data),updated_at=NOW() WHERE id=$14 RETURNING *`, [d.type === 'vendor' ? 'vendor' : 'customer', d.fullName.trim(), d.phone || '', email, d.companyName || '', d.location || '', d.address || '', d.area || '', Number(d.taxRate || 0), d.password || '', d.cnicFrontData || '', d.cnicBackData || '', d.chequeData || '', contactMatch[1]]);
      if (!rows[0]) return json(res, 404, { error: 'Contact not found' });
      if (d.password) {
        await query('UPDATE users SET email=$1,password_hash=$2 WHERE contact_id=$3', [email, await hashPassword(String(d.password)), contactMatch[1]]);
      } else {
        await query('UPDATE users SET email=$1 WHERE contact_id=$2', [email, contactMatch[1]]);
      }
      return json(res, 200, contactView(rows[0]));
    }

    if (path === '/api/invoices' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const url = new URL(req.url, 'http://localhost');
      const page = Math.max(1, Number(url.searchParams.get('page') || 1));
      const limit = Math.min(2000, Math.max(1, Number(url.searchParams.get('limit') || 2000)));
      const offset = (page - 1) * limit;
      const requestedType = url.searchParams.get('invoiceType');
      const tables = requestedType === 'vendor'
        ? [{ name: 'vendor_invoices', type: 'vendor' }]
        : requestedType === 'customer'
          ? [{ name: 'invoices', type: 'customer' }]
          : [{ name: 'invoices', type: 'customer' }, { name: 'vendor_invoices', type: 'vendor' }];
      const args = [];
      const conditions = [];
      const addParam = (value) => { args.push(value); return `$${args.length}`; };
      if (user.role === 'vendor' || user.role === 'customer') conditions.push(`customer_id=${addParam(user.contact_id)}`);
      const customerId = url.searchParams.get('customerId')?.trim();
      if (customerId && user.role === 'admin') conditions.push(`customer_id=${addParam(customerId)}`);
      const search = url.searchParams.get('search')?.trim();
      if (search) {
        const param = addParam(`%${search}%`);
        conditions.push(`(id ILIKE ${param} OR customer_name ILIKE ${param} OR customer_email ILIKE ${param})`);
      }
      const status = url.searchParams.get('status');
      if (status && status !== 'All') {
        if (status === 'Paid') conditions.push('balance <= 0');
        else conditions.push(`status=${addParam(status)}`);
      }
      const fromDate = url.searchParams.get('fromDate') || url.searchParams.get('fromMonth');
      if (fromDate) conditions.push(`date >= ${addParam(fromDate.length === 7 ? `${fromDate}-01` : fromDate)}`);
      const toDate = url.searchParams.get('toDate') || url.searchParams.get('toMonth');
      if (toDate) {
        conditions.push(toDate.length === 7
          ? `date < (${addParam(`${toDate}-01`)}::date + INTERVAL '1 month')::text`
          : `date <= ${addParam(toDate)}`);
      }
      const where = conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '';
      const union = tables.map(({ name, type }) => `SELECT ${invoiceColumns}, created_at, '${type}' AS result_invoice_type FROM ${name}${where}`).join(' UNION ALL ');
      const limitParam = addParam(limit);
      const offsetParam = addParam(offset);
      const [rowsResult, countResult] = await Promise.all([
        query(`SELECT * FROM (${union}) combined ORDER BY created_at DESC, id DESC LIMIT ${limitParam} OFFSET ${offsetParam}`, args),
        query(`SELECT COUNT(*)::int AS total FROM (${union}) combined`, args.slice(0, args.length - 2)),
      ]);
      const total = Number(countResult.rows[0]?.total || 0);
      return json(res, 200, { invoices: rowsResult.rows.map((row) => invoiceView(row, row.result_invoice_type)), page, limit, total, hasMore: offset + rowsResult.rows.length < total });
    }
    if (path === '/api/invoices' && method === 'POST') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const inv = req.body || {};
      const normalized = normalizeInvoice(inv);
      const table = normalized.invoiceType === 'vendor' ? 'vendor_invoices' : 'invoices';
      const vals = invoiceParams(inv);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`INSERT INTO ${table} (${invoiceColumns}) VALUES (${vals.map((_, i) => `$${i + 1}`).join(',')})`, vals);

        let newAmountPaid = normalized.amountPaid;
        let newBalance = normalized.balance;
        let newPayments = [...normalized.payments];
        if (normalized.customerId && newBalance > 0) {
          const creditResult = await client.query(
            `SELECT id,total_amount,amount_paid,balance,payments FROM ${table} WHERE customer_id=$1 AND id<>$2 AND (balance<0 OR total_amount<amount_paid OR total_amount<(SELECT COALESCE(SUM(COALESCE(NULLIF(payment->>'amount','')::numeric,0)),0) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(${table}.payments)='array' THEN ${table}.payments ELSE '[]'::jsonb END) payment)) ORDER BY date ASC,id ASC FOR UPDATE`,
            [normalized.customerId, normalized.id]
          );
          for (const creditInvoice of creditResult.rows) {
            if (newBalance <= 0) break;
            const paymentHistoryTotal = (Array.isArray(creditInvoice.payments) ? creditInvoice.payments : [])
              .reduce((sum, payment) => sum + Number(payment.amount || 0), 0);
            const oldPaidTotal = Math.max(Number(creditInvoice.amount_paid || 0), paymentHistoryTotal);
            const availableCredit = Math.max(0, oldPaidTotal - Number(creditInvoice.total_amount || 0));
            const adjustment = Math.min(availableCredit, newBalance);
            if (adjustment <= 0) continue;
            const oldPayments = Array.isArray(creditInvoice.payments) ? creditInvoice.payments : [];
            const updatedOldPayments = consumeUnappliedCredit(oldPayments, adjustment);
            const oldAmountPaid = roundCurrency(oldPaidTotal - adjustment);
            const oldBalance = roundCurrency(Number(creditInvoice.total_amount || 0) - oldAmountPaid);
            await client.query(
              `UPDATE ${table} SET amount_paid=$1,balance=$2,status=$3,payments=$4 WHERE id=$5`,
              [oldAmountPaid, oldBalance, oldBalance <= 0 ? 'Paid' : 'Due', JSON.stringify(updatedOldPayments), creditInvoice.id]
            );
            newAmountPaid = roundCurrency(newAmountPaid + adjustment);
            newBalance = roundCurrency(newBalance - adjustment);
            newPayments.push({
              amount: adjustment,
              appliedAmount: adjustment,
              date: normalized.date,
              paymentId: `credit-${creditInvoice.id}-${normalized.id}`,
              contactName: normalized.customerName || '',
              contactPhone: normalized.customerPhone || '',
            });
          }
          await client.query(
            `UPDATE ${table} SET amount_paid=$1,payment_date=$2,balance=$3,status=$4,payments=$5 WHERE id=$6`,
            [newAmountPaid, normalized.date, newBalance, newBalance <= 0 ? 'Paid' : normalized.status, JSON.stringify(newPayments), normalized.id]
          );
        }
        await client.query('COMMIT');
        return json(res, 201, { success: true, creditApplied: roundCurrency(newAmountPaid - normalized.amountPaid) });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    const invoiceMatch = path.match(/^\/api\/invoices\/([^/]+)$/);
    if (invoiceMatch && method === 'PUT') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' });
      const inv = req.body || {};
      const normalized = normalizeInvoice({ ...inv, id: decodeURIComponent(invoiceMatch[1]) });
      const table = normalized.invoiceType === 'vendor' ? 'vendor_invoices' : 'invoices';
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const vals = invoiceParams(normalized);
        await client.query(`UPDATE ${table} SET date=$2,customer_name=$3,customer_email=$4,customer_phone=$5,customer_id=$6,total_amount=$7,tax_rate=$8,tax_amount=$9,baraf=$10,rickshaw_rent=$11,worker_expense=$12,expense_total=$13,amount_paid=$14,payment_date=$15,balance=$16,status=$17,notes=$18,items=$19,payments=$20,invoice_type=$21 WHERE id=$1`, vals);
        const adjusted = await applyInvoiceCredit(client, normalized);
        if (adjusted.applied > 0) {
          await client.query(`UPDATE ${table} SET amount_paid=$1,payment_date=$2,balance=$3,status=$4,payments=$5 WHERE id=$6`, [adjusted.amountPaid, normalized.date, adjusted.balance, adjusted.balance <= 0 ? 'Paid' : normalized.status, JSON.stringify(adjusted.payments), normalized.id]);
        }
        await client.query('COMMIT');
        return json(res, 200, { success: true, creditApplied: adjusted.applied });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    if (invoiceMatch && method === 'DELETE') { if (!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const table=new URL(req.url,'http://localhost').searchParams.get('invoiceType')==='vendor'?'vendor_invoices':'invoices'; await query(`DELETE FROM ${table} WHERE id=$1`,[decodeURIComponent(invoiceMatch[1])]); return json(res,200,{success:true}); }

    if (path.startsWith('/api/settings/') && method === 'GET') {
      if (!user) return json(res,401,{error:'Authentication required'}); const uid=decodeURIComponent(path.split('/').pop()); const {rows}=await query('SELECT * FROM user_settings WHERE user_id=$1 OR user_id=$2 LIMIT 1',[uid,uid]); return json(res,200,rows[0]||null); }
    if (path === '/api/settings' && method === 'POST') {
      if (!user) return json(res,401,{error:'Authentication required'}); const s=req.body||{}; if(!s.user_id) return json(res,400,{error:'Missing user id'}); await query(`INSERT INTO user_settings(user_id,user_email,google_access_token,google_refresh_token,spreadsheet_settings,invoice_template,updated_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT (user_id) WHERE user_id IS NOT NULL DO UPDATE SET user_email=EXCLUDED.user_email,google_access_token=EXCLUDED.google_access_token,google_refresh_token=EXCLUDED.google_refresh_token,spreadsheet_settings=COALESCE(EXCLUDED.spreadsheet_settings,user_settings.spreadsheet_settings),invoice_template=COALESCE(EXCLUDED.invoice_template,user_settings.invoice_template),updated_at=NOW()`,[s.user_id,s.user_email||'',s.google_access_token||'',s.google_refresh_token||'',s.spreadsheet_settings?JSON.stringify(s.spreadsheet_settings):null,s.invoice_template?JSON.stringify(s.invoice_template):null]); return json(res,200,{success:true}); }

    if (path === '/api/ledger/bulk' && method === 'POST') {
      if (!adminOnly(user)) return json(res,403,{error:'Administrator access required'});
      const payload = req.body || {};
      const ledgerDate = String(payload.ledger_date || '').trim();
      if (!ledgerDate) return json(res,400,{error:'ledger_date is required'});
      const invoices = (Array.isArray(payload.invoices) ? payload.invoices : []).map((invoice) => ({
        invoice_id: invoice.invoice_id || invoice.id || '',
        guest_name: invoice.guest_name || '',
        hotel_name: invoice.hotel_name || '',
        total_amount: Number(invoice.total_amount || 0),
        invoice_type: invoice.invoice_type === 'vendor' ? 'vendor' : 'customer',
      })).filter((invoice) => invoice.invoice_id);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `INSERT INTO ledger_invoices(id,ledger_date,invoices) VALUES($1,$2,$3::jsonb)
           ON CONFLICT(ledger_date) DO UPDATE SET id=EXCLUDED.id,invoices=EXCLUDED.invoices`,
          [`ledger-${ledgerDate}`, ledgerDate, JSON.stringify(invoices)]
        );
        for (const id of Array.isArray(payload.deleteExpenseIds) ? payload.deleteExpenseIds : []) await client.query('DELETE FROM cash_expenses WHERE id=$1', [id]);
        for (const expense of Array.isArray(payload.expenses) ? payload.expenses : []) await client.query(
          'INSERT INTO cash_expenses(name,amount,description,tag,created_at) VALUES($1,$2,$3,$4,$5)',
          [expense.name || '', Number(expense.amount || 0), expense.description || '', expense.tag || 'expense', `${ledgerDate}T12:00:00.000Z`]
        );
        await client.query('COMMIT');
        return json(res,201,{success:true, invoicesSaved:invoices.length, expensesSaved:Array.isArray(payload.expenses) ? payload.expenses.length : 0});
      } catch (error) {
        await client.query('ROLLBACK');
        return json(res,400,{error:error.message || 'Failed to save ledger day'});
      } finally { client.release(); }
    }
    if (path === '/api/ledger/bulk' && method === 'DELETE') {
      if (!adminOnly(user)) return json(res,403,{error:'Administrator access required'});
      const ledgerDate = String(req.body?.ledger_date || '').trim();
      if (!ledgerDate) return json(res,400,{error:'ledger_date is required'});
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('DELETE FROM ledger_invoices WHERE ledger_date=$1', [ledgerDate]);
        const expenses = await client.query(`SELECT id,created_at FROM cash_expenses WHERE created_at >= $1::date AND created_at < ($1::date + INTERVAL '1 day')`, [ledgerDate]);
        for (const expense of expenses.rows) await client.query('DELETE FROM cash_expenses WHERE id=$1', [expense.id]);
        await client.query('COMMIT');
        return json(res,200,{success:true});
      } catch (error) {
        await client.query('ROLLBACK');
        return json(res,400,{error:error.message || 'Failed to delete ledger day'});
      } finally { client.release(); }
    }
    if (path === '/api/ledger-invoices' && method === 'GET') {
      const {rows}=await query(`SELECT ledger_invoices.id,ledger_invoices.ledger_date,ledger_invoices.created_at,invoice.invoice_id,invoice.guest_name,invoice.hotel_name,invoice.total_amount,invoice.invoice_type FROM ledger_invoices CROSS JOIN LATERAL jsonb_to_recordset(ledger_invoices.invoices) AS invoice(invoice_id TEXT,guest_name TEXT,hotel_name TEXT,total_amount NUMERIC,invoice_type TEXT) ORDER BY ledger_invoices.ledger_date DESC`);
      return json(res,200,rows.map((row) => ({ id: `${row.invoice_id}_${row.ledger_date}`, invoice_id: row.invoice_id, ledger_date: row.ledger_date, guest_name: row.guest_name, hotel_name: row.hotel_name, total_amount: Number(row.total_amount || 0), invoice_type: row.invoice_type === 'vendor' ? 'vendor' : 'customer', created_at: row.created_at })));
    }
    if (path === '/api/cash-expenses' && method === 'GET') { const {rows}=await query('SELECT * FROM cash_expenses ORDER BY created_at DESC'); return json(res,200,rows); }
    if (path === '/api/ledger-invoices' && method === 'POST') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); return json(res,410,{error:'Use POST /api/ledger/bulk instead'}); }
    if (path === '/api/cash-expenses' && method === 'POST') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const x=req.body||{}; await query('INSERT INTO cash_expenses(name,amount,description,tag) VALUES($1,$2,$3,$4)',[x.name,Number(x.amount||0),x.description||'',x.tag||'expense']); return json(res,201,{success:true}); }
    if (path.startsWith('/api/ledger-invoices/') && method === 'DELETE') {
      if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'});
      const rawId = decodeURIComponent(path.split('/').pop());
      const match = rawId.match(/^(.*)_(\d{4}-\d{2}-\d{2})$/);
      if (!match) return json(res,400,{error:'Invalid ledger invoice id'});
      await query(`UPDATE ledger_invoices SET invoices=(SELECT COALESCE(jsonb_agg(item),'[]'::jsonb) FROM jsonb_array_elements(invoices) item WHERE item->>'invoice_id'<>$1) WHERE ledger_date=$2`, [match[1], match[2]]);
      return json(res,200,{success:true});
    }
    if (path.startsWith('/api/cash-expenses/') && method === 'DELETE') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); await query('DELETE FROM cash_expenses WHERE id=$1',[decodeURIComponent(path.split('/').pop())]); return json(res,200,{success:true}); }
    if (path.startsWith('/api/public-invoice/') && method === 'GET') {
      const raw = decodeURIComponent(path.split('/').pop());
      const lookup = [raw, `%${raw.replace(/^INV-|^REF-/i, '')}`];
      const customerResult = await query('SELECT * FROM invoices WHERE id=$1 OR UPPER(id)=UPPER($1) OR id LIKE $2 LIMIT 1', lookup);
      if (customerResult.rows[0]) return json(res, 200, invoiceView(customerResult.rows[0], 'customer'));
      const vendorResult = await query('SELECT * FROM vendor_invoices WHERE id=$1 OR UPPER(id)=UPPER($1) OR id LIKE $2 LIMIT 1', lookup);
      return vendorResult.rows[0] ? json(res, 200, invoiceView(vendorResult.rows[0], 'vendor')) : json(res, 404, { error: 'Invoice not found' });
    }
    if (path === '/api/google/token-info' && method === 'POST') {
      const { accessToken } = req.body || {};
      if (!accessToken) return json(res, 400, { error: 'Access token is required' });
      const response = await fetch(`https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${encodeURIComponent(accessToken)}`);
      const body = await response.json().catch(() => ({}));
      if (!response.ok) return json(res, response.status, { error: body.error_description || 'Google token validation failed' });
      return json(res, 200, body);
    }
    if (path === '/api/google/spreadsheet-info' && method === 'POST') {
      const { spreadsheetId, accessToken } = req.body || {};
      if (!spreadsheetId || !accessToken) return json(res, 400, { error: 'Spreadsheet ID and access token are required' });
      const response = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}`, { headers: { Authorization: `Bearer ${accessToken}` } });
      const body = await response.json();
      if (!response.ok) return json(res, response.status, { error: body.error?.message || 'Google Sheets request failed' });
      return json(res, 200, { id: spreadsheetId, title: body.properties?.title || 'Untitled Spreadsheet', sheets: (body.sheets || []).map((x) => x.properties?.title).filter(Boolean) });
    }
    if (path === '/api/sync-booking-sheet' && method === 'POST') {
      const { invoiceId, customerName, items, spreadsheetId, sheetName, accessToken } = req.body || {};
      if (!invoiceId || !customerName || !Array.isArray(items) || !spreadsheetId || !sheetName || !accessToken) return json(res, 400, { error: 'Missing required spreadsheet sync fields' });
      const rows = items.map((item, index) => { const d = (x) => x ? new Date(x).toLocaleDateString('en-US') : ''; return [d(item.checkIn), d(item.checkOut), String(item.nights || 1), String(index + 1), customerName, invoiceId, String(item.quantity || 1), item.roomType || '']; });
      const range = encodeURIComponent(`'${sheetName}'!A1`);
      const response = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${range}:append?valueInputOption=USER_ENTERED`, { method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ values: rows }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) return json(res, response.status, { error: body.error?.message || 'Google Sheets append failed' });
      return json(res, 200, { success: true, rowsAdded: rows.length, startId: 1 });
    }
    return json(res,404,{error:'API route not found'});
  } catch (error) { console.error('API error:',error); return json(res,500,{error:error.message||'Internal server error'}); }
}
