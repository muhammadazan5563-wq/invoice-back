import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { query } from './db.js';

const scrypt = promisify(scryptCallback);
const SESSION_DAYS = 30;
const json = (res, status, value) => res.status(status).json(value);
const emailOf = (value) => String(value || '').trim().toLowerCase();
const hashToken = (value) => createHash('sha256').update(value).digest('hex');

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
  const balance = Math.max(0, Math.round(Number(row.balance || 0) * 100) / 100);
  return { rowIndex: 0, id: row.id, date: row.date, customerName: row.customer_name || '', customerId: row.customer_id || '', customerEmail: row.customer_email || '', customerPhone: row.customer_phone || '', totalAmount: Number(row.total_amount || 0), taxRate: Number(row.tax_rate || 0), taxAmount: Number(row.tax_amount || 0), expenses: { baraf: Number(row.baraf || 0), rickshawRent: Number(row.rickshaw_rent || 0), workerExpense: Number(row.worker_expense || 0) }, expenseTotal: Number(row.expense_total || 0), amountPaid: Number(row.amount_paid || 0), paymentDate: row.payment_date || '', balance, status: balance <= 0 ? 'Paid' : row.status || 'Pending', notes: row.notes || '', items: row.items || [], payments: row.payments || [], rawRow: [], invoiceType: type || row.invoice_type || 'customer' };
}
const invoiceColumns = 'id,date,customer_name,customer_email,customer_phone,customer_id,total_amount,tax_rate,tax_amount,baraf,rickshaw_rent,worker_expense,expense_total,amount_paid,payment_date,balance,status,notes,items,payments,invoice_type';
function normalizeInvoice(inv) {
  const items = Array.isArray(inv.items) ? inv.items : [];
  const subtotal = items.length ? items.reduce((sum, item) => sum + Number(item.total || (Number(item.quantity || 0) * Number(item.price || 0))), 0) : Number(inv.subtotal ?? inv.totalAmount ?? 0);
  const taxRate = Number(inv.taxRate || 0);
  const taxAmount = Math.round((subtotal * taxRate / 100) * 100) / 100;
  const expenses = inv.invoiceType === 'vendor' ? { baraf: 0, rickshawRent: 0, workerExpense: 0 } : {
    baraf: Number(inv.expenses?.baraf || 0), rickshawRent: Number(inv.expenses?.rickshawRent || 0), workerExpense: Number(inv.expenses?.workerExpense || 0),
  };
  const expenseTotal = expenses.baraf + expenses.rickshawRent + expenses.workerExpense;
  const totalAmount = Math.round((subtotal + taxAmount + expenseTotal) * 100) / 100;
  const payments = (Array.isArray(inv.payments) ? inv.payments : []).filter((payment) => Number(payment.amount || 0) > 0);
  const amountPaid = Math.round((payments.length ? payments.reduce((sum, payment) => sum + Number(payment.appliedAmount ?? payment.amount ?? 0), 0) : Number(inv.amountPaid || 0)) * 100) / 100;
  const balance = Math.max(0, Math.round((totalAmount - amountPaid) * 100) / 100);
  const status = balance <= 0 ? 'Paid' : inv.status === 'Overdue' ? 'Overdue' : inv.status === 'Unpaid' ? 'Unpaid' : 'Due';
  return { ...inv, totalAmount, taxRate, taxAmount, expenses, expenseTotal, amountPaid, balance, status, items, payments, paymentDate: payments.at(-1)?.date || inv.paymentDate || '' };
}
function invoiceParams(inv) { const normalized = normalizeInvoice(inv); return [normalized.id, normalized.date || '', normalized.customerName || '', normalized.customerEmail || '', normalized.customerPhone || '', normalized.customerId || '', normalized.totalAmount, normalized.taxRate, normalized.taxAmount, normalized.expenses.baraf, normalized.expenses.rickshawRent, normalized.expenses.workerExpense, normalized.expenseTotal, normalized.amountPaid, normalized.paymentDate, normalized.balance, normalized.status, normalized.notes || '', JSON.stringify(normalized.items), JSON.stringify(normalized.payments), normalized.invoiceType === 'vendor' ? 'vendor' : 'customer']; }
function contactView(c) { return { id: c.id, type: c.type, fullName: c.full_name, phone: c.phone, email: c.email, companyName: c.company_name, location: c.location, address: c.address, area: c.area, taxRate: Number(c.tax_rate || 0), cnicFrontUrl: c.cnic_front_data || c.cnic_front_url || '', cnicBackUrl: c.cnic_back_data || c.cnic_back_url || '', chequeUrl: c.cheque_data || c.cheque_url || '', tempPassword: c.temp_password || '', createdAt: c.created_at }; }
function adminOnly(user) { return user && user.role === 'admin'; }
function paymentJsonSql(column = 'payments') { return `CASE WHEN jsonb_typeof(${column}) = 'array' THEN ${column} ELSE '[]'::jsonb END`; }
async function dashboardSummary(user, today, mode = 'customer') {
  const scoped = user?.role === 'vendor' || user?.role === 'customer';
  const args = scoped ? [user.contact_id, today] : [today];
  const where = scoped ? 'WHERE customer_id=$1' : '';
  const todayParam = scoped ? '$2' : '$1';
  const { rows } = await query(`
    WITH combined AS (
      SELECT total_amount,amount_paid,balance,status,payments,date FROM ${mode === 'vendor' ? 'vendor_invoices' : 'invoices'} ${where}
    )
    SELECT COUNT(*)::int AS total_invoices,
      COALESCE(SUM(total_amount),0) AS total_revenue,
      COALESCE(SUM(amount_paid),0) AS total_paid,
      COALESCE(SUM(GREATEST(balance,0)),0) AS total_pending,
      COUNT(*) FILTER (WHERE status='Paid')::int AS paid_count,
      COUNT(*) FILTER (WHERE status IN ('Pending','Due'))::int AS pending_count,
      COUNT(*) FILTER (WHERE status='Overdue')::int AS overdue_count,
      COALESCE(SUM(GREATEST(balance,0)) FILTER (WHERE status='Overdue'),0) AS overdue_amount,
      COALESCE(SUM(GREATEST(balance,0)) FILTER (WHERE status IN ('Pending','Due')),0) AS due_amount,
      COALESCE(AVG(total_amount),0) AS average_invoice,
      COALESCE(SUM((SELECT SUM(CASE WHEN p->>'date'=${todayParam} THEN COALESCE(NULLIF(p->>'appliedAmount','')::numeric,NULLIF(p->>'amount','')::numeric,0) ELSE 0 END) FROM jsonb_array_elements(${paymentJsonSql()}) p)),0) AS today_collection,
      COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(${paymentJsonSql()}) p WHERE p->>'date'=${todayParam}))::int AS today_paid_count,
      COUNT(*) FILTER (WHERE status='Pending' AND date=${todayParam})::int AS today_pending_count
    FROM combined`, args);
  const r = rows[0] || {};
  return { totalInvoices: Number(r.total_invoices || 0), totalRevenue: Number(r.total_revenue || 0), totalPaid: Number(r.total_paid || 0), totalPending: Number(r.total_pending || 0), paidCount: Number(r.paid_count || 0), pendingCount: Number(r.pending_count || 0), overdueCount: Number(r.overdue_count || 0), overdueAmount: Number(r.overdue_amount || 0), dueAmount: Number(r.due_amount || 0), averageInvoice: Number(r.average_invoice || 0), todayCollection: Number(r.today_collection || 0), todayPaidCount: Number(r.today_paid_count || 0), todayPendingCount: Number(r.today_pending_count || 0) };
}

export default async function apiHandler(req, res) {
  const path = req.url.split('?')[0]; const method = req.method;
  try {
    if (path === '/api/auth/session' && method === 'GET') { const user = await currentUser(req); return user ? json(res, 200, sessionView(user, String(req.headers.authorization).replace(/^Bearer\s+/i, '').trim())) : json(res, 401, { error: 'Not authenticated' }); }
    if (path === '/api/auth/logout' && method === 'POST') { const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim(); if (token) await query('DELETE FROM sessions WHERE token_hash=$1', [hashToken(token)]); return json(res, 200, { success: true }); }
    if (path === '/api/auth/login' && method === 'POST') {
      const email = emailOf(req.body?.email); const password = String(req.body?.password || '');
      const { rows } = await query(`SELECT u.*,c.type,c.full_name,c.phone,c.company_name,c.location,c.address,c.area,c.tax_rate,c.cnic_front_url,c.cnic_back_url,c.cheque_url,c.temp_password,c.created_at AS contact_created_at FROM users u LEFT JOIN contacts c ON c.id=u.contact_id WHERE u.email=$1`, [email]);
      if (!rows[0] || !(await verifyPassword(password, rows[0].password_hash))) return json(res, 401, { error: 'Invalid email or password' });
      return json(res, 200, sessionView(rows[0], await createSession(rows[0].id)));
    }
    if (path === '/api/auth/bootstrap-admin' && method === 'POST') {
      if (process.env.ADMIN_BOOTSTRAP_SECRET && req.headers['x-bootstrap-secret'] !== process.env.ADMIN_BOOTSTRAP_SECRET) return json(res, 403, { error: 'Forbidden' });
      const email = emailOf(req.body?.email || process.env.ADMIN_EMAIL); const password = String(req.body?.password || process.env.ADMIN_PASSWORD || '');
      if (!email || password.length < 8) return json(res, 400, { error: 'Admin email and an 8+ character password are required' });
      await query(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin') ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash,role='admin'`, [email, await hashPassword(password)]); return json(res, 201, { success: true });
    }

    const user = await currentUser(req);
    if (path === '/api/dashboard/summary' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const params = new URL(req.url, 'http://localhost').searchParams;
      const today = params.get('date') || new Date().toISOString().slice(0, 10);
      return json(res, 200, await dashboardSummary(user, today, params.get('mode') === 'vendor' ? 'vendor' : 'customer'));
    }
    if (path === '/api/payment-logs' && method === 'GET') {
      if (!user) return json(res, 401, { error: 'Authentication required' });
      const url = new URL(req.url, 'http://localhost');
      const page = Math.max(1, Number(url.searchParams.get('page') || 1));
      const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
      const offset = (page - 1) * limit;
      const scope = user.role === 'vendor' || user.role === 'customer';
      const args = scope ? [user.contact_id, limit, offset] : [limit, offset];
      const where = scope ? 'WHERE customer_id=$1' : '';
      const limitParam = scope ? '$2' : '$1'; const offsetParam = scope ? '$3' : '$2';
      const { rows } = await query(`SELECT x.id,x.customer_name,x.customer_phone,p AS payment FROM (SELECT id,customer_name,customer_phone,payments FROM invoices ${where} UNION ALL SELECT id,customer_name,customer_phone,payments FROM vendor_invoices ${where}) x CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(x.payments)='array' THEN x.payments ELSE '[]'::jsonb END) p WHERE COALESCE(NULLIF(p->>'amount','')::numeric,0)>0 ORDER BY COALESCE(p->>'date','') DESC, x.id DESC LIMIT ${limitParam} OFFSET ${offsetParam}`, args);
      const logs = rows.map((row) => ({ paymentId: row.id + '-' + String(row.payment.paymentId || row.payment.date || 'payment'), date: row.payment.date || '', name: row.payment.contactName || row.customer_name || '', phone: row.payment.contactPhone || row.customer_phone || '', amount: Number(row.payment.amount || 0) }));
      return json(res, 200, { page, limit, logs, hasMore: logs.length === limit });
    }
    if (path === '/api/contacts' && method === 'GET') { if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' }); const { rows } = await query('SELECT * FROM contacts ORDER BY created_at DESC'); return json(res, 200, rows.map(contactView)); }
    if (path === '/api/contacts' && method === 'POST') {
      if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' }); const d = req.body || {}; const email = emailOf(d.email); const password = String(d.password || randomBytes(9).toString('base64url'));
      if (!d.fullName || !email || password.length < 6) return json(res, 400, { error: 'Full name, email and a 6+ character password are required' });
      const { rows } = await query(`INSERT INTO contacts(type,full_name,phone,email,company_name,location,address,area,tax_rate,temp_password,cnic_front_data,cnic_back_data,cheque_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`, [d.type === 'vendor' ? 'vendor' : 'customer', d.fullName.trim(), d.phone || '', email, d.companyName || '', d.location || '', d.address || '', d.area || '', Number(d.taxRate || 0), password, d.cnicFrontData || '', d.cnicBackData || '', d.chequeData || '']);
      const c = rows[0]; await query('INSERT INTO users(email,password_hash,role,contact_id) VALUES($1,$2,$3,$4)', [email, await hashPassword(password), c.type, c.id]); return json(res, 201, { contact: contactView(c), password });
    }
    const contactMatch = path.match(/^\/api\/contacts\/([^/]+)$/);
    if (contactMatch && method === 'PUT') { if (!adminOnly(user)) return json(res, 403, { error: 'Administrator access required' }); const d = req.body || {}; const { rows } = await query(`UPDATE contacts SET type=$1,full_name=$2,phone=$3,company_name=$4,location=$5,address=$6,area=$7,tax_rate=$8,cnic_front_data=COALESCE(NULLIF($9,''),cnic_front_data),cnic_back_data=COALESCE(NULLIF($10,''),cnic_back_data),cheque_data=COALESCE(NULLIF($11,''),cheque_data),updated_at=NOW() WHERE id=$12 RETURNING *`, [d.type === 'vendor' ? 'vendor' : 'customer', d.fullName, d.phone || '', d.companyName || '', d.location || '', d.address || '', d.area || '', Number(d.taxRate || 0), d.cnicFrontData || '', d.cnicBackData || '', d.chequeData || '', contactMatch[1]]); return rows[0] ? json(res, 200, contactView(rows[0])) : json(res, 404, { error: 'Contact not found' }); }

    if (path === '/api/invoices' && method === 'GET') {
      if (!user) return json(res,401,{error:'Authentication required'});
      const filter = user?.role === 'vendor' || user?.role === 'customer'; const args = filter ? [user.contact_id] : []; const where = filter ? ' WHERE customer_id=$1' : '';
      const [a,b] = await Promise.all([query(`SELECT * FROM invoices${where} ORDER BY created_at DESC`, args), query(`SELECT * FROM vendor_invoices${where} ORDER BY created_at DESC`, args)]); return json(res, 200, [...a.rows.map((r)=>invoiceView(r,'customer')), ...b.rows.map((r)=>invoiceView(r,'vendor'))]);
    }
    if (path === '/api/invoices' && method === 'POST') { if (!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const inv=req.body||{}; const table=inv.invoiceType==='vendor'?'vendor_invoices':'invoices'; const vals=invoiceParams(inv); await query(`INSERT INTO ${table} (${invoiceColumns}) VALUES (${vals.map((_,i)=>`$${i+1}`).join(',')})`, vals); return json(res,201,{success:true}); }
    const invoiceMatch = path.match(/^\/api\/invoices\/([^/]+)$/);
    if (invoiceMatch && method === 'PUT') { if (!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const inv=req.body||{}; const table=inv.invoiceType==='vendor'?'vendor_invoices':'invoices'; const vals=invoiceParams({...inv,id:decodeURIComponent(invoiceMatch[1])}); await query(`UPDATE ${table} SET date=$2,customer_name=$3,customer_email=$4,customer_phone=$5,customer_id=$6,total_amount=$7,tax_rate=$8,tax_amount=$9,baraf=$10,rickshaw_rent=$11,worker_expense=$12,expense_total=$13,amount_paid=$14,payment_date=$15,balance=$16,status=$17,notes=$18,items=$19,payments=$20,invoice_type=$21 WHERE id=$1`, vals); return json(res,200,{success:true}); }
    if (invoiceMatch && method === 'DELETE') { if (!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const table=new URL(req.url,'http://localhost').searchParams.get('invoiceType')==='vendor'?'vendor_invoices':'invoices'; await query(`DELETE FROM ${table} WHERE id=$1`,[decodeURIComponent(invoiceMatch[1])]); return json(res,200,{success:true}); }

    if (path.startsWith('/api/settings/') && method === 'GET') {
      if (!user) return json(res,401,{error:'Authentication required'}); const uid=decodeURIComponent(path.split('/').pop()); const {rows}=await query('SELECT * FROM user_settings WHERE user_id=$1 OR user_id=$2 LIMIT 1',[uid,uid]); return json(res,200,rows[0]||null); }
    if (path === '/api/settings' && method === 'POST') {
      if (!user) return json(res,401,{error:'Authentication required'}); const s=req.body||{}; if(!s.user_id) return json(res,400,{error:'Missing user id'}); await query(`INSERT INTO user_settings(user_id,user_email,google_access_token,google_refresh_token,spreadsheet_settings,invoice_template,updated_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT (user_id) WHERE user_id IS NOT NULL DO UPDATE SET user_email=EXCLUDED.user_email,google_access_token=EXCLUDED.google_access_token,google_refresh_token=EXCLUDED.google_refresh_token,spreadsheet_settings=COALESCE(EXCLUDED.spreadsheet_settings,user_settings.spreadsheet_settings),invoice_template=COALESCE(EXCLUDED.invoice_template,user_settings.invoice_template),updated_at=NOW()`,[s.user_id,s.user_email||'',s.google_access_token||'',s.google_refresh_token||'',s.spreadsheet_settings?JSON.stringify(s.spreadsheet_settings):null,s.invoice_template?JSON.stringify(s.invoice_template):null]); return json(res,200,{success:true}); }

    if (path === '/api/ledger-invoices' && method === 'GET') { const {rows}=await query('SELECT * FROM ledger_invoices ORDER BY created_at DESC'); return json(res,200,rows); }
    if (path === '/api/cash-expenses' && method === 'GET') { const {rows}=await query('SELECT * FROM cash_expenses ORDER BY created_at DESC'); return json(res,200,rows); }
    if (path === '/api/ledger-invoices' && method === 'POST') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const x=req.body||{}; await query('INSERT INTO ledger_invoices(id,guest_name,hotel_name,total_amount) VALUES($1,$2,$3,$4)',[x.id,x.guest_name,x.hotel_name,Number(x.total_amount||0)]); return json(res,201,{success:true}); }
    if (path === '/api/cash-expenses' && method === 'POST') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); const x=req.body||{}; await query('INSERT INTO cash_expenses(name,amount,description,tag) VALUES($1,$2,$3,$4)',[x.name,Number(x.amount||0),x.description||'',x.tag||'expense']); return json(res,201,{success:true}); }
    if (path.startsWith('/api/ledger-invoices/') && method === 'DELETE') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); await query('DELETE FROM ledger_invoices WHERE id=$1',[decodeURIComponent(path.split('/').pop())]); return json(res,200,{success:true}); }
    if (path.startsWith('/api/cash-expenses/') && method === 'DELETE') { if(!adminOnly(user)) return json(res,403,{error:'Administrator access required'}); await query('DELETE FROM cash_expenses WHERE id=$1',[decodeURIComponent(path.split('/').pop())]); return json(res,200,{success:true}); }
    if (path.startsWith('/api/public-invoice/') && method === 'GET') { const raw=decodeURIComponent(path.split('/').pop()); const {rows}=await query('SELECT * FROM invoices WHERE id=$1 OR UPPER(id)=UPPER($1) OR id LIKE $2 LIMIT 1',[raw,`%${raw.replace(/^INV-|^REF-/i,'')}`]); return rows[0]?json(res,200,invoiceView(rows[0],'customer')):json(res,404,{error:'Invoice not found'}); }
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
