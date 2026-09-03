require('dotenv').config();
var express = require('express');
var Pool = require('pg').Pool;
var cors = require('cors');
var crypto = require('crypto');

var app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

var PORT = process.env.PORT || 3000;
var ADMIN_SECRET = process.env.ADMIN_SECRET || '';
var FREE_MONTHLY_CREDITS = parseInt(process.env.FREE_CREDITS) || 3;

var pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ═══════════════════════════════════════
// 🔒 AUTH & HELPERS
// ═══════════════════════════════════════
function adminAuth(req, res, next) {
  var secret = req.headers['x-admin-secret'] || req.query.secret || (req.body && req.body.secret);
  if (!ADMIN_SECRET || !secret || secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  next();
}

function userAuth(req, res, next) {
  var telegramId = req.headers['x-telegram-id'] || req.body.telegram_id || req.query.telegram_id;
  if (!telegramId) return res.status(401).json({ error: 'Telegram ID required' });
  req.telegramId = String(telegramId).trim();
  next();
}

var rateLimitStore = new Map();
function rateLimiter(req, res, next) {
  var ip = req.ip || req.connection.remoteAddress;
  var now = Date.now();
  var record = rateLimitStore.get(ip);
  if (!record || now - record.start > 60000) { rateLimitStore.set(ip, { start: now, count: 1 }); return next(); }
  record.count++;
  if (record.count > 20) return res.status(429).json({ error: 'Too many requests' });
  next();
}
setInterval(function() { var now = Date.now(); rateLimitStore.forEach(function(r, ip) { if (now - r.start > 60000) rateLimitStore.delete(ip); }); }, 300000);

// ═══════════════════════════════════════
// 🗄️ DATABASE INIT
// ═══════════════════════════════════════
async function initDB() {
  await pool.query("CREATE TABLE IF NOT EXISTS si_users (telegram_id VARCHAR(50) PRIMARY KEY, name VARCHAR(200) DEFAULT '', credits INTEGER DEFAULT 0, free_credits_used INTEGER DEFAULT 0, last_free_reset DATE DEFAULT CURRENT_DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE TABLE IF NOT EXISTS si_clients (id SERIAL PRIMARY KEY, telegram_id VARCHAR(50) REFERENCES si_users(telegram_id), name VARCHAR(200) NOT NULL, phone VARCHAR(30), email VARCHAR(200), address TEXT, tax_code VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE TABLE IF NOT EXISTS si_invoices (id SERIAL PRIMARY KEY, telegram_id VARCHAR(50) REFERENCES si_users(telegram_id), client_id INTEGER REFERENCES si_clients(id), invoice_number VARCHAR(50), title VARCHAR(300), currency VARCHAR(10) DEFAULT 'IRR', subtotal BIGINT DEFAULT 0, tax_rate INTEGER DEFAULT 9, tax_amount BIGINT DEFAULT 0, discount BIGINT DEFAULT 0, total BIGINT DEFAULT 0, status VARCHAR(20) DEFAULT 'draft', template VARCHAR(30) DEFAULT 'classic', notes TEXT, credit_cost INTEGER DEFAULT 1, issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, due_date DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE TABLE IF NOT EXISTS si_items (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES si_invoices(id) ON DELETE CASCADE, description VARCHAR(500) NOT NULL, quantity INTEGER DEFAULT 1, unit_price BIGINT DEFAULT 0, amount BIGINT DEFAULT 0)");
  await pool.query("CREATE TABLE IF NOT EXISTS si_transactions (id SERIAL PRIMARY KEY, telegram_id VARCHAR(50) REFERENCES si_users(telegram_id), type VARCHAR(20) NOT NULL, amount INTEGER NOT NULL, balance_after INTEGER NOT NULL, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  console.log('Smart Invoice DB initialized (Credit-Based Model)');
}

// ═══════════════════════════════════════
// 👤 USER ENDPOINTS
// ═══════════════════════════════════════
app.post('/api/user/profile', rateLimiter, userAuth, async function(req, res) {
  try {
    var tgId = req.telegramId;
    var existing = await pool.query("SELECT * FROM si_users WHERE telegram_id=$1", [tgId]);
    if (existing.rows.length === 0) {
      await pool.query("INSERT INTO si_users (telegram_id, credits, free_credits_used) VALUES ($1, $2, 0)", [tgId, FREE_MONTHLY_CREDITS]);
      await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'free_grant', $2, $2, 'Free monthly credits')", [tgId, FREE_MONTHLY_CREDITS]);
      var newUser = await pool.query("SELECT * FROM si_users WHERE telegram_id=$1", [tgId]);
      return res.json({ success: true, user: newUser.rows[0], is_new: true });
    }
    var user = existing.rows[0];
    // Monthly free reset check could go here
    res.json({ success: true, user: user, is_new: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/credits/check', rateLimiter, userAuth, async function(req, res) {
  try {
    var cost = parseInt(req.body.cost) || 1;
    var user = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [req.telegramId]);
    if (user.rows.length === 0) return res.json({ success: false, message: 'User not found' });
    if (user.rows[0].credits < cost) return res.json({ success: false, message: '❌ اعتبار کافی نیست. برای خرید به @King_of_elessar پیام دهید.', balance: user.rows[0].credits, telegram_support: '@King_of_elessar' });
    res.json({ success: true, balance: user.rows[0].credits, cost: cost, sufficient: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/credits/consume', rateLimiter, userAuth, async function(req, res) {
  try {
    var cost = parseInt(req.body.cost) || 1;
    var desc = req.body.description || 'Invoice creation';
    var user = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [req.telegramId]);
    if (user.rows.length === 0) return res.json({ success: false, message: 'User not found' });
    if (user.rows[0].credits < cost) return res.json({ success: false, message: 'Insufficient credits', balance: user.rows[0].credits });
    var newBal = user.rows[0].credits - cost;
    await pool.query("UPDATE si_users SET credits=$1 WHERE telegram_id=$2", [newBal, req.telegramId]);
    await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'consume', -$2, $3, $4)", [req.telegramId, cost, newBal, desc]);
    res.json({ success: true, consumed: cost, balance: newBal });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 📊 HEALTH & ADMIN
// ═══════════════════════════════════════
app.get('/api/health', async function(req, res) {
  try {
    await pool.query('SELECT 1');
    var users = await pool.query('SELECT COUNT(*) as c FROM si_users');
    var invoices = await pool.query('SELECT COUNT(*) as c FROM si_invoices');
    res.json({ status: 'ok', db: 'connected', model: 'credit-based', users: parseInt(users.rows[0].c), invoices: parseInt(invoices.rows[0].c), support: '@King_of_elessar' });
  } catch(e) { res.status(500).json({ status: 'error', db: 'disconnected', error: e.message }); }
});

app.post('/api/admin/add-credits', adminAuth, async function(req, res) {
  var tgId = String(req.body.telegram_id || '').trim();
  var amount = parseInt(req.body.amount) || 0;
  if (!tgId || amount <= 0) return res.status(400).json({ error: 'Invalid data' });
  try {
    var ex = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [tgId]);
    if (ex.rows.length === 0) await pool.query("INSERT INTO si_users (telegram_id, credits) VALUES ($1, 0)", [tgId]);
    await pool.query("UPDATE si_users SET credits=credits+$1 WHERE telegram_id=$2", [amount, tgId]);
    var upd = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [tgId]);
    await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'admin_add', $2, $3, 'Manual add')", [tgId, amount, upd.rows[0].credits]);
    res.json({ success: true, telegram_id: tgId, added: amount, new_balance: upd.rows[0].credits });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/stats', adminAuth, async function(req, res) {
  try {
    var u = await pool.query('SELECT COUNT(*) as c FROM si_users');
    var i = await pool.query('SELECT COUNT(*) as c FROM si_invoices');
    res.json({ users: parseInt(u.rows[0].c), invoices: parseInt(i.rows[0].c) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 🚀 START
// ═══════════════════════════════════════
initDB().then(function() {
  app.listen(PORT, function() {
    console.log('Smart Invoice Server v1 (Credit-Based)');
    console.log('Port ' + PORT);
    console.log('Admin Secret: ' + (ADMIN_SECRET ? 'SET' : 'NOT SET ⚠️'));
  });
}).catch(function(err) { console.error('DB Init Failed: ' + err.message); process.exit(1); });
