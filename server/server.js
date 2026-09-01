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
var TELEGRAM_ADMIN_ID = process.env.TELEGRAM_ADMIN_ID || '';
var FREE_MONTHLY_CREDITS = parseInt(process.env.FREE_CREDITS) || 3;

var pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ═══════════════════════════════════════
// 🔒 AUTH MIDDLEWARE
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
  // Users table (linked to Telegram ID)
  await pool.query("CREATE TABLE IF NOT EXISTS si_users (telegram_id VARCHAR(50) PRIMARY KEY, name VARCHAR(200) DEFAULT '', credits INTEGER DEFAULT 0, free_credits_used INTEGER DEFAULT 0, last_free_reset DATE DEFAULT CURRENT_DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

  // Clients table (customer database for invoices)
  await pool.query("CREATE TABLE IF NOT EXISTS si_clients (id SERIAL PRIMARY KEY, telegram_id VARCHAR(50) REFERENCES si_users(telegram_id), name VARCHAR(200) NOT NULL, phone VARCHAR(30), email VARCHAR(200), address TEXT, tax_code VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

  // Invoices table
  await pool.query("CREATE TABLE IF NOT EXISTS si_invoices (id SERIAL PRIMARY KEY, telegram_id VARCHAR(50) REFERENCES si_users(telegram_id), client_id INTEGER REFERENCES si_clients(id), invoice_number VARCHAR(50), title VARCHAR(300), currency VARCHAR(10) DEFAULT 'IRR', subtotal BIGINT DEFAULT 0, tax_rate INTEGER DEFAULT 9, tax_amount BIGINT DEFAULT 0, discount BIGINT DEFAULT 0, total BIGINT DEFAULT 0, status VARCHAR(20) DEFAULT 'draft', template VARCHAR(30) DEFAULT 'classic', notes TEXT, credit_cost INTEGER DEFAULT 1, issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, due_date DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

  // Invoice items
  await pool.query("CREATE TABLE IF NOT EXISTS si_items (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES si_invoices(id) ON DELETE CASCADE, description VARCHAR(500) NOT NULL, quantity INTEGER DEFAULT 1, unit_price BIGINT DEFAULT 0, amount BIGINT DEFAULT 0)");

  // Credit transactions log
  await pool.query("CREATE TABLE IF NOT EXISTS si_transactions (id SERIAL PRIMARY KEY, telegram_id VARCHAR(50) REFERENCES si_users(telegram_id), type VARCHAR(20) NOT NULL, amount INTEGER NOT NULL, balance_after INTEGER NOT NULL, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

  console.log('Smart Invoice DB initialized (Credit-Based Model)');
}

// ═══════════════════════════════════════
// 👤 USER: GET OR CREATE PROFILE
// ═══════════════════════════════════════
app.post('/api/user/profile', rateLimiter, userAuth, async function(req, res) {
  try {
    var tgId = req.telegramId;
    var existing = await pool.query("SELECT * FROM si_users WHERE telegram_id=$1", [tgId]);

    if (existing.rows.length === 0) {
      // New user: give free credits
      await pool.query("INSERT INTO si_users (telegram_id, credits, free_credits_used) VALUES ($1, $2, 0)", [tgId, FREE_MONTHLY_CREDITS]);
      await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'free_grant', $2, $2, 'Free monthly credits')", [tgId, FREE_MONTHLY_CREDITS]);
      var newUser = await pool.query("SELECT * FROM si_users WHERE telegram_id=$1", [tgId]);
      return res.json({ success: true, user: newUser.rows[0], is_new: true });
    }

    // Check monthly free credit reset
    var user = existing.rows[0];
    var today = new Date().toISOString().split('T')[0];
    if (user.last_free_reset && user.last_free_reset.toISOString().split('T')[0] !== today) {
      var lastReset = new Date(user.last_free_reset);
      var now = new Date();
      if (now.getMonth() !== lastReset.getMonth() || now.getFullYear() !== lastReset.getFullYear()) {
        var newBalance = user.credits + FREE_MONTHLY_CREDITS;
        await pool.query("UPDATE si_users SET credits=$1, free_credits_used=0, last_free_reset=CURRENT_DATE WHERE telegram_id=$2", [newBalance, tgId]);
        await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'free_reset', $2, $3, 'Monthly free credits reset')", [tgId, FREE_MONTHLY_CREDITS, newBalance]);
        user.credits = newBalance;
        user.free_credits_used = 0;
      }
    }

    res.json({ success: true, user: user, is_new: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 💰 USER: CHECK CREDITS & CONSUME
// ═══════════════════════════════════════
app.post('/api/credits/check', rateLimiter, userAuth, async function(req, res) {
  try {
    var cost = parseInt(req.body.cost) || 1;
    var user = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [req.telegramId]);
    if (user.rows.length === 0) return res.json({ success: false, message: 'User not found' });
    var balance = user.rows[0].credits;
    if (balance < cost) {
      return res.json({ success: false, message: '❌ اعتبار کافی نیست. برای خرید اعتبار به @King_of_elessar پیام دهید.', balance: balance, needed: cost, telegram_support: '@King_of_elessar' });
    }
    res.json({ success: true, balance: balance, cost: cost, sufficient: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/credits/consume', rateLimiter, userAuth, async function(req, res) {
  try {
    var cost = parseInt(req.body.cost) || 1;
    var description = req.body.description || 'Invoice creation';
    var user = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [req.telegramId]);
    if (user.rows.length === 0) return res.json({ success: false, message: 'User not found' });
    if (user.rows[0].credits < cost) return res.json({ success: false, message: 'Insufficient credits', balance: user.rows[0].credits });

    var newBalance = user.rows[0].credits - cost;
    await pool.query("UPDATE si_users SET credits=$1 WHERE telegram_id=$2", [newBalance, req.telegramId]);
    await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'consume', -$2, $3, $4)", [req.telegramId, cost, newBalance, description]);

    res.json({ success: true, consumed: cost, balance: newBalance });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 📊 HEALTH
// ═══════════════════════════════════════
app.get('/api/health', async function(req, res) {
  try {
    await pool.query('SELECT 1');
    var users = await pool.query('SELECT COUNT(*) as c FROM si_users');
    var invoices = await pool.query('SELECT COUNT(*) as c FROM si_invoices');
    res.json({ status: 'ok', db: 'connected', model: 'credit-based', users: parseInt(users.rows[0].c), invoices: parseInt(invoices.rows[0].c), support: '@King_of_elessar' });
  } catch(e) { res.status(500).json({ status: 'error', db: 'disconnected', error: e.message }); }
});

// ═══════════════════════════════════════
// 🔑 ADMIN: ADD CREDITS TO USER
// ═══════════════════════════════════════
app.post('/api/admin/add-credits', adminAuth, async function(req, res) {
  var telegramId = String(req.body.telegram_id || '').trim();
  var amount = parseInt(req.body.amount) || 0;
  var note = req.body.note || 'Manual credit add';
  if (!telegramId || amount <= 0) return res.status(400).json({ error: 'Invalid telegram_id or amount' });

  try {
    // Ensure user exists
    var existing = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [telegramId]);
    if (existing.rows.length === 0) {
      await pool.query("INSERT INTO si_users (telegram_id, credits) VALUES ($1, 0)", [telegramId]);
    }

    await pool.query("UPDATE si_users SET credits=credits+$1 WHERE telegram_id=$2", [amount, telegramId]);
    var updated = await pool.query("SELECT credits FROM si_users WHERE telegram_id=$1", [telegramId]);
    var newBalance = updated.rows[0].credits;

    await pool.query("INSERT INTO si_transactions (telegram_id, type, amount, balance_after, description) VALUES ($1, 'admin_add', $2, $3, $4)", [telegramId, amount, newBalance, note]);

    res.json({ success: true, telegram_id: telegramId, added: amount, new_balance: newBalance });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 🔑 ADMIN: STATS
// ═══════════════════════════════════════
app.get('/api/admin/stats', adminAuth, async function(req, res) {
  try {
    var users = await pool.query('SELECT COUNT(*) as c FROM si_users');
    var invoices = await pool.query('SELECT COUNT(*) as c FROM si_invoices');
    var totalCredits = await pool.query('SELECT COALESCE(SUM(credits),0) as c FROM si_users');
    var revenue = await pool.query("SELECT COUNT(*) as c FROM si_transactions WHERE type='admin_add'");
    res.json({ users: parseInt(users.rows[0].c), invoices: parseInt(invoices.rows[0].c), total_credits_in_circulation: parseInt(totalCredits.rows[0].c), credit_purchases: parseInt(revenue.rows[0].c) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 🔑 ADMIN: LIST USERS
// ═══════════════════════════════════════
app.get('/api/admin/users', adminAuth, async function(req, res) {
  try {
    var page = parseInt(req.query.page) || 1;
    var limit = Math.min(parseInt(req.query.limit) || 30, 100);
    var offset = (page - 1) * limit;
    var countResult = await pool.query('SELECT COUNT(*) as c FROM si_users');
    var rows = await pool.query("SELECT telegram_id, name, credits, free_credits_used, last_free_reset, created_at FROM si_users ORDER BY created_at DESC LIMIT $1 OFFSET $2", [limit, offset]);
    res.json({ users: rows.rows, total: parseInt(countResult.rows[0].c), page: page, limit: limit });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 🔑 ADMIN: USER TRANSACTIONS
// ═══════════════════════════════════════
app.get('/api/admin/transactions/:telegramId', adminAuth, async function(req, res) {
  try {
    var rows = await pool.query("SELECT * FROM si_transactions WHERE telegram_id=$1 ORDER BY created_at DESC LIMIT 50", [req.params.telegramId]);
    res.json(rows.rows);
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
    console.log('Support: @King_of_elessar');
  });
}).catch(function(err) {
  console.error('DB Init Failed: ' + err.message);
  process.exit(1);
});
