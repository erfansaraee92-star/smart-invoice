require('dotenv').config();
var express = require('express');
var Pool = require('pg').Pool;
var cors = require('cors');
var bcrypt = require('bcryptjs');

var app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

var PORT = process.env.PORT || 3000;
var ADMIN_SECRET = process.env.ADMIN_SECRET || '';
var FREE_SIGNUP_CREDITS = parseInt(process.env.FREE_CREDITS) || 3;

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

// احراز هویت کاربر با هدر Authorization
async function userAuth(req, res, next) {
  var authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token required' });
  }
  var token = authHeader.split(' ')[1];
  try {
    var result = await pool.query("SELECT email FROM si_users WHERE api_token=$1", [token]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid or expired session' });
    req.userEmail = result.rows[0].email;
    next();
  } catch(e) { res.status(500).json({ error: 'Auth error' }); }
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
  // جدول کاربران با فیلدهای ایمیل، پسورد هش شده و توکن نشست
  await pool.query("CREATE TABLE IF NOT EXISTS si_users (email VARCHAR(255) PRIMARY KEY, password_hash VARCHAR(255) NOT NULL, name VARCHAR(200) DEFAULT '', credits INTEGER DEFAULT 0, api_token VARCHAR(64), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  
  await pool.query("CREATE TABLE IF NOT EXISTS si_clients (id SERIAL PRIMARY KEY, owner_email VARCHAR(255) REFERENCES si_users(email), name VARCHAR(200) NOT NULL, phone VARCHAR(30), email VARCHAR(200), address TEXT, tax_code VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  
  await pool.query("CREATE TABLE IF NOT EXISTS si_invoices (id SERIAL PRIMARY KEY, owner_email VARCHAR(255) REFERENCES si_users(email), client_id INTEGER REFERENCES si_clients(id), invoice_number VARCHAR(50), title VARCHAR(300), currency VARCHAR(10) DEFAULT 'IRR', subtotal BIGINT DEFAULT 0, tax_rate INTEGER DEFAULT 9, tax_amount BIGINT DEFAULT 0, discount BIGINT DEFAULT 0, total BIGINT DEFAULT 0, status VARCHAR(20) DEFAULT 'draft', template VARCHAR(30) DEFAULT 'classic', notes TEXT, credit_cost INTEGER DEFAULT 1, issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, due_date DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  
  await pool.query("CREATE TABLE IF NOT EXISTS si_items (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES si_invoices(id) ON DELETE CASCADE, description VARCHAR(500) NOT NULL, quantity INTEGER DEFAULT 1, unit_price BIGINT DEFAULT 0, amount BIGINT DEFAULT 0)");
  
  await pool.query("CREATE TABLE IF NOT EXISTS si_transactions (id SERIAL PRIMARY KEY, owner_email VARCHAR(255) REFERENCES si_users(email), type VARCHAR(20) NOT NULL, amount INTEGER NOT NULL, balance_after INTEGER NOT NULL, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  
  console.log('Smart Invoice Server v2 (Email/Password Auth)');
}

// ═══════════════════════════════════════
// 👤 AUTH ENDPOINTS (REGISTER / LOGIN)
// ═══════════════════════════════════════
app.post('/api/auth/register', rateLimiter, async function(req, res) {
  var email = (req.body.email || '').toLowerCase().trim();
  var password = req.body.password || '';
  var name = req.body.name || '';
  
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    var existing = await pool.query("SELECT email FROM si_users WHERE email=$1", [email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'این ایمیل قبلاً ثبت شده است.' });

    var hash = await bcrypt.hash(password, 10);
    var token = require('crypto').randomBytes(32).toString('hex');
    
    await pool.query("INSERT INTO si_users (email, password_hash, name, credits, api_token) VALUES ($1, $2, $3, $4, $5)", [email, hash, name, FREE_SIGNUP_CREDITS, token]);
    await pool.query("INSERT INTO si_transactions (owner_email, type, amount, balance_after, description) VALUES ($1, 'signup_bonus', $2, $2, 'اعتبار هدیه ثبت‌نام')", [email, FREE_SIGNUP_CREDITS]);

    res.json({ success: true, message: 'ثبت‌نام موفق! وارد شوید.', token: token, email: email, credits: FREE_SIGNUP_CREDITS });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', rateLimiter, async function(req, res) {
  var email = (req.body.email || '').toLowerCase().trim();
  var password = req.body.password || '';
  
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  try {
    var user = await pool.query("SELECT * FROM si_users WHERE email=$1", [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'ایمیل یا رمز عبور اشتباه است.' });

    var valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'ایمیل یا رمز عبور اشتباه است.' });

    // تولید توکن جدید برای هر بار ورود
    var newToken = require('crypto').randomBytes(32).toString('hex');
    await pool.query("UPDATE si_users SET api_token=$1 WHERE email=$2", [newToken, email]);

    res.json({ success: true, token: newToken, email: email, name: user.rows[0].name, credits: user.rows[0].credits });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/me', userAuth, async function(req, res) {
  try {
    var user = await pool.query("SELECT email, name, credits, created_at FROM si_users WHERE email=$1", [req.userEmail]);
    res.json({ success: true, user: user.rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 💰 CREDITS ENDPOINTS
// ═══════════════════════════════════════
app.post('/api/credits/check', userAuth, async function(req, res) {
  try {
    var cost = parseInt(req.body.cost) || 1;
    var user = await pool.query("SELECT credits FROM si_users WHERE email=$1", [req.userEmail]);
    if (user.rows[0].credits < cost) return res.json({ success: false, message: '❌ اعتبار کافی نیست. لطفاً بسته اعتباری تهیه کنید.', balance: user.rows[0].credits });
    res.json({ success: true, balance: user.rows[0].credits, sufficient: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/credits/consume', userAuth, async function(req, res) {
  try {
    var cost = parseInt(req.body.cost) || 1;
    var user = await pool.query("SELECT credits FROM si_users WHERE email=$1", [req.userEmail]);
    if (user.rows[0].credits < cost) return res.json({ success: false, message: 'Insufficient credits' });
    
    var newBal = user.rows[0].credits - cost;
    await pool.query("UPDATE si_users SET credits=$1 WHERE email=$2", [newBal, req.userEmail]);
    await pool.query("INSERT INTO si_transactions (owner_email, type, amount, balance_after, description) VALUES ($1, 'consume', -$2, $3, 'ساخت فاکتور')", [req.userEmail, cost, newBal]);
    
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
    res.json({ status: 'ok', db: 'connected', model: 'credit-based', auth: 'email-password', users: parseInt(users.rows[0].c) });
  } catch(e) { res.status(500).json({ status: 'error', db: 'disconnected' }); }
});

app.post('/api/admin/add-credits', adminAuth, async function(req, res) {
  var email = (req.body.email || '').toLowerCase().trim();
  var amount = parseInt(req.body.amount) || 0;
  if (!email || amount <= 0) return res.status(400).json({ error: 'Invalid data' });
  try {
    var ex = await pool.query("SELECT credits FROM si_users WHERE email=$1", [email]);
    if (ex.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    
    var newBal = ex.rows[0].credits + amount;
    await pool.query("UPDATE si_users SET credits=$1 WHERE email=$2", [newBal, email]);
    await pool.query("INSERT INTO si_transactions (owner_email, type, amount, balance_after, description) VALUES ($1, 'admin_add', $2, $3, 'شارژ توسط ادمین')", [email, amount, newBal]);
    
    res.json({ success: true, email: email, added: amount, new_balance: newBal });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════
// 🚀 START
// ═══════════════════════════════════════
initDB().then(function() {
  app.listen(PORT, function() {
    console.log('Smart Invoice Server v2 (Email/Password Auth)');
    console.log('Port ' + PORT);
  });
}).catch(function(err) { console.error('DB Init Failed:', err.message); process.exit(1); });
