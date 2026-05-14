const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

// DB SQLite
const db = new sqlite3.Database('db.sqlite');

// Création des tables
db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    tokens INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS exchanges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    game TEXT,
    reward INTEGER,
    uid TEXT,
    pseudo TEXT,
    status TEXT DEFAULT 'en_attente',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Middleware
app.use(cors({ origin: 'http://localhost:5500', credentials: true }));
app.use(express.json());
app.use(session({
  secret: 'bluelock_secret_key_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

// Middleware auth
const isAuth = (req, res, next) => {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Not authenticated' });
};

const isAdmin = (req, res, next) => {
  if (req.session.userId && req.session.email === 'admin@bluelock.mg') return next();
  res.status(403).json({ error: 'Forbidden' });
};

// Routes Auth
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name ||!email ||!password) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT id FROM users WHERE email =?', [email], async (err, existing) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run('INSERT INTO users (name, email, password) VALUES (?,?,?)', [name, email, hash], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true, userId: this.lastID });
    });
  });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email =?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    req.session.userId = user.id;
    req.session.email = user.email;
    res.json({ success: true, user: { id: user.id, email: user.email, name: user.name, tokens: user.tokens } });
  });
});

app.get('/api/me', isAuth, (req, res) => {
  db.get('SELECT id, email, name, tokens FROM users WHERE id =?', [req.session.userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ logged_in: true, user });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// User Routes
app.post('/api/claim', isAuth, (req, res) => {
  const userId = req.session.userId;
  db.get("SELECT created_at FROM exchanges WHERE user_id =? AND game = 'daily' ORDER BY id DESC LIMIT 1", [userId], (err, last) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (last) {
      const diff = Date.now() - new Date(last.created_at).getTime();
      if (diff < 86400000) return res.json({ error: 'Already claimed today' });
    }
    db.run('UPDATE users SET tokens = tokens + 5 WHERE id =?', [userId]);
    db.run("INSERT INTO exchanges (user_id, game, reward, status) VALUES (?, 'daily', 5, 'confirme')", [userId]);
    res.json({ success: true, tokens: 5 });
  });
});

app.post('/api/exchange', isAuth, (req, res) => {
  const { game, cost, reward, uid, pseudo } = req.body;
  const userId = req.session.userId;
  db.get('SELECT tokens FROM users WHERE id =?', [userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (user.tokens < cost) return res.json({ error: 'Not enough tokens' });
    db.run('UPDATE users SET tokens = tokens -? WHERE id =?', [cost, userId]);
    db.run('INSERT INTO exchanges (user_id, game, reward, uid, pseudo, status) VALUES (?,?,?,?,?, "en_attente")',
      [userId, game, reward, uid, pseudo]);
    res.json({ success: true });
  });
});

app.get('/api/history', isAuth, (req, res) => {
  db.all('SELECT * FROM exchanges WHERE user_id =? ORDER BY id DESC', [req.session.userId], (err, exchanges) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ exchanges });
  });
});

// Admin Routes
app.get('/api/admin/users', isAdmin, (req, res) => {
  db.all('SELECT id, email, name, tokens, created_at FROM users ORDER BY id DESC', (err, users) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ users });
  });
});

app.get('/api/admin/exchanges', isAdmin, (req, res) => {
  db.all('SELECT e.*, u.email, u.name FROM exchanges e JOIN users u ON e.user_id = u.id ORDER BY e.id DESC', (err, exchanges) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ exchanges });
  });
});

app.post('/api/admin/confirm', isAdmin, (req, res) => {
  const { id } = req.body;
  db.run('UPDATE exchanges SET status = "confirme" WHERE id =?', [id], (err) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

app.post('/api/admin/give-tokens', isAdmin, (req, res) => {
  const { email, amount } = req.body;
  db.run('UPDATE users SET tokens = tokens +? WHERE email =?', [amount, email], (err) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
