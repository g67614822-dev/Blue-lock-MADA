import express from 'express';
import session from 'express-session';
import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import cors from 'cors';

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

// DB SQLite auto-créée
const db = new Database('db.sqlite');

// Création des tables si elles existent pas
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
app.use(cors({
  origin: 'http://localhost:5500',
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: 'bluelock_secret_key_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
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
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  const existing = db.prepare('SELECT id FROM users WHERE email =?').get(email);
  if (existing) return res.status(400).json({ error: 'Email already exists' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const result = db.prepare('INSERT INTO users (name, email, password) VALUES (?,?,?)')
    .run(name, email, hash);

  res.json({ success: true, userId: result.lastInsertRowid });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email =?').get(email);

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  req.session.userId = user.id;
  req.session.email = user.email;

  res.json({
    success: true,
    user: { id: user.id, email: user.email, name: user.name, tokens: user.tokens }
  });
});

app.get('/api/me', isAuth, (req, res) => {
  const user = db.prepare('SELECT id, email, name, tokens FROM users WHERE id =?').get(req.session.userId);
  res.json({ logged_in: true, user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// User Routes
app.post('/api/claim', isAuth, (req, res) => {
  const userId = req.session.userId;

  const last = db.prepare(
    "SELECT created_at FROM exchanges WHERE user_id =? AND game = 'daily' ORDER BY id DESC LIMIT 1"
  ).get(userId);

  if (last) {
    const diff = Date.now() - new Date(last.created_at).getTime();
    if (diff < 86400000) return res.json({ error: 'Already claimed today' });
  }

  db.prepare('UPDATE users SET tokens = tokens + 5 WHERE id =?').run(userId);
  db.prepare("INSERT INTO exchanges (user_id, game, reward, status) VALUES (?, 'daily', 5, 'confirme')")
    .run(userId);

  res.json({ success: true, tokens: 5 });
});

app.post('/api/exchange', isAuth, (req, res) => {
  const { game, cost, reward, uid, pseudo } = req.body;
  const userId = req.session.userId;

  const user = db.prepare('SELECT tokens FROM users WHERE id =?').get(userId);
  if (user.tokens < cost) return res.json({ error: 'Not enough tokens' });

  db.prepare('UPDATE users SET tokens = tokens -? WHERE id =?').run(cost, userId);
  db.prepare(
    'INSERT INTO exchanges (user_id, game, reward, uid, pseudo, status) VALUES (?,?,?,?,?, "en_attente")'
  ).run(userId, game, reward, uid, pseudo);

  res.json({ success: true });
});

app.get('/api/history', isAuth, (req, res) => {
  const exchanges = db.prepare(
    'SELECT * FROM exchanges WHERE user_id =? ORDER BY id DESC'
  ).all(req.session.userId);
  res.json({ exchanges });
});

// Admin Routes
app.get('/api/admin/users', isAdmin, (req, res) => {
  const users = db.prepare('SELECT id, email, name, tokens, created_at FROM users ORDER BY id DESC').all();
  res.json({ users });
});

app.get('/api/admin/exchanges', isAdmin, (req, res) => {
  const exchanges = db.prepare(
    'SELECT e.*, u.email, u.name FROM exchanges e JOIN users u ON e.user_id = u.id ORDER BY e.id DESC'
  ).all();
  res.json({ exchanges });
});

app.post('/api/admin/confirm', isAdmin, (req, res) => {
  const { id } = req.body;
  db.prepare('UPDATE exchanges SET status = "confirme" WHERE id =?').run(id);
  res.json({ success: true });
});

app.post('/api/admin/give-tokens', isAdmin, (req, res) => {
  const { email, amount } = req.body;
  db.prepare('UPDATE users SET tokens = tokens +? WHERE email =?').run(amount, email);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Admin login: admin@bluelock.mg / crée-le via register');
});