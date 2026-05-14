const express = require('express');
const session = require('express-session');
const cors = require('cors');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'db.json');

if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], exchanges: [] }));
}

const readDB = () => JSON.parse(fs.readFileSync(DB_PATH));
const writeDB = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

app.use(cors({ origin: 'http://localhost:5500', credentials: true }));
app.use(express.json());
app.use(session({
  secret: 'bluelock_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

const isAuth = (req, res, next) => {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Not authenticated' });
};

const isAdmin = (req, res, next) => {
  if (req.session.email === 'admin@bluelock.mg') return next();
  res.status(403).json({ error: 'Forbidden' });
};

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const db = readDB();
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), name, email, password: hash, tokens: 0, created_at: new Date().toISOString() };
  db.users.push(user);
  writeDB(db);
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.email === email);
  if (!user ||!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  req.session.email = user.email;
  res.json({ success: true, user: { id: user.id, email: user.email, name: user.name, tokens: user.tokens } });
});

app.get('/api/me', isAuth, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.session.userId);
  res.json({ logged_in: true, user: { id: user.id, email: user.email, name: user.name, tokens: user.tokens } });
});

app.post('/api/claim', isAuth, (req, res) => {
  const db = readDB();
  const last = db.exchanges.filter(e => e.user_id === req.session.userId && e.game === 'daily').pop();
  if (last && Date.now() - new Date(last.created_at).getTime() < 86400000) return res.json({ error: 'Already claimed today' });
  const user = db.users.find(u => u.id === req.session.userId);
  user.tokens += 5;
  db.exchanges.push({ id: Date.now(), user_id: user.id, game: 'daily', reward: 5, status: 'confirme', created_at: new Date().toISOString() });
  writeDB(db);
  res.json({ success: true, tokens: 5 });
});

app.post('/api/exchange', isAuth, (req, res) => {
  const { game, cost, reward, uid, pseudo } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (user.tokens < cost) return res.json({ error: 'Not enough tokens' });
  user.tokens -= cost;
  db.exchanges.push({ id: Date.now(), user_id: user.id, game, reward, uid, pseudo, status: 'en_attente', created_at: new Date().toISOString() });
  writeDB(db);
  res.json({ success: true });
});

app.get('/api/history', isAuth, (req, res) => {
  const db = readDB();
  const exchanges = db.exchanges.filter(e => e.user_id === req.session.userId).reverse();
  res.json({ exchanges });
});

app.get('/api/admin/users', isAuth, isAdmin, (req, res) => {
  const db = readDB();
  res.json({ users: db.users.map(u => ({ id: u.id, email: u.email, name: u.name, tokens: u.tokens, created_at: u.created_at })) });
});

app.get('/api/admin/exchanges', isAuth, isAdmin, (req, res) => {
  const db = readDB();
  const exchanges = db.exchanges.map(e => {
    const user = db.users.find(u => u.id === e.user_id);
    return {...e, email: user?.email, name: user?.name };
  }).reverse();
  res.json({ exchanges });
});

app.post('/api/admin/confirm', isAuth, isAdmin, (req, res) => {
  const db = readDB();
  const ex = db.exchanges.find(e => e.id === req.body.id);
  if (ex) ex.status = 'confirme';
  writeDB(db);
  res.json({ success: true });
});

app.post('/api/admin/give-tokens', isAuth, isAdmin, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.email === req.body.email);
  if (user) user.tokens += req.body.amount;
  writeDB(db);
  res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => console.log('Server running on http://localhost:' + PORT));
