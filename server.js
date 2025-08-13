const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const expressLayouts = require('express-ejs-layouts');

const app = express();
const PORT = process.env.PORT || 3001;

// ---- views / layouts ----
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout'); // uses views/layout.ejs

// ---- static & parsing ----
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// ---- sessions ----
app.use(session({
  secret: process.env.SESSION_SECRET || 'plost-dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

// ---- db ----
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// create tables + seed
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS plugins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      link TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // helper: seed user (if not exists)
  const seedUser = (username, email, rawPassword, role, plugins = []) => {
    db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
      if (err) return console.error('Seed user error:', err);
      if (row) return; // already exists

      bcrypt.hash(rawPassword, 10, (hashErr, hash) => {
        if (hashErr) return console.error(hashErr);
        db.run(
          'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
          [username, email, hash, role],
          function insertedUser(err2) {
            if (err2) return console.error(err2);
            const userId = this.lastID;
            if (plugins.length) {
              const stmt = db.prepare('INSERT INTO plugins (user_id, name, description, link) VALUES (?, ?, ?, ?)');
              plugins.forEach(p => stmt.run([userId, p.name, p.description, p.link || null]));
              stmt.finalize();
            }
            console.log(`✅ Seeded user: ${email} / ${rawPassword}`);
          }
        );
      });
    });
  };

  // admin + test user
  seedUser('Admin', 'admin@example.com', 'changeme', 'admin');
  seedUser('TestUser', '499lphg82@example.com', 'example', 'user', [
    { name: 'FastTP', description: 'Instant teleport plugin with cooldown.', link: 'https://modrinth.com' },
    { name: 'BetterMOTD', description: 'Customizable MOTD with gradients.', link: 'https://spigotmc.org' },
    { name: 'NoLag', description: 'Optimizes server tick performance.', link: 'https://github.com' }
  ]);
});

// ---- locals ----
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.title = 'Plost'; // default title
  next();
});

// ---- auth guard ----
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};

// ================= ROUTES =================

// Home (hero + newest plugins grid)
app.get('/', (req, res) => {
  db.all(
    `SELECT p.*, u.username 
     FROM plugins p 
     JOIN users u ON u.id = p.user_id
     ORDER BY p.created_at DESC
     LIMIT 12`,
    (err, plugins) => {
      if (err) plugins = [];
      res.render('index', { title: 'Home', plugins });
    }
  );
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.render('login', { title: 'Login', error: 'Server error.' });
    if (!user) return res.render('login', { title: 'Login', error: 'Invalid credentials.' });

    bcrypt.compare(password, user.password, (cmpErr, ok) => {
      if (cmpErr || !ok) return res.render('login', { title: 'Login', error: 'Invalid credentials.' });
      req.session.user = { id: user.id, email: user.email, role: user.role, username: user.username };
      res.redirect('/');
    });
  });
});

// Register
app.get('/register', (req, res) => {
  res.render('register', { title: 'Register', error: null });
});

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!email || !password) {
    return res.render('register', { title: 'Register', error: 'Email and password required.' });
  }
  bcrypt.hash(password, 10, (hashErr, hash) => {
    if (hashErr) return res.render('register', { title: 'Register', error: 'Server error.' });
    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username || null, email, hash],
      (err2) => {
        if (err2) return res.render('register', { title: 'Register', error: 'User already exists.' });
        res.redirect('/login');
      }
    );
  });
});

// Publish (create plugin) - simple form
app.get('/publish', requireAuth, (req, res) => {
  res.render('upload', { title: 'Publish', error: null });
});

app.post('/publish', requireAuth, (req, res) => {
  const { name, description, link } = req.body;
  if (!name || !description) {
    return res.render('upload', { title: 'Publish', error: 'Name and description required.' });
  }
  db.run(
    'INSERT INTO plugins (user_id, name, description, link) VALUES (?, ?, ?, ?)',
    [req.session.user.id, name, description, link || null],
    (err) => {
      if (err) return res.render('upload', { title: 'Publish', error: 'Server error.' });
      res.redirect('/my');
    }
  );
});

// My plugins
app.get('/my', requireAuth, (req, res) => {
  db.all(
    'SELECT * FROM plugins WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.user.id],
    (err, plugins) => {
      if (err) plugins = [];
      res.render('plugins', { title: 'My Plugins', plugins });
    }
  );
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// 404 (optional)
// app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => {
  console.log(`🚀 Plost running at http://localhost:${PORT}`);
});
