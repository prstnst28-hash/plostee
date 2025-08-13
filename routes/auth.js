const express = require('express');

module.exports = (db, bcrypt) => {
  const router = express.Router();

  function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
  }

  router.get('/register', (req, res) => {
      res.render('register', { title: 'Register' });
  });

  router.post('/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) return res.render('register', { error: 'Email & password required.' });
    db.get(`SELECT id FROM users WHERE email = ?`, [email], async (err, row) => {
      if (row) return res.render('register', { error: 'Email already registered.' });
      const hash = await bcrypt.hash(password, 10);
      db.run(
        `INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)`,
        [email, hash, name || null, 'user'],
        function () {
          req.session.user = { id: this.lastID, email, role: 'user', name: name || null };
          res.redirect('/');
        }
      );
    });
  });

  router.get('/login', (req, res) => res.render('login', { error: null }));

  router.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
      if (!user) return res.render('login', { error: 'Invalid credentials.' });
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.render('login', { error: 'Invalid credentials.' });
      req.session.user = { id: user.id, email: user.email, role: user.role, name: user.name };
      res.redirect('/');
    });
  });

  router.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  // dashboard
  router.get('/dashboard', requireAuth, (req, res) => {
    db.all(`SELECT * FROM plugins WHERE author_id = ? ORDER BY id DESC`, [req.session.user.id], (err, plugins) => {
      res.render('dashboard', { plugins: plugins || [] });
    });
  });

  // change password
  router.get('/account/password', requireAuth, (req, res) => {
    res.render('login', { error: 'Use the form below to change password.' }); // simple message
  });

  router.post('/account/password', requireAuth, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.send('Missing fields.');
    db.get(`SELECT * FROM users WHERE id = ?`, [req.session.user.id], async (err, user) => {
      if (!user) return res.send('User not found.');
      const ok = await bcrypt.compare(oldPassword, user.password);
      if (!ok) return res.send('Wrong current password.');
      const hash = await bcrypt.hash(newPassword, 10);
      db.run(`UPDATE users SET password = ? WHERE id = ?`, [hash, user.id], () => res.redirect('/dashboard'));
    });
  });

  return router;
};
