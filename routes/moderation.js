const express = require('express');

module.exports = (db) => {
  const router = express.Router();

  function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
  }
  function requireMod(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    const role = req.session.user.role;
    if (role !== 'admin' && role !== 'moderator') return res.status(403).send('Forbidden');
    next();
  }

  // view queue
  router.get('/', requireAuth, requireMod, (req, res) => {
    db.all(
      `SELECT p.*, u.email AS author_email 
       FROM plugins p LEFT JOIN users u ON p.author_id = u.id
       WHERE status = 'pending' ORDER BY p.id ASC`,
      (err, rows) => {
        res.render('moderation', { pending: rows || [] });
      }
    );
  });

  // approve
  router.post('/:id/approve', requireAuth, requireMod, (req, res) => {
    const id = parseInt(req.params.id);
    db.run(
      `UPDATE plugins SET status = 'approved', reject_reason = NULL WHERE id = ?`,
      [id],
      () => res.redirect('/moderation')
    );
  });

  // reject
  router.post('/:id/reject', requireAuth, requireMod, (req, res) => {
    const id = parseInt(req.params.id);
    const reason = (req.body.reason || 'Rejected').slice(0, 500);
    db.run(
      `UPDATE plugins SET status = 'rejected', reject_reason = ? WHERE id = ?`,
      [reason, id],
      () => res.redirect('/moderation')
    );
  });

  return router;
};
