const express = require('express');
const multer = require('multer');
const path = require('path');
const fetch = require('node-fetch');
const { marked } = require('marked');
const sanitizeHtml = require('sanitize-html');
const fs = require('fs');

const uploadsDir = path.join(__dirname, '..', 'public', 'uploads');

// storage with file extension
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const safeExt = ext === '.png' || ext === '.jpg' || ext === '.jpeg' ? ext : '.png';
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${safeExt}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 300 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/png', 'image/jpeg'].includes(file.mimetype);
    cb(ok ? null : new Error('Only PNG/JPEG allowed'), ok);
  }
});

function renderMarkdown(md) {
  const html = marked.parse(md || '');
  return sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1', 'h2', 'img']),
    allowedAttributes: {
      a: ['href', 'name', 'target', 'rel'],
      img: ['src', 'alt']
    },
    transformTags: {
      a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' })
    }
  });
}

module.exports = (db) => {
  const router = express.Router();

  function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
  }

  // new/publish form
  router.get('/new', requireAuth, (req, res) => {
    res.render('upload', { error: null });
  });

  router.post('/new', requireAuth, upload.single('icon'), async (req, res) => {
    const { title, shortdesc, fulldesc, changelog, tags, versions, link } = req.body;

    if (!title || !shortdesc || !fulldesc || !link) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.render('upload', { error: 'Missing required fields.' });
    }
    if (shortdesc.length > 180) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.render('upload', { error: 'Short description must be ≤ 180 characters.' });
    }

    // check external URL (HEAD fallback GET)
    let okUrl = false;
    try {
      const head = await fetch(link, { method: 'HEAD' });
      okUrl = head.ok;
    } catch {}
    if (!okUrl) {
      try {
        const getr = await fetch(link, { method: 'GET' });
        okUrl = getr.ok;
      } catch {}
    }
    if (!okUrl) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.render('upload', { error: 'External URL unreachable.' });
    }

    const icon = req.file ? `/uploads/${path.basename(req.file.path)}` : '/placeholder.svg';

    db.run(
      `INSERT INTO plugins (title, shortdesc, fulldesc, changelog, tags, versions, icon, link, status, author_id) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
      [title, shortdesc, fulldesc, changelog || '', tags || '', versions || '', icon, link, req.session.user.id],
      () => res.redirect('/dashboard')
    );
  });

  // plugin detail
  router.get('/:id', (req, res) => {
    const id = parseInt(req.params.id);
    db.get(
      `SELECT p.*, u.email AS author_email 
       FROM plugins p LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?`,
      [id],
      (err, p) => {
        if (!p) return res.status(404).send('Not found');
        // show non-approved only to author/admin/mod
        const canSeePending =
          req.session.user &&
          (req.session.user.role === 'admin' ||
            req.session.user.role === 'moderator' ||
            req.session.user.id === p.author_id);
        if (p.status !== 'approved' && !canSeePending) return res.status(403).send('Not available');

        const htmlDesc = renderMarkdown(p.fulldesc);
        const htmlChangelog = renderMarkdown(p.changelog || '');
        res.render('plugin_detail', { plugin: p, htmlDesc, htmlChangelog });
      }
    );
  });

  return router;
};
