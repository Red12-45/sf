// routes/staticPages.js
const express = require('express');
const router  = express.Router();

/* Landing marketing page */
router.get('/', (req, res) => {
  if (req.session?.user) return res.redirect('/dashboard');
  res.render('landing');
});

/* Docs & support */
router.get('/customerservice',  (_req, res) => res.render('cs'));
router.get('/documentation',    (_req, res) => res.render('documentations'));

/* Legal */
router.get('/terms-and-conditions', (req, res) =>
  res.render('tnc', { host: req.get('host') })
);
router.get('/privacy',  (_req, res) => res.render('privacy'));

/* Lightweight health-check */
router.get('/healthz',  (_req, res) => res.status(200).send('OK'));

module.exports = router;
