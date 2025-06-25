// routes/profile.js
const express = require('express');

module.exports = function makeProfileRoutes({ db, isAuthenticated, requireMaster }) {
  const router = express.Router();

  /* ─────────── GET /profile – editable version ─────────── */
  router.get('/profile', isAuthenticated, requireMaster, async (req, res) => {
    try {
      const doc = await db.collection('users')
                          .doc(req.session.user.id)
                          .get();
      if (!doc.exists) return res.status(404).send('User not found');

      const userData = doc.data();
      if (userData.subscriptionExpiry) {
        userData.subscriptionExpiry =
          (typeof userData.subscriptionExpiry.toDate === 'function')
            ? userData.subscriptionExpiry.toDate()
            : new Date(userData.subscriptionExpiry);
      }
      res.render('profile', {
        user        : userData,
        csrfToken   : req.csrfToken(),
        success     : req.query.success || false,
        errorMessage: null
      });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ─────────── POST /profile – save edits ─────────── */
  router.post('/profile', isAuthenticated, requireMaster, async (req, res) => {
    try {
      const {
        name         = '',
        businessName = '',
        phone        = '',
        address      = '',
        location     = '',
        gstNumber    = ''
      } = req.body;

      // identical validations
      if (name.trim().length < 2)
        return res.redirect('/profile?error=Name%20must%20be%20at%20least%202%20characters');

      if (businessName.length > 80 || address.length > 200)
        return res.redirect('/profile?error=Field%20length%20limit%20exceeded');
      if (gstNumber && !/^[0-9A-Z]{15}$/.test(gstNumber.trim()))
        return res.redirect('/profile?error=Invalid%20GST%20number%20format');

      const update = {
        name        : name.trim(),
        businessName: businessName.trim(),
        phone       : phone.trim(),
        address     : address.trim(),
        location    : location.trim(),
        ...(gstNumber.trim() && { gstNumber: gstNumber.trim().toUpperCase() }),
        updatedAt   : new Date()
      };

      await db.collection('users')
              .doc(req.session.user.id)
              .update(update);

      Object.assign(req.session.user, update);

      res.redirect('/profile?success=1');
    } catch (e) {
      console.error('/profile POST error:', e);
      res.status(500).render('profile', {
        user        : req.body,
        csrfToken   : req.csrfToken(),
        success     : false,
        errorMessage: 'Something went wrong. Please try again.'
      });
    }
  });

  return router;
};
