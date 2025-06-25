// routes/billing.js
const express = require('express');

module.exports = function makeBillingRoutes({ db, isAuthenticated, requireMaster }) {
  const router = express.Router();

  // GET /billing
  router.get('/billing', isAuthenticated, requireMaster, async (req, res) => {
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

      res.render('billing', { user: userData });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  return router;
};
