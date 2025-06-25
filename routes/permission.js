// routes/permission.js  – ROUTE-ONLY module (factory pattern)
const express = require('express');
const admin   = require('firebase-admin');

module.exports = function permissionRoutesFactory ({
  isAuthenticated,
  restrictRoute,
  cacheDel
}) {

  const router = express.Router();
  const db     = admin.firestore();

  /* ─────────── GET /permission ─────────── */
  router.get(
    '/permission',
    isAuthenticated,
    restrictRoute('/permission'),
    async (req, res) => {
      if (!req.session.user.isMaster)
        return res.status(403).send('Access denied');

      try {
        const doc = await db.collection('permissions')
                            .doc(req.session.user.accountId)
                            .get();
        const lockedRoutes   = doc.exists ? (doc.data().lockedRoutes   || []) : [];
        const blockedActions = doc.exists ? (doc.data().blockedActions || {}) : {};

        const availableRoutes = [
          { path:'/profit',        label:'Profit Report' },
          { path:'/sales',         label:'Sales Report',   canLockActions:true },
          { path:'/expense',       label:'Expense Report', canLockActions:true },
          { path:'/add-product',   label:'Add Product' },
          { path:'/view-products', label:'View Products',  canLockActions:true }
        ];

        res.render('permission', {
          lockedRoutes,
          blockedActions,
          availableRoutes,
          success : req.query.success,
          user    : req.session.user
        });
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

  /* ─────────── POST /permission ─────────── */
  router.post(
    '/permission',
    isAuthenticated,
    restrictRoute('/permission'),
    async (req, res) => {
      if (!req.session.user.isMaster)
        return res.status(403).send('Access denied');

      try {
        /* 1️⃣ Whole-route locks */
        let lockedRoutes = req.body.lockedRoutes || [];
        if (!Array.isArray(lockedRoutes)) lockedRoutes = [lockedRoutes];

        /* 2️⃣ Fine-grained locks  (format: "edit@@/sales") */
        const raw = Array.isArray(req.body.actionLocks)
                      ? req.body.actionLocks
                      : (req.body.actionLocks ? [req.body.actionLocks] : []);

        const blockedActions = {};              // { '/sales': ['edit'], … }
        raw.forEach(tok => {
          const [action, route] = tok.split('@@');
          if (!blockedActions[route]) blockedActions[route] = [];
          blockedActions[route].push(action);
        });

        /* 3️⃣ Persist (overwrite) */
        await db.collection('permissions')
                .doc(req.session.user.accountId)
                .set({ lockedRoutes, blockedActions });

        await cacheDel(`permissions_${req.session.user.accountId}`);
        res.redirect('/permission?success=1');
      } catch (err) {
        console.error('Save-permission error:', err);
        res.status(500).send(err.toString());
      }
    }
  );

  return router;          // 🔑 factory returns an Express router
};
