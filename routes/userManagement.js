// routes/userManagement.js
const express      = require('express');
const bcrypt       = require('bcrypt');
const admin        = require('firebase-admin');

const router = express.Router();
const db     = admin.firestore();

/* ────────────────────────────────────────────────────────────
   Helper middleware – cloned from app.js so nothing is shared
   ──────────────────────────────────────────────────────────── */
const isAuthenticated = (req, res, next) =>
  req.session && req.session.user ? next() : res.redirect('/login');

const requireMaster = (req, res, next) =>
  req.session.user && req.session.user.isMaster
    ? next()
    : res.status(403).send('Access denied');

/* ─────────── GET /create-user ─────────── */
router.get('/create-user', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const snapshot = await db.collection('users')
      .where('accountId', '==', req.session.user.accountId)
      .get();

    const users = snapshot.docs.map(doc => {
      const d = doc.data();
      return {
        id       : doc.id,
        name     : d.name,
        email    : d.email,
        isMaster : d.isMaster,
        subUserId: d.subUserId
      };
    });

    res.render('createuser', { users });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

/* ─────────── POST /create-user ─────────── */
router.post('/create-user', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const subUsersQuery = await db.collection('users')
      .where('accountId', '==', req.session.user.accountId)
      .where('isMaster', '==', false)
      .get();

    if (subUsersQuery.size >= 2) {
      return res.status(400).send('Sub-user limit reached. Maximum 2 sub-users allowed.');
    }

    const { name, password, confirmPassword, subUserId } = req.body;
    if (password !== confirmPassword) return res.status(400).send('Passwords do not match');
    if (!subUserId.trim())            return res.status(400).send('Sub-user ID is required');

    const exist = await db.collection('users')
      .where('subUserId', '==', subUserId)
      .where('accountId', '==', req.session.user.accountId)
      .get();

    if (!exist.empty) return res.status(400).send('Sub-user ID already exists.');

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').add({
      name,
      password : hashedPassword,
      isMaster : false,
      accountId: req.session.user.accountId,
      subUserId,
      createdAt: new Date()
    });

    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

/* ─────────── POST /edit-user ─────────── */
router.post('/edit-user', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const { userId, name, password, confirmPassword } = req.body;
    if (password && password !== confirmPassword) {
      return res.status(400).send('Passwords do not match');
    }

    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId) {
      return res.status(403).send('Access denied');
    }

    const updateData = { name };
    if (password) updateData.password = await bcrypt.hash(password, 10);

    await userRef.update(updateData);
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

/* ─────────── POST /delete-user ─────────── */
router.post('/delete-user', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const { userId } = req.body;
    const userRef    = db.collection('users').doc(userId);
    const userDoc    = await userRef.get();

    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId) {
      return res.status(403).send('Access denied');
    }

    await userRef.delete();
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

module.exports = router;
