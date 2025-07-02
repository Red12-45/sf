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
const SUB_USER_LIMIT = 1;   // ← change here if you ever need more

const subUsersQuery = await db.collection('users')
  .where('accountId', '==', req.session.user.accountId)
  .where('isMaster', '==', false)
  .get();

console.log('Current sub-user count:', subUsersQuery.size);   // debug line

if (subUsersQuery.size >= SUB_USER_LIMIT) {
  return res.status(400).send(`Sub-user limit reached (max ${SUB_USER_LIMIT}).`);
}

 let { name, password, confirmPassword, subUserId } = req.body;

if (password.length < 8)
  return res.status(400).send('Password must be at least 8 characters');
if (password !== confirmPassword)
  return res.status(400).send('Passwords do not match');


/* ────────────────────────────────────────────────────────────
   Fallback: if CSP blocked the browser’s JS and we received
   no Sub-User ID, create a unique one right here.
   ──────────────────────────────────────────────────────────── */
subUserId = (subUserId || '').trim();
if (!subUserId) {
  subUserId = 'SUB-' + Math.random().toString(36).substring(2, 10).toUpperCase();
}


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

    // 1️⃣  Basic validations
    if (password) {
      if (password.length < 8)
        return res.status(400).send('Password must be at least 8 characters');
      if (password !== confirmPassword)
        return res.status(400).send('Passwords do not match');
    }

    // 2️⃣  Fetch the user and verify permissions
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId) {
      return res.status(403).send('Access denied');
    }

    // 3️⃣  Prevent reusing the same password
    if (password) {
      const existingHash = userDoc.data().password;
      const isSame = await bcrypt.compare(password, existingHash);
      if (isSame) {
        return res.status(400).send('Old and new password are the same');
      }
    }

    // 4️⃣  Build update payload
    const updateData = { name };
    if (password) {
      const hashed = await bcrypt.hash(password, 10);
      updateData.password = hashed;
    }

    // 5️⃣  Persist changes
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

/* ─────────── GET /generate-subuserid ───────────
   Returns a guaranteed-unique “SUB-XXXXXXXX” per account
   ----------------------------------------------------- */
router.get('/generate-subuserid', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    let id, exists = true;

    while (exists) {
      id = 'SUB-' + Math.random().toString(36).substring(2, 10).toUpperCase();
      const snap = await db.collection('users')
                           .where('accountId','==',accountId)
                           .where('subUserId','==',id)
                           .limit(1).get();
      exists = !snap.empty;                 // loop until unique
    }
    res.json({ id });
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});


module.exports = router;
