// routes/login.js
const express = require('express');
const bcrypt  = require('bcrypt');
const { body, validationResult } = require('express-validator');
const admin   = require('firebase-admin');

module.exports = (redisClient) => {
  const router = express.Router();
  const db     = admin.firestore();

  /* ─────────── brute-force protection helpers ─────────── */
  const MAX_LOGIN_ATTEMPTS = 5;          // failures before block
  const BLOCK_TIME_SECONDS = 15 * 60;    // 15-minute lock-out

  const getAttempts = async key =>
    parseInt(await redisClient.get(key) || '0', 10);

  const recordFailure = async key => {
    const attempts = await redisClient.incr(key);
    if (attempts === 1) await redisClient.expire(key, BLOCK_TIME_SECONDS);
    return attempts;
  };

  const clearFailures = async key => redisClient.del(key);

  /* ─────────── GET /login ─────────── */
  router.get('/login', (req, res) => {
    if (req.session && req.session.user) return res.redirect('/');
    res.render('login', { loginError: null, identifier: '' });
  });

  /* ─────────── POST /login ─────────── */
  router.post(
    '/login',
    [
      body('identifier')
        .notEmpty()
        .withMessage('Email / sub-user ID / phone is required.')
        .trim().escape(),
      body('password')
        .notEmpty()
        .withMessage('Password is required.')
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).render('login', {
          loginError: errors.array()[0].msg,
          identifier: req.body.identifier || ''
        });
      }

      try {
        let { identifier, password } = req.body;
        if (identifier.includes('@')) identifier = identifier.trim().toLowerCase();

        /* brute-force key (per-user when possible, else per-IP) */
        const bruteKey = identifier ? `bf:${identifier}` : `bfip:${req.ip}`;

        /* 1️⃣  Lock-out check */
        const currentAttempts = await getAttempts(bruteKey);
        if (currentAttempts >= MAX_LOGIN_ATTEMPTS) {
          const ttlSecs = await redisClient.ttl(bruteKey);
          const retryAfter = ttlSecs > 0
            ? Math.ceil(ttlSecs / 60)
            : Math.ceil(BLOCK_TIME_SECONDS / 60);
          return res.status(429).render('login', {
            loginError: `Too many failed attempts. Try again in ${retryAfter} minute${retryAfter === 1 ? '' : 's'}.`,
            identifier
          });
        }

        /* 2️⃣  Lookup user (email / subUserId / phone) */
        const [emailQ, subUserQ, phoneQ] = await Promise.all([
          db.collection('users').where('email', '==', identifier).get(),
          db.collection('users').where('subUserId', '==', identifier).get(),
          db.collection('users').where('phone', '==', identifier).get()
        ]);
        const userDoc = !emailQ.empty ? emailQ.docs[0]
                      : !subUserQ.empty ? subUserQ.docs[0]
                      : !phoneQ.empty   ? phoneQ.docs[0]
                      : null;

        if (!userDoc) {
          await recordFailure(bruteKey);
          const triesLeft = MAX_LOGIN_ATTEMPTS - (await getAttempts(bruteKey));
          return res.status(400).render('login', {
            loginError: triesLeft > 0
              ? `User not found. ${triesLeft} attempt${triesLeft === 1 ? '' : 's'} remaining.`
              : 'Too many failed attempts. Please try again later.',
            identifier
          });
        }

        /* 3️⃣  Password check */
        const userData = userDoc.data();
        const validPw  = await bcrypt.compare(password, userData.password);
        if (!validPw) {
          const tries = await recordFailure(bruteKey);
          const left  = MAX_LOGIN_ATTEMPTS - tries;
          return res.status(400).render('login', {
            loginError: left > 0
              ? `Invalid password – ${left} attempt${left === 1 ? '' : 's'} remaining.`
              : 'Too many failed attempts. Please try again later.',
            identifier
          });
        }

        /* 4️⃣  Success – wipe failures */
        await clearFailures(bruteKey);

        /* 5️⃣  Subscription logic (unchanged) */
        let subscriptionExpiry = userData.subscriptionExpiry
          ? (typeof userData.subscriptionExpiry.toDate === 'function'
              ? userData.subscriptionExpiry.toDate()
              : new Date(userData.subscriptionExpiry))
          : null;

        if (!userData.isMaster) {
          const masterDoc = await db.collection('users')
                                    .doc(userData.accountId).get();
          if (masterDoc.exists && masterDoc.data().subscriptionExpiry) {
            const d = masterDoc.data().subscriptionExpiry;
            subscriptionExpiry = typeof d.toDate === 'function'
              ? d.toDate()
              : new Date(d);
          }
        }

        /* 6️⃣  Attach to session */
        req.session.user = {
          id            : userDoc.id,
          name          : userData.name,
          email         : userData.email,
          businessName  : userData.businessName || '',
          isMaster      : userData.isMaster || false,
          accountId     : userData.accountId || userDoc.id,
          subscriptionExpiry
        };

        if (!req.session.user.isMaster) {
          const masterDoc = await db.collection('users')
                                    .doc(req.session.user.accountId).get();
          if (masterDoc.exists && masterDoc.data().businessName) {
            req.session.user.businessName = masterDoc.data().businessName;
          }
          const permDoc = await db.collection('permissions')
                                  .doc(req.session.user.accountId).get();
          const data = permDoc.exists ? permDoc.data() : {};
          req.session.lockedRoutes   = data.lockedRoutes   || [];
          req.session.blockedActions = data.blockedActions || {};
        }

        res.redirect('/');
      } catch (error) {
        console.error(error);
        res.status(500).render('login', {
          loginError: 'Something went wrong—please try again.',
          identifier: req.body.identifier || ''
        });
      }
    }
  );

  /* ─────────── GET /logout ─────────── */
  router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
  });

  return router;
};
