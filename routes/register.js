// routes/register.js
const express = require('express');
const bcrypt  = require('bcrypt');
const { body, validationResult } = require('express-validator');
const admin   = require('firebase-admin');

const router = express.Router();
const db     = admin.firestore();

/* ─────────── GET /register ─────────── */
router.get('/register', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('register', { errorMessage: null, oldInput: {} });
});

/* ─────────── POST /register ─────────── */
router.post(
  '/register',
  [
    body('name')
      .isLength({ min: 2, max: 60 })
      .withMessage('Name must be at least 2 characters.')
      .trim().escape(),

    body('email')
      .isEmail()
      .withMessage('Invalid email address.')
      .normalizeEmail(),

    body('phone')
      .optional({ checkFalsy: true })
      .isMobilePhone('en-IN')
      .withMessage('Invalid Indian phone number.')
      .trim().escape(),

    body('address')
      .isLength({ max: 200 })
      .withMessage('Address too long.')
      .trim().escape(),

    body('location')
      .optional({ checkFalsy: true })
      .trim().escape(),

    /* ─── optional GST Number (15-char GSTIN) ─── */
    body('gstNumber')
      .optional({ checkFalsy: true })
      .matches(/^[0-9A-Z]{15}$/)
      .withMessage('GST number must be 15 characters (digits/A-Z).'),

    body('password')
      .isStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
      })
      .withMessage('Password must be 8 chars incl. upper, lower, number & symbol.'),

    body('confirmPassword')
      .custom((val, { req }) => {
        if (val !== req.body.password) throw new Error('Passwords do not match');
        return true;
      })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    const {
      name, email, phone, address, location,
      businessName, gstNumber = '', password
    } = req.body;

    const oldInput = { name, email, phone, address, location, businessName };

    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        errorMessage: errors.array().map(e => e.msg).join('<br>'),
        oldInput
      });
    }

    try {
      const normalizedEmail = email.trim().toLowerCase();
      const exists = await db.collection('users')
        .where('email', '==', normalizedEmail)
        .limit(1).get();
      if (!exists.empty) {
        return res.status(400).render('register', {
          errorMessage: 'User already exists',
          oldInput
        });
      }

      /* 1️⃣  Hash password and create user */
      const hashed = await bcrypt.hash(password, 10);
      const userData = {
        name,
        email: normalizedEmail,
        phone,
        address,
        location,
        businessName,
        ...(gstNumber && { gstNumber: gstNumber.trim().toUpperCase() }),
        password: hashed,
        isMaster: true,
        createdAt: new Date()
      };

      const userRef = await db.collection('users').add(userData);

      /* 2️⃣  Set accountId AND a 30-day trial expiry */
      const trialExpiry = new Date();
      trialExpiry.setDate(trialExpiry.getDate() + 30);
      await userRef.update({
        accountId: userRef.id,
        subscriptionExpiry: trialExpiry
      });

      /* 3️⃣  Pre-create 10 counter shards */
      const shardBatch = db.batch();
      for (let i = 0; i < 10; i++) {
        const shardRef = db
          .collection('accounts').doc(userRef.id)
          .collection('counterShards').doc(String(i));
        shardBatch.set(shardRef, { value: 0 }, { merge: true });
      }
      await shardBatch.commit();

      /* 4️⃣  Done → send them to login */
      res.redirect('/login');
    } catch (err) {
      console.error(err);
      return res.status(500).render('register', {
        errorMessage: 'Something went wrong. Please try again.',
        oldInput
      });
    }
  }
);

module.exports = router;
