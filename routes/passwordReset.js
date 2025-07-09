// routes/passwordReset.js
const express = require('express');
const admin   = require('firebase-admin');
module.exports = function ({ db, crypto, transporter }) {
  const router = express.Router();

  /* ─────────── GET /forgot-password ─────────── */
  router.get('/forgot-password', (req, res) => {
    if (req.session?.user) return res.redirect('/');
    res.render('forgotPassword', { sent: false, error: null });
  });

  /* ─────────── POST /forgot-password ─────────── */
  router.post('/forgot-password', async (req, res) => {
    try {
      const emailRaw = req.body.email || '';
      const email    = emailRaw.trim().toLowerCase();

      if (!email) {
        return res.status(400).render('forgotPassword',
          { sent: false, error: 'Please enter your registered email.' });
      }

      // Master-account lookup
      const snap = await db.collection('users')
                           .where('email',    '==', email)
                           .where('isMaster', '==', true)
                           .limit(1).get();

      /* Success response even when the address is unknown ↓ */
      if (snap.empty)
        return res.render('forgotPassword', { sent: true, error: null });

      const userDoc = snap.docs[0];

      // Generate raw token → store SHA-256 hash only
      const rawToken  = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
      const expires   = new Date(Date.now() + 60 * 60 * 1000);   // 1 h

      await db.collection('passwordResets').doc(tokenHash).set({
        userId   : userDoc.id,
        email,
        expiresAt: expires,
        used     : false,
        createdAt: new Date()
      });

      const link = `${process.env.BASE_URL}` +
                   `/reset-password/${rawToken}`;

      // Fire the e-mail
      await transporter.sendMail({
        to      : email,
        from    : process.env.EMAIL_USER,
        subject : 'Reset your SalesFlow master password',
        html    : `
          <p>Hi ${userDoc.data().name},</p>
          <p>You (or someone using your email) requested a password reset.</p>
          <p><a href="${link}">Click here to choose a new password</a><br>
             (this link is valid for 1 hour and can be used once).</p>
          <p>If you didn’t request this, just ignore the email.</p>`
      });

      res.render('forgotPassword', { sent: true, error: null });

    } catch (err) {
      console.error('/forgot-password error:', err);
      res.status(500).render('forgotPassword',
        { sent: false, error: 'Something went wrong. Please try again.' });
    }
  });

  /* ─────────── GET /reset-password/:token ─────────── */
  router.get('/reset-password/:token', async (req, res) => {
    try {
      const rawToken  = req.params.token;
      const tokenHash = crypto.createHash('sha256')
                              .update(rawToken).digest('hex');

      const doc = await db.collection('passwordResets').doc(tokenHash).get();

      if (!doc.exists) {
        return res.status(400).render('resetPassword',
          { token: '', invalid: true, error: 'Invalid or expired link.' });
      }

      const data = doc.data();
      if (data.used || data.expiresAt.toDate() < new Date()) {
        return res.status(400).render('resetPassword',
          { token: '', invalid: true, error: 'Link has expired. Request a new one.' });
      }

      res.render('resetPassword', {
        token  : rawToken,   // raw token goes back to the form
        invalid: false,
        error  : null
      });

    } catch (err) {
      res.status(500).send(err.toString());
    }
  });

  /* ─────────── POST /reset-password ─────────── */
  router.post('/reset-password', async (req, res) => {
    try {
      const { token: rawToken, password, confirmPassword } = req.body;

      if (!password || password !== confirmPassword) {
        return res.status(400).render('resetPassword',
          { token: rawToken, invalid: false, error: 'Passwords do not match.' });
      }

      /* 🔑  IMPORTANT: hash the raw token exactly the same way you did
          when you first stored it (SHA-256 hex)                     */
      const tokenHash = crypto.createHash('sha256')
                              .update(rawToken)
                              .digest('hex');

      const tokenRef  = db.collection('passwordResets').doc(tokenHash);
      const tokenSnap = await tokenRef.get();

      if (!tokenSnap.exists) {
        return res.status(400).render('resetPassword',
          { token: '', invalid: true, error: 'Invalid or expired link.' });
      }

      const tData = tokenSnap.data();
      if (tData.used || tData.expiresAt.toDate() < new Date()) {
        return res.status(400).render('resetPassword',
          { token: '', invalid: true, error: 'Link has expired. Request a new one.' });
      }

    
     
    /* 🔒  Update the password directly in Firebase Authentication
   -----------------------------------------------------------
   IMPORTANT: on some legacy accounts the Firestore doc ID
   (tData.userId) ≠ the real Auth UID.  
   We therefore resolve the UID from the e-mail first to be
   100 % sure we hit the correct Auth record.                */
const authRec = await admin.auth().getUserByEmail(tData.email);
await admin.auth().updateUser(authRec.uid, { password });



      /* ☑️  Mark this reset token as consumed */
      await tokenRef.update({ used: true, usedAt: new Date() });

      res.redirect('/login');

    } catch (err) {
      console.error('/reset-password error:', err);
      res.status(500).render('resetPassword',
        { token: rawToken, invalid: false, error: 'Something went wrong. Please try again.' });
    }
  });

  return router;
};
