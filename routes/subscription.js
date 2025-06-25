// routes/subscription.js
module.exports = function makeSubscriptionRoutes({ db, isAuthenticated, razorpay, crypto }) {
  const express = require('express');
  const router  = express.Router();

  /* ─────────── SUBSCRIPTION & PAYMENT ROUTES ─────────── */

  // GET /pricing
  router.get('/pricing', (req, res) => {
    // now all users—subscribed or not—can view pricing
    res.render('pricing', { user: req.session.user || null });
  });

  /* ───── GET /subscribe/monthly  (secure) ───── */
  router.get('/subscribe/monthly', isAuthenticated, async (req, res) => {
    const amount   = 499 * 100;            // ₹499 → paise
    const currency = 'INR';
    const receipt  = `receipt_monthly_${Date.now()}`;

    try {
      const order = await razorpay.orders.create({ amount, currency, receipt });

      /* 🔐 Persist order – plan lives server-side only */
      await db.collection('paymentOrders').doc(order.id).set({
        userId : req.session.user.id,
        plan   : 'Monthly',
        days   : 30,
        amount,
        currency,
        paid   : false,
        createdAt : new Date()
      });

      /* No plan variable sent to client anymore */
      res.render('payment', { order, user: req.session.user });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ───── GET /subscribe/half-yearly  (secure) ───── */
  router.get('/subscribe/half-yearly', isAuthenticated, async (req, res) => {
    const amount   = 2699 * 100;
    const currency = 'INR';
    const receipt  = `receipt_halfyearly_${Date.now()}`;

    try {
      const order = await razorpay.orders.create({ amount, currency, receipt });
      await db.collection('paymentOrders').doc(order.id).set({
        userId : req.session.user.id,
        plan   : 'Half-Yearly',
        days   : 182,
        amount,
        currency,
        paid   : false,
        createdAt : new Date()
      });

      res.render('payment', { order, user: req.session.user });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ───── GET /subscribe/yearly  (secure) ───── */
  router.get('/subscribe/yearly', isAuthenticated, async (req, res) => {
    const amount   = 4799 * 100;
    const currency = 'INR';
    const receipt  = `receipt_yearly_${Date.now()}`;

    try {
      const order = await razorpay.orders.create({ amount, currency, receipt });
      await db.collection('paymentOrders').doc(order.id).set({
        userId : req.session.user.id,
        plan   : 'Yearly',
        days   : 365,
        amount,
        currency,
        paid   : false,
        createdAt : new Date()
      });

      res.render('payment', { order, user: req.session.user });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ───── POST /payment-success  (hardened) ───── */
  router.post('/payment-success', isAuthenticated, async (req, res) => {
    try {
      const {
        razorpay_payment_id,
        razorpay_order_id,
        razorpay_signature
      } = req.body;

      if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature)
        return res.status(400).send('Missing payment details');

      /* 1️⃣  Verify HMAC signature */
      const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
      shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
      if (shasum.digest('hex') !== razorpay_signature)
        return res.status(400).send('Payment signature invalid – request denied.');

      /* 2️⃣  Fetch the order we saved during /subscribe/* */
      const orderRef = db.collection('paymentOrders').doc(razorpay_order_id);
      const orderSnap = await orderRef.get();
      if (!orderSnap.exists)
        return res.status(400).send('Order not recognised');

      const order = orderSnap.data();
      if (order.paid)
        return res.status(400).send('Order already processed');
      if (order.userId !== req.session.user.id)
        return res.status(403).send('Order does not belong to current user');

      /* 3️⃣  OPTIONAL – verify with Razorpay Orders API if desired */

      /* 4️⃣  Extend subscription */
      const days = order.days;                     // 30 / 182 / 365
      const now  = new Date();

      const userRef  = db.collection('users').doc(req.session.user.id);
      const userSnap = await userRef.get();
      const curExp   = userSnap.data().subscriptionExpiry
                        ? new Date(userSnap.data().subscriptionExpiry.toDate
                                     ? userSnap.data().subscriptionExpiry.toDate()
                                     : userSnap.data().subscriptionExpiry)
                        : now;
      const newExp = curExp > now ? curExp : now;
      newExp.setDate(newExp.getDate() + days);

      await userRef.update({ subscriptionExpiry: newExp });
      req.session.user.subscriptionExpiry = newExp;

      /* 5️⃣  Mark order consumed */
      await orderRef.update({
        paid       : true,
        paymentId  : razorpay_payment_id,
        paidAt     : new Date()
      });

      res.redirect('/');
    } catch (e) {
      console.error('/payment-success error:', e);
      res.status(500).send('Payment processing failed, please contact support.');
    }
  });

  return router;
};
