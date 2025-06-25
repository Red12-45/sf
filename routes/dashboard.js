// routes/dashboard.js
const express = require('express');

module.exports = function makeDashboardRoutes({
  db,
  isAuthenticated,
  getCategories,
  pad,
  processSale,
  computeDailySummary
}) {
  const router = express.Router();

  /* ─────────── DASHBOARD (was GET "/") ─────────── */
  router.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      // IST-aware default date
      const istNow = new Date(
        new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })
      );
      const defaultDate =
        `${istNow.getFullYear()}-${pad(istNow.getMonth() + 1)}-${pad(istNow.getDate())}`;
      const saleDate = req.query.saleDate || defaultDate;

      /* ── PRODUCTS + BATCHES ── */
      const productsSnap = await db.collection('products')
        .where('accountId', '==', accountId).get();

      const products   = productsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
      const productIds = products.map(p => p.id);
      const batchesMap = {};

      if (productIds.length > 0) {
        const chunkSize = 10;
        const promises = [];

        for (let i = 0; i < productIds.length; i += chunkSize) {
          promises.push(
            db.collection('stockBatches')
              .where('productId', 'in', productIds.slice(i, i + chunkSize))
              .where('remainingQuantity', '>', 0)
              .orderBy('batchDate', 'asc')
              .get()
          );
        }

        const snaps = await Promise.all(promises);
        snaps.forEach(snap => {
          snap.docs.forEach(doc => {
            const d = doc.data();
            if (!batchesMap[d.productId]) batchesMap[d.productId] = [];
            batchesMap[d.productId].push({
              wholesale: d.purchasePrice,
              retail   : d.salePrice,
              qty      : d.remainingQuantity
            });
          });
        });
      }

      products.forEach(p => (p.batches = batchesMap[p.id] || []));

      /* ── PARALLEL FETCH ── */
      const [salesSnap, expSnap, categories, obDoc] = await Promise.all([
        db.collection('sales')
          .where('accountId', '==', accountId)
          .where('saleDate', '==', saleDate)
          .orderBy('createdAt', 'desc').get(),
        db.collection('expenses')
          .where('accountId', '==', accountId)
          .where('saleDate', '==', saleDate)
          .orderBy('createdAt', 'desc').get(),
        getCategories(accountId),
        db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get()
      ]);

      const sales    = salesSnap.docs.map(d => ({ id: d.id, ...d.data() }));
      const expenses = expSnap.docs.map(d => ({ id: d.id, ...d.data() }));

      /* ── OPENING BALANCE ── */
      let openingBalance = 0, openingTime = '', closingTime = '';
      if (obDoc.exists) {
        const ob = obDoc.data();
        openingBalance = ob.balance     || 0;
        openingTime    = ob.openingTime || '';
        closingTime    = ob.closingTime || '';
      }

      /* ── SUMMARIES ── */
      let totalProfit        = 0,
          totalSales         = 0,
          totalCashSales     = 0,
          totalOnlineSales   = 0,
          totalNotPaidSales  = 0,
          totalGstPayable    = 0;

      sales.forEach(s => {
        totalProfit += s.profit;
        const amt = s.retailPrice * s.saleQuantity;
        totalSales += amt;

        switch (s.status) {
          case 'Paid Cash':                   totalCashSales   += amt; break;
          case 'Paid Online':                 totalOnlineSales += amt; break;
          case 'Not Paid':                    totalNotPaidSales+= amt; break;
          case 'Half Cash + Half Online':
            if (s.paymentDetail1) totalCashSales   += s.paymentDetail1;
            if (s.paymentDetail2) totalOnlineSales += s.paymentDetail2;
            break;
          case 'Half Cash + Not Paid':
            if (s.paymentDetail1) totalCashSales   += s.paymentDetail1;
            if (s.paymentDetail2) totalNotPaidSales+= s.paymentDetail2;
            break;
          case 'Half Online + Not Paid':
            if (s.paymentDetail1) totalOnlineSales += s.paymentDetail1;
            if (s.paymentDetail2) totalNotPaidSales+= s.paymentDetail2;
            break;
        }
        if (s.gstPayable !== undefined) totalGstPayable += +s.gstPayable;
      });

      let totalCashExpenses = 0, totalOnlineExpenses = 0;
      expenses.forEach(e => {
        switch (e.expenseStatus) {
          case 'Paid Cash': totalCashExpenses   += e.expenseCost; break;
          case 'Paid Online': totalOnlineExpenses+= e.expenseCost; break;
          case 'Half Cash + Half Online':
            if (e.expenseDetail1) totalCashExpenses   += e.expenseDetail1;
            if (e.expenseDetail2) totalOnlineExpenses += e.expenseDetail2;
            break;
          case 'Half Cash + Not Paid':
            if (e.expenseDetail1) totalCashExpenses   += e.expenseDetail1;
            break;
          case 'Half Online + Not Paid':
            if (e.expenseDetail1) totalOnlineExpenses += e.expenseDetail1;
            break;
        }
      });

      const finalCash =
        parseFloat(openingBalance) + totalCashSales - totalCashExpenses;

      /* ── Subscription countdown ── */
      let subscriptionRemaining = 0;
      if (req.session.user.subscriptionExpiry) {
        const diff = new Date(req.session.user.subscriptionExpiry) - new Date();
        subscriptionRemaining = Math.max(
          Math.ceil(diff / (1000 * 60 * 60 * 24)), 0
        );
      }

      /* ── RENDER ── */
      res.render('index', {
        products, sales, expenses, saleDate, categories,
        openingBalance, openingTime, closingTime,
        totalProfit, totalSales, totalCashSales,
        totalOnlineSales, totalNotPaidSales,
        totalCashExpenses, totalOnlineExpenses,
        finalCash,
        totalGstPayable,
        subscriptionRemaining,
        user: req.session.user,
        currentInvoiceNo: req.session.currentInvoiceNo || null
      });
    } catch (err) {
      res.status(500).send(err.toString());
    }
  });

  /* ------------------------------------------------------------------
     Fallback route for <form action="/update-opening-balance"> …
     ------------------------------------------------------------------*/
  router.post('/update-opening-balance', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      const { saleDate, openingBalance, openingTime, closingTime } = req.body;

      await db.collection('openingBalances')
        .doc(`${accountId}_${saleDate}`)
        .set({
          balance     : +openingBalance,
          openingTime : openingTime || '',
          closingTime : closingTime || '',
          updatedAt   : new Date(),
          accountId
        }, { merge: true });

      res.redirect(`/?saleDate=${saleDate}`);
    } catch (err) {
      res.status(500).send(err.toString());
    }
  });

  /* ─────────── AJAX  POST  /api/sale  (always returns JSON) ─────────── */
  router.post('/api/sale', isAuthenticated, async (req, res) => {
    try {
      // 1️⃣  create the sale
      const sale = await processSale(req.body, req.session.user);

      // 2️⃣  fresh same-day summary for quick dashboard refresh
      const { summary } = await computeDailySummary(
        req.session.user.accountId,
        sale.saleDate
      );

      return res.json({ success: true, sale, summary });
    } catch (err) {
      console.error('/api/sale error:', err);
      return res
        .status(400)
        .json({ success: false, error: err.message || 'Something went wrong' });
    }
  });

  /* ─────────── AJAX  POST  /api/opening-balance ─────────── */
  router.post('/api/opening-balance', isAuthenticated, async (req, res) => {
    try {
      const { saleDate, openingBalance, openingTime, closingTime } = req.body;

      await db.collection('openingBalances')
        .doc(`${req.session.user.accountId}_${saleDate}`)
        .set({
          balance   : +openingBalance,
          openingTime,
          closingTime,
          updatedAt : new Date(),
          accountId : req.session.user.accountId
        }, { merge: true });

      const { summary, openingBalance: bal } =
        await computeDailySummary(req.session.user.accountId, saleDate);

      res.json({
        success        : true,
        openingBalance : bal,
        openingTime    : openingTime || '',
        closingTime    : closingTime || '',
        summary
      });
    } catch (err) {
      res.json({ success: false, error: err.toString() });
    }
  });

  return router;
};
