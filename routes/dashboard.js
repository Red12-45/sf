// routes/dashboard.js
// -----------------------------------------------------------------------------
// Dashboard (index.ejs) – full server code, badge totals fixed
// -----------------------------------------------------------------------------
'use strict';

const express = require('express');

/*  NOTE: app.js must call this factory with computeMonthTotal included:
      const dashboardRoutes = makeDashboardRoutes({
        db, isAuthenticated, getCategories, pad,
        processSale, computeDailySummary, computeMonthTotal
      });
*/
module.exports = function makeDashboardRoutes({
  db,
  isAuthenticated,
  getCategories,
  pad,                       // helper: n => "01".."12"
  processSale,               // shared Ajax helper
  computeDailySummary,       // helper already in app.js
  computeMonthTotal          // ★ NEW – pulled from app.js
}) {
  const router = express.Router();

// ★ NEW – tiny helper that returns the five badge numbers for any YYYY-MM
async function computeMonthlyBadges (accountId, month) {
  const start = `${month}-01`;
  const [y, m] = month.split('-');
  const nextM = (parseInt(m,10) % 12) + 1;
  const nextY = nextM === 1 ? +y + 1 : +y;
  const end = `${nextY}-${String(nextM).padStart(2,'0')}-01`;

  // pull every sale + expense in parallel
  const [salesSnap, expSnap] = await Promise.all([
    db.collection('sales')
      .where('accountId','==',accountId)
      .where('saleDate','>=',start)
      .where('saleDate','<', end)
      .get(),
    db.collection('expenses')
      .where('accountId','==',accountId)
      .where('saleDate','>=',start)
      .where('saleDate','<', end)
      .get()
  ]);

  let revenue = 0, gross = 0, expense = 0, gst = 0;
  salesSnap.forEach(d => {
    const s = d.data();
    const amt = s.totalSale !== undefined
                  ? +s.totalSale
                  : s.retailPrice * s.saleQuantity;
    revenue += amt;
    gross   += s.profit;
    gst     += s.gstPayable || 0;
  });
  expSnap.forEach(d => expense += (+d.data().expenseCost || 0));

  const net = +(gross - expense - gst).toFixed(2);

  return {
    revenue : +revenue.toFixed(2),
    gross   : +gross.toFixed(2),
    expense : +expense.toFixed(2),
    gst     : +gst.toFixed(2),
    net
  };
}


  /* ───────────────────────── GET /dashboard ───────────────────────── */
 /* ───────────────────────── GET /dashboard ───────────────────────── */
router.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;

    /* ---------- helpers ---------- */
    const utcNow = new Date();
    const istNow = new Date(utcNow.toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }));
    const todayYM = `${istNow.getFullYear()}-${pad(istNow.getMonth() + 1)}`;
    const defaultDate = `${todayYM}-${pad(istNow.getDate())}`;
    const saleDate = req.query.saleDate || defaultDate;

    /* ---------- PRODUCTS & FIFO batches ---------- */
    const productsSnap = await db.collection('products')
      .where('accountId', '==', accountId).get();

    const products = productsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const productIds = products.map(p => p.id);
    const batchesMap = {};

    if (productIds.length) {
      const chunk = 10, promises = [];
      for (let i = 0; i < productIds.length; i += chunk) {
        promises.push(
          db.collection('stockBatches')
            .where('productId', 'in', productIds.slice(i, i + chunk))
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
            retail: d.salePrice,
            qty: d.remainingQuantity
          });
        });
      });
    }
    products.forEach(p => (p.batches = batchesMap[p.id] || []));

    /* ---------- Parallel daily fetch ---------- */
    const [salesSnap, expSnap, categories, obDoc] = await Promise.all([
      db.collection('sales')
        .where('accountId', '==', accountId)
        .where('saleDate', '==', saleDate)
        .orderBy('createdAt', 'desc')
        .get(),
      db.collection('expenses')
        .where('accountId', '==', accountId)
        .where('saleDate', '==', saleDate)
        .orderBy('createdAt', 'desc')
        .get(),
      getCategories(accountId),
      db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get()
    ]);

    const sales = salesSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const expenses = expSnap.docs.map(d => ({ id: d.id, ...d.data() }));

    /* ---------- Opening balance & times ---------- */
    let openingBalance = 0, openingTime = '', closingTime = '';
    if (obDoc.exists) {
      const ob = obDoc.data();
      openingBalance = ob.balance || 0;
      openingTime = ob.openingTime || '';
      closingTime = ob.closingTime || '';
    }

    /* ---------- Daily totals ---------- */
    let totalProfit = 0,
        totalSales = 0,
        totalCashSales = 0,
        totalOnlineSales = 0,
        totalNotPaidSales = 0,
        totalGstPayable = 0;

    sales.forEach(s => {
      totalProfit += s.profit;
      const amt = s.totalSale !== undefined
        ? +s.totalSale
        : s.retailPrice * s.saleQuantity;
      totalSales += amt;

      switch (s.status) {
        case 'Paid Cash': totalCashSales += amt; break;
        case 'Paid Online': totalOnlineSales += amt; break;
        case 'Not Paid': totalNotPaidSales += amt; break;
        case 'Half Cash + Half Online':
          if (s.paymentDetail1) totalCashSales += s.paymentDetail1;
          if (s.paymentDetail2) totalOnlineSales += s.paymentDetail2;
          break;
        case 'Half Cash + Not Paid':
          if (s.paymentDetail1) totalCashSales += s.paymentDetail1;
          if (s.paymentDetail2) totalNotPaidSales += s.paymentDetail2;
          break;
        case 'Half Online + Not Paid':
          if (s.paymentDetail1) totalOnlineSales += s.paymentDetail1;
          if (s.paymentDetail2) totalNotPaidSales += s.paymentDetail2;
          break;
      }
      totalGstPayable += s.gstPayable || 0;
    });

    let totalCashExpenses = 0, totalOnlineExpenses = 0;
    expenses.forEach(e => {
      switch (e.expenseStatus) {
        case 'Paid Cash': totalCashExpenses += e.expenseCost; break;
        case 'Paid Online': totalOnlineExpenses += e.expenseCost; break;
        case 'Half Cash + Half Online':
          if (e.expenseDetail1) totalCashExpenses += e.expenseDetail1;
          if (e.expenseDetail2) totalOnlineExpenses += e.expenseDetail2;
          break;
        case 'Half Cash + Not Paid':
          if (e.expenseDetail1) totalCashExpenses += e.expenseDetail1;
          break;
        case 'Half Online + Not Paid':
          if (e.expenseDetail1) totalOnlineExpenses += e.expenseDetail1;
          break;
      }
    });

    const finalCash = +(openingBalance + totalCashSales - totalCashExpenses).toFixed(2);

    /* Month-to-date badges */
    const [y, m] = saleDate.split('-');
    const month = `${y}-${m}`;
    const monthStart = `${month}-01`;
    let nextM = parseInt(m, 10) + 1, nextY = parseInt(y, 10);
    if (nextM > 12) { nextM = 1; nextY++; }
    const monthEnd = `${nextY}-${pad(nextM)}-01`;

    const monthSalesSnap = await db.collection('sales')
      .where('accountId','==',accountId)
      .where('saleDate','>=',monthStart)
      .where('saleDate','<', monthEnd)
      .get();
    const monthSales = monthSalesSnap.docs.map(d => d.data());

    const totalRevenueAmount = monthSales.reduce((s,x) =>
      s + (x.totalSale !== undefined ? +x.totalSale : x.retailPrice * x.saleQuantity), 0);
    const profitWithoutExpenses = monthSales.reduce((s,x) => s + x.profit, 0);
    const totalExpensesAmount = await computeMonthTotal(accountId, month);
    const monthGstPayable = monthSales.reduce((s,x) => s + (x.gstPayable || 0), 0);
    const profitAfterExpenses = profitWithoutExpenses - totalExpensesAmount - monthGstPayable;

    /* =======================================================================
       EXTRA SECTION → analytics data for empty-page charts
       ======================================================================= */
    /* 1️⃣  Product Top-N (current month) */
    const monthStartChart = `${todayYM}-01`;
    let nextMChart = istNow.getMonth() + 2, nextYChart = istNow.getFullYear();
    if (nextMChart > 12) { nextMChart = 1; nextYChart++; }
    const monthEndChart = `${nextYChart}-${pad(nextMChart)}-01`;

    const [monthSalesSnap2] = await Promise.all([
      db.collection('sales')
        .where('accountId','==',accountId)
        .where('saleDate','>=',monthStartChart)
        .where('saleDate','<', monthEndChart)
        .get()
    ]);
    const monthSales2 = monthSalesSnap2.docs.map(d => d.data());

    const pMap = {};
    monthSales2.forEach(s => {
      const key = s.productId;
      if (!pMap[key]) pMap[key] = { productName: s.productName, unitsSold: 0, revenue: 0, profit: 0 };
      const qty = +s.saleQuantity;
      const amt = (s.totalSale !== undefined) ? +s.totalSale : s.retailPrice * qty;
      pMap[key].unitsSold += qty;
      pMap[key].revenue += amt;
      pMap[key].profit += s.profit;
    });
    const pArr = Object.values(pMap);
    const topSelling = [...pArr].sort((a, b) => b.unitsSold - a.unitsSold).slice(0, 10);
    const topRevenue = [...pArr].sort((a, b) => b.revenue - a.revenue).slice(0, 10);
    const topProfit = [...pArr].sort((a, b) => b.profit - a.profit).slice(0, 10);

    /* 2️⃣  Monthly (year-to-date) series */
    const chartYear = istNow.getFullYear();
    const yearStart = `${chartYear}-01-01`;
    const yearEnd = `${chartYear + 1}-01-01`;

    const [yearSalesSnap, yearExpSnap] = await Promise.all([
      db.collection('sales')
        .where('accountId','==',accountId)
        .where('saleDate','>=',yearStart)
        .where('saleDate','<', yearEnd)
        .get(),
      db.collection('expenses')
        .where('accountId','==',accountId)
        .where('saleDate','>=',yearStart)
        .where('saleDate','<', yearEnd)
        .get()
    ]);

    const monthlyProfit = {}, monthlyExpense = {}, monthlyGst = {};
    for (let i = 1; i <= 12; i++) {
      const ymKey = `${chartYear}-${pad(i)}`;
      monthlyProfit[ymKey] = 0;
      monthlyExpense[ymKey] = 0;
      monthlyGst[ymKey] = 0;
    }

    yearSalesSnap.docs.forEach(d => {
      const s = d.data(), ymKey = s.saleDate.slice(0, 7);
      if (monthlyProfit[ymKey] !== undefined) {
        monthlyProfit[ymKey] += s.profit;
        monthlyGst[ymKey] += (+s.gstPayable || 0);
      }
    });
    yearExpSnap.docs.forEach(d => {
      const e = d.data(), ymKey = e.saleDate.slice(0, 7);
      if (monthlyExpense[ymKey] !== undefined) monthlyExpense[ymKey] += (+e.expenseCost || 0);
    });

    /* ---------- Subscription countdown (unchanged) ---------- */
    let subscriptionRemaining = 0;
    if (req.session.user.subscriptionExpiry) {
      const diff = new Date(req.session.user.subscriptionExpiry) - new Date();
      subscriptionRemaining = Math.max(Math.ceil(diff / (1000 * 60 * 60 * 24)), 0);
    }

    /* ---------- render ---------- */
    res.render('index', {
      /* badges */
      totalRevenueAmount: +totalRevenueAmount.toFixed(2),
      profitWithoutExpenses: +profitWithoutExpenses.toFixed(2),
      totalExpensesAmount: +totalExpensesAmount.toFixed(2),
      monthGstPayable: +monthGstPayable.toFixed(2),
      profitAfterExpenses: +profitAfterExpenses.toFixed(2),

      /* daily */
      totalProfit: +totalProfit.toFixed(2),
      totalSales: +totalSales.toFixed(2),
      totalCashSales: +totalCashSales.toFixed(2),
      totalOnlineSales: +totalOnlineSales.toFixed(2),
      totalNotPaidSales: +totalNotPaidSales.toFixed(2),
      totalCashExpenses: +totalCashExpenses.toFixed(2),
      totalOnlineExpenses: +totalOnlineExpenses.toFixed(2),
      finalCash,
      totalGstPayable: +totalGstPayable.toFixed(2),

      /* misc */
      products, sales, expenses, saleDate, categories,
      openingBalance, openingTime, closingTime,
      subscriptionRemaining, user: req.session.user,
      currentInvoiceNo: req.session.currentInvoiceNo || null,

      /* chart data */
      topSelling, topRevenue, topProfit,
      monthlyProfit, monthlyExpense, monthlyGst,
      chartYear
    });

  } catch (err) {
    console.error('dashboard error:', err);
    res.status(500).send(err.toString());
  }
});  /* ←← END GET /dashboard */


  /* ───────────────────── Update Opening Balance (unchanged) ────────────────── */
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

      res.redirect(`/dashboard?saleDate=${saleDate}`);
    } catch (err) {
      res.status(500).send(err.toString());
    }
  });

  /* ───────────────────── AJAX helpers (sale & balance) ─────────────────────── */
router.post('/api/sale', isAuthenticated, async (req, res) => {
  try {
    const sale = await processSale(req.body, req.session.user);

    // daily recap
    const { summary } = await computeDailySummary(
      req.session.user.accountId, sale.saleDate
    );

    // monthly badges (YYYY-MM of the sale)
    const month = sale.saleDate.slice(0, 7);
    const badges = await computeMonthlyBadges(
      req.session.user.accountId, month
    );

    res.json({ success: true, sale, summary, badges });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || 'Error' });
  }
});


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

    /* ★ NEW: compute month badges for the same YYYY-MM */
    const badges = await computeMonthlyBadges(
      req.session.user.accountId,
      saleDate.slice(0, 7)
    );

    res.json({
      success        : true,
      openingBalance : bal,
      openingTime    : openingTime || '',
      closingTime    : closingTime || '',
      summary,
      badges                         // ← sends the five figures
    });
  } catch (err) {
    res.json({ success: false, error: err.toString() });
  }
});


  return router;
};
