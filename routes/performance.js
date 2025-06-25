// routes/performance.js   ← make sure the file name & extension are exact
const express = require('express');

/**
 * Factory: returns an initialized Express router
 * @param {object} opts
 * @param {FirebaseFirestore.Firestore} opts.db
 * @param {function} opts.isAuthenticated
 */
module.exports = function makePerformanceRoutes({ db, isAuthenticated }) {

  const router = express.Router();
  const pad = n => String(n).padStart(2, '0');

  /* ─────────── GET /performance ─────────── */
  router.get('/performance', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* 1️⃣  Date-window helpers */
      const today  = new Date();
      const curYM  = `${today.getFullYear()}-${pad(today.getMonth() + 1)}`;
      const {
        month = '', from = '', to = '', year = '',
        top: topParam = ''
      } = req.query;

      let startDate, endDate, periodLabel;
      if (month) {                                    // single month
        startDate = `${month}-01`;
        const [y, m] = month.split('-');
        let nextM = +m + 1, nextY = +y;
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(startDate)
                        .toLocaleString('default', { month:'long', year:'numeric' });

      } else if (from && to) {                        // month-range
        startDate = `${from}-01`;
        const [ty, tm] = to.split('-');
        let nextM = +tm + 1, nextY = +ty;
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = `${from} → ${to}`;

      } else if (year) {                              // whole year
        startDate   = `${year}-01-01`;
        endDate     = `${+year + 1}-01-01`;
        periodLabel = `Year ${year}`;

      } else {                                       // default = current month
        startDate = `${curYM}-01`;
        let nextM = today.getMonth() + 2, nextY = today.getFullYear();
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(startDate)
                        .toLocaleString('default', { month:'long', year:'numeric' });
      }

      const topN = Math.max(parseInt(topParam, 10) || 10, 1);

      /* 2️⃣  Fetch sales */
      const salesSnap = await db.collection('sales')
        .where('accountId','==',accountId)
        .where('saleDate','>=',startDate)
        .where('saleDate','<', endDate)
        .get();

      const sales = salesSnap.docs.map(d => d.data());

      /* 3️⃣  Aggregate */
      const map = {};
      sales.forEach(s => {
        const pid = s.productId;
        if (!map[pid]) map[pid] = {
          productName: s.productName,
          unitsSold  : 0,
          revenue    : 0,
          profit     : 0
        };
        const row = map[pid];
        const qty = +s.saleQuantity;
        row.unitsSold += qty;
        row.revenue   += (s.totalSale !== undefined
                           ? +s.totalSale
                           : s.retailPrice * qty);
        row.profit    += +s.profit;
      });

      const arr = Object.values(map);
      const topSelling = [...arr].sort((a,b)=>b.unitsSold - a.unitsSold).slice(0, topN);
      const topRevenue = [...arr].sort((a,b)=>b.revenue   - a.revenue ).slice(0, topN);
      const topProfit  = [...arr].sort((a,b)=>b.profit    - a.profit  ).slice(0, topN);

      /* 4️⃣  Render */
      res.render('performance', {
        topSelling,
        topRevenue,
        topProfit,
        periodLabel,
        month, from, to, year,
        topN
      });

    } catch (err) {
      console.error('/performance error:', err);
      res.status(500).send(err.toString());
    }
  });

  return router;
};
