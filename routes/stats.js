// routes/stats.js
const express = require('express');

module.exports = function makeStatsRoutes({ db, isAuthenticated, restrictRoute }) {
  const router = express.Router();

  const pad = n => String(n).padStart(2, '0');

  /* converts an expense row to the amount already paid */
  const paidPortion = row => {
    const s = row.expenseStatus || '';
    const c = +row.expenseCost || 0;
    switch (s) {
      case 'Not Paid'               : return 0;
      case 'Half Cash + Not Paid'   :
      case 'Half Online + Not Paid' :
        return row.expenseDetail1 !== undefined
               ? (+row.expenseDetail1 || 0)
               : c / 2;
      default                       : return c;          // fully settled
    }
  };

/* ─────────── GET /stats ─────────── */
router.get(
  '/stats',
  isAuthenticated,
  restrictRoute('/stats'),
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* ───── Helpers & query params ───── */
      const today = new Date();
      const ymNow = `${today.getFullYear()}-${pad(today.getMonth() + 1)}`;
      const {
        month = '', from = '', to = '', year = '', top: topParam = ''
      } = req.query;

/* 1️⃣  Build the filter window (filterStart → filterEnd)
       Precedence  →  a) From-To   b) Year   c) Month   d) Default-current-month */
let filterStart, filterEnd;
const hasRange = from && to;          // both supplied & non-empty
const hasYear  = year !== '';
const hasMonth = month !== '';

if (hasRange) {
  /* inclusive YYYY-MM → YYYY-MM */
  filterStart = `${from}-01`;
  const [toY, toM] = to.split('-').map(Number);
  const nextM  = toM === 12 ? 1 : toM + 1;
  const nextY  = toM === 12 ? toY + 1 : toY;
  filterEnd    = `${nextY}-${pad(nextM)}-01`;
} else if (hasYear) {
  /* whole calendar year */
  filterStart = `${year}-01-01`;
  filterEnd   = `${+year + 1}-01-01`;
} else if (hasMonth) {
  /* single month YYYY-MM */
  filterStart = `${month}-01`;
  const [y, m] = month.split('-').map(Number);
  const nextM  = m === 12 ? 1 : m + 1;
  const nextY  = m === 12 ? y + 1 : y;
  filterEnd    = `${nextY}-${pad(nextM)}-01`;
} else {
  /* default → current month */
  filterStart = `${ymNow}-01`;
  let nextM = today.getMonth() + 2;
  let nextY = today.getFullYear();
  if (nextM > 12) { nextM = 1; nextY++; }
  filterEnd = `${nextY}-${pad(nextM)}-01`;
}


      /* 2️⃣  Chart window → whole calendar year */
      const chartYear = year
        ? +year
        : (month ? +month.split('-')[0] : today.getFullYear());

      const yearStart = `${chartYear}-01-01`;
      const yearEnd   = `${chartYear + 1}-01-01`;

      const topN = Math.max(parseInt(topParam, 10) || 10, 1);

      /* ───── Parallel fetch ───── */
      const [
        periodSalesSnap, periodExpSnap, periodRecSnap,
        yearSalesSnap,   yearExpSnap,   yearRecSnap
      ] = await Promise.all([
        // KPI & Top-N for selected window
        db.collection('sales')
          .where('accountId','==',accountId)
          .where('saleDate','>=',filterStart)
          .where('saleDate','<', filterEnd)
          .get(),
        db.collection('expenses')
          .where('accountId','==',accountId)
          .where('saleDate','>=',filterStart)
          .where('saleDate','<', filterEnd)
          .get(),
        db.collection('recurringMonthly')
          .where('accountId','==',accountId)
          .get(),

        // 12-month trend (unchanged)
        db.collection('sales')
          .where('accountId','==',accountId)
          .where('saleDate','>=',yearStart)
          .where('saleDate','<', yearEnd)
          .get(),
        db.collection('expenses')
          .where('accountId','==',accountId)
          .where('saleDate','>=',yearStart)
          .where('saleDate','<', yearEnd)
          .get(),
        db.collection('recurringMonthly')
          .where('accountId','==',accountId)
          .get()
      ]);

      /* ───── KPI & Top-N for the selected window ───── */
      const sales      = periodSalesSnap.docs.map(d => d.data());
      const expenses   = periodExpSnap .docs.map(d => d.data());
      const recRowsNow = periodRecSnap.docs
        .map(d => d.data())
        .filter(r =>
          !r.deleted &&
          r.month >= filterStart.slice(0,7) &&
          r.month <  filterEnd.slice(0,7)
        );

      const totalRevenue    = sales.reduce((s,x)=>
                              s + (x.totalSale !== undefined
                                     ? +x.totalSale
                                     : x.retailPrice * x.saleQuantity), 0);
      const totalProfit     = sales.reduce((s,x)=>s + x.profit, 0);
      const totalExpenses   = [...expenses, ...recRowsNow]
                              .reduce((s,x)=>s + paidPortion(x), 0);
      const totalGstPayable = sales.reduce((s,x)=>s + (+x.gstPayable||0), 0);
      const netProfit       = totalProfit - totalExpenses - totalGstPayable;

      /* Top-N products (selected window) */
      const pMap = {};
      sales.forEach(s => {
        const k = s.productId;
        if (!pMap[k])
          pMap[k] = { productName:s.productName, unitsSold:0, revenue:0, profit:0 };
        const row = pMap[k];
        const qty = +s.saleQuantity;
        const amt = (s.totalSale !== undefined) ? +s.totalSale : s.retailPrice * qty;
        row.unitsSold += qty;
        row.revenue   += amt;
        row.profit    += s.profit;
      });
      const pArr       = Object.values(pMap);
      const topSelling = [...pArr].sort((a,b)=>b.unitsSold - a.unitsSold).slice(0, topN);
      const topRevenue = [...pArr].sort((a,b)=>b.revenue   - a.revenue ).slice(0, topN);
      const topProfit  = [...pArr].sort((a,b)=>b.profit    - a.profit  ).slice(0, topN);

      /* ───── 12-month trend buckets (unchanged) ───── */
      const monthlyProfit  = {};
      const monthlyExpense = {};
      const monthlyGst     = {};
      for (let m = 1; m <= 12; m++) {
        const ym = `${chartYear}-${pad(m)}`;
        monthlyProfit [ym] = 0;
        monthlyExpense[ym] = 0;
        monthlyGst    [ym] = 0;
      }

      const yearSales    = yearSalesSnap.docs.map(d => d.data());
      const yearExpenses = yearExpSnap .docs.map(d => d.data());
      const yearRecRows  = yearRecSnap.docs
        .map(d => d.data())
        .filter(r => !r.deleted && r.month.startsWith(String(chartYear)));

      yearSales.forEach(s => {
        const ym = s.saleDate.slice(0, 7);
        if (monthlyProfit[ym] !== undefined) {
          monthlyProfit[ym] += s.profit;
          monthlyGst   [ym] += (+s.gstPayable || 0);
        }
      });
      [...yearExpenses, ...yearRecRows].forEach(e => {
        const ym = e.saleDate ? e.saleDate.slice(0, 7) : e.month;
        if (monthlyExpense[ym] !== undefined) {
          monthlyExpense[ym] += paidPortion(e);
        }
      });

      /* ───── Label for the UI dropdowns ───── */
      let periodLabel, uiMonth = month, uiFrom = from, uiTo = to, uiYear = year;
      if (month) {
        periodLabel = new Date(`${month}-01`)
                        .toLocaleString('default',{ month:'long', year:'numeric' });
      } else if (from && to) {
        periodLabel = `${from} → ${to}`;
      } else if (year) {
        periodLabel = `Year ${year}`;
      } else {
        periodLabel = new Date(`${ymNow}-01`)
                        .toLocaleString('default',{ month:'long', year:'numeric' });
        uiMonth = ymNow;
      }

      /* ───── Render page ───── */
      res.render('stats', {
        topSelling,
        topRevenue,
        topProfit,
        monthlyProfit,
        monthlyExpense,
        monthlyGst,
        totalRevenue,
        totalExpenses,
        totalGstPayable,
        netProfit,
        periodLabel,
        month: uiMonth,
        from : uiFrom,
        to   : uiTo,
        year : uiYear,
        topN,
        chartYear
      });

    } catch (err) {
      console.error('/stats error:', err);
      res.status(500).send(err.toString());
    }
  }
);


  return router;
};
