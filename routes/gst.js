// routes/gst.js
const express = require('express');

module.exports = function ({ db, isAuthenticated, restrictRoute }) {
  const router = express.Router();

  /* ─────────── GST SUMMARY HELPER ─────────── *
     Returns an array like
       { month:'2025-06', taxable:₹, output:₹, input:₹, net:₹ }
     exactly matching the logic used previously.
  * --------------------------------------------------- */
  async function getGstSummary(accountId, startDate, endDate) {
    const salesSnap = await db.collection('sales')
      .where('accountId','==',accountId)
      .where('saleDate','>=',startDate)
      .where('saleDate','<', endDate)
      .get();

    const bucket = {};                       // { YYYY-MM : { taxable, output, input } }

    salesSnap.docs.forEach(doc => {
      const s  = doc.data();
      const ym = s.saleDate.substring(0, 7);
      if (!bucket[ym]) bucket[ym] = { taxable:0, output:0, input:0 };
      bucket[ym].taxable += +(s.totalSale || s.retailPrice * s.saleQuantity);
      bucket[ym].output  += +(s.outputTax  || 0);
      bucket[ym].input   += +(s.inputTax   || 0);
    });

    return Object.entries(bucket)
      .sort(([a],[b]) => a.localeCompare(b))
      .map(([month, v]) => ({
        month,
        taxable : +v.taxable.toFixed(2),
        output  : +v.output .toFixed(2),
        input   : +v.input  .toFixed(2),
        net     : +(v.output - v.input).toFixed(2)
      }));
  }

  /* ─────────── GET  /gst  ─────────── */
  router.get(
    '/gst',
    isAuthenticated,
    restrictRoute('/gst'),
    async (req, res) => {
      try {
        const accountId = req.session.user.accountId;

        const pad   = n => String(n).padStart(2, '0');
        const today = new Date();
        const curYM = `${today.getFullYear()}-${pad(today.getMonth() + 1)}`;

        const { month = '', from = '', to = '', year = '' } = req.query;
        let startDate, endDate, periodLabel;

        if (month) {                                   // single-month view
          startDate = `${month}-01`;
          const [y, m] = month.split('-');
          let nextM = +m + 1,
              nextY = +y;
          if (nextM > 12) { nextM = 1; nextY++; }
          endDate     = `${nextY}-${pad(nextM)}-01`;
          periodLabel = new Date(startDate)
                          .toLocaleString('default', { month:'long', year:'numeric' });

        } else if (from && to) {                       // month-range view
          startDate = `${from}-01`;
          const [ty, tm] = to.split('-');
          let nextM = +tm + 1,
              nextY = +ty;
          if (nextM > 12) { nextM = 1; nextY++; }
          endDate     = `${nextY}-${pad(nextM)}-01`;
          periodLabel = `${from} → ${to}`;

        } else if (year) {                             // whole-year view
          startDate   = `${year}-01-01`;
          endDate     = `${+year + 1}-01-01`;
          periodLabel = `Year ${year}`;

        } else {                                       // default = current month
          startDate = `${curYM}-01`;
          let nextM = today.getMonth() + 2,
              nextY = today.getFullYear();
          if (nextM > 12) { nextM = 1; nextY++; }
          endDate     = `${nextY}-${pad(nextM)}-01`;
          periodLabel = new Date(startDate)
                          .toLocaleString('default', { month:'long', year:'numeric' });
        }

        const rows   = await getGstSummary(accountId, startDate, endDate);
        const totals = rows.reduce((t, r) => ({
          taxable: t.taxable + r.taxable,
          output : t.output  + r.output,
          input  : t.input   + r.input,
          net    : t.net     + r.net
        }), { taxable:0, output:0, input:0, net:0 });

        res.render('gst', {
          rows,
          totals,
          periodLabel,
          month,
          from,
          to,
          year,
          user: req.session.user
        });
      } catch (err) {
        console.error('/gst error:', err);
        res.status(500).send(err.toString());
      }
    }
  );

  return router;
};
