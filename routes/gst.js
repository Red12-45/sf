/* routes/gst.js – FULL REPLACEMENT (year-only filter) */
const express = require('express');

module.exports = function ({ db, isAuthenticated, restrictRoute }) {
  const router = express.Router();

  /* ─────────── helper: getGstSummary ─────────── *
     Returns rows like
       { month:'2025-06', taxable:123, output:18, input:5, net:13 }
  * --------------------------------------------------- */
  async function getGstSummary(accountId, startDate, endDate) {
    const snap = await db.collection('sales')
                         .where('accountId', '==', accountId)
                         .where('saleDate',  '>=', startDate)
                         .where('saleDate',  '<',  endDate)
                         .get();

    const bucket = {};        // keyed by "YYYY-MM"

    snap.forEach(doc => {
      const s        = doc.data();
      const ym       = s.saleDate.slice(0, 7);               // "YYYY-MM"
      const taxable  = +(s.totalSale || s.retailPrice * s.saleQuantity);
      const output   = +(s.outputTax || 0);
      const input    = +(s.inputTax  || 0);

      if (!bucket[ym]) bucket[ym] = { taxable:0, output:0, input:0 };
      bucket[ym].taxable += taxable;
      bucket[ym].output  += output;
      bucket[ym].input   += input;
    });

    return Object.entries(bucket)
      .sort(([a], [b]) => a.localeCompare(b))                // chronological
      .map(([month, v]) => ({
        month,
        taxable: +v.taxable.toFixed(2),
        output : +v.output .toFixed(2),
        input  : +v.input  .toFixed(2),
        net    : +(v.output - v.input).toFixed(2)
      }));
  }

  /* ─────────── GET /gst ─────────── */
  router.get(
    '/gst',
    isAuthenticated,
    restrictRoute('/gst'),
    async (req, res) => {
      try {
        /* ── 1.  BASICS & INPUT ────────────────────────── */
        const accountId = req.session.user.accountId;
        const pad       = n => String(n).padStart(2, '0');
        const today     = new Date();

        const { year = '' } = req.query;                     // **year only**
        const targetYear    = year ? +year : today.getFullYear();

        /* ── 2.  DATE RANGE FOR WHOLE YEAR ─────────────── */
        const startDate   = `${targetYear}-01-01`;           // 1 Jan 00:00
        const endDate     = `${targetYear + 1}-01-01`;       // 1 Jan next yr
        const periodLabel = `Year ${targetYear}`;

        /* ── 3.  DATA ──────────────────────────────────── */
        const rows = await getGstSummary(accountId, startDate, endDate);

        const totals = rows.reduce((t, r) => ({
          taxable: t.taxable + r.taxable,
          output : t.output  + r.output,
          input  : t.input   + r.input,
          net    : t.net     + r.net
        }), { taxable:0, output:0, input:0, net:0 });

        /* ── 4.  RENDER ────────────────────────────────── */
        res.render('gst', {
          rows,
          totals,
          periodLabel,
          year: targetYear,
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
