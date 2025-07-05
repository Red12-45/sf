// routes/invoice.js
const express = require('express');
const admin   = require('firebase-admin');

module.exports = function ({ db, isAuthenticated, getNextInvoiceNo }) {
  const router = express.Router();

  /* ─────────── POST /api/invoice/start ─────────── */
  router.post('/api/invoice/start', isAuthenticated, async (req, res) => {
    try {
      if (!req.session.currentInvoiceNo) {
        req.session.currentInvoiceNo =
          await getNextInvoiceNo(req.session.user.accountId);
      }
      return res.json({
        success  : true,
        invoiceNo: req.session.currentInvoiceNo
      });
    } catch (err) {
      console.error('/api/invoice/start error:', err);
      return res.json({ success: false, error: err.toString() });
    }
  });

/* ─────────── GET /invoice/finish ─────────── */
router.get('/invoice/finish', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const invoiceNo = req.session.currentInvoiceNo;

    if (invoiceNo) {
      /* 1️⃣  Check if the invoice generated ANY sale rows */
      const snap = await db.collection('sales')
                           .where('accountId', '==', accountId)
                           .where('invoiceNo', '==', invoiceNo)
                           .limit(1)
                           .get();

      /* 2️⃣  If unused → decrement the sharded counter by 1 */
      if (snap.empty) {
        const rand = Math.floor(Math.random() * 10).toString();   // shard ‘0’‥‘9’
        await db.collection('accounts').doc(accountId)
                 .collection('counterShards').doc(rand)
                 .set(
                   { value: admin.firestore.FieldValue.increment(-1) },
                   { merge: true }
                 );
      }
    }
  } catch (err) {
    console.error('/invoice/finish rollback error:', err);
    /* proceed with redirect regardless – UX must not break */
  } finally {
    delete req.session.currentInvoiceNo;
    return res.redirect('/dashboard');
  }
});


/* ─────────── POST /api/invoice/finish ─────────── */
router.post('/api/invoice/finish', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const invoiceNo = req.session.currentInvoiceNo;

    if (invoiceNo) {
      /* 1️⃣  Was this invoice actually used? */
      const snap = await db.collection('sales')
                           .where('accountId', '==', accountId)
                           .where('invoiceNo', '==', invoiceNo)
                           .limit(1)
                           .get();

      /* 2️⃣  If NO sale rows → roll back the counter (undo the skip) */
      if (snap.empty) {
        const rand = Math.floor(Math.random() * 10).toString();   // shard ‘0’‥‘9’
        await db.collection('accounts').doc(accountId)
                 .collection('counterShards').doc(rand)
                 .set(
                   { value: admin.firestore.FieldValue.increment(-1) },
                   { merge: true }
                 );
      }
    }
  } catch (err) {
    console.error('/api/invoice/finish rollback error:', err);
    return res.json({ success: false, error: err.toString() });
  } finally {
    delete req.session.currentInvoiceNo;
  }
  return res.json({ success: true });
});


  /* ─────────── GET /invoice/:saleId  (single-item print) ─────────── */
  router.get('/invoice/:saleId', isAuthenticated, async (req, res) => {
    try {
      const { saleId } = req.params;

      /* 1️⃣  Fetch the sale row */
      const saleSnap = await db.collection('sales').doc(saleId).get();
      if (!saleSnap.exists) return res.status(404).send('Sale not found');

      const sale = { id: saleSnap.id, ...saleSnap.data() };
      if (sale.accountId !== req.session.user.accountId)
        return res.status(403).send('Access denied');

      /* 2️⃣  Business header */
      const userDoc = await db.collection('users')
                              .doc(req.session.user.accountId).get();
      const shop    = userDoc.exists ? userDoc.data() : {};

      /* 3️⃣  GST % helper */
      const gstPct = (sale.outputTax && sale.totalSale)
        ? ((sale.outputTax / sale.totalSale) * 100).toFixed(2)
        : '';

      /* 4️⃣  Render */
      res.render('invoice', {
        sale,
        gstPct,
        shop,
        v        : res.locals.v,
        csrfToken: req.csrfToken()
      });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ─────────── GET /invoice-number/:invoiceNo  (multi-item print) ─────────── */
  router.get('/invoice-number/:invoiceNo', isAuthenticated, async (req, res) => {
    try {
      const { invoiceNo } = req.params;
      const accountId     = req.session.user.accountId;

      /* 1️⃣  Fetch every sale row that belongs to this invoice */
      const snap = await db.collection('sales')
                           .where('accountId','==',accountId)
                           .where('invoiceNo','==',invoiceNo)
                           .orderBy('createdAt','asc')
                           .get();
      if (snap.empty) return res.status(404).send('Invoice not found');

      const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));

      /* 2️⃣  Business header */
      const shopDoc = await db.collection('users').doc(accountId).get();
      const shop    = shopDoc.exists ? shopDoc.data() : {};

      /* 3️⃣  Totals */
      const totalSale = items.reduce((t, i) => t + (+i.totalSale), 0);
      const outputTax = items.reduce((t, i) => t + (+i.outputTax || 0), 0);

      res.render('invoiceMulti', {
        items,
        invoiceNo,
        saleDate : items[0].saleDate,
        createdAt: items[0].createdAt,
        totalSale,
        outputTax,
        shop,
        v        : res.locals.v,
        csrfToken: req.csrfToken()
      });

    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  return router;
};
