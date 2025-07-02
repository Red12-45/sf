// routes/sales.js
// -----------------------------------------------------------------------------
// All server-side logic for sales.ejs
//   • GET /sales  (report page)
//   • POST /api/edit-sale   (inline edit)
//   • POST /api/delete-sale (delete row)
// -----------------------------------------------------------------------------
'use strict';

const express = require('express');
const admin   = require('firebase-admin');            // uses same singleton

module.exports = function makeSalesRoutes ({
  db,
  isAuthenticated,
  restrictRoute,
  restrictAction,
  recalcProductFromBatches,
  computeDailySummary,
  computeMonthTotal,
  cacheDel,
  pad                     // helper from app.js
}) {
  const router = express.Router();

// ★ NEW – returns the current-month badge totals for any YYYY-MM
async function computeMonthlyBadges (accountId, month) {
  const start = `${month}-01`;
  const [y, m] = month.split('-');
  const nextM = (parseInt(m, 10) % 12) + 1;
  const nextY = nextM === 1 ? +y + 1 : +y;
  const end   = `${nextY}-${String(nextM).padStart(2,'0')}-01`;

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
    gst     += (s.gstPayable || 0);
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


/* ────────────────────────────────────────────────────────────────
   GET /sales  – Sales & Expense report
   ──────────────────────────────────────────────────────────────── */
router.get(
  '/sales',
  isAuthenticated,
  restrictRoute('/sales'),
  async (req, res) => {
    try {
      const accountId          = req.session.user.accountId;
      let { saleDate, month, status } = req.query;

      /* 0️⃣  Month window for the badges */
      let monthStart, monthEnd;
      if (month) {
        monthStart = `${month}-01`;
        const [y, m] = month.split('-');
        let nextM = parseInt(m, 10) + 1, nextY = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        monthEnd = `${nextY}-${pad(nextM)}-01`;
      } else if (saleDate) {
        const [y, m] = saleDate.split('-');
        monthStart = `${y}-${m}-01`;
        let nextM = parseInt(m, 10) + 1, nextY = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        monthEnd = `${nextY}-${pad(nextM)}-01`;
      } else {
        const today = new Date();
        const curYM = `${today.getFullYear()}-${pad(today.getMonth() + 1)}`;
        monthStart = `${curYM}-01`;
        let nextM = today.getMonth() + 2, nextY = today.getFullYear();
        if (nextM > 12) { nextM = 1; nextY++; }
        monthEnd = `${nextY}-${pad(nextM)}-01`;
      }

      /* 1️⃣  Table-level queries with filters */
      let salesQ = db.collection('sales')
                     .where('accountId','==',accountId)
                     .orderBy('createdAt','desc');
      let expenseQ = db.collection('expenses')
                       .where('accountId','==',accountId)
                       .orderBy('createdAt','desc');
      if (saleDate) {
        salesQ   = salesQ.where('saleDate','==',saleDate);
        expenseQ = expenseQ.where('saleDate','==',saleDate);
      } else {
        salesQ   = salesQ.where('saleDate','>=',monthStart)
                         .where('saleDate','<', monthEnd);
        expenseQ = expenseQ.where('saleDate','>=',monthStart)
                           .where('saleDate','<', monthEnd);
        if (!month) month = monthStart.substring(0,7);
      }
      if (status && status.trim() && status !== 'All') {
        salesQ   = salesQ .where('status','==',status);
        expenseQ = expenseQ.where('expenseStatus','==',status);
      }

      /* 2️⃣  Month-totals queries (ignore status) */
      const monthSalesQ = db.collection('sales')
                            .where('accountId','==',accountId)
                            .where('saleDate','>=',monthStart)
                            .where('saleDate','<', monthEnd);
      const monthExpQ   = db.collection('expenses')
                            .where('accountId','==',accountId)
                            .where('saleDate','>=',monthStart)
                            .where('saleDate','<', monthEnd);

      /* 3️⃣  Parallel fetch */
      const [
        tableSalesSnap, tableExpSnap,
        monthSalesSnap, monthExpSnap
      ] = await Promise.all([
        salesQ.get(),   expenseQ.get(),
        monthSalesQ.get(), monthExpQ.get()
      ]);

      const sales    = tableSalesSnap.docs.map(d => ({ id:d.id, ...d.data() }));
      const expenses = tableExpSnap .docs.map(d => ({ id:d.id, ...d.data() }));
      const monthSales = monthSalesSnap.docs.map(d => d.data());

      /* 4️⃣  Month badges */
      const monthRevenueAmount = monthSales.reduce((s,x)=>
        s + (x.totalSale!==undefined
              ? +x.totalSale
              : x.retailPrice * x.saleQuantity), 0);
      const monthGrossProfit   = monthSales.reduce((s,x)=>s + x.profit, 0);
      const monthExpenseTotal  = await computeMonthTotal(accountId, month);
      const monthNetProfit     = monthGrossProfit - monthExpenseTotal;
      const monthGstPayable    = monthSales.reduce((s,x)=>s + (x.gstPayable||0),0);

      /* 5️⃣  Opening balances + open/close times */
      const allDates = [...new Set([
        ...sales.map(s=>s.saleDate),
        ...expenses.map(e=>e.saleDate)
      ])];
      const openingTimes    = {};
      const openingBalances = {};
      await Promise.all(allDates.map(async d=>{
        const ob = await db.collection('openingBalances')
                           .doc(`${accountId}_${d}`).get();
        if (ob.exists) {
          const o = ob.data();
          openingTimes[d]    = {
            openingTime: o.openingTime || '',
            closingTime: o.closingTime || ''
          };
          openingBalances[d] = +(o.balance || 0);
        } else {
          openingTimes[d]    = { openingTime:'', closingTime:'' };
          openingBalances[d] = 0;
        }
      }));

      /* 6️⃣  Render */
      res.render('sales', {
        sales, expenses, saleDate, month, status,
        totalRevenueAmount   : monthRevenueAmount,
        profitWithoutExpenses: monthGrossProfit,
        totalExpensesAmount  : monthExpenseTotal,
        profitAfterExpenses  : monthNetProfit,
        monthGstPayable,
        openingTimes,
        openingBalances,
        blockedActions: req.session.blockedActions || {}
      });
    } catch (err) {
      res.status(500).send(err.toString());
    }
  }
);

/* ────────────────────────────────────────────────────────────────
   POST /api/edit-sale  – inline edits (status, extraInfo, qty, totalSale)
   ──────────────────────────────────────────────────────────────── */
router.post(
  '/api/edit-sale',
  isAuthenticated,
  restrictAction('/sales','edit'),
  async (req, res) => {
    const { saleId, field, value, paymentDetail1, paymentDetail2 } = req.body;
    try {
      const saleRef  = db.collection('sales').doc(saleId);
      const saleSnap = await saleRef.get();
      if (!saleSnap.exists)
        return res.json({ success:false, error:'Sale not found' });

      const data = saleSnap.data();
      if (data.accountId !== req.session.user.accountId)
        return res.json({ success:false, error:'Access denied' });

      /* 1️⃣  STATUS quick-update */
      if (field === 'status') {
        const update = { status:value };
        if (paymentDetail1 !== undefined)
          update.paymentDetail1 = +parseFloat(paymentDetail1 || 0);
        if (paymentDetail2 !== undefined)
          update.paymentDetail2 = +parseFloat(paymentDetail2 || 0);
        await saleRef.update(update);

        const { summary } = await computeDailySummary(
          req.session.user.accountId, data.saleDate
        );
        const monthTotal = await computeMonthTotal(
          req.session.user.accountId, data.saleDate.substring(0,7)
        );
        return res.json({ success:true, updatedRow:update, summary, monthTotal });
      }

      /* 1️⃣-b  EXTRA-INFO */
      if (field === 'extraInfo') {
        const update = { extraInfo:(value||'').trim() };
        await saleRef.update(update);

        const { summary } = await computeDailySummary(
          req.session.user.accountId, data.saleDate
        );
        const monthTotal = await computeMonthTotal(
          req.session.user.accountId, data.saleDate.substring(0,7)
        );
        return res.json({ success:true, updatedRow:update, summary, monthTotal });
      }

      /* 2️⃣  Quantity / TotalSale edits → stock adjustments */
      let newQty       = +data.saleQuantity;
      let newTotalSale = +data.totalSale;
      if (field === 'saleQuantity') newQty       = +parseFloat(value);
      if (field === 'totalSale')    newTotalSale = +parseFloat(value);

      if (newQty <= 0)
        return res.json({ success:false, error:'Quantity must be > 0' });
      if (newTotalSale < 0)
        return res.json({ success:false, error:'Total amount cannot be negative' });

      const delta     = +(newQty - data.saleQuantity);    // + take more, − return
      const batchCol  = db.collection('stockBatches');
      const stockOps  = db.batch();
      let   batchesUsed = Array.isArray(data.batchesUsed)
                            ? [...data.batchesUsed] : [];

      /* ——— take MORE stock ——— */
      if (delta > 0) {
        let need = delta;
        const fifo = await batchCol
          .where('productId','==',data.productId)
          .where('remainingQuantity','>',0)
          .orderBy('batchDate','asc')
          .get();
        for (const b of fifo.docs) {
          if (need <= 0) break;
          const d    = b.data();
          const take = Math.min(d.remainingQuantity, need);
          stockOps.update(b.ref, {
            quantity         : admin.firestore.FieldValue.increment(-take),
            remainingQuantity: +(d.remainingQuantity - take).toFixed(3)
          });
          const idx = batchesUsed.findIndex(x=>x.id===b.id);
          if (idx > -1) batchesUsed[idx].qtyUsed += take;
          else          batchesUsed.push({ id:b.id, qtyUsed:take });
          need -= take;
        }
        if (need > 0)
          return res.json({ success:false, error:'Not enough stock' });

      /* ——— RETURN stock ——— */
      } else if (delta < 0) {
        let give = -delta;
        for (const u of [...batchesUsed].reverse()) {
          if (give <= 0) break;
          const ret = Math.min(u.qtyUsed, give);
          const ref  = batchCol.doc(u.id);
          const snap = await ref.get();
          if (snap.exists) {
            stockOps.update(ref, {
              quantity         : admin.firestore.FieldValue.increment(ret),
              remainingQuantity: admin.firestore.FieldValue.increment(ret)
            });
          }
          u.qtyUsed -= ret;
          give     -= ret;
        }
        batchesUsed = batchesUsed.filter(u => u.qtyUsed > 0.0001);
      }

      if (stockOps._ops.length) await stockOps.commit();

      /* refresh parent product */
      await recalcProductFromBatches(data.productId);

      /* FIFO-weighted wholesale */
      let wSum = 0;
      for (const u of batchesUsed) {
        const bd = await batchCol.doc(u.id).get();
        if (bd.exists) wSum += bd.data().purchasePrice * u.qtyUsed;
      }
      const avgWholesale  = +(wSum / newQty).toFixed(2);
      const retailPerUnit = +(newTotalSale / newQty).toFixed(2);
      const profitPerUnit = +(retailPerUnit - avgWholesale).toFixed(2);
      const totalProfit   = +(profitPerUnit * newQty).toFixed(2);

      /* write back */
      await saleRef.update({
        saleQuantity   : newQty,
        totalSale      : newTotalSale,
        retailPrice    : retailPerUnit,
        wholesalePrice : avgWholesale,
        profitPerUnit,
        profit         : totalProfit,
        batchesUsed,
        productName    : data.productName.replace(/ \(updated\)$/, '')
      });

      const { summary } = await computeDailySummary(
        req.session.user.accountId, data.saleDate
      );

      return res.json({
        success:true,
        updatedRow:{
          saleQuantity  : +newQty.toFixed(3),
          totalSale     : +newTotalSale.toFixed(2),
          retailPrice   : retailPerUnit,
          wholesalePrice: avgWholesale,
          profitPerUnit,
          profit        : totalProfit,
          productName   : data.productName.replace(/ \(updated\)$/, '')
        },
        summary
      });
    } catch (err) {
      console.error(err);
      res.json({ success:false, error:err.message });
    }
  }
);

/* ────────────────────────────────────────────────────────────────
   POST /api/delete-sale  – delete row & restore stock
   ──────────────────────────────────────────────────────────────── */
router.post('/api/delete-sale', isAuthenticated, restrictAction('/sales','delete'), async (req, res) => {
  const { saleId } = req.body;

  try {
    // 1. Fetch the sale
    const saleRef = db.collection('sales').doc(saleId);
    const saleDoc = await saleRef.get();
    if (!saleDoc.exists) return res.json({ success: true });

    const sale = saleDoc.data();
    if (sale.accountId !== req.session.user.accountId) {
      return res.json({ success: false, error: 'Access denied' });
    }

    // 2. Prepare to restore stock quantities
    const productId = sale.productId;
/* ─────────── 1. RESTORE STOCK ─────────── */
const batchCol  = db.collection('stockBatches');
const batchOps  = db.batch();   
const prodRef   = db.collection('products').doc(productId);   // master doc
const missing   = [];

let didUpdate = false;                      // ← NEW – track writes

if (Array.isArray(sale.batchesUsed)) {
  for (const bu of sale.batchesUsed) {
    const ref  = batchCol.doc(bu.id);
    const snap = await ref.get();
    if (snap.exists) {
      batchOps.update(ref, {
        quantity         : admin.firestore.FieldValue.increment(bu.qtyUsed),
        remainingQuantity: admin.firestore.FieldValue.increment(bu.qtyUsed)
      });
      didUpdate = true;                     // at least one real write
    } else {
      missing.push(bu);                     // will recreate later
    }
  }
}

/* bump the master product stock back by the exact sale qty */
batchOps.update(prodRef, {
  quantity: admin.firestore.FieldValue.increment(sale.saleQuantity)
});
didUpdate = true;

/* commit only when we really queued something */
if (didUpdate) await batchOps.commit();

/* recreate any batches that were missing entirely -------------------- */
for (const bu of missing) {
  await batchCol.add({
    productId,
    productName      : sale.productName.replace(/ \(updated\)$/, ''),
    purchasePrice    : sale.wholesalePrice,
    salePrice        : sale.retailPrice,
    quantity         : bu.qtyUsed,
    remainingQuantity: bu.qtyUsed,
    batchDate        : new Date(),
    accountId        : sale.accountId,
    unit             : sale.unit || ''
  });
}


    // 5. Delete the sale record
    await saleRef.delete();

    // 6. Recalculate product stock from batches
    await recalcProductFromBatches(productId);

    // 7. Recompute updated totals for the day and month
await Promise.all([
  cacheDel(`dailySum_${sale.accountId}_${sale.saleDate}`),
  cacheDel(`monthTotal_${sale.accountId}_${sale.saleDate.substring(0, 7)}`),
  cacheDel(`products_${sale.accountId}`),      // full list
  cacheDel(`product_${productId}`)             // single-item cache
]);

/* 1️⃣  Fresh month aggregate */
const monthTotal = await computeMonthTotal(
  sale.accountId,
  sale.saleDate.substring(0, 7)       // "YYYY-MM"
);

/* 2️⃣  Fresh daily summary (will be re-cached for 30 s inside) */
const { summary } = await computeDailySummary(
  sale.accountId, sale.saleDate
);


const badges = await computeMonthlyBadges(
  sale.accountId,
  sale.saleDate.substring(0, 7)       // "YYYY-MM"
);

res.json({ success: true, summary, monthTotal, badges });

  } catch (e) {
    console.error('delete-sale error:', e);
    res.json({ success: false, error: e.toString() });
  }
});

  return router;
};
