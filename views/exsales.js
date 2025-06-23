function paidPortion (row) {
  const status = row.expenseStatus || '';
  const cost   = +row.expenseCost || 0;

  switch (status) {
    case 'Not Paid':
      return 0;

    case 'Half Cash + Not Paid':
    case 'Half Online + Not Paid':
      // Use the explicit paid half if supplied,
      // otherwise assume an even 50-50 split.
      return row.expenseDetail1 !== undefined
             ? (+row.expenseDetail1 || 0)
             : cost / 2;

    // Everything else is fully settled
    default:
      return cost;
  }
}

async function computeDailySummary(accountId, saleDate) {
  /* 0. HOT-CACHE (30 s) – most dashboards reload within this */
  const ck = `dailySum_${accountId}_${saleDate}`;
  const cached = await cacheGet(ck);
  if (cached) return cached;            // hit ➜ <0.5 ms path

  /* 1. ORIGINAL Firestore work (unchanged logic) */
  const [salesSnap, expSnap, obDoc] = await Promise.all([
    db.collection('sales')
      .where('accountId','==',accountId)
      .where('saleDate',  '==',saleDate)
      .get(),
    db.collection('expenses')
      .where('accountId','==',accountId)
      .where('saleDate',  '==',saleDate)
      .get(),
    db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get()
  ]);

  const s = {
    totalProfit:0, totalSales:0,
    totalCashSales:0, totalOnlineSales:0, totalNotPaidSales:0,
    totalCashExpenses:0, totalOnlineExpenses:0,
    totalGstPayable:0
  };

  salesSnap.forEach(doc => {
    const d   = doc.data();
    const amt = d.totalSale !== undefined
                  ? +parseFloat(d.totalSale)
                  : d.retailPrice * d.saleQuantity;

    s.totalProfit += d.profit;
    s.totalSales  += amt;

    switch (d.status) {
      case 'Paid Cash':               s.totalCashSales   += amt; break;
      case 'Paid Online':             s.totalOnlineSales += amt; break;
      case 'Not Paid':                s.totalNotPaidSales+= amt; break;
      case 'Half Cash + Half Online':
        if (d.paymentDetail1) s.totalCashSales   += d.paymentDetail1;
        if (d.paymentDetail2) s.totalOnlineSales += d.paymentDetail2;
        break;
      case 'Half Cash + Not Paid':
        if (d.paymentDetail1) s.totalCashSales   += d.paymentDetail1;
        if (d.paymentDetail2) s.totalNotPaidSales+= d.paymentDetail2;
        break;
      case 'Half Online + Not Paid':
        if (d.paymentDetail1) s.totalOnlineSales += d.paymentDetail1;
        if (d.paymentDetail2) s.totalNotPaidSales+= d.paymentDetail2;
        break;
    }
    s.totalGstPayable += (d.gstPayable || 0);
  });

  expSnap.forEach(doc => {
    const d = doc.data();
    switch (d.expenseStatus) {
      case 'Paid Cash':               s.totalCashExpenses += d.expenseCost; break;
      case 'Paid Online':             s.totalOnlineExpenses+= d.expenseCost; break;
      case 'Half Cash + Half Online':
        if (d.expenseDetail1) s.totalCashExpenses   += d.expenseDetail1;
        if (d.expenseDetail2) s.totalOnlineExpenses += d.expenseDetail2;
        break;
      case 'Half Cash + Not Paid':
        if (d.expenseDetail1) s.totalCashExpenses   += d.expenseDetail1;
        break;
      case 'Half Online + Not Paid':
        if (d.expenseDetail1) s.totalOnlineExpenses += d.expenseDetail1;
        break;
    }
  });

  const openingBal = obDoc.exists ? (obDoc.data().balance || 0) : 0;
  s.finalCash      = +((+openingBal) + s.totalCashSales - s.totalCashExpenses).toFixed(2);
  s.totalSales     = +s.totalSales.toFixed(2);
  s.totalProfit    = +s.totalProfit.toFixed(2);

  const result = { summary: s, openingBalance: openingBal };

  /* 2. STORE in Redis (30 s TTL) */
  await cacheSet(ck, result, 30);

  return result;
}


async function computeMonthTotal(accountId, month) {

  const start = `${month}-01`;
  const [y, m] = month.split('-');
  let nextM = parseInt(m, 10) + 1, nextY = parseInt(y, 10);
  if (nextM > 12) { nextM = 1; nextY++; }
  const end = `${nextY}-${String(nextM).padStart(2, '0')}-01`;

  /* 1️⃣  Pull every EXPENSE in the month */
  const expSnap = await db.collection('expenses')
    .where('accountId','==',accountId)
    .where('saleDate',  '>=', start)
    .where('saleDate',  '<',  end)
    .get();

const expenseTotal = expSnap.docs
  .reduce((s, d) => s + paidPortion(d.data()), 0);

  /* 2️⃣  Pull this month’s RECURRING snapshot rows */
  const recSnap = await db.collection('recurringMonthly')
    .where('accountId','==',accountId)
    .where('month',     '==', month)
    .get();

const recTotal = recSnap.docs
  .filter(d => !d.data().deleted)
  .reduce((s, d) => s + paidPortion(d.data()), 0);

  return +(expenseTotal + recTotal).toFixed(2);
}


app.get(
  '/sales',
  isAuthenticated,
  restrictRoute('/sales'),
  async (req, res) => {
    try {
      const accountId          = req.session.user.accountId;
      // (updated code)
let { saleDate, month, status } = req.query;   // ← month is now mutable


      /* ─── 0. Work out the month window we’ll “lock” the badges to ─── */
      
      let monthStart, monthEnd;

      if (month) {                                        // user picked a month
        monthStart = `${month}-01`;
        const [y, m] = month.split('-');
        let nextM = parseInt(m, 10) + 1,
            nextY = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        monthEnd = `${nextY}-${pad(nextM)}-01`;

      } else if (saleDate) {                              // single-day filter
        const [y, m] = saleDate.split('-');
        monthStart = `${y}-${m}-01`;
        let nextM  = parseInt(m, 10) + 1,
            nextY  = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        monthEnd = `${nextY}-${pad(nextM)}-01`;

      } else {                                           // default = current month
        const today = new Date();
        const curYM = `${today.getFullYear()}-${pad(today.getMonth() + 1)}`;
        monthStart  = `${curYM}-01`;
        let nextM   = today.getMonth() + 2,
            nextY   = today.getFullYear();
        if (nextM > 12) { nextM = 1; nextY++; }
        monthEnd    = `${nextY}-${pad(nextM)}-01`;
      }

   /* ─── 1. Build the MAIN (filtered) queries for the table ─── */
let salesQ = db.collection('sales')
               .where('accountId', '==', accountId)
               .orderBy('createdAt', 'desc');

let expenseQ = db.collection('expenses')
                 .where('accountId', '==', accountId)
                 .orderBy('createdAt', 'desc');

/* -----------------------------------------------------------
   Apply date filters in priority order
   1. ?saleDate=YYYY-MM-DD       → single-day view
   2. ?month=YYYY-MM             → explicit month view
   3. (no filter)                → **current month** view  ← NEW
----------------------------------------------------------- */
if (saleDate) {

  // 1️⃣ single day
  salesQ   = salesQ  .where('saleDate', '==', saleDate);
  expenseQ = expenseQ.where('saleDate', '==', saleDate);

} else if (month) {

  // 2️⃣ explicit month from query-string
  salesQ   = salesQ .where('saleDate', '>=', monthStart)
                    .where('saleDate', '<',  monthEnd);
  expenseQ = expenseQ.where('saleDate', '>=', monthStart)
                     .where('saleDate', '<',  monthEnd);

} else {

  // 3️⃣ DEFAULT → use the *current* month window calculated above
  salesQ   = salesQ .where('saleDate', '>=', monthStart)
                    .where('saleDate', '<',  monthEnd);
  expenseQ = expenseQ.where('saleDate', '>=', monthStart)
                     .where('saleDate', '<',  monthEnd);

  // populate <input type="month"> so it shows the current month pre-selected
  month = monthStart.substring(0, 7);          // e.g. "2025-06"
}

/* (status filter unchanged) */
if (status && status.trim() && status !== 'All') {
  salesQ   = salesQ  .where('status',        '==', status);
  expenseQ = expenseQ.where('expenseStatus', '==', status);
}


      /* ─── 2. ***Separate*** queries for MONTH totals (no status filter) ─── */
      const monthSalesQ = db.collection('sales')
                            .where('accountId', '==', accountId)
                            .where('saleDate',  '>=', monthStart)
                            .where('saleDate',  '<',  monthEnd);

      const monthExpQ   = db.collection('expenses')
                            .where('accountId', '==', accountId)
                            .where('saleDate',  '>=', monthStart)
                            .where('saleDate',  '<',  monthEnd);

      /* ─── 3. Run everything in parallel ─── */
      const [
        tableSalesSnap, tableExpSnap,
        monthSalesSnap, monthExpSnap
      ] = await Promise.all([
        salesQ.get(),   expenseQ.get(),
        monthSalesQ.get(), monthExpQ.get()
      ]);

      const sales          = tableSalesSnap.docs.map(d => ({ id: d.id, ...d.data() }));
      const expenses       = tableExpSnap .docs.map(d => ({ id: d.id, ...d.data() }));
      const monthSales     = monthSalesSnap.docs.map(d => d.data());
      const monthExpenses  = monthExpSnap .docs.map(d => d.data());

    /* ─── 4. Compute MONTH-locked badge totals ─── */
const monthRevenueAmount = monthSales.reduce((sum, s) =>
  sum + (s.totalSale !== undefined
           ? parseFloat(s.totalSale)
           : s.retailPrice * s.saleQuantity), 0);

const monthGrossProfit   = monthSales.reduce((sum, s) => sum + s.profit, 0);
const monthExpenseTotal  = await computeMonthTotal(accountId, month);
const monthNetProfit     = monthGrossProfit - monthExpenseTotal;

/* NEW ➜ total GST you owe this month */
const monthGstPayable    = monthSales.reduce((sum, s) =>
  sum + (s.gstPayable || 0), 0);


      /* ─── 5. Opening balances & times (unchanged) ─── */
      const dateSet = new Set();
      sales.forEach(s   => dateSet.add(s.saleDate));
      expenses.forEach(e=> dateSet.add(e.saleDate));
      const allDates = Array.from(dateSet);

      const openingTimes    = {};
      const openingBalances = {};
      await Promise.all(allDates.map(async date => {
        const obRef = db.collection('openingBalances').doc(`${accountId}_${date}`);
        const obDoc = await obRef.get();
        if (obDoc.exists) {
          const d = obDoc.data();
          openingTimes[date]    = {
            openingTime: d.openingTime || '',
            closingTime: d.closingTime || ''
          };
          openingBalances[date] = parseFloat(d.balance || 0);
        } else {
          openingTimes[date]    = { openingTime: '', closingTime: '' };
          openingBalances[date] = 0;
        }
      }));

      /* ─── 6. Render – pass MONTH totals to the badges ─── */
     res.render('sales', {
  sales,
  expenses,

  saleDate,
  month,
  status,

  // *** BADGE figures (month-locked) ***
  totalRevenueAmount   : monthRevenueAmount,
  profitWithoutExpenses: monthGrossProfit,
  totalExpensesAmount  : monthExpenseTotal,
  profitAfterExpenses  : monthNetProfit,
  monthGstPayable,                       // ★ NEW

  openingTimes,
  openingBalances,
  blockedActions: req.session.blockedActions || {}
});


    } catch (err) {
      res.status(500).send(err.toString());
    }
  }
);


// GET /download-sales
app.get('/download-sales', isAuthenticated, restrictRoute('/sales'), async (req, res) => {
  try {
    const accountId           = req.session.user.accountId;
    const { saleDate, month, status } = req.query;

    /* 1. build the same query logic used in /sales */
    let q = db.collection('sales')
              .where('accountId', '==', accountId)
              .orderBy('createdAt', 'desc');

    if (saleDate) {
      q = q.where('saleDate', '==', saleDate);
    } else if (month) {
      const [y, m] = month.split('-');
      const start  = `${month}-01`;
      let nextM    = parseInt(m, 10) + 1,
          nextY    = parseInt(y, 10);
      if (nextM > 12) { nextM = 1; nextY++; }
      const end = `${nextY}-${String(nextM).padStart(2, '0')}-01`;
      q = q.where('saleDate', '>=', start).where('saleDate', '<', end);
    }
    if (status && status.trim() && status !== 'All') {
      q = q.where('status', '==', status);
    }

    const snap  = await q.get();
    const sales = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    /* 2. create the workbook */
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('Sales');

    ws.columns = [
      { header: 'Sale Date',       key: 'saleDate',        width: 12 },
      { header: 'Product',         key: 'productName',     width: 32 },
      { header: 'Wholesale ₹',     key: 'wholesalePrice',  width: 14 },
      { header: 'Retail ₹',        key: 'retailPrice',     width: 12 },
      { header: 'Quantity',        key: 'saleQuantity',    width: 10 },
      { header: 'Unit',            key: 'unit',            width: 8  },
      { header: 'Total Sale ₹',    key: 'totalSale',       width: 14 },
      { header: 'Profit / Unit ₹', key: 'profitPerUnit',   width: 16 },
      { header: 'Total Profit ₹',  key: 'profit',          width: 14 },
        { header: 'GST Payable ₹',   key: 'gstPayable',      width: 14 },
      { header: 'Status',          key: 'status',          width: 24 },
      { header: 'Extra Info',      key: 'extraInfo',       width: 32 },
      { header: 'Created At',      key: 'createdAt',       width: 22 }
    ];

  sales.forEach(s => ws.addRow({
  ...s,
  totalSale   : s.totalSale || (s.retailPrice * s.saleQuantity),
  gstPayable  : s.gstPayable !== undefined ? s.gstPayable : '',
  createdAt   : (s.createdAt?.toDate ? s.createdAt.toDate()
                                     : new Date(s.createdAt))
                .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
}));

    /* 3. stream it to the client */
    res.setHeader('Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition',
      `attachment; filename="sales_${Date.now()}.xlsx"`);

    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    res.status(500).send(err.toString());
  }
});


/* ─────────── AJAX inline edit   /api/edit-sale ─────────── */
app.post('/api/edit-sale', isAuthenticated, restrictAction('/sales','edit'),    async (req, res) => {
  try {
    const { saleId, field, value, paymentDetail1, paymentDetail2 } = req.body;
    const saleRef  = db.collection('sales').doc(saleId);
    const saleSnap = await saleRef.get();
    if (!saleSnap.exists) return res.json({ success:false, error:'Sale not found' });

    const data = saleSnap.data();
    if (data.accountId !== req.session.user.accountId)
      return res.json({ success:false, error:'Access denied' });

    /* ------------------------------------------------------------------
       1️⃣ Pure-status edits (unchanged) – skip all quantity / price maths
    ------------------------------------------------------------------ */
    if (field === 'status') {
      const update = { status:value };
      if (paymentDetail1 !== undefined) update.paymentDetail1 = +parseFloat(paymentDetail1 || 0);
      if (paymentDetail2 !== undefined) update.paymentDetail2 = +parseFloat(paymentDetail2 || 0);
      await saleRef.update(update);
      const { summary } = await computeDailySummary(
        req.session.user.accountId, exp.saleDate
      );

      /* ▼ NEW — fresh month grand-total */
      const monthTotal = await computeMonthTotal(
        req.session.user.accountId,
        exp.saleDate.substring(0, 7)     // "YYYY-MM"
      );

      return res.json({
        success   : true,
        updatedRow: update,
        summary,
        monthTotal                         // ▲ include in response
      });

    }

    /* ------------------------------------------------------------------
       2️⃣ We’re changing either **saleQuantity** or **totalSale**
          → need to return/consume stock, recalc FIFO & profit
    ------------------------------------------------------------------ */
    let newQty       = +data.saleQuantity;
    let newTotalSale = +data.totalSale;

    if (field === 'saleQuantity') newQty       = +parseFloat(value);
    if (field === 'totalSale')    newTotalSale = +parseFloat(value);

    /* early sanity */
    if (newQty <= 0)  return res.json({ success:false, error:'Quantity must be > 0' });
    if (newTotalSale < 0) return res.json({ success:false, error:'Total amount cannot be negative' });

    /* Δ stock adjustment (same FIFO logic as before) ------------------- */
    const delta = +(newQty - data.saleQuantity);
    const batchCol = db.collection('stockBatches');
    const stockOps = db.batch();
    let batchesUsed = Array.isArray(data.batchesUsed) ? [...data.batchesUsed] : [];

    if (delta > 0) {                                // need MORE stock
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
        if (idx>-1) batchesUsed[idx].qtyUsed += take;
        else        batchesUsed.push({ id:b.id, qtyUsed:take });
        need -= take;
      }
      if (need > 0) return res.json({ success:false, error:'Not enough stock' });

        } else if (delta < 0) {                         // RETURN stock
      let give = -delta;
      for (const u of [...batchesUsed].reverse()) {
        if (give <= 0) break;
        const ret = Math.min(u.qtyUsed, give);

        const ref  = batchCol.doc(u.id);
        const snap = await ref.get();               // fetch once
        if (!snap.exists) continue;                 // edge-case: batch gone

        const d       = snap.data();
        const after   = d.remainingQuantity + ret;  // would-be balance
        const capped  = Math.min(after, d.quantity);// never exceed original

        stockOps.update(ref, {
          // quantity column tracks historical purchased qty; keep increment
          quantity: admin.firestore.FieldValue.increment(ret),
          // remainingQuantity is **absolute** capped value
          remainingQuantity: capped
        });

        u.qtyUsed -= ret;
        give     -= ret;
      }
      batchesUsed = batchesUsed.filter(u => u.qtyUsed > 0.0001);
    }

    if (stockOps._ops.length) await stockOps.commit();

    /* refresh parent product ------------------------------------------ */
    await recalcProductFromBatches(data.productId);

    /* FIFO weighted wholesale ----------------------------------------- */
    let wSum = 0;
    for (const u of batchesUsed) {
      const bd = await batchCol.doc(u.id).get();
      if (bd.exists) wSum += bd.data().purchasePrice * u.qtyUsed;
    }
    const avgWholesale  = +(wSum / newQty).toFixed(2);   // ₹ / unit
    const retailPerUnit = +(newTotalSale / newQty).toFixed(2);
    const profitPerUnit = +(retailPerUnit - avgWholesale).toFixed(2);
    const totalProfit   = +(profitPerUnit * newQty).toFixed(2);

    /* write back ------------------------------------------------------- */
    await saleRef.update({
      saleQuantity   : newQty,
      totalSale      : newTotalSale,
      retailPrice    : retailPerUnit,   // still per-unit for reports
      wholesalePrice : avgWholesale,
      profitPerUnit,
      profit         : totalProfit,
      batchesUsed,
      /* strip any legacy “ (updated)” suffix and always store a clean name */
      productName    : data.productName.replace(/ \(updated\)$/, '')
    });

    const { summary } = await computeDailySummary(req.session.user.accountId, data.saleDate);

    return res.json({
      success:true,
     updatedRow:{
        saleQuantity  : +newQty.toFixed(3),
        totalSale     : +newTotalSale.toFixed(2),
        retailPrice   : retailPerUnit,
        wholesalePrice: avgWholesale,
        profitPerUnit,
        profit        : totalProfit,
        /* return the clean product name as well */
        productName   : data.productName.replace(/ \(updated\)$/, '')
      },
      summary
    });

  } catch (err) {
    console.error(err);
    return res.json({ success:false, error:err.message });
  }
});


app.post('/api/delete-sale', isAuthenticated, restrictAction('/sales','delete'), async (req, res) => {
  const { saleId } = req.body;
  try {
    const saleRef = db.collection('sales').doc(saleId);
    const saleDoc = await saleRef.get();
    if (!saleDoc.exists) return res.json({ success:true });

    const sale = saleDoc.data();
    if (sale.accountId !== req.session.user.accountId)
      return res.json({ success:false, error:'Access denied' });

    const productId = sale.productId;
    const batchCol  = db.collection('stockBatches');
    const batchOps  = db.batch();
    
    const missing   = [];

    if (Array.isArray(sale.batchesUsed)) {
      for (const bu of sale.batchesUsed) {
        const ref  = batchCol.doc(bu.id);
        const snap = await ref.get();
        if (snap.exists) {
          batchOps.update(ref, {
            quantity         : admin.firestore.FieldValue.increment(bu.qtyUsed),
            remainingQuantity: admin.firestore.FieldValue.increment(bu.qtyUsed)
          });
        } else {
          missing.push(bu);
        }
      }
    }
    const hasWrites = batchOps._mutations?.length || 0;   // safest available
if (hasWrites) {
  await batchOps.commit();
}

    /* recreate missing batches with correct numbers --------------------- */
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

        await saleRef.delete();           // 1️⃣ remove sale first
    await recalcProductFromBatches(productId);   // 2️⃣ then correct stock


  /* ▼ NEW – re-compute month running total */
const monthTotal = await computeMonthTotal(
  sale.accountId,
  exp.saleDate.substring(0, 7)        // "YYYY-MM"
);

const { summary } = await computeDailySummary(
  sale.accountId, exp.saleDate
);

res.json({ success: true, summary, monthTotal });


  } catch (e) {
    console.error('delete-sale error:', e);
    res.json({ success:false, error:e.toString() });
  }
});


/* ─────────── UPDATED SALE & EXPENSE ROUTES + AJAX ENDPOINTS ─────────── */
// full‑page POST /sale
app.post('/sale', isAuthenticated, async (req, res) => {
  try {
    await processSale(req.body, req.session.user);
    res.redirect(`/?saleDate=${req.body.saleDate}`);
  } catch (e) {
    res.status(500).send(e.toString());
  }
});
