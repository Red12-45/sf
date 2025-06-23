async function ensureRecurringSnapshot(accountId, month) {
  /* 0️⃣  Build a set of templateIds that are already snapshotted */
  const existingSnap = await db.collection('recurringMonthly')
                               .where('accountId', '==', accountId)
                               .where('month',      '==', month)
                               .get();
  const have = new Set(existingSnap.docs.map(d => d.data().templateId));

  /* 1️⃣  Work out first day of NEXT month (for “future” filter) */
  const [y, m] = month.split('-');
  let nextM = parseInt(m, 10) + 1,
      nextY = parseInt(y, 10);
  if (nextM > 12) { nextM = 1; nextY++; }
  const nextMonthStart = new Date(
    `${nextY}-${String(nextM).padStart(2, '0')}-01T00:00:00Z`
  );

  /* 2️⃣  Pull every master template for this account */
  const tplSnap = await db.collection('recurringExpenses')
                          .where('accountId', '==', accountId)
                          .get();

  const batch = db.batch();

  tplSnap.docs.forEach(doc => {
    const d = doc.data();

    /* ── 🆕  Skip templates retired in, or before, this month ── */
    if (d.removalMonth && d.removalMonth <= month) return;

    /* Skip templates created AFTER this month finishes           */
    const created = d.createdAt
      ? (typeof d.createdAt.toDate === 'function'
          ? d.createdAt.toDate()
          : new Date(d.createdAt))
      : new Date(0);
    if (created >= nextMonthStart) return;

    /* Skip if we already have a snapshot row for this template   */
    if (have.has(doc.id)) return;

    const id = `${accountId}_${month}_${doc.id}`;

batch.set(db.collection('recurringMonthly').doc(id),{
  accountId,
  month,
  templateId   : doc.id,
  expenseReason: d.expenseReason,
  expenseCost  : 0,           // user will enter the real value later
  expenseStatus: 'Not Paid',
  createdAt    : new Date()
});

  });

  if (batch._ops?.length) await batch.commit();   // ← only when needed
}


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

async function processExpense(body, user) {
  const accountId = user.accountId;
  const saleDate  = body.saleDate;

  // Normalise to arrays so single-row & multi-row both work
  const reasons  = Array.isArray(body.expenseReason) ? body.expenseReason  : [body.expenseReason];
  const costs    = Array.isArray(body.expenseCost)   ? body.expenseCost    : [body.expenseCost];
  const statuses = Array.isArray(body.expenseStatus) ? body.expenseStatus  : [body.expenseStatus];
  const d1s      = Array.isArray(body.expenseDetail1)? body.expenseDetail1 : [body.expenseDetail1];
  const d2s      = Array.isArray(body.expenseDetail2)? body.expenseDetail2 : [body.expenseDetail2];

  /* 🔄 Validate & trim once */
  reasons .forEach((v,i)=>reasons [i]=(v||'').toString().substring(0,100).trim());
  statuses.forEach((v,i)=>statuses[i]=(v||'').toString().substring(0,40) .trim());

  const batch = db.batch();
  let lastRef = null;

  for (let i = 0; i < reasons.length; i++) {
    const ref = db.collection('expenses').doc();   // pre-allocate ID
    lastRef   = ref;
    const data = {
      expenseReason : reasons[i],
      expenseCost   : parseFloat(costs[i]),
      expenseStatus : statuses[i] || 'Paid Cash',
      saleDate,
      accountId,
      createdAt     : new Date(),
      ...(d1s[i] && { expenseDetail1: parseFloat(d1s[i]) }),
      ...(d2s[i] && { expenseDetail2: parseFloat(d2s[i]) })
    };
    batch.set(ref, data);
  }

  await batch.commit();
  await cacheDel(`dailySum_${accountId}_${saleDate}`);

  return (await lastRef.get()).data();             // keep Ajax contract
}


app.get(
  '/expense',
  isAuthenticated,
  restrictRoute('/expense'),
  async (req, res) => {
    try {
      const accountId   = req.session.user.accountId;

      /* ─── 1. work out month window (unchanged) ─── */
      const today         = new Date();
      const currentYear   = today.getFullYear();
      const currentMonth  = pad(today.getMonth() + 1);
      const defaultMonth  = `${currentYear}-${currentMonth}`;
      const monthParam    = req.query.month || defaultMonth;       // ← keep param name
      const startDate     = `${monthParam}-01`;
      const [y, m]        = monthParam.split('-');
      let nextM = parseInt(m, 10) + 1,
          nextY = parseInt(y, 10);
      if (nextM > 12) { nextM = 1; nextY++; }
      const nextMonth = `${nextY}-${pad(nextM)}-01`;

const todayYM   = `${currentYear}-${currentMonth}`;   // "YYYY-MM"
const isFuture  = monthParam > todayYM;   


/* expenses: always fetch */
const expenseSnap = await db.collection('expenses')
  .where('accountId','==',accountId)
  .where('saleDate','>=',startDate)
  .where('saleDate','<', nextMonth)
  .orderBy('createdAt','desc')
  .get();

/* recurringMonthSnap: empty if future month selected */
const recurringMonthSnap = isFuture
  ? { docs: [] }                                     // ➜ nothing to show
  : await db.collection('recurringMonthly')
      .where('accountId','==',accountId)
      .where('month','==',monthParam)
      .orderBy('expenseReason','asc')
      .get();

const expenses          = expenseSnap.docs.map(d => ({ id:d.id, ...d.data() }));
const recurringMonthly = recurringMonthSnap.docs
  .map(d => ({ id:d.id, ...d.data() }))
  .filter(t => !t.deleted);          // ⬅️  hide soft-deleted rows
/* use the helper so half-paid rows count only once */
const totalExpense = expenses.reduce((s, e) => s + paidPortion(e), 0);

const recTotal = recurringMonthly.reduce((s, t) => s + paidPortion(t), 0);

const grandTotal = totalExpense + recTotal;



      const groupedExpenses = {};
      expenses.forEach(e => {
        const created = (e.createdAt.toDate) ? e.createdAt.toDate() : new Date(e.createdAt);
        const dateStr = created.toISOString().substring(0, 10);
        (groupedExpenses[dateStr] = groupedExpenses[dateStr] || []).push(e);
      });

      

res.render('expense', {
  month            : monthParam,
  groupedExpenses,
  totalExpense,
  recurringMonthly,   // ← keep
  recTotal,           // ← keep
  grandTotal,         // ← keep
  blockedActions   : req.session.blockedActions || {}
});


    } catch (err) {
      res.status(500).send(err.toString());
    }
});


app.post('/add-recurring-expense', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
const { recurringReason } = req.body;

const DEFAULT_STATUS = 'Not Paid';


/* ① create the master template */
const tplRef = await db.collection('recurringExpenses').add({
  accountId,
  expenseReason : recurringReason.trim(),
  createdAt     : new Date()
});

/* ② auto-generate snapshots for current & next 24 months */
const batch = db.batch();
const today = new Date();
for (let i = 0; i < 24; i++) {                       // 2-year horizon
  const dt   = new Date(today.getFullYear(), today.getMonth() + i, 1);
  const ym   = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2,'0')}`;
  const id   = `${accountId}_${ym}_${tplRef.id}`;

  batch.set(
    db.collection('recurringMonthly').doc(id),
    {
      accountId,
      month        : ym,
      templateId   : tplRef.id,
      expenseReason: recurringReason.trim(),
      expenseCost  : 0,
      expenseStatus: 'Not Paid',
      createdAt    : new Date()
    },
    { merge:true }                                   // overwrite-safe
  );
}
await batch.commit();

/* ③ back to the UI */
const month = req.body.month || new Date().toISOString().substring(0,7);
res.redirect(`/expense?month=${month}`);

  } catch (err) {
    res.status(500).send(err.toString());
  }
});


app.post('/expense', isAuthenticated, restrictRoute('/expense'), async (req, res) => {
  try {
    await processExpense(req.body, req.session.user);
    const month = req.body.saleDate.substring(0,7);
    const dest = req.body.redirectTo === 'expense'
      ? `/expense?month=${month}`
      : `/?saleDate=${req.body.saleDate}`;
    res.redirect(dest);
  } catch (e) {
    res.status(500).send(e.toString());
  }
});


app.post('/api/expense', isAuthenticated, async (req, res) => {
  try {
    /* 0️⃣  Fire the insert (can be 1 or many rows) */
    await processExpense(req.body, req.session.user);

    /* 1️⃣  Fetch JUST the rows we created:
           – total rows = length of expenseReason[]  */
    const rowsInserted = Array.isArray(req.body.expenseReason)
                           ? req.body.expenseReason.length
                           : 1;

    const snap = await db.collection('expenses')
      .where('accountId','==',req.session.user.accountId)
      .orderBy('createdAt','desc')
      .limit(rowsInserted)
      .get();

    /* Reverse so they come back oldest➜newest */
    const addedExpenses = snap.docs.reverse().map(d => {
      const e = d.data();
      const created = e.createdAt?.toDate ? e.createdAt.toDate()
                                          : new Date(e.createdAt);
      return {
        id         : d.id,
        yyyy_mm_dd : e.saleDate,                                     // YYYY-MM-DD
        dateLabel  : created.toLocaleString('default',{ month:'long', day:'numeric' }),
        timeLabel  : created.toLocaleTimeString(),
        ...e
      };
    });

    /* 2️⃣  Re-compute this month’s running total */
    const month   = req.body.saleDate.substring(0,7);                // "YYYY-MM"
    const monthTotal = await computeMonthTotal(req.session.user.accountId, month);

    /* 3️⃣  Done */
    return res.json({
      success   : true,
      monthTotal,
      expenses  : addedExpenses           // ALWAYS an array
    });

  } catch (err) {
    console.error('/api/expense error:', err);
    return res.json({ success:false, error: err.toString() });
  }
});


app.post(
  '/api/edit-expense',
  isAuthenticated,
  restrictAction('/expense', 'edit'),
  async (req, res) => {
    try {
     const {
  expenseId,
  field,
  value,
  paymentDetail1 = req.body.expenseDetail1,
  paymentDetail2 = req.body.expenseDetail2
} = req.body;

      const ALLOWED = ['expenseStatus', 'expenseCost', 'expenseReason'];
      if (!ALLOWED.includes(field))
        return res.json({ success:false, error:'Invalid field' });

      const expRef  = db.collection('expenses').doc(expenseId);
      const expSnap = await expRef.get();
      if (!expSnap.exists)
        return res.json({ success:false, error:'Expense not found' });

      const exp = expSnap.data();
      if (exp.accountId !== req.session.user.accountId)
        return res.json({ success:false, error:'Access denied' });

      /* ---------- build update ---------- */
      const update = { updatedAt: new Date() };

      if (field === 'expenseStatus') {
        update.expenseStatus = value;
        if (paymentDetail1 !== undefined)
          update.expenseDetail1 = +parseFloat(paymentDetail1 || 0);
        if (paymentDetail2 !== undefined)
          update.expenseDetail2 = +parseFloat(paymentDetail2 || 0);

      } else if (field === 'expenseCost') {
        const num = +parseFloat(value);
        if (!Number.isFinite(num) || num < 0)
          return res.json({ success:false, error:'Invalid amount' });
        update.expenseCost = num;

      } else if (field === 'expenseReason') {
        const txt = (value || '').toString().substring(0,100).trim();
        if (!txt) return res.json({ success:false, error:'Reason required' });
        update.expenseReason = txt;
      }

await expRef.update(update);

/* ── keep the day summary (unchanged) ── */
const { summary } = await computeDailySummary(
  req.session.user.accountId, exp.saleDate
);

/* ── NEW: fresh month total after the status/amount/reason change ── */
const monthTotal = await computeMonthTotal(
  req.session.user.accountId,
  exp.saleDate.substring(0, 7)        // ➜ "YYYY-MM"
);

/* ── return monthTotal so the front-end can call updateMonthTotal() ── */
res.json({ success:true, updatedRow:update, summary, monthTotal });

    } catch (err) {
      console.error('edit-expense error:', err);
      return res.json({ success:false, error:err.toString() });
    }
  }
);


app.post(
  '/api/delete-expense',
  isAuthenticated,
  restrictAction('/expense', 'delete'),
  async (req, res) => {
    const { expenseId } = req.body;

    try {
      const expRef = db.collection('expenses').doc(expenseId);
      const expDoc = await expRef.get();

      /* ✨ idempotent: already gone → succeed silently */
      if (!expDoc.exists) return res.json({ success: true });

      const exp = expDoc.data();
      if (exp.accountId !== req.session.user.accountId)
        return res.json({ success: false, error: 'Access denied' });

      /* 1️⃣ delete row */
      await expRef.delete();

      /* 2️⃣ fresh daily summary (same day) */
      const { summary } = await computeDailySummary(
        req.session.user.accountId,
        exp.saleDate
      );

      /* 3️⃣ fresh month-total (YYYY-MM) */
      const monthTotal = await computeMonthTotal(
        req.session.user.accountId,
        exp.saleDate.substring(0, 7)
      );

      /* 4️⃣ done */
      return res.json({ success: true, summary, monthTotal });

    } catch (e) {
      return res.json({ success: false, error: e.toString() });
    }
  }
);

app.post('/api/recurring-monthly/:recId', isAuthenticated, async (req, res) => {
  try {
    const { recId } = req.params;
    const snapRef   = db.collection('recurringMonthly').doc(recId);
    const snap      = await snapRef.get();

    if (!snap.exists) throw new Error('Row not found');

    /* 1️⃣  Build a white-list of fields we allow from the browser */
    const update = {};
    if (req.body.expenseCost   !== undefined)
      update.expenseCost   = parseFloat(req.body.expenseCost);

    if (req.body.expenseReason !== undefined)
      update.expenseReason = req.body.expenseReason.trim();

    if (req.body.expenseStatus !== undefined)
      update.expenseStatus = req.body.expenseStatus.trim();

    /* Nothing to change?  Bail out early. */
    if (!Object.keys(update).length)
      return res.json({ success:true });

    /* 2️⃣  Persist changes */
    await snapRef.update(update);

    /* 3️⃣  Return fresh month-total badge */
    const monthTotal = await computeMonthTotal(
      req.session.user.accountId,
      snap.data().month
    );

    return res.json({ success:true, monthTotal });
  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  }
});


app.post('/delete-recurring-monthly/:recId', isAuthenticated, async (req, res) => {
  try {
    const { recId } = req.params;
    const ref  = db.collection('recurringMonthly').doc(recId);
    const snap = await ref.get();

    /* 1️⃣  Permission check */
    if (!snap.exists || snap.data().accountId !== req.session.user.accountId) {
      const msg = 'Access denied';
      return req.xhr
        ? res.json({ success: false, error: msg })
        : res.status(403).send(msg);
    }

    /* 2️⃣  Soft-delete this MONTH’S snapshot row           */
    await ref.update({ deleted: true, updatedAt: new Date() });

    /* 3️⃣  Retire the master template from this month on   */
const tplId  = snap.data().templateId || null;
const month  = snap.data().month;
const todayYM = new Date().toISOString().substring(0,7);   // "YYYY-MM"

if (tplId && month === todayYM) {
  /* 1️⃣ mark template inactive from now on */
  await db.collection('recurringExpenses')
          .doc(tplId)
          .set({ removalMonth:month, updatedAt:new Date() },{ merge:true });

  /* 2️⃣ hide any existing snapshots in future months */
const futSnap = await db.collection('recurringMonthly')
  .where('accountId','==',snap.data().accountId)
  .where('templateId','==',tplId)           // 🔒 equality filters only
  .get();

const futBatch = db.batch();
futSnap.docs.forEach(d => {
  if (d.data().month > month) {             // ➜ future only
    futBatch.update(d.ref, { deleted:true, updatedAt:new Date() });
  }
});
if (futBatch._ops?.length) await futBatch.commit();
}

    /* 4️⃣  Respond */
   if (req.xhr) {
  const monthTotal = await computeMonthTotal(req.session.user.accountId, month);
  return res.json({ success: true, monthTotal });
}
    res.redirect(`/expense?month=${month}`);

  } catch (err) {
    if (req.xhr) return res.json({ success: false, error: err.toString() });
    res.status(500).send(err.toString());
  }
});


