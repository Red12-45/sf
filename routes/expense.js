/* routes/expense.js – ALL expense-related logic moved out of app.js */
const express = require('express');

module.exports = function makeExpenseRoutes ({
  db,
  isAuthenticated,
  restrictRoute,
  restrictAction,
  cacheDel,
  computeDailySummary,
  computeMonthTotal
}) {
  const router = express.Router();

  /* ─────────── helpers ─────────── */
  const pad = n => String(n).padStart(2, '0');
  const paidPortion = (row) => {
    const status = row.expenseStatus || '';
    const cost   = +row.expenseCost || 0;
    switch (status) {
      case 'Not Paid':                        return 0;
      case 'Half Cash + Not Paid':
      case 'Half Online + Not Paid':
        return row.expenseDetail1 !== undefined
               ? (+row.expenseDetail1 || 0)
               : cost / 2;
      default:                               return cost;
    }
  };

  /* ─────────── helper: toTitleCase ─────────── */
const toTitleCase = str =>
  String(str)
    .trim()
    .split(/\s+/)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');


  // ★ NEW – returns the five badge numbers for any YYYY-MM
async function computeMonthlyBadges (accountId, month) {
  const start = `${month}-01`;
  const [y, m] = month.split('-');
  const nextM  = (parseInt(m, 10) % 12) + 1;
  const nextY  = nextM === 1 ? +y + 1 : +y;
  const end    = `${nextY}-${String(nextM).padStart(2,'0')}-01`;

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
    const s   = d.data();
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


  /* ─────────── processExpense (shared) ─────────── */
  async function processExpense (body, user) {
    const accountId = user.accountId;
    const saleDate  = body.saleDate;

    const reasons  = Array.isArray(body.expenseReason) ? body.expenseReason  : [body.expenseReason];
    const costs    = Array.isArray(body.expenseCost)   ? body.expenseCost    : [body.expenseCost];
    const statuses = Array.isArray(body.expenseStatus) ? body.expenseStatus  : [body.expenseStatus];
    const d1s      = Array.isArray(body.expenseDetail1)? body.expenseDetail1 : [body.expenseDetail1];
    const d2s      = Array.isArray(body.expenseDetail2)? body.expenseDetail2 : [body.expenseDetail2];

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

  /* ─────────── monthly expenses view ─────────── */
  router.get(
    '/expense',
    isAuthenticated,
    restrictRoute('/expense'),
    async (req, res) => {
      try {
        const accountId   = req.session.user.accountId;

        const today         = new Date();
        const currentYear   = today.getFullYear();
        const currentMonth  = pad(today.getMonth() + 1);
        const defaultMonth  = `${currentYear}-${currentMonth}`;
        const monthParam    = req.query.month || defaultMonth;
        const startDate     = `${monthParam}-01`;
        const [y, m]        = monthParam.split('-');
        let nextM = parseInt(m, 10) + 1,
            nextY = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        const nextMonth = `${nextY}-${pad(nextM)}-01`;
        const todayYM   = `${currentYear}-${currentMonth}`;
        const isFuture  = monthParam > todayYM;

        const expenseSnap = await db.collection('expenses')
          .where('accountId','==',accountId)
          .where('saleDate','>=',startDate)
          .where('saleDate','<', nextMonth)
          .orderBy('createdAt','desc')
          .get();

/* ────────────────  A. month-snapshot (lazy create)  ──────────────── */
let recurringMonthSnap = isFuture
  ? { docs: [] }                                     // future → nothing yet
  : await db.collection('recurringMonthly')
      .where('accountId', '==', accountId)
      .where('month',     '==', monthParam)
      .orderBy('expenseReason', 'asc')
      .get();

/* If the user navigates to a past/current month that has no snapshot
   yet, create it ON-DEMAND from the active templates. */
if (!isFuture && recurringMonthSnap.empty) {
  const tplSnap = await db.collection('recurringExpenses')
    .where('accountId', '==', accountId)
    .get();                                           // we’ll filter below

  const batch = db.batch();
tplSnap.docs.forEach(tplDoc => {
  const tpl = tplDoc.data();

  /* ① Skip templates that are retired */
  if (tpl.removalMonth) return;

  /* ② Do NOT back-fill before the template began */
  const tplStart = tpl.startMonth ||
                   (tpl.createdAt
                      ? tpl.createdAt.toDate().toISOString().slice(0, 7)
                      : monthParam);               // fail-safe
  if (monthParam < tplStart) return;               // not active yet

  /* ③ Create (or merge) the month snapshot */
  const snapId = `${accountId}_${monthParam}_${tplDoc.id}`;
  batch.set(
    db.collection('recurringMonthly').doc(snapId),
    {
      accountId,
      month        : monthParam,
      templateId   : tplDoc.id,
      expenseReason: tpl.expenseReason,
      expenseCost  : 0,
      expenseStatus: 'Not Paid',
      createdAt    : new Date()
    },
    { merge: true }
  );
});

  if (batch._ops?.length) await batch.commit();

  /* Re-query so the rest of the handler works with fresh data */
  recurringMonthSnap = await db.collection('recurringMonthly')
    .where('accountId', '==', accountId)
    .where('month',     '==', monthParam)
    .orderBy('expenseReason', 'asc')
    .get();
}

/* ────────────────  B. final maps  ──────────────── */
const expenses = expenseSnap.docs.map(d => ({ id: d.id, ...d.data() }));
const recurringMonthly = recurringMonthSnap.docs
  .map(d => ({ id: d.id, ...d.data() }))
  .filter(t => !t.deleted);


        const totalExpense  = expenses.reduce((s, e) => s + paidPortion(e), 0);
        const recTotal      = recurringMonthly.reduce((s, t) => s + paidPortion(t), 0);
        const grandTotal    = totalExpense + recTotal;

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
          recurringMonthly,
          recTotal,
          grandTotal,
          blockedActions   : req.session.blockedActions || {}
        });
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

/* ─────────── create / RE-CREATE recurring template  ────────────────── */
router.post('/add-recurring-expense', isAuthenticated, async (req, res) => {
  try {
    const accountId  = req.session.user.accountId;

    /* 1️⃣ Normalise the reason */
const rawReason  = (req.body.recurringReason || '').trim();

// Display version: Capitalized, compact spacing
const reasonDisp = toTitleCase(rawReason.replace(/\s+/g, ' '));

// Normalized key: lowercase, compacted spaces
const reasonKey  = rawReason.toLowerCase().replace(/\s+/g, ' ').trim();

if (!reasonKey) return res.status(400).send('Recurring-expense reason is required.');

    /* 2️⃣ Deterministic template ID */
    const tplId = `${accountId}_${reasonKey}`;

    /* 3️⃣ FIRST ACTIVE MONTH
           – use the month shown in the UI (`req.body.month`)
           – fallback to the server’s current month if absent           */
const uiMonth   = (req.body.month || '').trim();            // "YYYY-MM" or ""
const today     = new Date();
const ymToday   = `${today.getFullYear()}-${pad(today.getMonth() + 1)}`;

/*─────────────────────────────────────────────────────────────────────────
  Decide the template’s FIRST active month:
  • If the UI month is   ↟future or current↟ ➜ honour it.
  • If the UI month is   ↡past↡               ➜ bump to today’s month.
─────────────────────────────────────────────────────────────────────────*/
let firstMonth  = /^[0-9]{4}-[0-9]{2}$/.test(uiMonth) ? uiMonth : ymToday;
if (firstMonth < ymToday) firstMonth = ymToday;   // never start in the past


    /* ===============================================================
       ATOMIC TRANSACTION – creates, re-activates, or blocks duplicates
       ============================================================== */
    await db.runTransaction(async txn => {
      const tplRef  = db.collection('recurringExpenses').doc(tplId);
      const tplSnap = await txn.get(tplRef);

      const exists        = tplSnap.exists;
      const removalMonth  = exists ? tplSnap.get('removalMonth') : null;
      const startMonthOld = exists ? tplSnap.get('startMonth')   : null;
      const isActive      = exists && !removalMonth;

      if (isActive) throw new Error('DUPLICATE');       // hard stop

      /* ① Create OR revive the master template */
      txn.set(
        tplRef,
        {
          accountId,
          expenseReason : reasonDisp,
          reasonKey,
          removalMonth  : null,                         // (re)activate
          startMonth    : startMonthOld || firstMonth,  // preserve earliest
          updatedAt     : new Date(),
          ...(exists ? {} : { createdAt: new Date() })  // only on first create
        },
        { merge: true }
      );

      /* ② Ensure a snapshot for the FIRST active month */
      const snapId = `${accountId}_${firstMonth}_${tplId}`;
      txn.set(
        db.collection('recurringMonthly').doc(snapId),
        {
          accountId,
          month        : firstMonth,
          templateId   : tplId,
          expenseReason: reasonDisp,
          expenseCost  : 0,
          expenseStatus: 'Not Paid',
          createdAt    : new Date(),
          deleted      : false
        },
        { merge: true }
      );
    });

    /* 4️⃣ OPTIONAL – revive any *future* snapshots previously deleted */
    const reviveSnapPromise = (async () => {
      const futSnap = await db.collection('recurringMonthly')
        .where('accountId', '==', accountId)
        .where('templateId','==', tplId)
        .where('deleted',    '==', true)
        .get();

      if (futSnap.empty) return;
      const batch = db.batch();
      futSnap.docs.forEach(d => batch.update(d.ref, {
        deleted      : false,
        expenseReason: reasonDisp,
        updatedAt    : new Date()
      }));
      await batch.commit();
    })();

    await reviveSnapPromise;

    /* Redirect back to the month where the user was working */
    return res.redirect(`/expense?month=${firstMonth}`);

  } catch (err) {
    if (err.message === 'DUPLICATE') {
      return res.status(400).send(
        'A recurring-expense template with this name already exists.'
      );
    }
    console.error('add-recurring-expense error:', err);
    res.status(500).send(err.toString());
  }
});



  /* ─────────── full-page POST /expense ─────────── */
  router.post('/expense', isAuthenticated, restrictRoute('/expense'), async (req, res) => {
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

  /* ─────────── AJAX: POST /api/expense ─────────── */
  router.post('/api/expense', isAuthenticated, async (req, res) => {
    try {
      await processExpense(req.body, req.session.user);

      const rowsInserted = Array.isArray(req.body.expenseReason)
                             ? req.body.expenseReason.length
                             : 1;

      const snap = await db.collection('expenses')
        .where('accountId','==',req.session.user.accountId)
        .orderBy('createdAt','desc')
        .limit(rowsInserted)
        .get();

      const addedExpenses = snap.docs.reverse().map(d => {
        const e = d.data();
        const created = e.createdAt?.toDate ? e.createdAt.toDate()
                                            : new Date(e.createdAt);
        return {
          id         : d.id,
          yyyy_mm_dd : e.saleDate,
          dateLabel  : created.toLocaleString('default',{ month:'long', day:'numeric' }),
          timeLabel  : created.toLocaleTimeString(),
          ...e
        };
      });

     await cacheDel(`dailySum_${req.session.user.accountId}_${req.body.saleDate}`);

/* 1️⃣  Fresh daily summary (force = true bypasses any residual cache) */
const { summary } = await computeDailySummary(
  req.session.user.accountId,
  req.body.saleDate,
  true                                // ← force fresh calculation
);

/* 2️⃣  Fresh month aggregate */
const month     = req.body.saleDate.substring(0, 7);   // "YYYY-MM"
const monthTotal= await computeMonthTotal(
  req.session.user.accountId,
  month
);

    const badges = await computeMonthlyBadges(
      req.session.user.accountId,
      req.body.saleDate.slice(0, 7)
    );


/* 3️⃣  Send everything the browser needs */
return res.json({
  success   : true,
  summary,          // ← NEW
  monthTotal,
  badges ,
  expenses  : addedExpenses
});

    } catch (err) {
      console.error('/api/expense error:', err);
      return res.json({ success:false, error: err.toString() });
    }
  });

  /* ─────────── AJAX: EDIT EXPENSE ─────────── */
  router.post(
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

        const { summary } = await computeDailySummary(
          req.session.user.accountId, exp.saleDate
        );

        const monthTotal = await computeMonthTotal(
          req.session.user.accountId,
          exp.saleDate.substring(0, 7)
        );

        res.json({ success:true, updatedRow:update, summary, monthTotal });

      } catch (err) {
        console.error('edit-expense error:', err);
        return res.json({ success:false, error:err.toString() });
      }
    }
  );

  /* ─────────── AJAX: DELETE EXPENSE ─────────── */
  router.post(
    '/api/delete-expense',
    isAuthenticated,
    restrictAction('/expense', 'delete'),
    async (req, res) => {
      const { expenseId } = req.body;

      try {
        const expRef = db.collection('expenses').doc(expenseId);
        const expDoc = await expRef.get();

        if (!expDoc.exists) return res.json({ success: true });

        const exp = expDoc.data();
        if (exp.accountId !== req.session.user.accountId)
          return res.json({ success: false, error: 'Access denied' });

        await expRef.delete();

  /* ▼ PURGE hot-cache, recompute, and reply */

/* 0️⃣  Kick the Redis key so the next read is fresh            */
await cacheDel(`dailySum_${exp.accountId}_${exp.saleDate}`);

/* 1️⃣  Fresh daily summary (force = true bypasses any cache)   */
const { summary } = await computeDailySummary(
  exp.accountId,
  exp.saleDate,
  true                           // ← force fresh calculation
);

/* 2️⃣  Fresh month aggregate                                    */
const monthTotal = await computeMonthTotal(
  exp.accountId,
  exp.saleDate.substring(0, 7)   // "YYYY-MM"
);

/* 3️⃣  Fresh month-to-date badges                               */
const badges = await computeMonthlyBadges(
  exp.accountId,
  exp.saleDate.slice(0, 7)       // use the same YYYY-MM
);

/* 4️⃣  Send the up-to-date numbers back                         */
return res.json({ success: true, summary, monthTotal, badges });



      } catch (e) {
        return res.json({ success: false, error: e.toString() });
      }
    }
  );

 /* ─────────── EDIT recurring snapshot row (now propagates a rename) ─────────── */
router.post('/api/recurring-monthly/:recId', isAuthenticated, async (req, res) => {
  try {
    const { recId } = req.params;
    const snapRef   = db.collection('recurringMonthly').doc(recId);
    const snap      = await snapRef.get();
    if (!snap.exists) throw new Error('Row not found');

    const row        = snap.data();
    const accountId  = row.accountId;
    const templateId = row.templateId;

    /*───────────────────────────────────────────────────────────────────────
      A.  RENAME  → update template and *all* snapshots in one go
    ───────────────────────────────────────────────────────────────────────*/
    if (req.body.expenseReason !== undefined) {
      const newDisp = toTitleCase(req.body.expenseReason);   // Title-Case

      /* ① update master template */
      await db.collection('recurringExpenses')
              .doc(templateId)
              .update({ expenseReason: newDisp, updatedAt: new Date() });

      /* ② fetch every month that already exists for this template   */
      const allSnaps = await db.collection('recurringMonthly')
        .where('accountId','==',accountId)
        .where('templateId','==',templateId)
        .get();

      /* ③ batch-update “expenseReason” everywhere */
      const batch = db.batch();
      allSnaps.docs.forEach(d => batch.update(d.ref, {
        expenseReason: newDisp,
        updatedAt    : new Date()
      }));
      await batch.commit();

      /* same JSON shape as before, plus the new display string      */
      const monthTotal = await computeMonthTotal(accountId, row.month);
      return res.json({ success:true, monthTotal, expenseReason:newDisp });
    }

    /*───────────────────────────────────────────────────────────────────────
      B.  COST / STATUS edits (previous behaviour, untouched)
    ───────────────────────────────────────────────────────────────────────*/
    const update = {};
    if (req.body.expenseCost   !== undefined)
      update.expenseCost   = parseFloat(req.body.expenseCost);
    if (req.body.expenseStatus !== undefined)
      update.expenseStatus = req.body.expenseStatus.trim();

    if (!Object.keys(update).length)
      return res.json({ success:true });

    await snapRef.update(update);
    const monthTotal = await computeMonthTotal(accountId, row.month);
    return res.json({ success:true, monthTotal });

  } catch (err) {
    console.error('recurring-monthly edit error:', err);
    res.status(500).json({ success:false, error: err.message });
  }
});


  /* ─────────── DELETE recurring snapshot row ─────────── */
  router.post('/delete-recurring-monthly/:recId', isAuthenticated, async (req, res) => {
    try {
      const { recId }  = req.params;
      const snapRef    = db.collection('recurringMonthly').doc(recId);
      const snapDoc    = await snapRef.get();

      if (!snapDoc.exists || snapDoc.data().accountId !== req.session.user.accountId) {
        const msg = 'Access denied';
        return req.xhr
          ? res.json({ success:false, error:msg })
          : res.status(403).send(msg);
      }

      const row       = snapDoc.data();
      const accountId = row.accountId;
      const tplId     = row.templateId || null;
      const month     = row.month;
      const todayYM   = new Date().toISOString().slice(0, 7);

      /* 1️⃣  HARD-delete this month’s snapshot */
      await snapRef.delete();

      /* 2️⃣  If deleting the CURRENT month, retire template & wipe future months */
      if (tplId && month === todayYM) {
        // retire the master template
        await db.collection('recurringExpenses')
                .doc(tplId)
                .set({ removalMonth: month, updatedAt: new Date() }, { merge:true });

        // fetch ALL snapshots for this template (no inequality ⇒ no index)
        const allSnap = await db.collection('recurringMonthly')
          .where('accountId', '==', accountId)
          .where('templateId','==', tplId)
          .get();

        const batch = db.batch();
        allSnap.docs.forEach(d => {
          if (d.data().month > month) batch.delete(d.ref);  // delete only future
        });
        if (batch._ops?.length) await batch.commit();
      }

      /* 3️⃣  Reply */
      if (req.xhr) {
        const monthTotal = await computeMonthTotal(accountId, month);
        return res.json({ success:true, monthTotal });
      }
      res.redirect(`/expense?month=${month}`);

    } catch (err) {
      if (req.xhr) return res.json({ success:false, error:err.toString() });
      res.status(500).send(err.toString());
    }
  });


  return router;
};
