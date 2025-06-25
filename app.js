// app.js – Ultimate Optimized version (Ajax‑ready, no missing pieces)
const express = require('express');
const admin = require('firebase-admin');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { createClient } = require('redis');       // using Node Redis client
const { RedisStore } = require('connect-redis'); // import RedisStore from connect-redis
// ─────────── security deps (NEW) ───────────
const rateLimit = require('express-rate-limit');  // 🔒
const csrf = require('csurf');               // 🔒
const favicon = require('serve-favicon');
const Razorpay = require('razorpay');
const compression = require('compression');
const cors = require('cors');          // NEW
const crypto     = require('crypto');      
const nodemailer = require('nodemailer'); 

require('dotenv').config();
// ─── Logger (Pino) ──────────────────────────────────────────────
const pino   = require('pino');
const logger = pino({
  level: process.env.LOG_LEVEL || (
    process.env.NODE_ENV === 'production' ? 'info' : 'debug'
  ),
  transport: process.env.NODE_ENV === 'development'
    ? { target: 'pino-pretty',
        options: { colorize: true, translateTime: 'SYS:standard' } }
    : undefined
});
// ─── HTTP-logger middleware (after the logger exists) ───────────
const pinoHttp = require('pino-http')({
  logger,
  autoLogging : false,
  serializers : {
    req (req) { return { method:req.method, url:req.url }; }
  },
  // ↓ skip static, health & favicon to save ~6 µs/req
  ignore : (req) =>
    req.url.startsWith('/healthz') ||
    req.url.startsWith('/favicon.ico') ||
    /\.(?:js|css|png|jpe?g|svg|woff2?)$/i.test(req.url)
});

/* ─────────── env sanity check ─────────── */
const REQUIRED_ENV = [
  'SESSION_SECRET',
  'REDIS_URL',
  'RAZORPAY_KEY_ID',
  'RAZORPAY_KEY_SECRET',
  'EMAIL_USER',
  'EMAIL_PASS'
];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error('❌  Missing env vars →', missing.join(', '));
  process.exit(1);
}

/* ─────────── global crash safety ─────────── */
process.on('unhandledRejection', err => {
  logger.error({ err }, 'Unhandled Promise Rejection');
});

process.on('uncaughtException', async err => {
  logger.error({ err }, 'Uncaught Exception – soft-recovery attempt');

  /* ── 1.  Kick the Redis client so it starts a fresh handshake ── */
  try { await redisClient.quit();          /* ignore failures  */ } catch (_) {}
  try { redisClient.connect().catch(()=>{}); } catch (_) {}

  /* ── 2.  Nothing to do for Firestore – its gRPC layer auto-retries ── */

  /* ── 3.  Stay alive ── */
  // DO NOT call process.exit() here.
});

// ─────────── cache ───────────
/* ─────────── Distributed cache (shared by every worker) ─────────── */
const cacheKey = k => `cache:${k}`;          // neat namespacing prefix

const cacheGet = async key => {
  try {
    const raw = await redisClient.get(cacheKey(key));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    logger.warn({ err, key }, 'Redis cache → GET failed (fail-open)');
    return null;                             // fall back to live DB read
  }
};
const cacheSet = async (key, value, ttlSec = 300) => {
  try {
    await redisClient.set(
      cacheKey(key),
      JSON.stringify(value),
      { EX: ttlSec }                         // seconds-to-live
    );
  } catch (err) {
    logger.warn({ err, key }, 'Redis cache → SET failed');
  }
};
const cacheDel = async key => {
  try { await redisClient.del(cacheKey(key)); }
  catch (err) { logger.warn({ err, key }, 'Redis cache → DEL failed'); }
};

// ─────────── Firebase Admin ───────────
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

/* ─────────── Express base ─────────── */
const app = express();

/* ─────────── HELMET SECURITY MIDDLEWARE (externalised) ─────────── */
require('./routes/helmetConfig')(app);

/* ─── FAST-PATH: static assets & favicon (Brotli/Gzip first) ─── */
const expressStaticGzip = require('express-static-gzip');

app.use('/', expressStaticGzip(path.join(__dirname, 'public'), {
  enableBrotli   : true,
  orderPreference: ['br', 'gz'],

  /* ↓ tell serve-static to SKIP directory indexes  
        so the request falls through to your route */
  index          : false,                // *** critical ***

  setHeaders(res, filePath) {
    if (/\.(?:js|css|svg|ico|png|jpe?g|woff2?)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

/* ───────── Per-request CSP nonce ───────── */
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.set('trust proxy', 1);     // behind Nginx / Cloudflare / Render / etc.

// Force HTTPS behind a proxy / load-balancer
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' &&
      req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});

app.use(pinoHttp);

/* ─────────── Redis client & session store ─────────── */
const ONE_YEAR = 365 * 24 * 60 * 60 * 1000;           // 12-month lifetime (ms)

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    keepAlive: 10_000,
    reconnectStrategy: retries => Math.min(retries * 100, 30_000),
    tls: process.env.REDIS_URL.startsWith('rediss://') ? {} : undefined
  }
})
redisClient
  // log “ready” only **once** to stop startup spam
  .once('ready', () => logger.info('✅ Redis ready (initial connection)'))

  // each reconnect attempt is still useful, keep it:
  .on('reconnecting', ({ attempt, delay }) =>
    logger.warn({ attempt, delay }, 'Redis reconnecting'))

  // connection actually closed
  .on('end', () => logger.warn('⚠️ Redis connection closed'))

  // serious or ECONNRESET errors
  .on('error', err => {
    if (err.code !== 'ECONNRESET') {
      logger.error({ err }, 'Redis error');
    } else {
      logger.warn('⚠️ Redis ECONNRESET – reconnecting…');
    }
  });
redisClient.connect().catch(console.error);     // kick off the first connect

/* ─────────── Dual-store session middleware ───────────
   • Uses Redis when it is ‘ready’.
   • Instantly switches to MemoryStore when Redis drops.
   • Swaps back to Redis the moment `.ready` fires again.
   • Zero code changes anywhere else – req.session works as before.
────────────────────────────────────────────────────────*/
const MemoryStore = session.MemoryStore;
const memoryStore = new MemoryStore({
  checkPeriod: 15 * 60 * 1000   // wipe expired sessions every 15 min
});

const redisStore  = new RedisStore({
  client      : redisClient,
  prefix      : 'sess:',
  ttl         : ONE_YEAR / 1000,      // seconds
  disableTouch: false                 // ← keep
});
const makeSession = (store) => session({
  store,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,                      // refresh on every hit
  cookie: {
    maxAge  : ONE_YEAR,               // 365 days
    httpOnly: true,
    secure  : process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});
const redisSession   = makeSession(redisStore);
const memorySession  = makeSession(memoryStore);
/* flag toggled by Redis client events */
let useRedis = true;
/* hot-swap middleware – runs on every request */
app.use((req, res, next) => {
  (useRedis ? redisSession : memorySession)(req, res, next);
});
/* wire up Redis state changes */
redisClient
  .on('ready', () => {
    if (!useRedis) {
      useRedis = true;
      logger.info('Session store ➜ Redis (connection restored)');
    }
  })
  .on('end', () => {
    if (useRedis) {
      useRedis = false;
      logger.warn('Session store ➜ Memory (Redis connection closed)');
    }
  })
  .on('error', (err) => {
    /* network blips turn the flag off; other code already logs the error */
    useRedis = false;
  });
/* ─────────── keep sub-user session in sync ─────────── */
app.use(async (req, res, next) => {
  if (req.session?.user && !req.session.user.isMaster) {
    try {
      const doc = await db.collection('permissions')
                          .doc(req.session.user.accountId)
                          .get();
      const data = doc.exists ? doc.data() : {};
      req.session.lockedRoutes   = data.lockedRoutes   || [];
      req.session.blockedActions = data.blockedActions || {};
    } catch (err) {
      console.error('perm-sync error:', err);
    }
  }
  next();
});
app.use((req, res, next) => {
  // make the logged-in user (if any) available to every EJS view
  res.locals.user = req.session?.user || null;
  next();
});

app.use(compression());
const buildId = process.env.RENDER_GIT_COMMIT || Date.now().toString();

app.use((req, res, next) => {
  // expose buildId to every EJS template as `v`
  res.locals.v = buildId;
  // disable caching for HTML responses so templates always re-render with the newest `v`
  if (req.accepts('html')) {
    res.setHeader('Cache-Control',
      'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma',  'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

/* ─────────── CORS & logging ─────────── */
app.use(cors({
  origin      : (process.env.ALLOWED_ORIGINS || '').split(','),
  credentials : true
}));

// Global rate-limit – hits every sensitive endpoint
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 min
  max: 300,                   // per IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/api', '/login', '/register'], apiLimiter);

/* extra lock on high-risk routes */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 min
  max: 20,                    // much tighter
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/forgot-password', '/reset-password', '/payment-success'], authLimiter);

// CSRF protection (MUST come _after_ session middleware)
app.use(csrf());
app.use((req, res, next) => {
  // make the token available to all your EJS templates
  res.locals.csrfToken = req.csrfToken();
  next();
});

/* CSRF & generic error shields (keep these LAST) */
app.use((err, req, res, next) => {        // CSRF failure handler
  if (err.code === 'EBADCSRFTOKEN')
    return res.status(403).send('Invalid CSRF token');
  next(err);
});
/* ───────── generic error handler ───────── */
app.use((err, req, res, next) => {
  logger.error({ err, url: req.url }, 'Request failed');

  // Typical network-outage codes: ENOTFOUND DNS, EAI_AGAIN DNS, ECONNRESET etc.
  const transient = ['ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET', 'ETIMEDOUT'];
  if (transient.includes(err.code)) {
    return res.status(503).send('Service temporarily unavailable – retry in a minute.');
  }
  res.status(500).send('Internal Server Error');
});

app.locals.formatIST = date => {
  const d = (typeof date?.toDate === 'function') 
            ? date.toDate() 
            : new Date(date);
  return d.toLocaleTimeString('en-IN', { hour12: false, timeZone: 'Asia/Kolkata' });
};

app.locals.attr = (s = '') => String(s)
  .replace(/&/g, '&amp;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#x27;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
if (process.env.NODE_ENV === 'production') app.set('view cache', true);

// ─────────── helpers ───────────
const pad = n => String(n).padStart(2, '0');
/* NEW ➜ case-insensitive, space-insensitive key
   — now *never* crashes if s is empty/undefined — */
const normalizeName = s =>
  (s || '')                 // ⬅️  guarantees a string
    .toLowerCase()          // ignore case
    .replace(/\s+/g, ' ')   // collapse whitespace runs
    .trim();

const getCategories = async accountId => {
  // Always pull fresh rows from Firestore
  const snap = await db.collection('products')
                       .where('accountId', '==', accountId)
                       .get();
  const uniq = [...new Set(
    snap.docs.map(d => d.data().category).filter(Boolean)
  )];
  return uniq;                          // straight from DB
};

const getUnits = async accountId => {
  // Fresh fetch every time
  const snap = await db.collection('products')
                       .where('accountId', '==', accountId)
                       .get();
  const uniq = [...new Set(
    snap.docs
        .map(d => (d.data().unit || '').toLowerCase())
        .filter(Boolean)
  )];
  return uniq;                          // no Redis layer
};

/* ─────────── DAILY SUMMARY (used by Ajax & dashboard) ─────────── */

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
/* ────────────────────────────────────────────────────────────────
   computeMonthTotal(accountId, month)          ★ NEW 2025-06-21 ★
   Returns the grand total (regular + recurring) for the month,
   skipping rows whose status is “Not Paid”.
   ----------------------------------------------------------------*/
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

/* ===============================================================
   paidPortion(row) – return only what’s already paid
   =============================================================== */
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
// processSale — creates one sale, updates stock/batches and
//               returns the saved document               (AJAX + full-page)
// ────────────────────────────────────────────────────────────────
async function processSale(body, user) {
  /* 0️⃣  PRE-WORK ────────── */
  const accountId = user.accountId;
  // (only now it’s safe to run a separate Firestore tx)
  if (!body.invoiceNo || !body.invoiceNo.trim()) {
    body.invoiceNo = await getNextInvoiceNo(accountId);
  }
  /* --------------- 1.  MAIN TRANSACTION --------------- */
  const saleData = await db.runTransaction(async tx => {
    let {
      productId,
      customProductId,
      retailPrice: totalSaleInput,
      saleQuantity,
      saleDate,
      status,
      invoiceNo,
      extraInfo,
      paymentDetail1,
      paymentDetail2
    } = body;
    /* 🔒 Sanitise free-text note (≤200 chars, no leading/trailing space) */
    extraInfo = extraInfo ? extraInfo.toString().substring(0, 200).trim() : '';
  saleQuantity = +parseFloat(saleQuantity);
/* 🔒 hard stop – never allow zero or negative qty */
if (!Number.isFinite(saleQuantity) || saleQuantity <= 0) {
  throw new Error('Quantity must be greater than zero');
}
const totalSale = +parseFloat(totalSaleInput);
    /* ――― 1. Load product row ――― */
    const selectedProductId = (customProductId?.trim()) ? customProductId : productId;
    const productRef        = db.collection('products').doc(selectedProductId);
    const productDoc        = await tx.get(productRef);
    if (!productDoc.exists || productDoc.data().accountId !== accountId)
      throw new Error('Product not found or unauthorized');
    const product = productDoc.data();

    /* ――― 2. FIFO consume batches ――― */
    const batchQuery = db.collection('stockBatches')
                         .where('productId','==',selectedProductId)
                         .where('remainingQuantity','>',0)
                         .orderBy('batchDate','asc');
    const batchSnap = await tx.get(batchQuery);
    let remaining      = saleQuantity;
    let totalWholesale = 0;
    const batchesUsed  = [];
    for (const b of batchSnap.docs) {
      if (remaining <= 0) break;
      const d    = b.data();
      const take = Math.min(d.remainingQuantity, remaining);
      tx.update(b.ref, {
        quantity         : admin.firestore.FieldValue.increment(-take),
        remainingQuantity: +(d.remainingQuantity - take).toFixed(3)
      });
      totalWholesale += d.purchasePrice * take;
      batchesUsed.push({ id: b.id, qtyUsed: take });
      remaining -= take;
    }
    if (remaining > 0) throw new Error('Not enough stock');
    /* ――― 3. Profit & GST math ――― */
    const avgWholesale  = +(totalWholesale / saleQuantity).toFixed(2);
    const retailPerUnit = +(totalSale     / saleQuantity).toFixed(2);
    const profitPerUnit = +(retailPerUnit - avgWholesale).toFixed(2);
    const totalProfit   = +(profitPerUnit * saleQuantity).toFixed(2);
    let outputTax = 0, inputTax = 0, gstPayable = 0;
if (typeof product.inclusiveTax === 'number') {
  const r = product.inclusiveTax;
  if (r > 0) {                                   // normal 5, 12, 18 … %
    outputTax  = +(totalSale      * r / (100 + r)).toFixed(2);
    inputTax   = +(totalWholesale * r / (100 + r)).toFixed(2);
    gstPayable = +(outputTax - inputTax).toFixed(2);
  } else {                                       // r === 0 ➜ exempt item
    outputTax = inputTax = gstPayable = 0;
  }
}
    /* ――― 4. Insert sale row ――― */
    const saleRef = db.collection('sales').doc();   // pre-allocate ID
    const row     = {
      productId      : selectedProductId,
      productName    : product.productName,
      unit           : product.unit || '',
      wholesalePrice : avgWholesale,
      retailPrice    : retailPerUnit,
      saleQuantity,
      saleDate,
      invoiceNo,
      totalSale,
      profitPerUnit,
      profit         : totalProfit,
      status,
      outputTax,
      inputTax,
      gstPayable,
      extraInfo,
      batchesUsed,
      createdAt      : new Date(),
      accountId,
      ...(paymentDetail1 && { paymentDetail1:+parseFloat(paymentDetail1) }),
      ...(paymentDetail2 && { paymentDetail2:+parseFloat(paymentDetail2) })
    };
    tx.set(saleRef, row);

    /* 5.  🔄  Stock recalc moved OUTSIDE the transaction  */
    row.id = saleRef.id;            // bubble ID to caller
    return row;
  });
  /* --------------- 2.  POST-COMMIT UPDATE --------------- */
  // Re-compute parent-product stock *after* the transaction closes
  await recalcProductFromBatches(saleData.productId);
  await cacheDel(`dailySum_${accountId}_${saleData.saleDate}`);
  return saleData;
}

/* ─────────── processExpense (shared) ─────────── */
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

/* ─────────── Global subscription check middleware ─────────── */
app.use((req, res, next) => {
  if (!req.session || !req.session.user) return next();
  const allowedPaths = [
    '/', '/dashboard', '/login', '/register', '/documentation', '/pricing',
    '/subscribe/monthly', '/subscribe/half-yearly', '/subscribe/yearly',
    '/payment-success', '/logout', '/terms-and-conditions', '/privacy', '/customerservice','/billing'
  ];
  if (allowedPaths.includes(req.path)) return next();
  const subscriptionExpiry = req.session.user.subscriptionExpiry;
  if (!subscriptionExpiry || new Date(subscriptionExpiry) <= new Date()) {
    return res.redirect('/pricing');
  }
  next();
});

/* ─────────── PERMISSION HELPERS ─────────── */
const requireMaster   = (req,res,next)=>
  req.session.user && req.session.user.isMaster
    ? next() : res.status(403).send('Access denied');
const isAuthenticated = (req,res,next)=>
  req.session && req.session.user ? next() : res.redirect('/login');
const restrictRoute   = routeId => (req,res,next)=>{
  if(req.session.user.isMaster) return next();
  if(req.session.lockedRoutes?.includes(routeId))
    return res.status(403).send('Access denied');
  next();
};

/* ────────────────────────────────────────────────────────────────
   ★ ACTION-LEVEL PERMISSION HELPER (NEW)
   ──────────────────────────────────────────────────────────────── */
const restrictAction = (routeId, action) => (req, res, next) => {
  if (req.session.user.isMaster) return next();
  const ba = req.session.blockedActions || {};
  if (Array.isArray(ba[routeId]) && ba[routeId].includes(action))
    return res.status(403).send('Access denied');
  next();
};

async function getNextInvoiceNo(accountId) {
  const SHARDS = 10;
  const rand   = Math.floor(Math.random() * SHARDS).toString(); // '0' … '9'
  /* 1️⃣  Increment one shard */
  const shardRef = db
    .collection('accounts').doc(accountId)
    .collection('counterShards').doc(rand);
  await shardRef.set(
    { value: admin.firestore.FieldValue.increment(1) },
    { merge: true }
  );
  /* 2️⃣  Read all shards and sum */
  const snap = await db
    .collection('accounts').doc(accountId)
    .collection('counterShards').get();
  const total = snap.docs.reduce((s, d) => s + (+d.data().value || 0), 0);
  /* 3️⃣  Format */
  return 'INV-' + String(total).padStart(6, '0');
}

/* ─────────── Razorpay ─────────── */
const razorpay = new Razorpay({
  key_id:    process.env.RAZORPAY_KEY_ID,
  key_secret:process.env.RAZORPAY_KEY_SECRET
});

// ─────────── email (nodemailer) ───────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

const registerRoutes = require('./routes/register');
app.use('/', registerRoutes);
const loginRoutes = require('./routes/login')(redisClient);
app.use('/', loginRoutes);

/* ─────────── USER MANAGEMENT ROUTES (Master Only) ─────────── */
const userManagementRoutes = require('./routes/userManagement');
app.use('/', userManagementRoutes);

/* ───── Permission routes (factory) ───── */
const makePermissionRoutes = require('./routes/permission');   // step 1 – import factory
const permissionRoutes = makePermissionRoutes({                // step 2 – build router
  isAuthenticated,
  restrictRoute,
  cacheDel
});
app.use('/', permissionRoutes);

/* ─────────── PUBLIC LANDING ────────── */
const staticPages = require('./routes/staticPages');
app.use('/', staticPages);

/* ─────────── DASHBOARD (was GET "/") ─────────── */
// -- identical logic, ONLY the path changed to "/dashboard" --
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    // NEW – force “now” to IST before extracting year/month/day
    const istNow = new Date(
      new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })
    );
    const defaultDate = `${istNow.getFullYear()}-${pad(istNow.getMonth()+1)}-${pad(istNow.getDate())}`;
    const saleDate  = req.query.saleDate || defaultDate;
    // Fetch products + batches
    const productsSnap = await db.collection('products').where('accountId','==',accountId).get();
    const products = productsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const productIds = products.map(p => p.id);
    const batchesMap = {};
    if (productIds.length > 0) {
      const chunkSize = 10;
      const batchPromises = [];
      for (let i = 0; i < productIds.length; i += chunkSize) {
        const chunk = productIds.slice(i, i+chunkSize);
        batchPromises.push(
          db.collection('stockBatches')
            .where('productId','in',chunk)
            .where('remainingQuantity','>',0)
            .orderBy('batchDate','asc')
            .get()
        );
      }
      const batchSnaps = await Promise.all(batchPromises);
      batchSnaps.forEach(snap => {
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
    products.forEach(p => p.batches = batchesMap[p.id] || []);

    // Concurrent fetch sales, expenses, categories, opening balance
    const [salesSnap, expSnap, categories, obDoc] = await Promise.all([
      db.collection('sales').where('accountId','==',accountId).where('saleDate','==',saleDate).orderBy('createdAt','desc').get(),
      db.collection('expenses').where('accountId','==',accountId).where('saleDate','==',saleDate).orderBy('createdAt','desc').get(),
      getCategories(accountId),
      db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get()
    ]);
    const sales = salesSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const expenses = expSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    let openingBalance=0, openingTime='', closingTime='';
    if (obDoc.exists) {
      const ob = obDoc.data();
      openingBalance = ob.balance || 0;
      openingTime    = ob.openingTime || '';
      closingTime    = ob.closingTime || '';
    }
    // Summaries
   let totalProfit = 0,
    totalSales = 0,
    totalCashSales = 0,
    totalOnlineSales = 0,
    totalNotPaidSales = 0,
    totalGstPayable = 0;          // ➊  add this
    sales.forEach(s => {
      totalProfit += s.profit;
      const amt = s.retailPrice * s.saleQuantity;
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
        if (s.gstPayable !== undefined) {
    totalGstPayable += +s.gstPayable;
  }
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
    const finalCash = parseFloat(openingBalance) + totalCashSales - totalCashExpenses;

    // Subscription remaining days
    let subscriptionRemaining = 0;
    if (req.session.user.subscriptionExpiry) {
      const diff = new Date(req.session.user.subscriptionExpiry) - new Date();
      subscriptionRemaining = Math.max(Math.ceil(diff / (1000*60*60*24)), 0);
    }
   res.render('index', {
  products, sales, expenses, saleDate, categories,
  openingBalance, openingTime, closingTime,
  totalProfit, totalSales, totalCashSales,
  totalOnlineSales, totalNotPaidSales,
  totalCashExpenses, totalOnlineExpenses,
  finalCash,
  totalGstPayable,
  subscriptionRemaining,
  user: req.session.user,
  /* NEW ▼ passes the in-progress number (or null) to every template */
  currentInvoiceNo : req.session.currentInvoiceNo || null
});
  } catch (err) {
    res.status(500).send(err.toString());
  }
});

// GET /expense – monthly expenses view  ★ NOW pulls recurring templates
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

/* ─────────── RECURRING-EXPENSE TEMPLATES ─────────── */
/* POST /add-recurring-expense – create template */
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

/* ─────────── ADD-PRODUCT ROUTES (externalised) ─────────── */
const makeAddProductRoutes = require('./routes/addProduct');
const addProductRoutes     = makeAddProductRoutes({
  db,
  isAuthenticated,
  restrictRoute,
  getCategories,
  getUnits,
  normalizeName
});
app.use('/', addProductRoutes);

// GET /view-products
app.get('/view-products', isAuthenticated, restrictRoute('/view-products'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const filterCategory = req.query.filterCategory || '';
    const stockThreshold = req.query.stockThreshold || '';
    const sortOrder = req.query.sortOrder || 'asc';
    let q = db.collection('products').where('accountId','==',accountId);
    if (filterCategory.trim() !== '') q = q.where('category','==',filterCategory);
    if (stockThreshold.trim() !== '') q = q.where('quantity','<',parseInt(stockThreshold));
    q = q.orderBy('productName', sortOrder);
    const snap = await q.get();
    const products = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    const productIds = products.map(p => p.id);
    const batchesMap = {};
    if (productIds.length > 0) {
      const chunkSize = 10;   // ↑ fewer round-trips, same RAM usage
      const batchPromises = [];
      for (let i = 0; i < productIds.length; i += chunkSize) {
        const chunk = productIds.slice(i, i+chunkSize);
        batchPromises.push(db.collection('stockBatches').where('productId','in',chunk).get());
      }
      const batchSnaps = await Promise.all(batchPromises);
      batchSnaps.forEach(snap => {
        snap.docs.forEach(doc => {
          const d = doc.data();
          const pid = d.productId;
          if (!batchesMap[pid]) batchesMap[pid] = [];
          d.profitMargin = d.salePrice - d.purchasePrice;
          batchesMap[pid].push({ id: doc.id, ...d });
        });
      });
    }
    products.forEach(p => p.batches = batchesMap[p.id] || []);
    const categories = await getCategories(accountId);
    res.render('viewProducts', { products, categories, filterCategory, stockThreshold, sortOrder, blockedActions : req.session.blockedActions || {}  });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});

/* ─────────── DOWNLOAD PRODUCTS ROUTES (externalised) ─────────── */
const makeProductDownloadRoutes = require('./routes/productDownload');
const productDownloadRoutes     = makeProductDownloadRoutes({
  db,
  isAuthenticated,
  restrictRoute
});
app.use('/', productDownloadRoutes);

/* ─────────── STOCK BATCH MANAGEMENT ─────────── */
// POST /delete-stock-batch/:batchId
app.post('/delete-stock-batch/:batchId', isAuthenticated, restrictAction('/view-products','delete'), async (req, res) => {
  try {
    const { batchId } = req.params;
    const batchRef    = db.collection('stockBatches').doc(batchId);
    const batchDoc    = await batchRef.get();
    if (!batchDoc.exists) return res.status(404).send('Stock batch not found');
    if (batchDoc.data().accountId !== req.session.user.accountId) return res.status(403).send('Access denied');
    // Grab parent productId
    const productId = batchDoc.data().productId;
    // Delete the batch & recalc
    await batchRef.delete();
    await recalcProductFromBatches(productId);
    // If AJAX, send back updated product JSON
    if (req.xhr) {
      const prodSnap = await db.collection('products').doc(productId).get();
      const p = prodSnap.data();
      return res.json({
        success: true,
        product: {
          id:             productId,
          wholesalePrice: p.wholesalePrice,
          retailPrice:    p.retailPrice,
          quantity:       p.quantity,
          profitMargin:   p.profitMargin
        }
      });
    }
    // Otherwise full‐page flow
    res.redirect('/view-products');
  } catch (error) {
    console.error('Error deleting stock batch:', error);
    if (req.xhr) return res.json({ success: false, error: error.toString() });
    res.status(500).send(error.toString());
  }
});
/* ─────────── STOCK BATCH HELPER (transaction-aware) ───────────
   • If a Firestore transaction object is supplied, we reuse it.
   • Otherwise we create a standalone transaction (old behaviour).
   ----------------------------------------------------------------*/
async function recalcProductFromBatches(productId, tx = null) {
  const work = async (transaction) => {
    /* 1️⃣  Read every batch that still belongs to this product */
    const batchQuery = db.collection('stockBatches')
                         .where('productId', '==', productId);
    const batchSnap  = await transaction.get(batchQuery);

    let totalRemaining = 0,
        totalWholesale = 0,
        totalRetail    = 0;

    batchSnap.docs.forEach(doc => {
      const d   = doc.data();
      const qty = +d.remainingQuantity || 0;
      totalRemaining += qty;
      totalWholesale += qty * (+d.purchasePrice);
      totalRetail    += qty * (+d.salePrice);
    });
    /* 2️⃣  Protect against divide-by-zero */
    const safeDivide  = (num, den) => den > 0 ? +(num / den).toFixed(2) : 0;
    const newWholesale= safeDivide(totalWholesale, totalRemaining);
    const newRetail   = safeDivide(totalRetail,    totalRemaining);
    const profitMargin= +(newRetail - newWholesale).toFixed(2);
    /* 3️⃣  Persist the freshly-computed figures */
    transaction.update(
      db.collection('products').doc(productId),
      {
        quantity      : +totalRemaining.toFixed(3),
        wholesalePrice: newWholesale,
        retailPrice   : newRetail,
        profitMargin,
        updatedAt     : new Date()
      }
    );
  };

  /* Re-use current transaction when available, else start a new one */
  if (tx) {
    await work(tx);                // already inside a transaction
  } else {
    await db.runTransaction(work); // standalone call
  }
}

/* ─────────── EDIT STOCK BATCH ROUTES (externalised) ─────────── */
const makeEditStockBatchRoutes = require('./routes/editStockBatch');
const editStockBatchRoutes     = makeEditStockBatchRoutes({
  db,
  isAuthenticated,
  getCategories,
  getUnits,
  normalizeName,
  recalcProductFromBatches
});
app.use('/', editStockBatchRoutes);


// POST /api/edit-stock-batch-field/:batchId
app.post('/api/edit-stock-batch-field/:batchId', isAuthenticated,restrictAction('/view-products','edit'), async (req, res) => {
  try {
    const { batchId } = req.params;
    const { field, value } = req.body;
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchSnap = await batchRef.get();
    if (!batchSnap.exists) throw new Error('Batch not found');
    if (batchSnap.data().accountId !== req.session.user.accountId) throw new Error('Access denied');
    // build update
    const update = { updatedAt: new Date() };
    if (field === 'purchasePrice' || field === 'salePrice') {
      update[field] = parseFloat(value);
    } else if (field === 'quantity') {
      const qty = parseInt(value, 10);
      update.quantity = qty;
      update.remainingQuantity = qty;
    } else {
      throw new Error('Invalid field');
    }
    await batchRef.update(update);
    // re‑compute profitMargin on this batch only
    const updated = (await batchRef.get()).data();
    const profitMargin = updated.salePrice - updated.purchasePrice;
    await batchRef.update({ profitMargin });

    // **NEW**: recalc parent product and fetch its updated data
    const productId = batchSnap.data().productId;
    await recalcProductFromBatches(productId);
    const productSnap = await db.collection('products').doc(productId).get();
    const prod = productSnap.data();

    res.json({
      success: true,
      batch: {
        purchasePrice: updated.purchasePrice,
        salePrice:     updated.salePrice,
        quantity:      updated.quantity,
        remainingQuantity: updated.remainingQuantity,
        profitMargin
      },
      product: {
        id: productSnap.id,
        wholesalePrice: prod.wholesalePrice,
        retailPrice:    prod.retailPrice,
        quantity:       prod.quantity,
        profitMargin:   prod.profitMargin
      }
    });
  } catch (err) {
    res.json({ success: false, error: err.toString() });
  }
});
/* ────────────────────────────────────────────────────────────────
   GET /sales  – Sales & Expense report
   • Table rows honour *all* filters (saleDate, month, status)
   • Summary badges are locked to the chosen month
   ──────────────────────────────────────────────────────────────── */
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

/* ─────────── DOWNLOAD SALES ROUTES (externalised) ─────────── */
const makeSalesDownloadRoutes = require('./routes/salesDownload');
const salesDownloadRoutes     = makeSalesDownloadRoutes({
  db,
  isAuthenticated,
  restrictRoute
});
app.use('/', salesDownloadRoutes);

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
    req.session.user.accountId,
    data.saleDate
  );
  const monthTotal = await computeMonthTotal(
    req.session.user.accountId,
    data.saleDate.substring(0, 7)
  );
  return res.json({
    success   : true,
    updatedRow: update,
    summary,
    monthTotal
  });
}

/* ------------------------------------------------------------------
   1️⃣-b Extra-Info edit – simple text update, no maths
------------------------------------------------------------------ */
if (field === 'extraInfo') {
  const update = { extraInfo: (value || '').trim() };
  await saleRef.update(update);

  const { summary } = await computeDailySummary(
    req.session.user.accountId,
    data.saleDate
  );
  const monthTotal = await computeMonthTotal(
    req.session.user.accountId,
    data.saleDate.substring(0, 7)
  );

  return res.json({
    success   : true,
    updatedRow: update,
    summary,
    monthTotal
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

app.post('/delete-product/:productId', isAuthenticated, restrictAction('/view-products','delete'), async (req, res) => {
  try {
    const { productId } = req.params;
    const prodRef  = db.collection('products').doc(productId);
    const prodSnap = await prodRef.get();
    if (!prodSnap.exists)        return res.status(404).send('Product not found');
    if (prodSnap.data().accountId !== req.session.user.accountId)
      return res.status(403).send('Access denied');

    /* 1. must have zero stock AND zero batches --------------------------- */
    if (prodSnap.data().quantity > 0)
      return res.status(400).send('Cannot delete – stock still available');

    const batchCheck = await db.collection('stockBatches')
                               .where('productId','==',productId)
                               .limit(1)
                               .get();
    if (!batchCheck.empty)
      return res.status(400).send('Cannot delete – batches still exist');

    /* 2. delete product -------------------------------------------------- */
    await prodRef.delete();

    /* 3. reply ----------------------------------------------------------- */
    if (req.xhr) {                        // AJAX call from viewProducts.ejs
      return res.json({ success:true });
    }
    res.redirect('/view-products');
  } catch (err) {
    console.error(err);
    if (req.xhr) return res.json({ success:false, error:err.toString() });
    res.status(500).send(err.toString());
  }
});

/* ─────────── PROFIT ROUTES (externalised) ─────────── */
const makeProfitRoutes = require('./routes/profit');
const profitRoutes     = makeProfitRoutes({
  db,
  isAuthenticated,
  restrictRoute
});
app.use('/', profitRoutes);

/* ─────────── SUBSCRIPTION & PAYMENT ROUTES (externalised) ─────────── */
const makeSubscriptionRoutes = require('./routes/subscription');
const subscriptionRoutes     = makeSubscriptionRoutes({
  db,                 // Firestore instance
  isAuthenticated,    // middleware
  razorpay,           // pre-initialised Razorpay client
  crypto              // Node crypto (for HMAC verify)
});
app.use('/', subscriptionRoutes);


/* ─────────── PROFILE ROUTES (externalised) ─────────── */
const makeProfileRoutes = require('./routes/profile');
const profileRoutes     = makeProfileRoutes({
  db,
  isAuthenticated,
  requireMaster
});
app.use('/', profileRoutes);

/* ─────────── BILLING ROUTES (externalised) ─────────── */
const makeBillingRoutes = require('./routes/billing');
const billingRoutes     = makeBillingRoutes({
  db,
  isAuthenticated,
  requireMaster
});
app.use('/', billingRoutes);


/* ------------------------------------------------------------------
   Fallback route for <form action="/update-opening-balance"> … </form>
   ------------------------------------------------------------------*/
   app.post('/update-opening-balance', isAuthenticated, async (req, res) => {
    try {
      const accountId                  = req.session.user.accountId;
      const { saleDate, openingBalance,
              openingTime, closingTime } = req.body;
  
      await db.collection('openingBalances')
              .doc(`${accountId}_${saleDate}`)
              .set({
                balance     : +openingBalance,
                openingTime : openingTime || '',
                closingTime : closingTime || '',
                updatedAt   : new Date(),
                accountId
              }, { merge: true });
  
      res.redirect(`/?saleDate=${saleDate}`);
    } catch (err) {
      res.status(500).send(err.toString());
    }
  });

/* ─────────── EMPLOYEE ROUTES (externalised) ─────────── */
const makeEmployeeRoutes = require('./routes/employeeReporting');
const employeeRoutes     = makeEmployeeRoutes({
  db,
  isAuthenticated
});
app.use('/', employeeRoutes);

/* ─────────── AJAX  POST  /api/sale  (always returns JSON) ─────────── */
app.post('/api/sale', isAuthenticated, async (req, res) => {
  try {
    // 1️⃣  create the sale
    const sale = await processSale(req.body, req.session.user);

    // 2️⃣  fresh same-day summary for the quick dashboard refresh
    const { summary } = await computeDailySummary(
      req.session.user.accountId,
      sale.saleDate
    );

    return res.json({ success: true, sale, summary });
  } catch (err) {
    console.error('/api/sale error:', err);
    /* ALWAYS reply with JSON, even on failure */
    return res
      .status(400)
      .json({ success: false, error: err.message || 'Something went wrong' });
  }
});

// full‑page POST /expense
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

const { summary } = await computeDailySummary(
  exp.accountId,
  exp.saleDate
);

const monthTotal = await computeMonthTotal(
  exp.accountId,
  exp.saleDate.substring(0, 7)        // "YYYY-MM"
);

      /* 4️⃣ done */
      return res.json({ success: true, summary, monthTotal });

    } catch (e) {
      return res.json({ success: false, error: e.toString() });
    }
  }
);

/* ─────────── AJAX: EDIT EXPENSE  (expanded 2025-06-21) ─────────── */
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

// ─────────── AJAX: EDIT MONTHLY SNAPSHOT ROW ───────────
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

/* POST /delete-recurring-monthly/:recId – soft-delete *and* retire template */
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
// AJAX: POST /api/opening-balance
app.post('/api/opening-balance', isAuthenticated, async (req, res) => {
  try {
    const { saleDate, openingBalance, openingTime, closingTime } = req.body;
    await db.collection('openingBalances')
      .doc(`${req.session.user.accountId}_${saleDate}`)
      .set({
        balance: +openingBalance,
        openingTime,
        closingTime,
        updatedAt: new Date(),
        accountId: req.session.user.accountId
      }, { merge: true });
    const { summary, openingBalance: bal } = await computeDailySummary(req.session.user.accountId, saleDate);
    res.json({
  success      : true,
  openingBalance: bal,
  openingTime  : openingTime || '',
  closingTime  : closingTime || '',
  summary
});
  } catch (e) {
    res.json({ success: false, error: e.toString() });
  }
});

// ─────────── AJAX:  DELETE SALE  ───────────
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

        await saleRef.delete();           // 1️⃣ remove sale first
    await recalcProductFromBatches(productId);   // 2️⃣ then correct stock
/* ▼ NEW – re-compute month running total */
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

/* 3️⃣  Send the up-to-date numbers back to the browser */
res.json({ success: true, summary, monthTotal });
  } catch (e) {
    console.error('delete-sale error:', e);
    res.json({ success:false, error:e.toString() });
  }
});

/* ─────────── PERFORMANCE ROUTES (externalised) ─────────── */
const makePerformanceRoutes = require('./routes/performance');   // ← path & name
const performanceRoutes     = makePerformanceRoutes({            // ← factory call
  db,
  isAuthenticated
});
app.use('/', performanceRoutes);

/* ─────────── STATS ROUTES (externalised) ─────────── */
const makeStatsRoutes = require('./routes/stats');        // NEW
const statsRoutes     = makeStatsRoutes({                 // NEW
  db,
  isAuthenticated,
  restrictRoute
});
app.use('/', statsRoutes); 

/* ─────────── PASSWORD RESET ROUTES (externalised) ─────────── */
const makePasswordRoutes = require('./routes/passwordReset');   // NEW
const passwordRoutes     = makePasswordRoutes({                 // NEW
  db,
  bcrypt,
  crypto,
  transporter
});
app.use('/', passwordRoutes);                                   // NEW

/* ─────────── INVOICE ROUTES (externalised) ─────────── */
const makeInvoiceRoutes = require('./routes/invoice');      // NEW
const invoiceRoutes     = makeInvoiceRoutes({               // NEW
  db,
  isAuthenticated,
  getNextInvoiceNo                                       // helper already in app.js
});
app.use('/', invoiceRoutes);

/* ─────────── GST ROUTES (externalised) ─────────── */
const makeGstRoutes = require('./routes/gst');       // NEW LINE
const gstRoutes     = makeGstRoutes({                // NEW LINE
  db,                                                 // Firestore instance
  isAuthenticated,
  restrictRoute
});
app.use('/', gstRoutes);   

/* ───── Boot-strap server (moved out) ───── */
const startServer = require('./routes/startServer');
startServer({ app, logger, redisClient, admin });
