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


/* ─────────── DASHBOARD ROUTES (externalised) ─────────── */
const makeDashboardRoutes = require('./routes/dashboard');
const dashboardRoutes = makeDashboardRoutes({
  db,                    // Firestore instance
  isAuthenticated,       // auth middleware
  getCategories,         // helper
  pad,                   // helper for date-padding
  processSale,           // ★ MUST be passed
  computeDailySummary    // ★ MUST be passed
});
app.use('/', dashboardRoutes);


/* ─────────── EXPENSE ROUTES (externalised) ─────────── */
const makeExpenseRoutes = require('./routes/expense');
const expenseRoutes     = makeExpenseRoutes({
  db,
  isAuthenticated,
  restrictRoute,
  restrictAction,
  cacheDel,
  computeDailySummary,
  computeMonthTotal
});
app.use('/', expenseRoutes);


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

/* ─────────── VIEW PRODUCTS ROUTES (externalised) ─────────── */
const makeViewProductsRoutes = require('./routes/viewProducts');
const viewProductsRoutes     = makeViewProductsRoutes({
  db,
  isAuthenticated,
  restrictRoute,
  restrictAction,
  getCategories,
  recalcProductFromBatches
});
app.use('/', viewProductsRoutes);

/* ─────────── DOWNLOAD PRODUCTS ROUTES (externalised) ─────────── */
const makeProductDownloadRoutes = require('./routes/productDownload');
const productDownloadRoutes     = makeProductDownloadRoutes({
  db,
  isAuthenticated,
  restrictRoute
});
app.use('/', productDownloadRoutes);

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

// ─────────── SALES ROUTES (externalised) ───────────
const makeSalesRoutes = require('./routes/sales');
const salesRoutes     = makeSalesRoutes({
  db,
  isAuthenticated,
  restrictRoute,
  restrictAction,
  recalcProductFromBatches,
  computeDailySummary,
  computeMonthTotal,
  cacheDel,
  pad
});
app.use('/', salesRoutes);


/* ─────────── DOWNLOAD SALES ROUTES (externalised) ─────────── */
const makeSalesDownloadRoutes = require('./routes/salesDownload');
const salesDownloadRoutes     = makeSalesDownloadRoutes({
  db,
  isAuthenticated,
  restrictRoute
});

app.use('/', salesDownloadRoutes);

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


/* ─────────── EMPLOYEE ROUTES (externalised) ─────────── */
const makeEmployeeRoutes = require('./routes/employeeReporting');
const employeeRoutes     = makeEmployeeRoutes({
  db,
  isAuthenticated
});
app.use('/', employeeRoutes);


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
