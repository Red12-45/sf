

// app.js – Ultimate Optimized version (Ajax‑ready, no missing pieces)

const express = require('express');
const admin = require('firebase-admin');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { createClient } = require('redis');       // using Node Redis client
const { RedisStore } = require('connect-redis'); // import RedisStore from connect-redis

// ─────────── security deps (NEW) ───────────
const helmet = require('helmet');              // 🔒
const rateLimit = require('express-rate-limit');  // 🔒
const csrf = require('csurf');               // 🔒
const { body, validationResult } = require('express-validator'); // 🔒


const favicon = require('serve-favicon');
const Razorpay = require('razorpay');
const ExcelJS = require('exceljs');      
const compression = require('compression');

const cors = require('cors');          // NEW


const http = require('http');
const cluster = require('cluster');
const os = require('os');

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
app.disable('x-powered-by');              // hide Express fingerprint
app.use(helmet.hidePoweredBy()); 

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

// later, plug it into Express

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
const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    /* keep idle connections alive (some cloud hosts kill quiet TCP streams) */
    keepAlive: 10_000,                          // ping kernel every 10 s

    /* exponential back-off:  0.1 s → … → max 30 s */
    reconnectStrategy: retries => Math.min(retries * 100, 30_000),

    /* auto-TLS when the URL starts with “rediss://” (Redis Cloud, Upstash, etc.) */
    tls: process.env.REDIS_URL.startsWith('rediss://') ? {} : undefined
  }
});

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
  client: redisClient,
  prefix: 'sess:'
});
/* reusable factory so both stores share identical cookie settings */
const makeSession = (store) => session({
  store,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge  : 24 * 60 * 60 * 1000,   // 1 day
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



/* ─────────── Helmet – strict CSP ─────────── */
app.use(
helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          
          "https://cdnjs.cloudflare.com",
          "https://cdn.jsdelivr.net",
          "https://www.gstatic.com",
          // razorpay checkout script
          "https://checkout.razorpay.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://fonts.googleapis.com"
        ],
        connectSrc: [
          "'self'",
          "https://*.firebaseio.com",
          "https://firestore.googleapis.com",
          // for XHR/secure calls back to Razorpay
          "https://*.razorpay.com"
        ],
        imgSrc: ["'self'", "data:", "blob:"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
        // **here** add the API domain so the checkout iframe can load
        frameSrc: [
          "'self'",
          "https://checkout.razorpay.com",
          "https://api.razorpay.com"
        ],
        // if you want to be extra-sure for legacy browsers:
        childSrc: [
          "'self'",
          "https://checkout.razorpay.com",
          "https://api.razorpay.com"
        ]
      }
    }
  })
);


app.use(express.urlencoded({ extended: false }));
app.use(express.json());


/* ─────────── CORS & logging ─────────── */
app.use(cors({
  origin      : (process.env.ALLOWED_ORIGINS || '').split(','),
  credentials : true
}));



app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true })); // 2 years

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

/* ────────────────────────────────────────────────────────────────
   ensureRecurringSnapshot(accountId, month)      ★ UPDATED 2025-06-21 ★
   • Creates a snapshot row for every template that *should* exist
     in the given month **but is missing**.
   • A template that carries   removalMonth: 'YYYY-MM'
     is considered “retired” from that month onwards.
   ----------------------------------------------------------------*/
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

    batch.set(
      db.collection('recurringMonthly').doc(id),
      {
        accountId,
        month,
        templateId   : doc.id,
        expenseReason: d.expenseReason,
        expenseCost  : d.defaultCost,
        expenseStatus: 'Not Paid',   // every month starts fresh
        createdAt    : new Date()
      }
    );
  });

  if (batch._ops?.length) await batch.commit();   // ← only when needed
}





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
    .filter(d => d.data().expenseStatus !== 'Not Paid')
    .reduce((s,d)=> s + (+d.data().expenseCost || 0), 0);

  /* 2️⃣  Pull this month’s RECURRING snapshot rows */
  const recSnap = await db.collection('recurringMonthly')
    .where('accountId','==',accountId)
    .where('month',     '==', month)
    .get();

  const recTotal = recSnap.docs
    .filter(d => d.data().expenseStatus !== 'Not Paid' && !d.data().deleted)
    .reduce((s,d)=> s + (+d.data().expenseCost || 0), 0);

  return +(expenseTotal + recTotal).toFixed(2);
}



/* ─────────── processSale (shared full-page + Ajax) ─────────── */
// ────────────────────────────────────────────────────────────────
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
  const ctrRef = db.collection('counters').doc(accountId);

  return db.runTransaction(async tx => {

    /* 1️⃣  Read the current counter (0 when brand-new account) */
    const snap = await tx.get(ctrRef);
    let seq = (snap.exists && typeof snap.data().invoiceSeq === 'number')
                ? snap.data().invoiceSeq          // ← do **not** +1 yet
                : 0;

    /* 2️⃣  Search forward until we hit the first unused number   */
    /*     Real-world loops ≈0–2 so this stays very fast.         */
    while (true) {
      if (seq === 0) seq = 1;                       // bootstrap on first run
      const candidate = 'INV-' + String(seq).padStart(6, '0');

      const dupSnap = await db.collection('sales')
                              .where('accountId','==',accountId)
                              .where('invoiceNo','==',candidate)
                              .limit(1).get();

      if (dupSnap.empty) {                          // ✅ free → lock & return
        tx.set(ctrRef, { invoiceSeq: seq }, { merge:true });
        return candidate;
      }

      seq++;                                        // already used → try next
    }
  });
}

app.post('/api/invoice/start', isAuthenticated, async (req, res) => {
  try {
    if (!req.session.currentInvoiceNo) {
      req.session.currentInvoiceNo =
        await getNextInvoiceNo(req.session.user.accountId);
    }
    return res.json({ success: true, invoiceNo: req.session.currentInvoiceNo });
  } catch (err) {
    console.error('/api/invoice/start error:', err);
    return res.json({ success: false, error: err.toString() });
  }
});
app.get('/invoice/finish', isAuthenticated, (req, res) => {
  delete req.session.currentInvoiceNo;
  res.redirect('/dashboard');
});


/* ───────────  AJAX “Finish Invoice”  ─────────── */
app.post('/api/invoice/finish', isAuthenticated, (req, res) => {
  delete req.session.currentInvoiceNo;      // clear the session flag
  return res.json({ success: true });
});

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


/* ─────────── AUTHENTICATION ROUTES ─────────── */
// GET /register
app.get('/register', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('register', { errorMessage: null, oldInput: {} });
});


// POST /register
app.post(
  '/register',
  [
  body('name')
    .isLength({ min: 2, max: 60 })
    .withMessage('Name must be at least 2 characters.')
    .trim().escape(),

  body('email')
    .isEmail()
    .withMessage('Invalid email address.')
    .normalizeEmail(),

  body('phone')
    .optional({ checkFalsy: true })
    .isMobilePhone('en-IN')
    .withMessage('Invalid Indian phone number.')
    .trim().escape(),

  body('address')
    .isLength({ max: 200 })
    .withMessage('Address too long.')
    .trim().escape(),

  body('location')
    .optional({ checkFalsy: true })
    .trim().escape(),

  /* ─── NEW – optional GST Number (15-char GSTIN) ─── */
  body('gstNumber')
    .optional({ checkFalsy: true })
    .matches(/^[0-9A-Z]{15}$/)
    .withMessage('GST number must be 15 characters (digits/A-Z).'),

  body('password')
    .isStrongPassword({
      minLength : 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers  : 1,
      minSymbols  : 1
    })
    .withMessage('Password must be 8 chars incl. upper, lower, number & symbol.'),

  body('confirmPassword')
    .custom((val, { req }) => {
      if (val !== req.body.password)
        throw new Error('Passwords do not match');
      return true;
    })
],

  async (req, res) => {
    const errors = validationResult(req);
    const {
  name, email, phone, address, location,
  businessName, gstNumber = '', password
} = req.body;

    const oldInput = { name, email, phone, address, location, businessName  };

    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        errorMessage: errors.array().map(e => e.msg).join('<br>'),
        oldInput
      });
    }

    try {
      const normalizedEmail = email.trim().toLowerCase();
      const exists = await db.collection('users')
        .where('email', '==', normalizedEmail)
        .limit(1).get();
      if (!exists.empty) {
        return res.status(400).render('register', {
          errorMessage: 'User already exists',
          oldInput
        });
      }

          // 1️⃣ Hash password and create user
      const hashed = await bcrypt.hash(password, 10);
      const userData = {
  name,
  email        : normalizedEmail,
  phone,
  address,
  location,
  businessName,
  ...(gstNumber && { gstNumber: gstNumber.trim().toUpperCase() }), // ✅ optional
  password     : hashed,
  isMaster     : true,
  createdAt    : new Date()
};

const userRef = await db.collection('users').add(userData);


      // 2️⃣ Set accountId AND a 30-day trial expiry
      const trialExpiry = new Date();
      trialExpiry.setDate(trialExpiry.getDate() + 30);
      await userRef.update({
        accountId: userRef.id,
        subscriptionExpiry: trialExpiry
      });

      // 3️⃣ Done → send them to login
      res.redirect('/login');

    } catch (err) {
      console.error(err);
      return res.status(500).render('register', {
        errorMessage: 'Something went wrong. Please try again.',
        oldInput
      });
    }
  }
);





// ─────────── brute‑force protection ───────────
const MAX_LOGIN_ATTEMPTS  = 5;      // failures before block
const BLOCK_TIME_SECONDS  = 15 * 60; // 15‑minute lock‑out

/**
 * Returns current failure count for key.
 * key =   "bf:<identifier>"  (preferred)  when user types an email / sub‑user ID / phone
 *       or "bfip:<ip>"       (fallback)   when identifier missing/garbled
 */
const getAttempts = async key =>
  parseInt(await redisClient.get(key) || '0', 10);

/** Increment failures and (re)set expiry. */
const recordFailure = async key => {
  const attempts = await redisClient.incr(key);
  if (attempts === 1) await redisClient.expire(key, BLOCK_TIME_SECONDS);
  return attempts;
};

/** On successful login → wipe the counter. */
const clearFailures = async key => redisClient.del(key);



// GET /login
app.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/');
  }
  // first time or after failure: no error, blank identifier
  res.render('login', {
    loginError: null,
    identifier: ''
  });
});

// POST /login  (brute-force protected)
// POST /login  (brute-force + 🔒 validation)
app.post(
  '/login',
  [
    body('identifier')
      .notEmpty()
      .withMessage('Email / sub-user ID / phone is required.')
      .trim().escape(),
    body('password')
      .notEmpty()
      .withMessage('Password is required.')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('login', {
        loginError: errors.array()[0].msg,
        identifier: req.body.identifier || ''
      });
    }

    try {
      let { identifier, password } = req.body;

      // normalize identifier
      if (identifier.includes('@')) identifier = identifier.trim().toLowerCase();

      // pick key for brute-force table
      const bruteKey = identifier ? `bf:${identifier}` : `bfip:${req.ip}`;

      /* 1️⃣  Lock-out check (unchanged) */
      const currentAttempts = await getAttempts(bruteKey);
      if (currentAttempts >= MAX_LOGIN_ATTEMPTS) {
  const ttlSecs = await redisClient.ttl(bruteKey);        // −1 or −2 ⇒ no TTL
  const retryAfter = ttlSecs > 0
      ? Math.ceil(ttlSecs / 60)                           // real time left
      : Math.ceil(BLOCK_TIME_SECONDS / 60);               // default 15 min
  return res.status(429).render('login', {
    loginError: `Too many failed attempts. Try again in ${retryAfter} minute${retryAfter === 1 ? '' : 's'}.`,
    identifier
  });
}

      /* 2️⃣  Lookup user (unchanged) */
      const [emailQ, subUserQ, phoneQ] = await Promise.all([
        db.collection('users').where('email', '==', identifier).get(),
        db.collection('users').where('subUserId', '==', identifier).get(),
        db.collection('users').where('phone', '==', identifier).get()
      ]);
      const userDoc = !emailQ.empty
        ? emailQ.docs[0]
        : !subUserQ.empty
          ? subUserQ.docs[0]
          : !phoneQ.empty
            ? phoneQ.docs[0]
            : null;

      if (!userDoc) {
        await recordFailure(bruteKey);
        const triesLeft = MAX_LOGIN_ATTEMPTS - (await getAttempts(bruteKey));
        return res.status(400).render('login', {
          loginError: triesLeft > 0
            ? `User not found. ${triesLeft} attempt${triesLeft === 1 ? '' : 's'} remaining.`
            : 'Too many failed attempts. Please try again later.',
          identifier
        });
      }

      /* 3️⃣  Password check (unchanged) */
      const userData = userDoc.data();
      const validPw = await bcrypt.compare(password, userData.password);
      if (!validPw) {
        const tries = await recordFailure(bruteKey);
        const left = MAX_LOGIN_ATTEMPTS - tries;
        return res.status(400).render('login', {
          loginError: left > 0
            ? `Invalid password – ${left} attempt${left === 1 ? '' : 's'} remaining.`
            : 'Too many failed attempts. Please try again later.',
          identifier
        });
      }

      /* 4️⃣  Success – wipe failures */
      await clearFailures(bruteKey);

      /* 5️⃣  Subscription logic (unchanged) */
      let subscriptionExpiry = userData.subscriptionExpiry
        ? (typeof userData.subscriptionExpiry.toDate === 'function'
            ? userData.subscriptionExpiry.toDate()
            : new Date(userData.subscriptionExpiry))
        : null;

      if (!userData.isMaster) {
        const masterDoc = await db.collection('users')
                                  .doc(userData.accountId).get();
        if (masterDoc.exists && masterDoc.data().subscriptionExpiry) {
          const d = masterDoc.data().subscriptionExpiry;
          subscriptionExpiry = typeof d.toDate === 'function' ? d.toDate() : new Date(d);
        }
      }

      /* 6️⃣  Attach to session & redirect (unchanged) */
         /* 6️⃣  Attach to session & redirect (with businessName) */
   req.session.user = {
     id              : userDoc.id,
     name            : userData.name,
     email           : userData.email,
     businessName    : userData.businessName||'',  // ← added
     isMaster        : userData.isMaster || false,
     accountId       : userData.accountId || userDoc.id,
     subscriptionExpiry
   };

   // If this is a sub-user, overwrite businessName with the master’s
   if (!req.session.user.isMaster) {
     const masterDoc = await db.collection('users')
                               .doc(req.session.user.accountId).get();
     if (masterDoc.exists && masterDoc.data().businessName) {
       req.session.user.businessName = masterDoc.data().businessName;
     }
   }

      if (!req.session.user.isMaster) {
  const permDoc = await db.collection('permissions')
                          .doc(req.session.user.accountId).get();
  const data = permDoc.exists ? permDoc.data() : {};
  req.session.lockedRoutes    = data.lockedRoutes    || [];
  req.session.blockedActions  = data.blockedActions  || {};   // ← NEW
}
      res.redirect('/');

    } catch (error) {
      console.error(error);
      res.status(500).render('login', {
        loginError: 'Something went wrong—please try again.',
        identifier: req.body.identifier || ''
      });
    }
  }
);



// GET /logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// GET /customerservice
app.get('/customerservice', (req, res) => res.render('cs'));

// GET /documentation
app.get('/documentation', (req, res) => res.render('documentations'));


/* ─────────── USER MANAGEMENT ROUTES (Master Only) ─────────── */
// GET /create-user
app.get('/create-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send('Access denied');
  try {
    const snapshot = await db.collection('users')
      .where('accountId','==',req.session.user.accountId)
      .get();
    const users = snapshot.docs.map(doc => {
      const d = doc.data();
      return { id: doc.id, name: d.name, email: d.email, isMaster: d.isMaster, subUserId: d.subUserId };
    });
    res.render('createuser', { users });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /create-user
app.post('/create-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send('Access denied');
  try {
    const subUsersQuery = await db.collection('users')
      .where('accountId','==',req.session.user.accountId)
      .where('isMaster','==',false)
      .get();
    if (subUsersQuery.size >= 2) return res.status(400).send('Sub‑user limit reached. Maximum 2 sub‑users allowed.');

    const { name, password, confirmPassword, subUserId } = req.body;
    if (password !== confirmPassword) return res.status(400).send('Passwords do not match');
    if (!subUserId.trim()) return res.status(400).send('Sub‑user ID is required');

    const exist = await db.collection('users')
      .where('subUserId','==',subUserId)
      .where('accountId','==',req.session.user.accountId)
      .get();
    if (!exist.empty) return res.status(400).send('Sub‑user ID already exists.');

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').add({
      name, password: hashedPassword, isMaster: false,
      accountId: req.session.user.accountId, subUserId,
      createdAt: new Date()
    });
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /edit-user
app.post('/edit-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send('Access denied');
  try {
    const { userId, name, password, confirmPassword } = req.body;
    if (password && password !== confirmPassword) return res.status(400).send('Passwords do not match');

    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId)
      return res.status(403).send('Access denied');

    const updateData = { name };
    if (password) updateData.password = await bcrypt.hash(password, 10);

    await userRef.update(updateData);
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /delete-user
app.post('/delete-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send('Access denied');
  try {
    const { userId } = req.body;
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId)
      return res.status(403).send('Access denied');
    await userRef.delete();
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


/* ─────────── PERMISSION MANAGEMENT (Master Only) ─────────── */
// ─────────── PERMISSION MANAGEMENT (Master Only) ───────────

// GET /permission
// GET /permission
app.get('/permission',
  isAuthenticated,
  restrictRoute('/permission'),
  async (req, res) => {
    if (!req.session.user.isMaster) return res.status(403).send('Access denied');
    try {
      const doc = await db.collection('permissions')
                          .doc(req.session.user.accountId)
                          .get();
      const lockedRoutes   = doc.exists ? (doc.data().lockedRoutes   || []) : [];
      const blockedActions = doc.exists ? (doc.data().blockedActions || {}) : [];

      const availableRoutes = [
        { path:'/profit',        label:'Profit Report' },
        { path:'/sales',         label:'Sales Report',   canLockActions:true },
        { path:'/expense',       label:'Expense Report', canLockActions:true },
        { path:'/add-product',   label:'Add Product' },
        { path:'/view-products', label:'View Products',  canLockActions:true }
      ];

      res.render('permission', {
        lockedRoutes,
        blockedActions,
        availableRoutes,
        success : req.query.success,
        user    : req.session.user          // <- ✅  add this line
      });
    } catch (e) {
      res.status(500).send(e.toString());
    }
});


/* ─────────── PERMISSION SAVE ─────────── */
app.post(
  '/permission',
  isAuthenticated,
  restrictRoute('/permission'),
  async (req, res) => {
    if (!req.session.user.isMaster)
      return res.status(403).send('Access denied');

    try {
      /* 1️⃣  Whole-route locks --------------------------------------- */
      let lockedRoutes = req.body.lockedRoutes || [];
      if (!Array.isArray(lockedRoutes))
        lockedRoutes = [lockedRoutes];

      /* 2️⃣  Fine-grained locks  e.g.  "edit@@/sales" ----------------- */
      const raw = Array.isArray(req.body.actionLocks)
                    ? req.body.actionLocks
                    : (req.body.actionLocks ? [req.body.actionLocks] : []);

      const blockedActions = {};          // { '/sales': ['edit'], … }
      raw.forEach(tok => {
        const [action, route] = tok.split('@@');
        if (!blockedActions[route]) blockedActions[route] = [];
        blockedActions[route].push(action);
      });

      /* 3️⃣  Write — **NO merge**  (old routes disappear) ------------- */
      await db.collection('permissions')
              .doc(req.session.user.accountId)
              .set({ lockedRoutes, blockedActions });   // ← important change

      await cacheDel(`permissions_${req.session.user.accountId}`);
      return res.redirect('/permission?success=1');

    } catch (e) {
      console.error('Save-permission error:', e);
      return res.status(500).send(e.toString());
    }
  }
);


/* ─────────── PROTECTED APP ROUTES ─────────── */
// GET /
/* ─────────── PUBLIC LANDING ────────── */
// (Insert this near the very top of your route section)
app.get('/', (req, res) => {
  // Logged-in users get forwarded to their dashboard
  if (req.session?.user) return res.redirect('/dashboard');
  // Everyone else sees the beautiful marketing page
  res.render('landing');         // v is already supplied by the global middleware
});


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


// GET /expense – monthly expenses view
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

/* 2-B.  M O N T H - S P E C I F I C  recurring snapshot ------------- */
await ensureRecurringSnapshot(accountId, monthParam);

const [expenseSnap, recurringMonthSnap] = await Promise.all([
  db.collection('expenses')
    .where('accountId', '==', accountId)
    .where('saleDate',  '>=', startDate)
    .where('saleDate',  '<',  nextMonth)
    .orderBy('createdAt', 'desc')
    .get(),
  db.collection('recurringMonthly')              // ← monthly snapshot
    .where('accountId','==',accountId)
    .where('month','==',monthParam)
    .orderBy('expenseReason','asc')
    .get()
]);

const expenses          = expenseSnap.docs.map(d => ({ id:d.id, ...d.data() }));
const recurringMonthly = recurringMonthSnap.docs
  .map(d => ({ id:d.id, ...d.data() }))
  .filter(t => !t.deleted);          // ⬅️  hide soft-deleted rows

const totalExpense = expenses
  .filter(e => e.expenseStatus !== 'Not Paid')   // skip unpaid expenses
  .reduce((s, e) => s + (e.expenseCost || 0), 0);

const recTotal = recurringMonthly               // monthly snapshot
  .filter(t => t.expenseStatus !== 'Not Paid')   // skip unpaid snapshots
  .reduce((s, t) => s + (t.expenseCost || 0), 0);

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
    const {
  recurringReason,
  recurringDefaultCost
  // ◆ recurringStatus field intentionally discarded
} = req.body;

const DEFAULT_STATUS = 'Not Paid';


    await db.collection('recurringExpenses').add({
      accountId,
      expenseReason : recurringReason.trim(),
      defaultCost   : parseFloat(recurringDefaultCost),
      expenseStatus : DEFAULT_STATUS,

      createdAt     : new Date()
    });

    /* return to the same month **/
    const month = req.body.month || new Date().toISOString().substring(0, 7);
    res.redirect(`/expense?month=${month}`);
  } catch (err) {
    res.status(500).send(err.toString());
  }
});






// GET /add-product – render form
app.get('/add-product', isAuthenticated, restrictRoute('/add-product'), async (req, res) => {
  try {
    const accountId     = req.session.user.accountId;
    const selectedCat   = req.query.category     || '';
    const selectedUnit  = req.query.selectedUnit || '';
    const sortOrder     = req.query.sortOrder    || 'asc';

    const [categories, units] = await Promise.all([
      getCategories(accountId),
      getUnits(accountId)
    ]);

    let q = db.collection('products').where('accountId','==',accountId);
    if (selectedCat.trim() !== '') q = q.where('category','==',selectedCat);
    q = q.orderBy('productName', sortOrder);
    const snap = await q.get();
    const existingProducts = snap.docs.map(d => ({ id: d.id, name: d.data().productName }));

    res.render('addProduct', {
      success: req.query.success,
      errorMessage: null,
      categories,
      units,
      existingProducts,
      selectedCategory: selectedCat,
      selectedUnit,
      sortOrder
    });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});

/* ─────────── POST /add-product – create or update ─────────── */
/* ─────────── POST /add-product – create or update ─────────── */
app.post(
  '/add-product',
  isAuthenticated,
  restrictRoute('/add-product'),
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      const {
        existingProduct,
        productName    = '',        // default to empty string
        wholesalePrice,
        retailPrice,
        quantity,
        inclusiveTax,
        selectedCategory,
        newCategory,
        selectedUnit,
        newUnit
      } = req.body;


const wp = +parseFloat(wholesalePrice);
const rp = +parseFloat(retailPrice);
const qty = +parseFloat(quantity);

/* NEW ▸ inclusive-tax validation */
let taxPct = null;
if (inclusiveTax && inclusiveTax.toString().trim() !== '') {
  taxPct = +parseFloat(inclusiveTax);
  if (!Number.isFinite(taxPct) || taxPct < 0 || taxPct > 100)
    return res.status(400).send('Inclusive-Tax % must be between 0 and 100');
}


if (!Number.isFinite(wp) || wp <= 0 ||
    !Number.isFinite(rp) || rp <= 0 ||
    !Number.isFinite(qty) || qty <= 0)
  return res.status(400).send('Prices and quantity must be > 0');


      let category = newCategory?.trim()
        ? newCategory.trim()
        : (selectedCategory || '');

      // normalise runs of spaces, then trim
      category = category.replace(/\s+/g, ' ').trim();

      // title-case for storage (e.g. "drinks" → "Drinks")
      if (category) {
        category = category[0].toUpperCase() + category.slice(1).toLowerCase();
      }

      /* ──────────────────────────────────────────────────────────────
         ✨ DUPLICATE CATEGORY GUARD  (case- & space-insensitive)
         – Runs only when the user typed a brand-new category.
         – Uses the existing helper  normalizeName()  and  getCategories().
      ────────────────────────────────────────────────────────────── */
      if (newCategory?.trim()) {
        const existingCats = await getCategories(accountId);   // cached helper
        const isDup = existingCats.some(
          c => normalizeName(c) === normalizeName(category)
        );

        if (isDup) {
          return res
            .status(400)
            .send('Category already exists — choose a different name.');
        }
      }

     /* ──────────────────────────
         Unit normalisation & guard
      ────────────────────────── */
      const unitRawInput = newUnit?.trim() || selectedUnit || '';

      // collapse extra spaces, trim, then lower-case for storage
      let unit = unitRawInput.replace(/\s+/g, ' ').trim().toLowerCase();

      /* ✨ DUPLICATE UNIT GUARD  (case- & space-insensitive)
         – Runs only when the user typed a brand-new unit.
         – Re-uses  normalizeName()  and  getUnits().
      */
      if (newUnit?.trim()) {
        const existingUnits = await getUnits(accountId);      // cached helper
        const isDupUnit = existingUnits.some(
          u => normalizeName(u) === normalizeName(unit)
        );

        if (isDupUnit) {
          return res
            .status(400)
            .send('Unit already exists — choose a different name.');
        }
      }


      /* --------------------------------------------------------------
         0. Validation
      -------------------------------------------------------------- */
      if (existingProduct === 'new' && !productName.trim())
        return res.status(400).send('Product name is required');

      /* --------------------------------------------------------------
         1. Duplicate-detection helpers
      -------------------------------------------------------------- */
      const nameKey = normalizeName(productName);  // now 100 % safe
      let productRef  = null;
      let productSnap = null;

      if (existingProduct && existingProduct !== 'new') {
        /* --------------------------------------------------------------
           1A.  UPDATE path — explicit product selected
        -------------------------------------------------------------- */
        productRef  = db.collection('products').doc(existingProduct);
        productSnap = await productRef.get();
        if (!productSnap.exists)
          return res.status(404).send('Selected product not found');

      } else {
        /* --------------------------------------------------------------
           1B.  CREATE / implicit-update path — need dup-check
        -------------------------------------------------------------- */
        const fastDup = await db.collection('products')
          .where('accountId', '==', accountId)
          .where('nameKey',   '==', nameKey)
          .limit(1)
          .get();

        if (!fastDup.empty) {
          productRef  = fastDup.docs[0].ref;
          productSnap = fastDup.docs[0];

        } else {
          /* ─── Legacy fallback – scan once, patch missing nameKey ─── */
          const all = await db.collection('products')
            .where('accountId','==', accountId)
            .select('productName')        // lighter payload
            .get();

          const legacy = all.docs.find(d =>
            normalizeName(d.data().productName) === nameKey
          );

          if (legacy) {
            await legacy.ref.update({ nameKey });  // back-fill
            productRef  = legacy.ref;
            productSnap = legacy;
          }
        }
      }

      /* --------------------------------------------------------------
         2. UPDATE flow
      -------------------------------------------------------------- */
      if (productRef && productSnap) {
        const d    = productSnap.data();
        const curQ = d.quantity || 0;
        const newQ = curQ + qty;

        const newWholesale = +(
  ((curQ * d.wholesalePrice) + (qty * wp)) / newQ
).toFixed(2);
const newRetail = +(
  ((curQ * d.retailPrice) + (qty * rp)) / newQ
).toFixed(2);


       await productRef.update({
  quantity      : newQ,
  wholesalePrice: newWholesale,
  retailPrice   : newRetail,
  profitMargin  : newRetail - newWholesale,
  updatedAt     : new Date(),
  ...(unit       && { unit }),
  ...(category   && { category }),
  // ⬇️  only overwrite when the user actually entered a value
  ...(taxPct !== null && { inclusiveTax: taxPct })
});


      /* --------------------------------------------------------------
         3. CREATE flow
      -------------------------------------------------------------- */
      } else {
        const data = {
  productName     : productName.trim(),
  nameKey,
  wholesalePrice  : wp,
  retailPrice     : rp,
  quantity        : qty,
  profitMargin    : rp - wp,
  category,
  unit,
  createdAt       : new Date(),
  accountId,
  ...(taxPct !== null && { inclusiveTax: taxPct }), // ✅ persist GST %

  /* ── legacy compat fields (unchanged) ── */
  oldestWholesale : wp,
  oldestBatchQty  : qty,
  secondWholesale : null,
  oldestRetail    : rp,
  secondRetail    : null
};

        productRef  = await db.collection('products').add(data);
        productSnap = { id: productRef.id, data: () => data };
      }

      /* --------------------------------------------------------------
         4. Always create a NEW stock batch
      -------------------------------------------------------------- */
      await db.collection('stockBatches').add({
        productId        : productRef.id,
        productName      : productSnap.data().productName,
        purchasePrice    : wp,
        salePrice        : rp,
        quantity         : qty,
        remainingQuantity: qty,
        batchDate        : new Date(),
        accountId,
        unit
      });



      res.redirect('/add-product?success=1');
    } catch (err) {
      res.status(500).send(err.toString());
    }
  }
);




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

/* ─────────── DOWNLOAD PRODUCTS → EXCEL ─────────── */
// GET /download-products
app.get('/download-products', isAuthenticated, restrictRoute('/view-products'), async (req, res) => {
  try {
    const accountId                  = req.session.user.accountId;
    const { filterCategory='', stockThreshold='', sortOrder='asc' } = req.query;

    /* 1. replicate the same Firestore query used in /view-products */
    let q = db.collection('products').where('accountId','==',accountId);
    if (filterCategory.trim() !== '')
      q = q.where('category','==',filterCategory);
    if (stockThreshold.trim() !== '')
      q = q.where('quantity','<',parseFloat(stockThreshold));
    q = q.orderBy('productName', sortOrder);

    const prodSnap  = await q.get();
    const products  = prodSnap.docs.map(d => ({ id:d.id, ...d.data() }));
    const productIds= products.map(p=>p.id);

    /* 2. pull batches so we can compute avg profit */
    const batchesMap = {};
    if (productIds.length) {
      const batchPromises = [];
      for (let i=0; i<productIds.length; i+=10) {
        const slice = productIds.slice(i,i+10);
        batchPromises.push(
          db.collection('stockBatches')
            .where('productId','in',slice)
            .get()
        );
      }
      const batchSnaps = await Promise.all(batchPromises);
      batchSnaps.forEach(s=>{
        s.docs.forEach(b=>{
          const d=b.data(); const pid=d.productId;
          if (!batchesMap[pid]) batchesMap[pid]=[];
          batchesMap[pid].push(d);
        });
      });
    }

    /* 3. create workbook */
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('Products');

    ws.columns = [
      { header:'Serial',          key:'serial',          width:8  },
      { header:'Product Name',    key:'productName',     width:30 },
      { header:'Wholesale ₹',     key:'wholesalePrice',  width:14 },
      { header:'Retail ₹',        key:'retailPrice',     width:12 },
      { header:'Quantity',        key:'quantity',        width:10 },
      { header:'Unit',            key:'unit',            width:8  },
      { header:'Profit /Unit ₹',  key:'profitMargin',    width:16 },
      { header:'Avg Profit ₹',    key:'avgProfit',       width:14 },
      { header:'Category',        key:'category',        width:16 }
    ];

    products.forEach((p, idx) => {
      /* compute average profit exactly like the page does */
      let avgProfit = 0;
      const batches = batchesMap[p.id] || [];
      if (batches.length) {
        const tQty  = batches.reduce((s,b)=>s+(+b.quantity||0), 0);
        const tProf = batches.reduce((s,b)=>
                      s + ((+b.salePrice - +b.purchasePrice)*(+b.quantity||0)), 0);
        avgProfit = tQty ? tProf / tQty : 0;
      } else {
        avgProfit = (+p.retailPrice - +p.wholesalePrice);
      }

      ws.addRow({
        serial: idx + 1,

        productName   : p.productName,
        wholesalePrice: (+p.wholesalePrice).toFixed(2),
        retailPrice   : (+p.retailPrice).toFixed(2),
        quantity      : (+p.quantity).toFixed(2),
        unit          : p.unit || '',
        profitMargin  : (+p.profitMargin).toFixed(2),
        avgProfit     : avgProfit.toFixed(2),
        category      : p.category || ''
      });
    });

    /* 4. stream to client */
    res.setHeader('Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition',
      `attachment; filename="products_${Date.now()}.xlsx"`);

    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    res.status(500).send(err.toString());
  }
});



/* ─────────── STOCK BATCH MANAGEMENT ─────────── */
// POST /delete-stock-batch/:batchId
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


// GET /edit-stock-batch/:batchId
app.get('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const { batchId } = req.params;
    const batchRef    = db.collection('stockBatches').doc(batchId);
    const batchSnap   = await batchRef.get();
    if (!batchSnap.exists) {
      return res.status(404).send('Stock batch not found');
    }
    if (batchSnap.data().accountId !== req.session.user.accountId) {
      return res.status(403).send('Access denied');
    }

    // load categories and units for the dropdowns
    const [categories, units] = await Promise.all([
      getCategories(req.session.user.accountId),
      getUnits(req.session.user.accountId)
    ]);

  // build a mutable batch object
const batchData = { id: batchSnap.id, ...batchSnap.data() };

// fall back to parent-product fields when missing
const productRef  = db.collection('products').doc(batchData.productId);
const productSnap = await productRef.get();
if (productSnap.exists) {
  const pData = productSnap.data();
  batchData.category = batchData.category || pData.category || '';
  if (batchData.inclusiveTax === undefined && pData.inclusiveTax !== undefined) {
    batchData.inclusiveTax = pData.inclusiveTax;         // ★ NEW: pre-fill GST %
  }
}


    res.render('editStockBatch', {
      batch:      batchData,
      categories,
      units
    });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});


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


// POST /edit-stock-batch/:batchId
app.post('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const { batchId }   = req.params;
    const {
      productName, purchasePrice, salePrice, quantity, inclusiveTax,
      newCategory, selectedCategory, newUnit, selectedUnit
    } = req.body;

    /* 0. permissions --------------------------------------------------- */
    const batchRef  = db.collection('stockBatches').doc(batchId);
    const batchSnap = await batchRef.get();
    if (!batchSnap.exists)                   return res.status(404).send('Stock batch not found');
    if (batchSnap.data().accountId !== req.session.user.accountId)
      return res.status(403).send('Access denied');

    const accountId   = req.session.user.accountId;
    const productId   = batchSnap.data().productId;
    const newName     = productName.trim();
    const newNameKey  = normalizeName(newName);

    /* 1. apply field edits to this *batch* ----------------------------- */
    const pp  = +parseFloat(purchasePrice);
    const sp  = +parseFloat(salePrice);
    const qty = +parseFloat(quantity);

    // 🚨 VALIDATION — all numbers must be positive
if (!Number.isFinite(pp)  || pp  <= 0 ||
    !Number.isFinite(sp)  || sp  <= 0 ||
    !Number.isFinite(qty) || qty <= 0) {
  return res.status(400).send('Prices and quantity must be greater than zero');
}
// NEW ➜ Inclusive-Tax % validation (0–100 or blank)
let taxPct = null;
if (inclusiveTax && inclusiveTax.toString().trim() !== '') {
  taxPct = +parseFloat(inclusiveTax);
  if (!Number.isFinite(taxPct) || taxPct < 0 || taxPct > 100) {
    return res.status(400).send('Inclusive-Tax % must be between 0 and 100');
  }
}


    /* ──────────────────────────
       Category normalisation & guard
    ────────────────────────── */
    const catInput = newCategory?.trim() || selectedCategory || '';

    // collapse spaces → trim → Title-case for storage
    let category = catInput.replace(/\s+/g, ' ').trim();
    if (category) {
      category = category[0].toUpperCase() + category.slice(1).toLowerCase();
    }

    /* ✨ DUPLICATE CATEGORY check (case- & space-insensitive) */
    if (newCategory?.trim()) {
      const existingCats = await getCategories(accountId);      // helper
      const dupCat = existingCats.some(
        c => normalizeName(c) === normalizeName(category)
      );
      if (dupCat) {
        return res
          .status(400)
          .send('Category already exists — choose a different name.');
      }
    }

    /* ──────────────────────────
       Unit normalisation & guard
    ────────────────────────── */
    const unitInput = newUnit?.trim() || selectedUnit || '';
    let unit = unitInput.replace(/\s+/g, ' ').trim().toLowerCase();

    /* ✨ DUPLICATE UNIT check (case- & space-insensitive) */
    if (newUnit?.trim()) {
      const existingUnits = await getUnits(accountId);          // helper
      const dupUnit = existingUnits.some(
        u => normalizeName(u) === normalizeName(unit)
      );
      if (dupUnit) {
        return res
          .status(400)
          .send('Unit already exists — choose a different name.');
      }
    }


/* ----- keep previously-sold units intact ----- */
/* ----- keep previously-sold units intact ----- */
const oldQty    = batchSnap.data().quantity          || 0;
const oldRemain = batchSnap.data().remainingQuantity ?? oldQty;
const deltaQty  = qty - oldQty;
const newRemain = Math.max(0, +(oldRemain + deltaQty).toFixed(3)); // NEW – never negative


await batchRef.update({
  productName      : newName,
  purchasePrice    : pp,
  salePrice        : sp,
  quantity         : qty,
  remainingQuantity: newRemain,
  profitMargin     : +(sp - pp).toFixed(2),
...(unit     && { unit }),   
  ...(category && { category }),
  updatedAt        : new Date()
});


    /* 2. 🆕 merge-duplicates if another product already has newNameKey -- */
    const dupSnap = await db.collection('products')
      .where('accountId','==',accountId)
      .where('nameKey','==',newNameKey)
      .limit(1).get();

    let targetProdId = productId;                 // assume we keep the same doc
    if (!dupSnap.empty && dupSnap.docs[0].id !== productId) {
      /* a duplicate exists → we’ll keep *that* doc and migrate batches */
      const keeperId = dupSnap.docs[0].id;
      const batchList = await db.collection('stockBatches')
                                .where('productId','==',productId)
                                .get();

      const moveOps = db.batch();
      batchList.docs.forEach(doc => {
        moveOps.update(doc.ref, { productId: keeperId });
      });
      await moveOps.commit();

      // delete the now-orphaned product doc
      await db.collection('products').doc(productId).delete();
      targetProdId = keeperId;
    }

    /* 3. refresh the surviving product doc ---------------------------- */
    const prodRef = db.collection('products').doc(targetProdId);
await prodRef.set({
  productName : newName,
  nameKey     : newNameKey,

  // persist the normalised values we already calculated above
  ...(unit      && { unit }),          // ← “kg”, “pcs”, etc. (already lower-cased)
  ...(category  && { category }),      // ← title-cased category

  ...(taxPct !== null && { inclusiveTax: taxPct }),  // keep GST % when supplied
  updatedAt   : new Date()
}, { merge: true });



          await recalcProductFromBatches(targetProdId);
    

      res.redirect('/view-products');

  } catch (e) {
    res.status(500).send(e.toString());
  }
});




/* ─────────── SALES & PROFIT REPORTING ─────────── */
// ────────────────────────────────────────────────────────────────
// GET  /sales  – Sales + Expense report with optional filters
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
      const monthExpenses  = monthExpSnap .docs.map(d => d.data());

    /* ─── 4. Compute MONTH-locked badge totals ─── */
const monthRevenueAmount = monthSales.reduce((sum, s) =>
  sum + (s.totalSale !== undefined
           ? parseFloat(s.totalSale)
           : s.retailPrice * s.saleQuantity), 0);

const monthGrossProfit   = monthSales.reduce((sum, s) => sum + s.profit, 0);
const monthExpenseTotal  = monthExpenses.reduce((sum, e) => sum + e.expenseCost, 0);
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




/* ─────────── DOWNLOAD SALES → EXCEL ─────────── */
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

// GET /profit
app.get('/profit', isAuthenticated, restrictRoute('/profit'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    let salesQuery   = db.collection('sales').where('accountId','==',accountId);
    let expenseQuery = db.collection('expenses').where('accountId','==',accountId);
    const { month, year } = req.query;

    /* ---------- date filter logic (unchanged) ---------- */
    if (month) {
      const [y,m] = month.split('-');
      const startDate = `${month}-01`;
      let nextM=parseInt(m,10)+1, nextY=parseInt(y,10);
      if(nextM>12){ nextM=1; nextY++; }
      const nextMonth = `${nextY}-${pad(nextM)}-01`;
      salesQuery   = salesQuery.where('saleDate','>=',startDate).where('saleDate','<',nextMonth);
      expenseQuery = expenseQuery.where('saleDate','>=',startDate).where('saleDate','<',nextMonth);
    } else if (year) {
      const startDate = `${year}-01-01`;
      const endDate   = `${parseInt(year)+1}-01-01`;
      salesQuery   = salesQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
      expenseQuery = expenseQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
    } else {
      const currentYear = new Date().getFullYear();
      const startDate = `${currentYear}-01-01`;
      const endDate   = `${currentYear+1}-01-01`;
      salesQuery   = salesQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
      expenseQuery = expenseQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
    }
    /* ---------- fetch ---------- */
    const [salesSnap, expSnap] = await Promise.all([salesQuery.get(), expenseQuery.get()]);
    const sales    = salesSnap.docs.map(d=>d.data());
    const expenses = expSnap.docs.map(d=>d.data());

    /* ---------- totals ---------- */
    const totalProfit      = sales.reduce((sum,s)=> sum + s.profit,0);
    const totalExpenses    = expenses.reduce((sum,e)=> sum + e.expenseCost,0);
    const totalGstPayable  = sales.reduce((sum,s)=> sum + (s.gstPayable||0),0);

    const netProfit        = totalProfit - totalExpenses - totalGstPayable;

    /* ---------- month buckets ---------- */
    const profitByMonth = {};
    sales.forEach(s=>{
      const m = s.saleDate.substring(0,7);
      if (!profitByMonth[m]) profitByMonth[m]={ profit:0, expenses:0, gst:0, netProfit:0 };
      profitByMonth[m].profit += s.profit;
      profitByMonth[m].gst    += (s.gstPayable||0);
    });
    expenses.forEach(e=>{
      const m = e.saleDate.substring(0,7);
      if (!profitByMonth[m]) profitByMonth[m]={ profit:0, expenses:0, gst:0, netProfit:0 };
      profitByMonth[m].expenses += e.expenseCost;
    });
    Object.keys(profitByMonth).forEach(m=>{
      const row = profitByMonth[m];
      row.netProfit = row.profit - row.expenses - row.gst;
    });

    /* ---------- render ---------- */
    res.render('profit',{
      sales, expenses,
      totalProfit,
      totalExpenses,
      totalGstPayable,
      netProfit,
      profitByMonth,
      monthFilter: month || '',
      yearFilter : req.query.year || ''
    });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});




/* ─────────── SUBSCRIPTION & PAYMENT ROUTES ─────────── */
// GET /pricing
// app.get('/pricing', (req, res) => {
//   const now = new Date();
//   if (req.session.user?.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > now)
//     return res.redirect('/');
//   res.render('pricing', { user: req.session.user || null });
// });

app.get('/pricing', (req, res) => {
  // now all users—subscribed or not—can view pricing
  res.render('pricing', { user: req.session.user || null });
});


/* ───── GET /subscribe/monthly  (secure) ───── */
app.get('/subscribe/monthly', isAuthenticated, async (req, res) => {
  const amount   = 499 * 100;            // ₹499 → paise
  const currency = 'INR';
  const receipt  = `receipt_monthly_${Date.now()}`;

  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });

    /* 🔐 Persist order – plan lives server-side only */
    await db.collection('paymentOrders').doc(order.id).set({
      userId : req.session.user.id,
      plan   : 'Monthly',
      days   : 30,
      amount,
      currency,
      paid   : false,
      createdAt : new Date()
    });

    /* No plan variable sent to client anymore */
    res.render('payment', { order, user: req.session.user });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

/* ───── GET /subscribe/half-yearly  (secure) ───── */
app.get('/subscribe/half-yearly', isAuthenticated, async (req, res) => {
  const amount   = 2699 * 100;
  const currency = 'INR';
  const receipt  = `receipt_halfyearly_${Date.now()}`;

  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });

    await db.collection('paymentOrders').doc(order.id).set({
      userId : req.session.user.id,
      plan   : 'Half-Yearly',
      days   : 182,
      amount,
      currency,
      paid   : false,
      createdAt : new Date()
    });

    res.render('payment', { order, user: req.session.user });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});


/* ───── GET /subscribe/yearly  (secure) ───── */
app.get('/subscribe/yearly', isAuthenticated, async (req, res) => {
  const amount   = 4799 * 100;
  const currency = 'INR';
  const receipt  = `receipt_yearly_${Date.now()}`;

  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });

    await db.collection('paymentOrders').doc(order.id).set({
      userId : req.session.user.id,
      plan   : 'Yearly',
      days   : 365,
      amount,
      currency,
      paid   : false,
      createdAt : new Date()
    });

    res.render('payment', { order, user: req.session.user });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});


/* ───── POST /payment-success  (hardened) ───── */
app.post('/payment-success', isAuthenticated, async (req, res) => {
  try {
    const {
      razorpay_payment_id,
      razorpay_order_id,
      razorpay_signature
    } = req.body;

    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature)
      return res.status(400).send('Missing payment details');

    /* 1️⃣  Verify HMAC signature */
    const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    if (shasum.digest('hex') !== razorpay_signature)
      return res.status(400).send('Payment signature invalid – request denied.');

    /* 2️⃣  Fetch the order we saved during /subscribe/* */
    const orderRef = db.collection('paymentOrders').doc(razorpay_order_id);
    const orderSnap = await orderRef.get();
    if (!orderSnap.exists)
      return res.status(400).send('Order not recognised');

    const order = orderSnap.data();
    if (order.paid)
      return res.status(400).send('Order already processed');
    if (order.userId !== req.session.user.id)
      return res.status(403).send('Order does not belong to current user');

    /* 3️⃣  OPTIONAL – you can call Razorpay Orders API here to
           verify that order.status === 'paid' & amount === order.amount */

    /* 4️⃣  Extend subscription */
    const days = order.days;                     // 30 / 182 / 365
    const now  = new Date();

    const userRef  = db.collection('users').doc(req.session.user.id);
    const userSnap = await userRef.get();
    const curExp   = userSnap.data().subscriptionExpiry
                      ? new Date(userSnap.data().subscriptionExpiry.toDate
                                   ? userSnap.data().subscriptionExpiry.toDate()
                                   : userSnap.data().subscriptionExpiry)
                      : now;
    const newExp = curExp > now ? curExp : now;
    newExp.setDate(newExp.getDate() + days);

    await userRef.update({ subscriptionExpiry: newExp });
    req.session.user.subscriptionExpiry = newExp;

    /* 5️⃣  Mark order consumed */
    await orderRef.update({
      paid       : true,
      paymentId  : razorpay_payment_id,
      paidAt     : new Date()
    });

    res.redirect('/');
  } catch (e) {
    console.error('/payment-success error:', e);
    res.status(500).send('Payment processing failed, please contact support.');
  }
});



/* ─────────── PROFILE & BILLING (Master Only) ─────────── */
// GET /profile
/* ─────────── GET /profile – editable version ─────────── */
app.get('/profile', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.session.user.id).get();
    if (!doc.exists) return res.status(404).send('User not found');

    const userData = doc.data();
    if (userData.subscriptionExpiry) {
      userData.subscriptionExpiry = (typeof userData.subscriptionExpiry.toDate === 'function')
        ? userData.subscriptionExpiry.toDate()
        : new Date(userData.subscriptionExpiry);
    }

    res.render('profile', {
      user        : userData,
      csrfToken   : req.csrfToken(),
      success     : req.query.success || false,
      errorMessage: null
    });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

/* ─────────── POST /profile – save edits ─────────── */
app.post('/profile', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const {
  name         = '',
  businessName = '',
  phone        = '',
  address      = '',
  location     = '',
  gstNumber    = ''
} = req.body;


    /* simple length validations (mirrors registration rules) */
    if (name.trim().length < 2)
      return res.redirect('/profile?error=Name%20must%20be%20at%20least%202%20characters');

    if (businessName.length > 80 || address.length > 200)
      return res.redirect('/profile?error=Field%20length%20limit%20exceeded');
    if (gstNumber && !/^[0-9A-Z]{15}$/.test(gstNumber.trim()))
  return res.redirect('/profile?error=Invalid%20GST%20number%20format');


    /* update Firestore */
    const update = {
  name        : name.trim(),
  businessName: businessName.trim(),
  phone       : phone.trim(),
  address     : address.trim(),
  location    : location.trim(),
  ...(gstNumber.trim() && { gstNumber: gstNumber.trim().toUpperCase() }),
  updatedAt   : new Date()
};

    await db.collection('users').doc(req.session.user.id).update(update);

    /* keep session in sync so header shows new name immediately */
    Object.assign(req.session.user, update);

    res.redirect('/profile?success=1');
  } catch (e) {
    console.error('/profile POST error:', e);
    res.status(500).render('profile', {
      user        : req.body,
      csrfToken   : req.csrfToken(),
      success     : false,
      errorMessage: 'Something went wrong. Please try again.'
    });
  }
});


// GET /billing
app.get('/billing', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.session.user.id).get();
    if (!doc.exists) return res.status(404).send('User not found');
    const userData = doc.data();
    if (userData.subscriptionExpiry) {
      userData.subscriptionExpiry = (typeof userData.subscriptionExpiry.toDate === 'function')
        ? userData.subscriptionExpiry.toDate()
        : new Date(userData.subscriptionExpiry);
    }
    res.render('billing', { user: userData });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

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
  


/* ─────────── EMPLOYEE REPORTING ─────────── */
// GET /employees
app.get('/employees', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const [reportsSnap, employeesSnap] = await Promise.all([
      db.collection('employeeReports')
        .where('accountId','==',accountId)
        .orderBy('reportDate','desc')
        .get(),
      db.collection('employees')
        .where('accountId','==',accountId)
        .orderBy('name','asc')
        .get()
    ]);
    const reports   = reportsSnap.docs.map(d=>({ id:d.id, ...d.data() }));
    const employees = employeesSnap.docs.map(d=>({ id:d.id, ...d.data() }));
    res.render('employees', { reports, employees });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// POST /employee/checkin
app.post('/employee/checkin', isAuthenticated, async (req, res) => {
  try {
    const { employeeId, reportTime, reportDate } = req.body;
    const accountId = req.session.user.accountId;
    const existing = await db.collection('employeeReports')
      .where('accountId','==',accountId)
      .where('employeeId','==',employeeId)
      .where('reportDate','==',reportDate)
      .get();
    if (!existing.empty) return res.status(400).send('Check-in already recorded');

    const empDoc = await db.collection('employees').doc(employeeId).get();
    if (!empDoc.exists) return res.status(400).send('Employee not found');

    await db.collection('employeeReports').add({
      employeeId,
      employeeName: empDoc.data().name,
      reportTime,
      leaveTime: '',
      reportDate,
      accountId,
      createdAt: new Date()
    });
    res.redirect('/employees');
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// POST /employee/checkout
app.post('/employee/checkout', isAuthenticated, async (req, res) => {
  try {
    const { employeeId, leaveTime, reportDate } = req.body;
    const accountId = req.session.user.accountId;
    const snap = await db.collection('employeeReports')
      .where('accountId','==',accountId)
      .where('employeeId','==',employeeId)
      .where('reportDate','==',reportDate)
      .get();
    if (snap.empty) return res.status(400).send('No check-in record found');
    const doc = snap.docs[0];
    await doc.ref.update({ leaveTime, updatedAt: new Date() });
    res.redirect('/employees');
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// GET /employeeReport
app.get('/employeeReport', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    let reportsQuery = db.collection('employeeReports').where('accountId','==',accountId).orderBy('reportDate','desc');
    const { month } = req.query;
    if (month && month.trim()) {
      const [y,m] = month.split('-');
      const startDate = `${month}-01`;
      let nextM=parseInt(m,10)+1, nextY=parseInt(y,10);
      if(nextM>12){ nextM=1; nextY++; }
      const nextMonth=`${nextY}-${pad(nextM)}-01`;
      reportsQuery = reportsQuery.where('reportDate','>=',startDate).where('reportDate','<',nextMonth);
    }
    const snap = await reportsQuery.get();
    const reports = snap.docs.map(d=>({ id:d.id, ...d.data() }));
    res.render('employeedReport', { reports, month: month||'' });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// GET /create-employee
app.get('/create-employee', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const snap = await db.collection('employees').where('accountId','==',accountId).orderBy('name','asc').get();
    const employees = snap.docs.map(d=>({ id:d.id, ...d.data() }));
    res.render('createEmployee', { employees });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// POST /create-employee
app.post('/create-employee', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { name } = req.body;
    await db.collection('employees').add({ name, accountId, createdAt: new Date() });
    res.redirect('/create-employee');
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// POST /delete-employee
app.post('/delete-employee', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { employeeId } = req.body;
    const empRef = db.collection('employees').doc(employeeId);
    const empDoc= await empRef.get();
    if (!empDoc.exists || empDoc.data().accountId !== accountId) {
      return res.status(403).send('Access denied or Employee not found');
    }
    await empRef.delete();
    res.redirect('/create-employee');
  } catch (e) {
    res.status(500).send(e.toString());
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



/* ─────────── AJAX: EDIT EXPENSE  (expanded 2025-06-21) ─────────── */
app.post(
  '/api/edit-expense',
  isAuthenticated,
  restrictAction('/expense', 'edit'),
  async (req, res) => {
    try {
      const { expenseId, field, value, expenseDetail1, expenseDetail2 } = req.body;


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

      /* ---------- fresh daily summary ---------- */
      const { summary } = await computeDailySummary(
        req.session.user.accountId, exp.saleDate
      );

      return res.json({
        success: true,
        updatedRow: update,
        summary
      });

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

app.post('/api/recurring-monthly/:recId', isAuthenticated, async (req, res) => {
  try {
    const { recId } = req.params;
    const {
      expenseCost,
      expenseStatus,
      expenseReason,
      propagate = 'true'
    } = req.body;

    const ref  = db.collection('recurringMonthly').doc(recId);
    const snap = await ref.get();

    /* 1️⃣  Access control */
    if (!snap.exists || snap.data().accountId !== req.session.user.accountId)
      return res.json({ success: false, error: 'Access denied' });

    /* 2️⃣  Build patch */
const patch        = { updatedAt: new Date() };

/* Track changed fields so we can optionally push them back to the
   master template when ?propagate=true (default).                   */
let newCost    = undefined;   // number → defaultCost
let newReason  = undefined;   // string → expenseReason


    if (expenseCost !== undefined) {
      newCost = +parseFloat(expenseCost);
      if (!Number.isFinite(newCost) || newCost < 0)
        return res.json({ success: false, error: 'Invalid amount' });
      patch.expenseCost = newCost;
    }

    if (expenseStatus !== undefined)  patch.expenseStatus = expenseStatus;

    if (expenseReason !== undefined) {
  newReason = (expenseReason || '').toString().substring(0,100).trim();
  if (!newReason)                 // empty after trimming
    return res.json({ success:false, error:'Reason required' });

  patch.expenseReason = newReason;
}

    /* 3️⃣  Propagate to the master template **only** when:
           • the user ticked “propagate”, AND
           • the default cost actually changed                              */
    if ((propagate === true || propagate === 'true') &&
    (typeof newCost === 'number' || typeof newReason === 'string')) {

  const tplId = snap.data().templateId;
  if (tplId) {
    const tplUpdate = { updatedAt: new Date() };
    if (typeof newCost   === 'number') tplUpdate.defaultCost   = newCost;
    if (typeof newReason === 'string') tplUpdate.expenseReason = newReason;

    await db.collection('recurringExpenses')
            .doc(tplId)
            .update(tplUpdate);
  }
}
const monthTotal = await computeMonthTotal(
  req.session.user.accountId, snap.data().month
);

return res.json({ success: true, monthTotal });
  } catch (err) {
    console.error('/api/recurring-monthly error:', err);
    return res.json({ success: false, error: err.toString() });
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
    const tplId = snap.data().templateId || null;
    const month = snap.data().month;
    if (tplId) {
      await db.collection('recurringExpenses')
              .doc(tplId)
              .set(
                { removalMonth: month, updatedAt: new Date() },
                { merge: true }
              );
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

/* ─────────── AJAX:  DELETE SALE  ─────────── */
// ─────────── AJAX: DELETE SALE ───────────
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



// GET /tnc – Terms & Conditions
app.get('/terms-and-conditions', (req, res) => {
  res.render('tnc', { host: req.get('host') });
});

// In app.js, after your documentation route for example:

// GET /privacy
app.get('/privacy', (req, res) => {
  res.render('privacy');
});


/* ─────────── Health check ─────────── */
app.get('/healthz', (req, res) => res.status(200).send('OK'));

/* ─────────── PERFORMANCE INSIGHTS ─────────── */
// GET /performance
app.get('/performance',
  isAuthenticated,
  
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* ───── 1. Determine date window ───── */
     
      const today  = new Date();
      const curYM  = `${today.getFullYear()}-${pad(today.getMonth()+1)}`;
      const {
        month   = '',
        from    = '',
        to      = '',
        year    = '',
        top: topParam = ''
      } = req.query;

      let startDate, endDate, periodLabel;

      if (month) {                                          // single month
        startDate   = `${month}-01`;
        const [y,m] = month.split('-');
        let nextM = parseInt(m,10)+1, nextY=parseInt(y,10);
        if (nextM>12){ nextM=1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(`${month}-01`).toLocaleString('default',{ month:'long', year:'numeric' });

      } else if (from && to) {                              // month‑range
        startDate   = `${from}-01`;
        const [ty,tm] = to.split('-');
        let nextM = parseInt(tm,10)+1, nextY=parseInt(ty,10);
        if (nextM>12){ nextM=1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = `${from} → ${to}`;

      } else if (year) {                                    // whole year
        startDate   = `${year}-01-01`;
        endDate     = `${parseInt(year,10)+1}-01-01`;
        periodLabel = `Year ${year}`;

      } else {                                             // default = current month
        startDate   = `${curYM}-01`;
        let nextM = today.getMonth()+2, nextY=today.getFullYear();
        if (nextM>12){ nextM=1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(startDate).toLocaleString('default',{ month:'long', year:'numeric' });
      }

      /* Top‑N (default 10) */
      const topN = Math.max(parseInt(topParam,10)||10, 1);

      /* ───── 2. Fetch sales in window ───── */
      let q = db.collection('sales')
                .where('accountId','==',accountId)
                .where('saleDate','>=',startDate)
                .where('saleDate','<', endDate);
      const snap  = await q.get();
      const sales = snap.docs.map(d => d.data());

      /* ───── 3. Aggregate by product ───── */
      const map = {};
      sales.forEach(s=>{
        const pid = s.productId;
        if (!map[pid]) map[pid] = {
          productName : s.productName,
          unitsSold   : 0,
          revenue     : 0,
          profit      : 0
        };
        const row = map[pid];
        const qty = +s.saleQuantity;
        row.unitsSold += qty;
        row.revenue   += (s.totalSale !== undefined
                          ? +parseFloat(s.totalSale)
                          : s.retailPrice * qty);
        row.profit    += +s.profit;
      });

      const arr = Object.values(map);

      const topSelling = [...arr]
        .sort((a,b)=>b.unitsSold - a.unitsSold)
        .slice(0,topN);

      const topRevenue = [...arr]
        .sort((a,b)=>b.revenue - a.revenue)
        .slice(0,topN);

      const topProfit  = [...arr]
        .sort((a,b)=>b.profit - a.profit)
        .slice(0,topN);

      /* ───── 4. Render ───── */
      res.render('performance', {
        topSelling,
        topRevenue,
        topProfit,
        periodLabel,
        month, from, to, year,
        topN
      });

    } catch (err) {
      console.error('/performance error:', err);
      res.status(500).send(err.toString());
    }
  }
);


/* ─────────── STATS DASHBOARD ─────────── */
// GET /stats
/* ─────────── STATS DASHBOARD ─────────── */
// GET /stats
app.get(
  '/stats',
  isAuthenticated,
  restrictRoute('/stats'),          // keep if you use route-locking
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* 1️⃣  Resolve date window → default = current month */
    
      const today = new Date();
      const currentYear = today.getFullYear();

      const {
        month = '',
        from  = '',
        to    = '',
        year  = '',
        top: topParam = ''
      } = req.query;

      let startDate, endDate, periodLabel;
      let uiMonth = month, uiFrom = from, uiTo = to, uiYear = year;

      if (month) {                                          // single month
        startDate = `${month}-01`;
        const [y, m] = month.split('-');
        let nextM = parseInt(m, 10) + 1, nextY = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(`${month}-01`)
                        .toLocaleString('default', { month: 'long', year: 'numeric' });

      } else if (from && to) {                              // month-range
        startDate = `${from}-01`;
        const [ty, tm] = to.split('-');
        let nextM = parseInt(tm, 10) + 1, nextY = parseInt(ty, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = `${from} → ${to}`;

      } else if (year) {                                    // explicit year
        startDate   = `${year}-01-01`;
        endDate     = `${parseInt(year, 10) + 1}-01-01`;
        periodLabel = `Year ${year}`;

      } else {                                             // DEFAULT = current month
        const curYM = `${currentYear}-${pad(today.getMonth() + 1)}`;

        /* start of this month (YYYY-MM-01) */
        startDate = `${curYM}-01`;

        /* first day of NEXT month */
        let nextM = today.getMonth() + 2,
            nextY = currentYear;
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate = `${nextY}-${pad(nextM)}-01`;

        /* “June 2025”-style label */
        periodLabel = new Date(startDate)
                        .toLocaleString('default', { month: 'long', year: 'numeric' });

        /* pre-select the current month in the filter panel */
        uiMonth = curYM;
      }

      /* how many rows to show in the Top-N lists (default 10) */
      const topN = Math.max(parseInt(topParam, 10) || 10, 1);

      /* 2️⃣  Fetch sales + expenses in the window (+ GST map) */
      const [salesSnap, expSnap] = await Promise.all([
        db.collection('sales')
          .where('accountId', '==', accountId)
          .where('saleDate',  '>=', startDate)
          .where('saleDate',  '<',  endDate)
          .get(),
        db.collection('expenses')
          .where('accountId', '==', accountId)
          .where('saleDate',  '>=', startDate)
          .where('saleDate',  '<',  endDate)
          .get()
      ]);

      const sales    = salesSnap.docs.map(d => d.data());
      const expenses = expSnap .docs.map(d => d.data());

      /* 2-B ► build GST map & total */
      const monthlyGst = {};        // { YYYY-MM : ₹ }
      let   totalGstPayable = 0;
      sales.forEach(s => {
        const ym  = s.saleDate.substring(0, 7);
        const gst = +s.gstPayable || 0;
        monthlyGst[ym] = (monthlyGst[ym] || 0) + gst;
        totalGstPayable += gst;
      });

      /* 3️⃣  Per-product aggregation + global totals */
      const prodMap = {};
      let totalProfit        = 0,
          totalSales         = 0,
          totalCashSales     = 0,
          totalOnlineSales   = 0,
          totalNotPaidSales  = 0;   // (kept for future badge work)

      sales.forEach(s => {
        /* ⓐ global totals */
        totalProfit += s.profit;

        const rowAmt = (s.totalSale !== undefined)
          ? +parseFloat(s.totalSale)
          : s.retailPrice * s.saleQuantity;
        totalSales += rowAmt;

        switch (s.status) {
          case 'Paid Cash':                   totalCashSales   += rowAmt; break;
          case 'Paid Online':                 totalOnlineSales += rowAmt; break;
          case 'Not Paid':                    totalNotPaidSales+= rowAmt; break;
          case 'Half Cash + Half Online':
            if (s.paymentDetail1) totalCashSales   += s.paymentDetail1;
            if (s.paymentDetail2) totalOnlineSales += s.paymentDetail2;
            break;
          case 'Half Cash + Not Paid':
            if (s.paymentDetail1) totalCashSales   += s.paymentDetail1;
            if (s.paymentDetail2) totalNotPaidSales+= s.paymentDetail2;
            break;
          case 'Half Online + Not Paid':
            if (s.paymentDetail1) totalOnlineSales += s.paymentDetail1;
            if (s.paymentDetail2) totalNotPaidSales+= s.paymentDetail2;
            break;
        }

        /* ⓑ per-product bucket for Top-N tables */
        const pid = s.productId;
        if (!prodMap[pid]) {
          prodMap[pid] = {
            productName : s.productName,
            unitsSold   : 0,
            revenue     : 0,
            profit      : 0
          };
        }
        const p = prodMap[pid];
        p.unitsSold += +s.saleQuantity;
        p.revenue   += rowAmt;
        p.profit    += s.profit;
      });

      const prodArr = Object.values(prodMap);

      const topSelling = [...prodArr]
        .sort((a, b) => b.unitsSold - a.unitsSold)
        .slice(0, topN);

      const topRevenue = [...prodArr]
        .sort((a, b) => b.revenue - a.revenue)
        .slice(0, topN);

      const topProfit = [...prodArr]
        .sort((a, b) => b.profit - a.profit)
        .slice(0, topN);

      /* 4️⃣  Period-level totals */
      const totalRevenue = sales.reduce((sum, s) =>
        sum + (s.totalSale !== undefined
                 ? +parseFloat(s.totalSale)
                 : s.retailPrice * s.saleQuantity), 0);

      const monthlyProfit  = {};
      const monthlyExpense = {};

      sales.forEach(s => {
        const ym = s.saleDate.substring(0, 7);
        monthlyProfit[ym] = (monthlyProfit[ym] || 0) + +s.profit;
      });

      expenses.forEach(e => {
        const ym = e.saleDate.substring(0, 7);
        monthlyExpense[ym] = (monthlyExpense[ym] || 0) + +e.expenseCost;
      });

      /* 5️⃣  Render */
      res.render('stats', {
        topSelling,
        topRevenue,
        topProfit,
        monthlyProfit,
        monthlyExpense,
        totalRevenue,           // overall turnover in the chosen window
        periodLabel,
        month : uiMonth,
        from  : uiFrom,
        to    : uiTo,
        totalGstPayable,        // GST owed for the period
        monthlyGst,             // bar-chart ready { ym:₹ }
        year  : uiYear,
        topN
      });

    } catch (err) {
      console.error('/stats error:', err);
      res.status(500).send(err.toString());
    }
  }
);



/* ─────────── PASSWORD RESET ROUTES (MASTER-ONLY) ─────────── */

// GET /forgot-password
app.get('/forgot-password', (req, res) => {
  if (req.session?.user) return res.redirect('/');
  res.render('forgotPassword', { sent: false, error: null });
});

// POST /forgot-password
app.post('/forgot-password', async (req, res) => {
  try {
    const emailRaw = req.body.email || '';
    const email    = emailRaw.trim().toLowerCase();
    if (!email) {
      return res.status(400).render('forgotPassword',
        { sent: false, error: 'Please enter your registered email.' });
    }

    // master-account lookup
    const snap = await db.collection('users')
                         .where('email',    '==', email)
                         .where('isMaster', '==', true)
                         .limit(1).get();

    /* Always show success even if no match → no user enumeration */
    if (snap.empty) return res.render('forgotPassword', { sent: true, error: null });

    const userDoc = snap.docs[0];

// generate raw token + SHA-256 hash (store only the hash)
const rawToken = crypto.randomBytes(32).toString('hex');
const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
const expires   = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

await db.collection('passwordResets').doc(tokenHash).set({
  userId    : userDoc.id,
  email,
  expiresAt : expires,
  used      : false,
  createdAt : new Date()
});

const link = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password/${rawToken}`;


    // fire the email
    await transporter.sendMail({
      to      : email,
      from    : process.env.EMAIL_USER,
      subject : 'Reset your DashInsight master password',
      html    : `
        <p>Hi ${userDoc.data().name},</p>
        <p>You (or someone using your email) requested a password reset.</p>
        <p><a href="${link}">Click here to choose a new password</a><br>
           (this link is valid for 1 hour and can be used once).</p>
        <p>If you didn’t request this, just ignore the email.</p>`
    });

    res.render('forgotPassword', { sent: true, error: null });
  } catch (err) {
    console.error('/forgot-password error:', err);
    res.status(500).render('forgotPassword',
      { sent: false, error: 'Something went wrong. Please try again.' });
  }
});

// GET /reset-password/:token
app.get('/reset-password/:token', async (req, res) => {
  try {
   const rawToken   = req.params.token;
const tokenHash  = crypto.createHash('sha256').update(rawToken).digest('hex');
const doc        = await db.collection('passwordResets').doc(tokenHash).get();

    if (!doc.exists) {
      return res.status(400).render('resetPassword',
        { token: '', invalid: true, error: 'Invalid or expired link.' });
    }
    const data = doc.data();
    if (data.used || data.expiresAt.toDate() < new Date()) {
      return res.status(400).render('resetPassword',
        { token: '', invalid: true, error: 'Link has expired. Request a new one.' });
    }
    res.render('resetPassword', { token, invalid: false, error: null });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});

// POST /reset-password
app.post('/reset-password', async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    if (!password || password !== confirmPassword) {
      return res.status(400).render('resetPassword',
        { token, invalid: false, error: 'Passwords do not match.' });
    }

    const tokenRef  = db.collection('passwordResets').doc(token);
    const tokenSnap = await tokenRef.get();
    if (!tokenSnap.exists) {
      return res.status(400).render('resetPassword',
        { token: '', invalid: true, error: 'Invalid or expired link.' });
    }

    const tData = tokenSnap.data();
    if (tData.used || tData.expiresAt.toDate() < new Date()) {
      return res.status(400).render('resetPassword',
        { token: '', invalid: true, error: 'Link has expired. Request a new one.' });
    }

    // update master password
    const hashed = await bcrypt.hash(password, 10);
    await db.collection('users').doc(tData.userId).update({ password: hashed });

    // mark token consumed
    await tokenRef.update({ used: true, usedAt: new Date() });

    res.redirect('/login');
  } catch (err) {
    console.error('/reset-password error:', err);
    res.status(500).render('resetPassword',
      { token, invalid: false, error: 'Something went wrong. Please try again.' });
  }
});

/* ─────────── SINGLE INVOICE (HTML-for-print) ─────────── */

// GET /invoice/:saleId
app.get(
  '/invoice/:saleId',
  isAuthenticated,                    // same guard you use elsewhere
  async (req, res) => {
    try {
      const { saleId } = req.params;

      // 1️⃣  Fetch the sale row
      const saleSnap = await db.collection('sales').doc(saleId).get();
      if (!saleSnap.exists)
        return res.status(404).send('Sale not found');

      const sale = { id: saleSnap.id, ...saleSnap.data() };

      if (sale.accountId !== req.session.user.accountId)
        return res.status(403).send('Access denied');

      // 2️⃣  Pull business header
      const userDoc = await db.collection('users')
                              .doc(req.session.user.accountId).get();
      const shop    = userDoc.exists ? userDoc.data() : {};

      // 3️⃣  GST % helper
      const gstPct = (sale.outputTax && sale.totalSale)
        ? ((sale.outputTax / sale.totalSale) * 100).toFixed(2)
        : '';

      // 4️⃣  Render
      res.render('invoice', {
        sale,
        gstPct,
        shop,
        v: res.locals.v,
        csrfToken: req.csrfToken()
      });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  }
);



// GET /invoice-number/:invoiceNo  – print ALL sales that share this number
app.get(
  '/invoice-number/:invoiceNo',
  isAuthenticated,
  async (req, res) => {
    try {
      const { invoiceNo } = req.params;
      const accountId     = req.session.user.accountId;

      // 1️⃣ Fetch every sale row that belongs to this invoice
      const snap = await db.collection('sales')
                           .where('accountId','==',accountId)
                           .where('invoiceNo','==',invoiceNo)
                           .orderBy('createdAt','asc')
                           .get();
      if (snap.empty) return res.status(404).send('Invoice not found');

      const items = snap.docs.map(d => ({ id:d.id, ...d.data() }));

      // 2️⃣ Business header
      const shopDoc = await db.collection('users').doc(accountId).get();
      const shop    = shopDoc.exists ? shopDoc.data() : {};

      // 3️⃣ Totals
      const totalSale = items.reduce((t,i)=>t + (+i.totalSale), 0);
      const outputTax = items.reduce((t,i)=>t + (+i.outputTax||0), 0);

      res.render('invoiceMulti', {
        items,
        invoiceNo,
        saleDate : items[0].saleDate,
        createdAt: items[0].createdAt,
        totalSale,
        outputTax,
        shop,
        v: res.locals.v,
        csrfToken: req.csrfToken()
      });

    } catch (e) {
      res.status(500).send(e.toString());
    }
  }
);


/* ─────────── GST SUMMARY HELPER ─────────── *
   Returns an array like
   [
     { month:'2025-06', taxable:₹, output:₹, input:₹, net:₹ },
     …
   ]
   The month window and ordering exactly match your other
   “profit” & “stats” pages, so one line of UI is enough.
* --------------------------------------------------- */
async function getGstSummary(accountId, startDate, endDate) {
  const salesSnap = await db.collection('sales')
    .where('accountId','==',accountId)
    .where('saleDate','>=',startDate)
    .where('saleDate','<', endDate)
    .get();

  const bucket = {};                // { YYYY-MM : { taxable, output, input } }

  salesSnap.docs.forEach(doc => {
    const s = doc.data();
    const ym = s.saleDate.substring(0,7);
    if (!bucket[ym]) bucket[ym] = { taxable:0, output:0, input:0 };
    bucket[ym].taxable += +(s.totalSale || s.retailPrice * s.saleQuantity);
    bucket[ym].output  += +(s.outputTax  || 0);
    bucket[ym].input   += +(s.inputTax   || 0);
  });

  return Object.entries(bucket)          // [[ym,obj], …]
    .sort(([a],[b]) => a.localeCompare(b))
    .map(([month, v]) => ({
      month,
      taxable : +v.taxable.toFixed(2),
      output  : +v.output .toFixed(2),
      input   : +v.input  .toFixed(2),
      net     : +(v.output - v.input).toFixed(2)
    }));
}

/* ─────────── GST SUMMARY  /gst  ─────────── */
app.get(
  '/gst',
  isAuthenticated,
  restrictRoute('/gst'),          // keep this if you use route-locking
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* Re-use the exact window logic from /stats so UX is identical */
      const pad = n => String(n).padStart(2,'0');
      const today = new Date();
      const curYM = `${today.getFullYear()}-${pad(today.getMonth()+1)}`;

      const { month='', from='', to='', year='' } = req.query;
      let startDate, endDate, periodLabel;

      if (month) {                                    // single month
        startDate = `${month}-01`;
        const [y,m] = month.split('-');
        let nextM=parseInt(m,10)+1, nextY=parseInt(y,10);
        if (nextM>12){ nextM=1; nextY++; }
        endDate   = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(startDate)
                        .toLocaleString('default',{ month:'long', year:'numeric' });

      } else if (from && to) {                        // month-range
        startDate = `${from}-01`;
        const [ty,tm] = to.split('-');
        let nextM=parseInt(tm,10)+1, nextY=parseInt(ty,10);
        if (nextM>12){ nextM=1; nextY++; }
        endDate   = `${nextY}-${pad(nextM)}-01`;
        periodLabel = `${from} → ${to}`;

      } else if (year) {                              // whole year
        startDate = `${year}-01-01`;
        endDate   = `${parseInt(year,10)+1}-01-01`;
        periodLabel = `Year ${year}`;

      } else {                                       // default = current month
        startDate = `${curYM}-01`;
        let nextM=today.getMonth()+2, nextY=today.getFullYear();
        if (nextM>12){ nextM=1; nextY++; }
        endDate = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(startDate)
                        .toLocaleString('default',{ month:'long', year:'numeric' });
      }

      const rows = await getGstSummary(accountId, startDate, endDate);
      const totals = rows.reduce((t,r)=>({
        taxable: t.taxable + r.taxable,
        output : t.output  + r.output,
        input  : t.input   + r.input,
        net    : t.net     + r.net
      }), {taxable:0,output:0,input:0,net:0});

     res.render('gst', {
        rows,
        totals,
        periodLabel,
        month,
        from,
        to,
        year,
        user : req.session.user            // ← makes <%= user.businessName %> work
      });
    } catch (err) {
      console.error('/gst error:', err);
      res.status(500).send(err.toString());
    }
  }
);

//* ─────────── START THE SERVER (memory-aware) ─────────── */
const PORT = process.env.PORT || 3000;

/* ── Compute a safe worker count ──────────────────────────────────────────
   • Render dynos = 512 MiB RAM by default (exposed in RENDER_MEMORY_LIMIT_MIB)
   • 1 worker of this app ≈ 70 MiB RSS (measured).
   • Keep a 25 % head-room → usable = 0.75 × memLimit.
   • workers = min(CPU cores, floor(usable / 70 MiB)).
   • You can still hard-set WEB_CONCURRENCY in the Render dashboard.
   ---------------------------------------------------------------------- */
const MB                = 1024 * 1024;
const memLimitMiB       = parseInt(process.env.RENDER_MEMORY_LIMIT_MIB || 512, 10);
const approxPerWorkerMiB= 70;                       // tweak if profiling changes
const maxByRam          = Math.floor((memLimitMiB * 0.75) / approxPerWorkerMiB) || 1;
const cpuCount          = os.cpus().length;

const CPUS = Math.max(
  1,
  parseInt(process.env.WEB_CONCURRENCY || Math.min(cpuCount, maxByRam), 10)
);

/* ────────── MODE A – cluster (≥2 workers) ────────── */
if (CPUS > 1 && cluster.isPrimary) {
  logger.info(`🛡  Master ${process.pid} starting ${CPUS} worker(s)…`);

  for (let i = 0; i < CPUS; i++) cluster.fork();

  /* simple respawn – keeps the dyno alive */
  cluster.on('exit', (worker, code, signal) => {
    logger.warn(`⚠️  Worker ${worker.process.pid} exited (${signal || code}); restarting…`);
   setTimeout(() => cluster.fork(), 2000); cluster.fork();
  });

/* ────────── MODE B – single-process fallback ────────── */
} else {
  if (cluster.isPrimary) {
    logger.info('ℹ️  Running in single-process mode (memory-safe)');
  }

  const server = http.createServer(app).listen(PORT, () => {
    logger.info(`✅  PID ${process.pid} listening on :${PORT}`);
  });

  /* ─── graceful shutdown + hard-kill safeguard ─── */
  let killTimer = null;

  const graceful = async (reason) => {
    if (killTimer) return;                       // already running – ignore duplicate
    logger.warn(`⏳  PID ${process.pid} shutting down – ${reason}`);

    killTimer = setTimeout(() => {
      logger.error('❌  Force-killing stuck process (grace period elapsed)');
      process.exit(1);
    }, 30_000).unref();

    server.close(() => logger.info('HTTP closed'));

    await Promise.allSettled([
      redisClient.quit().catch(() => {}),
      admin.app().delete().catch(() => {})
    ]);

    clearTimeout(killTimer);
    process.exit(0);
  };

  process
    .on('SIGTERM', () => graceful('SIGTERM'))
    .on('SIGINT',  () => graceful('SIGINT'))
    .on('uncaughtException', (err) => {
      console.error('❌  Uncaught exception:', err);
      graceful('uncaughtException');
    });
}
