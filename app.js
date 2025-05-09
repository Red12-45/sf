// app.js – Ultimate Optimized version (Ajax‑ready, no missing pieces)

const express             = require('express');
const admin               = require('firebase-admin');
const path                = require('path');
const bcrypt              = require('bcrypt');
const session = require('express-session');
const { createClient } = require('redis');       // using Node Redis client
const { RedisStore } = require('connect-redis'); // import RedisStore from connect-redis

// ─────────── security deps (NEW) ───────────
const helmet        = require('helmet');              // 🔒
const rateLimit     = require('express-rate-limit');  // 🔒
const csrf          = require('csurf');               // 🔒
const { body, validationResult } = require('express-validator'); // 🔒


const favicon             = require('serve-favicon');
const Razorpay            = require('razorpay');
const ExcelJS             = require('exceljs');      
const compression         = require('compression');

const crypto     = require('crypto');      
const nodemailer = require('nodemailer'); 

const cluster = require('cluster');
const os = require('os');

require('dotenv').config();

// ─────────── cache ───────────
const NodeCache = require('node-cache');
const cache     = new NodeCache({ stdTTL: 300, checkperiod: 120 });

// ─────────── Firebase Admin ───────────
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ─────────── Express base ───────────
const app = express();


const redisClient = createClient({
  url: process.env.REDIS_URL
});
redisClient.connect().catch(console.error);  // connect to Redis (for node-redis v4)

// 2. Create RedisStore instance for sessions
const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'sess:'  // optional key prefix in Redis, defaults to "sess:"
});

app.use(session({
  store: redisStore,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 86400000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

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

/* ─────────── Security middleware stack (NEW) ─────────── */
app.use(helmet({
  hidePoweredBy: true,
  contentSecurityPolicy: {
    directives: {
      defaultSrc    : ["'self'"],
      scriptSrc     : [
        "'self'",
        "'unsafe-inline'",            // your inline <script> blocks
        "https://cdnjs.cloudflare.com",  // ChartDataLabels plugin
        "https://cdn.jsdelivr.net",       // ← add this
        "https://www.gstatic.com",
        "https://checkout.razorpay.com"
      ],
      scriptSrcAttr : ["'self'", "'unsafe-inline'"],  // your inline onclick=""
      styleSrc      : [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com"
      ],
      connectSrc    : [
        "'self'",
        "https://*.firebaseio.com",
        "https://firestore.googleapis.com",
        "https://*.razorpay.com"
      ],
      imgSrc     : ["'self'", "data:"],
      fontSrc    : ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"]
    }
  }
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

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// CSRF protection (MUST come _after_ session middleware)
app.use(csrf());
app.use((req, res, next) => {
  // make the token available to all your EJS templates
  res.locals.csrfToken = req.csrfToken();
  next();
});
// Redis safety-net
redisClient.on('error', err => console.error('Redis error:', err));

/* CSRF & generic error shields (keep these LAST) */
app.use((err, req, res, next) => {        // CSRF failure handler
  if (err.code === 'EBADCSRFTOKEN')
    return res.status(403).send('Invalid CSRF token');
  next(err);
});
app.use((err, req, res, next) => {        // generic 500
  console.error(err);
  res.status(500).send('Internal Server Error');
});



// serve static assets with a long maxAge—but they'll be re-requested whenever `v` changes
app.use(express.static('public', { maxAge: '365d' }));

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));



app.locals.formatIST = date => {
  const d = (typeof date?.toDate === 'function') 
            ? date.toDate() 
            : new Date(date);
  return d.toLocaleTimeString('en-IN', { hour12: false, timeZone: 'Asia/Kolkata' });
};



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
  const key = `categories_${accountId}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const snap = await db.collection('products').where('accountId', '==', accountId).get();
  const uniq = [...new Set(snap.docs.map(d => d.data().category).filter(c => c))];
  cache.set(key, uniq);
  return uniq;
};

const getPermissions = async accountId => {
  const key = `permissions_${accountId}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const doc = await db.collection('permissions').doc(accountId).get();
  const locked = doc.exists ? (doc.data().lockedRoutes || []) : [];
  cache.set(key, locked);
  return locked;
};

const getUnits = async accountId => {
  const key = `units_${accountId}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const snap = await db.collection('products').where('accountId', '==', accountId).get();
  const uniq = [...new Set(snap.docs.map(d => (d.data().unit || '').toLowerCase()).filter(u => u))];
  cache.set(key, uniq);
  return uniq;
};

/* ─────────── DAILY SUMMARY (used by Ajax) ─────────── */
async function computeDailySummary(accountId, saleDate) {
  const [salesSnap, expSnap, obDoc] = await Promise.all([
    db.collection('sales').where('accountId', '==', accountId).where('saleDate', '==', saleDate).get(),
    db.collection('expenses').where('accountId', '==', accountId).where('saleDate', '==', saleDate).get(),
    db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get()
  ]);

  const s = {
    totalProfit: 0,
    totalSales: 0,
    totalCashSales: 0,
    totalOnlineSales: 0,
    totalNotPaidSales: 0,
    totalCashExpenses: 0,
    totalOnlineExpenses: 0
  };

  salesSnap.forEach(doc => {
    const d = doc.data();
    const amt = d.retailPrice * d.saleQuantity;
    s.totalProfit += d.profit;
    s.totalSales += amt;
    switch (d.status) {
      case 'Paid Cash':            s.totalCashSales += amt; break;
      case 'Paid Online':          s.totalOnlineSales += amt; break;
      case 'Not Paid':             s.totalNotPaidSales += amt; break;
      case 'Half Cash + Half Online':
        if (d.paymentDetail1) s.totalCashSales += d.paymentDetail1;
        if (d.paymentDetail2) s.totalOnlineSales += d.paymentDetail2;
        break;
      case 'Half Cash + Not Paid':
        if (d.paymentDetail1) s.totalCashSales += d.paymentDetail1;
        if (d.paymentDetail2) s.totalNotPaidSales += d.paymentDetail2;
        break;
      case 'Half Online + Not Paid':
        if (d.paymentDetail1) s.totalOnlineSales += d.paymentDetail1;
        if (d.paymentDetail2) s.totalNotPaidSales += d.paymentDetail2;
        break;
    }
  });

  expSnap.forEach(doc => {
    const d = doc.data();
    switch (d.expenseStatus) {
      case 'Paid Cash':            s.totalCashExpenses += d.expenseCost; break;
      case 'Paid Online':          s.totalOnlineExpenses += d.expenseCost; break;
      case 'Half Cash + Half Online':
        if (d.expenseDetail1) s.totalCashExpenses += d.expenseDetail1;
        if (d.expenseDetail2) s.totalOnlineExpenses += d.expenseDetail2;
        break;
      case 'Half Cash + Not Paid':
        if (d.expenseDetail1) s.totalCashExpenses += d.expenseDetail1;
        break;
      case 'Half Online + Not Paid':
        if (d.expenseDetail1) s.totalOnlineExpenses += d.expenseDetail1;
        break;
    }
  });

  const openingBal = obDoc.exists ? (obDoc.data().balance || 0) : 0;
  s.finalCash = parseFloat(openingBal) + s.totalCashSales - s.totalCashExpenses;
  s.totalSales = +s.totalSales.toFixed(2);
  s.totalProfit = +s.totalProfit.toFixed(2);

  return { summary: s, openingBalance: openingBal };
}

/* ─────────── processSale (shared full‑page + Ajax) ─────────── */
// ────────────────────────────────────────────────────────────────
// processSale — creates one sale, updates stock/batches and
//               returns the saved document               (AJAX + full‑page)
// ────────────────────────────────────────────────────────────────
/* ─────────── processSale (shared full‑page + Ajax) ─────────── */
async function processSale(body, user) {
  const accountId = user.accountId;

  // NOTICE:  `retailPrice` in the incoming body is now the **TOTAL Sale value**
  let {
    productId,
    customProductId,
    retailPrice: totalSaleInput,      // ① renamed for clarity
    saleQuantity,
    saleDate,
    status,
    extraInfo = '',
    paymentDetail1,
    paymentDetail2
  } = body;

  saleQuantity     = +parseFloat(saleQuantity);
  const totalSale  = +parseFloat(totalSaleInput);   // ② total amount    (₹)

  /* 1. resolve the product (unchanged) ---------------------------------- */
  const selectedProductId = (customProductId?.trim()) ? customProductId : productId;
  const productRef = db.collection('products').doc(selectedProductId);
  const productDoc = await productRef.get();
  if (!productDoc.exists || productDoc.data().accountId !== accountId)
    throw new Error('Product not found or unauthorized');

  const product = productDoc.data();

  /* 2. FIFO stock consumption (unchanged) ------------------------------- */
  const batchesSnap = await db.collection('stockBatches')
    .where('productId', '==', selectedProductId)
    .where('remainingQuantity', '>', 0)
    .orderBy('batchDate', 'asc')
    .get();

  let remaining      = saleQuantity;
  let totalWholesale = 0;
  const batch        = db.batch();
  const batchesUsed  = [];

  for (const b of batchesSnap.docs) {
    if (remaining <= 0) break;
    const d    = b.data();
    const take = Math.min(d.remainingQuantity, remaining);

    batch.update(b.ref, {
      quantity         : admin.firestore.FieldValue.increment(-take),
      remainingQuantity: +(d.remainingQuantity - take).toFixed(3)
    });

    totalWholesale += d.purchasePrice * take;
    batchesUsed.push({ id: b.id, qtyUsed: take });
    remaining -= take;
  }

  if (remaining > 0) throw new Error('Not enough stock');
  await batch.commit();

  /* 3. profit maths – re-keyed for TOTAL-SALE input --------------------- */
  const avgWholesale  = +(totalWholesale / saleQuantity).toFixed(2);      // FIFO ₹ / unit
  const retailPerUnit = +(totalSale / saleQuantity).toFixed(2);           // NEW
  const profitPerUnit = +(retailPerUnit - avgWholesale).toFixed(2);
  const totalProfit   = +(profitPerUnit * saleQuantity).toFixed(2);

  /* 4. parent-product stock refresh (unchanged) ------------------------- */
  await recalcProductFromBatches(selectedProductId);

  /* 5. write the sale --------------------------------------------------- */
  const saleData = {
    productId      : selectedProductId,
    productName    : product.productName,
    unit           : product.unit || '',
    wholesalePrice : avgWholesale,   // FIFO ₹ / unit
    retailPrice    : retailPerUnit,  // still stored *per-unit* for reports
    saleQuantity,
    saleDate,
    totalSale,                       // NEW: exact user-entered amount
    profitPerUnit,
    profit         : totalProfit,
    status,
    extraInfo,
    batchesUsed,
    createdAt      : new Date(),
    accountId,
    ...(paymentDetail1 && { paymentDetail1:+parseFloat(paymentDetail1) }),
    ...(paymentDetail2 && { paymentDetail2:+parseFloat(paymentDetail2) })
  };

  const saleRef = await db.collection('sales').add(saleData);
  saleData.id   = saleRef.id;
  return saleData;
}



/* ─────────── processExpense (shared) ─────────── */
async function processExpense(body, user) {
  const accountId = user.accountId;
  const saleDate  = body.saleDate;

  // Normalise to arrays so single‑row & multi‑row both work
  const reasons  = Array.isArray(body.expenseReason) ? body.expenseReason  : [body.expenseReason];
  const costs    = Array.isArray(body.expenseCost)   ? body.expenseCost    : [body.expenseCost];
  const statuses = Array.isArray(body.expenseStatus) ? body.expenseStatus  : [body.expenseStatus];
  const d1s      = Array.isArray(body.expenseDetail1)? body.expenseDetail1 : [body.expenseDetail1];
  const d2s      = Array.isArray(body.expenseDetail2)? body.expenseDetail2 : [body.expenseDetail2];

  const saved = [];

  for (let i = 0; i < reasons.length; i++) {
    const data = {
      expenseReason : reasons[i],
      expenseCost   : parseFloat(costs[i]),
      expenseStatus : statuses[i] || 'Paid Cash',
      saleDate,
      accountId,
      createdAt     : new Date()
    };
    if (d1s[i]) data.expenseDetail1 = parseFloat(d1s[i]);
    if (d2s[i]) data.expenseDetail2 = parseFloat(d2s[i]);

    await db.collection('expenses').add(data);
    saved.push(data);
  }

  // Return the last one so the Ajax patch keeps working
  return saved[saved.length - 1];
}

/* ─────────── Global subscription check middleware ─────────── */
app.use((req, res, next) => {
  if (!req.session || !req.session.user) return next();
  const allowedPaths = [
    '/', '/login', '/register', '/documentation', '/pricing',
    '/subscribe/monthly', '/subscribe/half-yearly', '/subscribe/yearly',
    '/payment-success', '/logout','/tnc', '/privacy', '/customerservice'
  ];
  if (allowedPaths.includes(req.path)) return next();
  const subscriptionExpiry = req.session.user.subscriptionExpiry;
  if (!subscriptionExpiry || new Date(subscriptionExpiry) <= new Date()) {
    return res.redirect('/pricing');
  }
  next();
});

/* ─────────── subscription / auth middle‑ware ─────────── */
const requireMaster    = (req, res, next) => req.session.user && req.session.user.isMaster ? next() : res.status(403).send('Access denied');
const isAuthenticated  = (req, res, next) => req.session && req.session.user ? next() : res.redirect('/login');
const restrictRoute    = routeId => async (req, res, next) => {
  if (req.session.user.isMaster) return next();
  if (req.session.lockedRoutes?.includes(routeId)) return res.status(403).send('Access denied');
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


/* ─────────── AUTHENTICATION ROUTES ─────────── */
// GET /register
app.get('/register', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('register', { errorMessage: null, oldInput: {} });
});
// POST /register
// POST /register  (🔒 hardened)
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

    body('password')
      .isStrongPassword({
        minLength: 8, minLowercase: 1,
        minUppercase: 1, minNumbers: 1, minSymbols: 1
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
      name, email, phone, address,
      location, password
    } = req.body;

    const oldInput = { name, email, phone, address, location };

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

      const hashed = await bcrypt.hash(password, 10);
      const userRef = await db.collection('users').add({
        name,
        email: normalizedEmail,
        phone,
        address,
        location,
        password: hashed,
        isMaster: true,
        createdAt: new Date()
      });
      await userRef.update({ accountId: userRef.id });
      res.redirect('/login');

    } catch (err) {
      console.error(err);
      res.status(500).render('register', {
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
        const retryAfter = Math.ceil(await redisClient.ttl(bruteKey) / 60);
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
      req.session.user = {
        id        : userDoc.id,
        name      : userData.name,
        email     : userData.email,
        isMaster  : userData.isMaster || false,
        accountId : userData.accountId || userDoc.id,
        subscriptionExpiry
      };
      if (!req.session.user.isMaster) {
        const permDoc = await db.collection('permissions')
                                .doc(req.session.user.accountId).get();
        req.session.lockedRoutes = permDoc.exists
          ? (permDoc.data().lockedRoutes || [])
          : [];
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
// GET /permission
app.get('/permission', isAuthenticated, restrictRoute('/permission'), async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send('Access denied');
  try {
    const lockedRoutes = await getPermissions(req.session.user.accountId);
    const availableRoutes = [
      { path: '/profit', label: 'Profit Report' },
      { path: '/sales', label: 'Sales Report' },
      { path: '/expense', label: 'Expense Report' },
      { path: '/add-product', label: 'Add Product' },
      { path: '/view-products', label: 'View Products' }
    ];
    res.render('permission', { lockedRoutes, availableRoutes, success: req.query.success });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /permission
app.post('/permission', isAuthenticated, restrictRoute('/permission'), async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send('Access denied');
  try {
    let lockedRoutes = req.body.lockedRoutes || [];
    if (!Array.isArray(lockedRoutes)) lockedRoutes = [lockedRoutes];
    await db.collection('permissions').doc(req.session.user.accountId).set({ lockedRoutes }, { merge: true });
    cache.del(`permissions_${req.session.user.accountId}`);
    res.redirect('/permission?success=1');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


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
    let totalProfit = 0, totalSales = 0, totalCashSales = 0,
        totalOnlineSales = 0, totalNotPaidSales = 0;
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
      totalProfit, totalSales, totalCashSales, totalOnlineSales, totalNotPaidSales,
      totalCashExpenses, totalOnlineExpenses, finalCash, subscriptionRemaining,
      user: req.session.user
    });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});


// GET /expense – monthly expenses view
app.get('/expense', isAuthenticated, restrictRoute('/expense'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const today     = new Date();
    const currentYear  = today.getFullYear();
    const currentMonth = pad(today.getMonth()+1);
    const defaultMonth = `${currentYear}-${currentMonth}`;
    const monthParam   = req.query.month || defaultMonth;
    const startDate    = `${monthParam}-01`;
    let [year, mon]    = monthParam.split('-');
    let nextMon        = parseInt(mon,10) + 1;
    let nextYear       = parseInt(year,10);
    if (nextMon > 12) { nextMon = 1; nextYear++; }
    const nextMonth = `${nextYear}-${pad(nextMon)}-01`;

    const expenseSnap = await db.collection('expenses')
      .where('accountId','==',accountId)
      .where('saleDate','>=', startDate)
      .where('saleDate','<', nextMonth)
      .orderBy('createdAt','desc')
      .get();
    const expenses = expenseSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const totalExpense = expenses.reduce((sum,e)=>sum+e.expenseCost,0);

    const groupedExpenses = {};
    expenses.forEach(exp => {
      const created = (exp.createdAt.toDate) ? exp.createdAt.toDate() : new Date(exp.createdAt);
      const dateStr = created.toISOString().substring(0,10);
      groupedExpenses[dateStr] = groupedExpenses[dateStr] || [];
      groupedExpenses[dateStr].push(exp);
    });

    res.render('expense', { month: monthParam, groupedExpenses, totalExpense });
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
        selectedCategory,
        newCategory,
        selectedUnit,
        newUnit
      } = req.body;

      const wp  = +parseFloat(wholesalePrice);
      const rp  = +parseFloat(retailPrice);
      const qty = +parseFloat(quantity);

      const category = newCategory?.trim()
        ? newCategory.trim()
        : (selectedCategory || '');

      const unitRaw = newUnit?.trim() || selectedUnit || '';
      const unit    = unitRaw.toLowerCase();

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

        const newWholesale = ((curQ * d.wholesalePrice) + (qty * wp)) / newQ;
        const newRetail    = ((curQ * d.retailPrice ) + (qty * rp)) / newQ;

        await productRef.update({
          quantity      : newQ,
          wholesalePrice: newWholesale,
          retailPrice   : newRetail,
          profitMargin  : newRetail - newWholesale,
          updatedAt     : new Date(),
          ...(unit     && { unit }),
          ...(category && { category })
        });

      /* --------------------------------------------------------------
         3. CREATE flow
      -------------------------------------------------------------- */
      } else {
        const data = {
          productName : productName.trim(),
          nameKey,
          wholesalePrice: wp,
          retailPrice   : rp,
          quantity      : qty,
          profitMargin  : rp - wp,
          category,
          unit,
          createdAt     : new Date(),
          accountId,
          // legacy compat
          oldestWholesale: wp,
          oldestBatchQty : qty,
          secondWholesale: null,
          oldestRetail   : rp,
          secondRetail   : null
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

      cache.del(`categories_${accountId}`);
      cache.del(`units_${accountId}`);

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
      const chunkSize = 10;
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
    res.render('viewProducts', { products, categories, filterCategory, stockThreshold, sortOrder });
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
        serial        : (idx+1).toFixed(2),
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
app.post('/delete-stock-batch/:batchId', isAuthenticated, async (req, res) => {
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


async function recalcProductFromBatches(productId) {
  const snap = await db.collection('stockBatches')
    .where('productId','==',productId)
    .get();
  let totalRemaining=0, totalWholesale=0, totalRetail=0;
  snap.docs.forEach(doc => {
    const d = doc.data();
    totalRemaining += d.remainingQuantity;
    totalWholesale  += d.remainingQuantity * d.purchasePrice;
    totalRetail     += d.remainingQuantity * d.salePrice;
  });
  let newWholesale=0, newRetail=0, profitMargin=0;
  if (totalRemaining>0) {
    newWholesale = totalWholesale / totalRemaining;
    newRetail    = totalRetail    / totalRemaining;
    profitMargin = newRetail - newWholesale;
  }
  await db.collection('products').doc(productId).update({
    quantity: totalRemaining,
    wholesalePrice: newWholesale,
    retailPrice: newRetail,
    profitMargin,
    updatedAt: new Date()
  });
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

    // if the batch has no category, fall back to the parent product's category
    const productRef  = db.collection('products').doc(batchData.productId);
    const productSnap = await productRef.get();
    if (productSnap.exists) {
      batchData.category = batchData.category || productSnap.data().category || '';
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
app.post('/api/edit-stock-batch-field/:batchId', isAuthenticated, async (req, res) => {
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
      productName, purchasePrice, salePrice, quantity,
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

    const unitRaw = newUnit?.trim() || selectedUnit || '';
    const catRaw  = newCategory?.trim() || selectedCategory || '';

    await batchRef.update({
      productName : newName,
      purchasePrice: pp,
      salePrice   : sp,
      quantity    : qty,
      remainingQuantity: qty,
      profitMargin: +(sp - pp).toFixed(2),
      ...(unitRaw && { unit: unitRaw.toLowerCase() }),
      ...(catRaw  && { category: catRaw }),
      updatedAt: new Date()
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
      ...(unitRaw && { unit: unitRaw.toLowerCase() }),
      ...(catRaw  && { category: catRaw }),
      updatedAt   : new Date()
    }, { merge: true });

    await recalcProductFromBatches(targetProdId);
    cache.del(`categories_${accountId}`);
    cache.del(`units_${accountId}`);

    res.redirect('/view-products');
  } catch (e) {
    res.status(500).send(e.toString());
  }
});




/* ─────────── SALES & PROFIT REPORTING ─────────── */
// ────────────────────────────────────────────────────────────────
// GET  /sales  – Sales + Expense report with optional filters
app.get('/sales', isAuthenticated, restrictRoute('/sales'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { saleDate, month, status } = req.query;

    // 1. Build the two Firestore queries
    let salesQ   = db.collection('sales')
                     .where('accountId','==',accountId)
                     .orderBy('createdAt','desc');
    let expenseQ = db.collection('expenses')
                     .where('accountId','==',accountId)
                     .orderBy('createdAt','desc');

    if (saleDate) {
      salesQ   = salesQ.where('saleDate','==',saleDate);
      expenseQ = expenseQ.where('saleDate','==',saleDate);
    } else if (month) {
      const [y,m] = month.split('-');
      const start = `${month}-01`;
      let nextM   = parseInt(m,10) + 1, nextY = parseInt(y,10);
      if (nextM > 12) { nextM = 1; nextY++; }
      const end   = `${nextY}-${String(nextM).padStart(2,'0')}-01`;
      salesQ   = salesQ.where('saleDate','>=',start).where('saleDate','<',end);
      expenseQ = expenseQ.where('saleDate','>=',start).where('saleDate','<',end);
    }

    if (status && status.trim() && status !== 'All') {
      salesQ = salesQ.where('status','==',status);
    }

    // 2. Run them in parallel
    const [salesSnap, expSnap] = await Promise.all([ salesQ.get(), expenseQ.get() ]);
    const sales    = salesSnap.docs.map(d => ({ id:d.id, ...d.data() }));
    const expenses = expSnap .docs.map(d => ({ id:d.id, ...d.data() }));

    // 3. Totals
    const profitWithoutExpenses = sales.reduce((sum,s)=>sum+s.profit,0);
    const totalExpensesAmount   = expenses.reduce((sum,e)=>sum+e.expenseCost,0);
    const profitAfterExpenses   = profitWithoutExpenses - totalExpensesAmount;

    const totalRevenueAmount = sales.reduce((sum,s)=>
      sum + (s.totalSale !== undefined
               ? parseFloat(s.totalSale)
               : s.retailPrice * s.saleQuantity)
    ,0);

    // 4. Opening balances / times (unchanged)
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
        const data = obDoc.data();
        openingTimes[date]    = {
          openingTime: data.openingTime || '',
          closingTime: data.closingTime || ''
        };
        openingBalances[date] = parseFloat(data.balance || 0);
      } else {
        openingTimes[date]    = { openingTime:'', closingTime:'' };
        openingBalances[date] = 0;
      }
    }));

    // 5. Render
    res.render('sales', {
      sales,
      expenses,
      saleDate,
      month,
      status,
      profitWithoutExpenses,
      totalExpensesAmount,
      profitAfterExpenses,
      totalRevenueAmount,        // ➜ NEW
      openingTimes,
      openingBalances
    });
  } catch (err) {
    res.status(500).send(err.toString());
  }
});



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
      { header: 'Status',          key: 'status',          width: 24 },
      { header: 'Extra Info',      key: 'extraInfo',       width: 32 },
      { header: 'Created At',      key: 'createdAt',       width: 22 }
    ];

    sales.forEach(s => ws.addRow({
      ...s,
      totalSale:     s.totalSale || (s.retailPrice * s.saleQuantity),
      createdAt:     (s.createdAt?.toDate ? s.createdAt.toDate()
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
app.post('/api/edit-sale', isAuthenticated, async (req, res) => {
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
      const { summary } = await computeDailySummary(req.session.user.accountId, data.saleDate);
      return res.json({ success:true, updatedRow:update, summary });
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
        const ref = batchCol.doc(u.id);
        stockOps.update(ref, {
          quantity         : admin.firestore.FieldValue.increment(ret),
          remainingQuantity: admin.firestore.FieldValue.increment(ret)
        });
        u.qtyUsed -= ret;
        give -= ret;
      }
      batchesUsed = batchesUsed.filter(u=>u.qtyUsed>0.0001);
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
      productName    : data.productName.includes('(updated)') ? data.productName
                                                              : data.productName + ' (updated)'
    });

    const { summary } = await computeDailySummary(req.session.user.accountId, data.saleDate);

    return res.json({
      success:true,
      updatedRow:{
        saleQuantity : +newQty.toFixed(3),
        totalSale    : +newTotalSale.toFixed(2),
        retailPrice  : retailPerUnit,
        wholesalePrice:avgWholesale,
        profitPerUnit,
        profit       : totalProfit,
        productName  : data.productName.includes('(updated)') ? data.productName
                                                              : data.productName + ' (updated)'
      },
      summary
    });

  } catch (err) {
    console.error(err);
    return res.json({ success:false, error:err.message });
  }
});


app.post('/delete-product/:productId', isAuthenticated, async (req, res) => {
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
    let salesQuery    = db.collection('sales').where('accountId','==',accountId);
    let expenseQuery  = db.collection('expenses').where('accountId','==',accountId);
    const { month, year } = req.query;

    if (month) {
      const [y,m] = month.split('-');
      const startDate = `${month}-01`;
      let nextM=parseInt(m,10)+1, nextY=parseInt(y,10);
      if(nextM>12){ nextM=1; nextY++; }
      const nextMonth = `${nextY}-${pad(nextM)}-01`;
      salesQuery    = salesQuery.where('saleDate','>=',startDate).where('saleDate','<',nextMonth);
      expenseQuery  = expenseQuery.where('saleDate','>=',startDate).where('saleDate','<',nextMonth);
    } else if (year) {
      const startDate = `${year}-01-01`;
      const endDate   = `${parseInt(year)+1}-01-01`;
      salesQuery    = salesQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
      expenseQuery  = expenseQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
    } else {
      const currentYear = new Date().getFullYear();
      const startDate = `${currentYear}-01-01`;
      const endDate   = `${currentYear+1}-01-01`;
      salesQuery    = salesQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
      expenseQuery  = expenseQuery.where('saleDate','>=',startDate).where('saleDate','<',endDate);
    }

    const [salesSnap, expSnap] = await Promise.all([salesQuery.get(), expenseQuery.get()]);
    const sales = salesSnap.docs.map(d=>d.data());
    const expenses = expSnap.docs.map(d=>d.data());

    const totalProfit   = sales.reduce((sum,s)=>(sum+s.profit),0);
    const totalExpenses = expenses.reduce((sum,e)=>(sum+e.expenseCost),0);
    const netProfit     = totalProfit - totalExpenses;

    const profitByMonth = {};
    sales.forEach(s => {
      const m = s.saleDate.substring(0,7);
      if (!profitByMonth[m]) profitByMonth[m] = { profit:0, expenses:0, netProfit:0 };
      profitByMonth[m].profit += s.profit;
    });
    expenses.forEach(e => {
      const m = e.saleDate.substring(0,7);
      if (!profitByMonth[m]) profitByMonth[m] = { profit:0, expenses:0, netProfit:0 };
      profitByMonth[m].expenses += e.expenseCost;
    });
    Object.keys(profitByMonth).forEach(m => {
      profitByMonth[m].netProfit = profitByMonth[m].profit - profitByMonth[m].expenses;
    });

    res.render('profit', {
      sales, expenses,
      totalProfit, totalExpenses: totalExpenses, netProfit,
      profitByMonth,
      monthFilter: month || '',
      yearFilter: req.query.year || ''
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


// GET /subscribe/monthly
app.get('/subscribe/monthly', isAuthenticated, async (req, res) => {
  const amount  = 400  * 100;
  const currency= 'INR';
  const receipt = `receipt_monthly_${Date.now()}`;
  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });
    res.render('payment', { order, plan:'Monthly', amount:400, user:req.session.user });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// GET /subscribe/half-yearly
app.get('/subscribe/half-yearly', isAuthenticated, async (req, res) => {
  const amount  = 4599 * 100;
  const currency= 'INR';
  const receipt = `receipt_halfyearly_${Date.now()}`;
  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });
    res.render('payment',{ order, plan:'Half-Yearly', amount:4599, user:req.session.user });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// GET /subscribe/yearly
app.get('/subscribe/yearly', isAuthenticated, async (req, res) => {
  const amount  = 8599 * 100;
  const currency= 'INR';
  const receipt = `receipt_yearly_${Date.now()}`;
  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });
    res.render('payment',{ order, plan:'Yearly', amount:8599, user:req.session.user });
  } catch (e) {
    res.status(500).send(e.toString());
  }
});

// POST /payment-success
app.post('/payment-success', isAuthenticated, async (req, res) => {
  try {
    const { plan } = req.body;
    let days;
    if (plan==='Monthly')      days=30;
    else if (plan==='Half-Yearly') days=182;
    else if (plan==='Yearly')   days=365;
    else return res.status(400).send('Invalid plan');

    const now     = new Date();
    let newExpiry = req.session.user.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > now
      ? new Date(req.session.user.subscriptionExpiry)
      : now;
    newExpiry.setDate(newExpiry.getDate() + days);

    await db.collection('users').doc(req.session.user.id).update({ subscriptionExpiry: newExpiry });
    req.session.user.subscriptionExpiry = newExpiry;
    res.redirect('/');
  } catch (e) {
    res.status(500).send(e.toString());
  }
});


/* ─────────── PROFILE & BILLING (Master Only) ─────────── */
// GET /profile
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
    res.render('profile', { user: userData });
  } catch (e) {
    res.status(500).send(e.toString());
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


app.post('/api/delete-expense', isAuthenticated, async (req, res) => {
  const { expenseId } = req.body;
  try {
    const expRef = db.collection('expenses').doc(expenseId);
    const expDoc = await expRef.get();

    /* NEW ✨ — idempotent */
    if (!expDoc.exists) {
      return res.json({ success: true });          // already deleted
    }

    const exp = expDoc.data();
    if (exp.accountId !== req.session.user.accountId)
      return res.json({ success: false, error: 'Access denied' });

    // delete & refresh
    await expRef.delete();
    const { summary } = await computeDailySummary(
      req.session.user.accountId,
      exp.saleDate
    );
    res.json({ success: true, summary });
  } catch (e) {
    res.json({ success: false, error: e.toString() });
  }
});



app.post('/api/expense', isAuthenticated, async (req, res) => {
  try {
    const saved = await processExpense(req.body, req.session.user);
    // saved does *not* include its own ID yet — grab it:
    const snap = await db.collection('expenses')
                         .where('accountId','==',req.session.user.accountId)
                         .orderBy('createdAt','desc')
                         .limit(1)
                         .get();
    const doc = snap.docs[0];
    const expense = { id: doc.id, ...doc.data() };

    const { summary } = await computeDailySummary(req.session.user.accountId, req.body.saleDate);
    res.json({ success: true, expense, summary });
  } catch (e) {
    res.json({ success: false, error: e.toString() });
  }
});


// AJAX: POST /api/sale
app.post('/api/sale', isAuthenticated, async (req, res) => {
  try {
    const sale    = await processSale(req.body, req.session.user);
    const { summary } = await computeDailySummary(req.session.user.accountId, req.body.saleDate);
    res.json({ success: true, sale, summary });
  } catch (e) {
    res.json({ success: false, error: e.toString() });
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
    res.json({ success: true, openingBalance: bal, summary });
  } catch (e) {
    res.json({ success: false, error: e.toString() });
  }
});

/* ─────────── AJAX:  DELETE SALE  ─────────── */
// ─────────── AJAX: DELETE SALE ───────────
// ─────────── AJAX:  DELETE SALE  ───────────
app.post('/api/delete-sale', isAuthenticated, async (req, res) => {
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
    if (batchOps._ops.length) await batchOps.commit();

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

    await recalcProductFromBatches(productId);                            // NEW
    await saleRef.delete();

    const { summary } = await computeDailySummary(sale.accountId, sale.saleDate);
    res.json({ success:true, summary });

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

/* ─────────── PERFORMANCE INSIGHTS ─────────── */
// GET /performance
app.get('/performance',
  isAuthenticated,
  
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* ───── 1. Determine date window ───── */
      const pad = n => String(n).padStart(2,'0');
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
app.get(
  '/stats',
  isAuthenticated,
  restrictRoute('/stats'),          // keep if you use route‑locking
  async (req, res) => {
    try {
      const accountId = req.session.user.accountId;

      /* 1️⃣  Resolve date window → default = whole current year */
      const pad = n => String(n).padStart(2, '0');
      const today       = new Date();
      const currentYear = today.getFullYear();

      const {
        month = '',
        from  = '',
        to    = '',
        year  = '',
        top: topParam = ''
      } = req.query;

      let startDate, endDate, periodLabel;
      let uiMonth   = month;               // pre‑fill pickers
      let uiFrom    = from;
      let uiTo      = to;
      let uiYear    = year;

      if (month) {                                          // single month
        startDate   = `${month}-01`;
        const [y, m] = month.split('-');
        let nextM = parseInt(m, 10) + 1, nextY = parseInt(y, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = new Date(`${month}-01`)
                        .toLocaleString('default', { month: 'long', year: 'numeric' });

      } else if (from && to) {                              // month range
        startDate   = `${from}-01`;
        const [ty, tm] = to.split('-');
        let nextM = parseInt(tm, 10) + 1, nextY = parseInt(ty, 10);
        if (nextM > 12) { nextM = 1; nextY++; }
        endDate     = `${nextY}-${pad(nextM)}-01`;
        periodLabel = `${from} → ${to}`;

      } else if (year) {                                    // explicit year
        startDate   = `${year}-01-01`;
        endDate     = `${parseInt(year, 10) + 1}-01-01`;
        periodLabel = `Year ${year}`;

      } else {                                             // DEFAULT = current year
        startDate   = `${currentYear}-01-01`;
        endDate     = `${currentYear + 1}-01-01`;
        periodLabel = `Year ${currentYear}`;
        uiYear      = currentYear;      // pre‑fill the “Year” input
      }

      const topN = Math.max(parseInt(topParam, 10) || 10, 1);

      /* 2️⃣  Fetch sales + expenses in the window (parallel) */
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

      /* 3️⃣  Top‑N product aggregation */
      const prodMap = {};
      sales.forEach(s => {
        const id = s.productId;
        if (!prodMap[id]) prodMap[id] = {
          productName: s.productName,
          unitsSold  : 0,
          revenue    : 0,
          profit     : 0
        };
        const qty = +s.saleQuantity;
        prodMap[id].unitsSold += qty;
        prodMap[id].revenue   += (s.totalSale !== undefined
                                   ? +parseFloat(s.totalSale)
                                   : s.retailPrice * qty);
        prodMap[id].profit    += +s.profit;
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

      /* 4️⃣  Monthly Profit & Expense totals */
      const monthlyProfit  = {};
      const monthlyExpense = {};

      sales.forEach(s => {
        const ym = s.saleDate.substring(0, 7);             // "YYYY‑MM"
        monthlyProfit[ym] = (monthlyProfit[ym] || 0) + +s.profit;
      });

      expenses.forEach(e => {
        const ym = e.saleDate.substring(0, 7);
        monthlyExpense[ym] = (monthlyExpense[ym] || 0) + +e.expenseCost;
      });

      /* 5️⃣  Render */
      res.render('stats', {
        /* Top‑N */
        topSelling,
        topRevenue,
        topProfit,

        /* Month‑level totals */
        monthlyProfit,
        monthlyExpense,

        /* UI helpers / form values */
        periodLabel,
        month : uiMonth,
        from  : uiFrom,
        to    : uiTo,
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

    // generate & persist token
    const token   = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000);   // 1 hour

    await db.collection('passwordResets').doc(token).set({
      userId   : userDoc.id,
      email,
      expiresAt: expires,
      used     : false,
      createdAt: new Date()
    });

    const link = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password/${token}`;

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
    const { token } = req.params;
    const doc = await db.collection('passwordResets').doc(token).get();
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


/* ─────────── START THE SERVER ─────────── */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

