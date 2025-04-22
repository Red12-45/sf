// app.js – Ultimate Optimized version (Ajax‑ready, no missing pieces)

const express             = require('express');
const admin               = require('firebase-admin');
const path                = require('path');
const bcrypt              = require('bcrypt');
const session             = require('express-session');
const { FirestoreStore }  = require('@google-cloud/connect-firestore');
const favicon             = require('serve-favicon');
const Razorpay            = require('razorpay');
const compression         = require('compression');
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
app.use(compression());
app.use(express.static('public', { maxAge: '1d' }));
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());



app.use(session({
  store: new FirestoreStore({ dataset: admin.firestore(), kind: 'express-sessions' }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
if (process.env.NODE_ENV === 'production') app.set('view cache', true);

// ─────────── helpers ───────────
const pad = n => String(n).padStart(2, '0');

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
  let {
    productId,
    customProductId,
    retailPrice,
    saleQuantity,
    saleDate,
    status,
    extraInfo,
    paymentDetail1,
    paymentDetail2
  } = body;

  // ensure we never send undefined to Firestore
  extraInfo = extraInfo || '';

  // parse floats
  saleQuantity = parseFloat(saleQuantity);
  const userAmt = parseFloat(retailPrice);

  // resolve product
  const selectedProductId = customProductId?.trim() ? customProductId : productId;
  const productRef = db.collection('products').doc(selectedProductId);
  const productDoc = await productRef.get();
  if (!productDoc.exists || productDoc.data().accountId !== accountId) {
    throw new Error('Product not found or unauthorized');
  }
  const product = productDoc.data();

  // FIFO from batches
  const batchesSnap = await db.collection('stockBatches')
    .where('productId', '==', selectedProductId)
    .where('remainingQuantity', '>', 0)
    .orderBy('batchDate', 'asc')
    .get();

  let remaining = saleQuantity,
      totalWh = 0,
      totalRt = 0;

  const batchUpdate = db.batch();
  batchesSnap.forEach(b => {
    if (remaining <= 0) return;
    const d = b.data();
    const take = Math.min(d.remainingQuantity, remaining);
    totalWh += d.purchasePrice * take;
    totalRt += d.salePrice * take;
    batchUpdate.update(b.ref, { remainingQuantity: d.remainingQuantity - take });
    remaining -= take;
  });
  if (remaining > 0) throw new Error('Not enough stock');

  await batchUpdate.commit();

  // averages
  const avgWholesale     = totalWh / saleQuantity;
  const avgRetailDefault = totalRt / saleQuantity;

  // interpret retailPrice as total sale
  const totalSaleAmt  = (userAmt > 0 ? userAmt : avgRetailDefault * saleQuantity);
  const perUnitRetail = (userAmt > 0 ? userAmt / saleQuantity : avgRetailDefault);

  const profitPerUnit = perUnitRetail - avgWholesale;
  const totalProfit   = totalSaleAmt - (avgWholesale * saleQuantity);

  // decrement product.quantity
  await productRef.update({
    quantity: admin.firestore.FieldValue.increment(-saleQuantity)
  });

  // build sale record
  const saleData = {
    productId:      selectedProductId,
    productName:    product.productName,
    unit:           product.unit || '',
    wholesalePrice: avgWholesale,
    retailPrice:    perUnitRetail,
    defaultRetail:  avgRetailDefault,
    saleQuantity,
    saleDate,   
    profitPerUnit,
    profit:         totalProfit,
    totalSale:      totalSaleAmt,
    status,
    extraInfo,
    createdAt:      new Date(),
    accountId,
    ...(paymentDetail1 && { paymentDetail1: parseFloat(paymentDetail1) }),
    ...(paymentDetail2 && { paymentDetail2: parseFloat(paymentDetail2) })
  };

  const saleRef = await db.collection('sales').add(saleData);
  saleData.id = saleRef.id;
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

/* ─────────── AUTHENTICATION ROUTES ─────────── */
// GET /register
app.get('/register', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('register', { errorMessage: null, oldInput: {} });
});
// POST /register
app.post('/register', async (req, res) => {
  const { name, email, phone, address, location, password, confirmPassword } = req.body;
  const oldInput = { name, email, phone, address, location };
  try {
    if (password !== confirmPassword)
      return res.status(400).render('register', { errorMessage: 'Passwords do not match', oldInput });

    const normalizedEmail = email.trim().toLowerCase();
    const userQuery = await db.collection('users').where('email', '==', normalizedEmail).limit(1).get();
    if (!userQuery.empty)
      return res.status(400).render('register', { errorMessage: 'User already exists', oldInput });

    const hashed = await bcrypt.hash(password, 10);
    const newUserRef = await db.collection('users').add({
      name, email: normalizedEmail, phone, address, location,
      password: hashed, isMaster: true, createdAt: new Date()
    });
    await newUserRef.update({ accountId: newUserRef.id });
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).render('register', {
      errorMessage: 'Something went wrong. Please try again.',
      oldInput
    });
  }
});

// GET /login
app.get('/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('login');
});
// POST /login
app.post('/login', async (req, res) => {
  try {
    let { identifier, password } = req.body;
    if (identifier.includes('@')) identifier = identifier.trim().toLowerCase();
    const [emailQ, subUserQ, phoneQ] = await Promise.all([
      db.collection('users').where('email','==',identifier).get(),
      db.collection('users').where('subUserId','==',identifier).get(),
      db.collection('users').where('phone','==',identifier).get()
    ]);
    let userDoc = !emailQ.empty ? emailQ.docs[0] : !subUserQ.empty ? subUserQ.docs[0] : !phoneQ.empty ? phoneQ.docs[0] : null;
    if (!userDoc) return res.status(400).send('User not found');

    const userData = userDoc.data();
    let subscriptionExpiry = userData.subscriptionExpiry
      ? (typeof userData.subscriptionExpiry.toDate === 'function' ? userData.subscriptionExpiry.toDate() : new Date(userData.subscriptionExpiry))
      : null;

    if (!userData.isMaster) {
      const masterDoc = await db.collection('users').doc(userData.accountId).get();
      if (masterDoc.exists && masterDoc.data().subscriptionExpiry) {
        subscriptionExpiry = (typeof masterDoc.data().subscriptionExpiry.toDate === 'function')
          ? masterDoc.data().subscriptionExpiry.toDate()
          : new Date(masterDoc.data().subscriptionExpiry);
      }
    }

    const validPassword = await bcrypt.compare(password, userData.password);
    if (!validPassword) return res.status(400).send('Invalid password');

    req.session.user = {
      id: userDoc.id,
      name: userData.name,
      email: userData.email,
      isMaster: userData.isMaster || false,
      accountId: userData.accountId || userDoc.id,
      subscriptionExpiry
    };

    if (!req.session.user.isMaster) {
      const permDoc = await db.collection('permissions').doc(req.session.user.accountId).get();
      req.session.lockedRoutes = permDoc.exists ? (permDoc.data().lockedRoutes || []) : [];
    }

    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

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
app.get('/', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const today     = new Date();
    const defaultDate = `${today.getFullYear()}-${pad(today.getMonth()+1)}-${pad(today.getDate())}`;
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
    let totalProfit = 0, totalSales = 0, totalCashSales = 0, totalOnlineSales = 0, totalNotPaidSales = 0;
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

// ─────────── POST /add-product – create or update ───────────
app.post('/add-product', isAuthenticated, restrictRoute('/add-product'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const {
      existingProduct,
      productName,
      wholesalePrice,
      retailPrice,
      quantity,
      selectedCategory,
      newCategory,
      selectedUnit,
      newUnit
    } = req.body;

    const wp       = parseFloat(wholesalePrice);
    const rp       = parseFloat(retailPrice);
    const qty      = parseFloat(quantity);
    const category = (newCategory?.trim()) ? newCategory.trim() : (selectedCategory || '');
    const unitRaw  = (newUnit?.trim())     ? newUnit.trim()     : (selectedUnit   || '');
    const unit     = unitRaw.toLowerCase();

    let productDoc;
    if (existingProduct && existingProduct !== 'new') {
      // update existing
      const ref  = db.collection('products').doc(existingProduct);
      const snap = await ref.get();
      if (!snap.exists) return res.status(404).send('Selected product not found');

      const d    = snap.data();
      const curQ = d.quantity || 0;
      const newQ = curQ + qty;
      const wW   = ((curQ * d.wholesalePrice) + (qty * wp)) / newQ;
      const wR   = ((curQ * d.retailPrice ) + (qty * rp)) / newQ;

      await ref.update({
        quantity:      newQ,
        wholesalePrice:wW,
        retailPrice:   wR,
        profitMargin:  wR - wW,
        updatedAt:     new Date(),
        ...(unit     && { unit }),
        ...(category && { category })
      });
      productDoc = snap;

    } else {
      // new product
      const dup = await db.collection('products')
        .where('accountId','==',accountId)
        .where('productName','==',productName)
        .limit(1).get();

      if (!dup.empty) {
        // if same name exists, re-run as update
        productDoc            = dup.docs[0];
        req.body.existingProduct = productDoc.id;
        return app._router.handle(req, res);
      }

      const data = {
        productName,
        wholesalePrice: wp,
        retailPrice:    rp,
        quantity:       qty,
        profitMargin:   rp - wp,
        category,
        unit,
        createdAt:      new Date(),
        accountId,
        // legacy batch‑tracking fields kept for backwards compatibility
        oldestWholesale: wp,
        oldestBatchQty:  qty,
        secondWholesale: null,
        oldestRetail:    rp,
        secondRetail:    null
      };
      const ref = await db.collection('products').add(data);
      productDoc = { id: ref.id, data: () => data };
    }

    // always add a new stockBatch
    await db.collection('stockBatches').add({
      productId:         productDoc.id,
      productName:       productDoc.data().productName,
      purchasePrice:     wp,
      salePrice:         rp,
      quantity:          qty,
      remainingQuantity: qty,
      batchDate:         new Date(),
      accountId,
      unit
    });

    // clear our caches so the sidebar/category lists refresh
    cache.del(`categories_${accountId}`);
    cache.del(`units_${accountId}`);

    res.redirect('/add-product?success=1');
  } catch (err) {
    res.status(500).send(err.toString());
  }
});



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
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchDoc = await batchRef.get();
    if (!batchDoc.exists) return res.status(404).send('Stock batch not found');
    if (batchDoc.data().accountId !== req.session.user.accountId) return res.status(403).send('Access denied');

    // still load categories/units, but no parent‐product lookup
    const [categories, units] = await Promise.all([
      getCategories(req.session.user.accountId),
      getUnits(req.session.user.accountId)
    ]);

    res.render('editStockBatch', {
      batch: { id: batchDoc.id, ...batchDoc.data() },
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
    const { batchId } = req.params;
    const {
      productName,
      purchasePrice,
      salePrice,
      quantity,
      newCategory,
      selectedCategory,
      newUnit,
      selectedUnit
    } = req.body;

    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchSnap = await batchRef.get();
    if (!batchSnap.exists) return res.status(404).send('Stock batch not found');
    if (batchSnap.data().accountId !== req.session.user.accountId) return res.status(403).send('Access denied');

    // only update the batch—no parent product update or recalc
    const updateData = {
      purchasePrice: parseFloat(purchasePrice),
      salePrice:     parseFloat(salePrice),
      quantity:      parseFloat(quantity),
      remainingQuantity: parseFloat(quantity),
      updatedAt:     new Date()
    };
    if (productName?.trim()) updateData.productName = productName.trim();
    const unitRaw = newUnit?.trim() || selectedUnit;
    if (unitRaw) updateData.unit = unitRaw.toLowerCase();
    const category = newCategory?.trim() || selectedCategory;
    if (category) updateData.category = category;

    await batchRef.update(updateData);
    res.redirect('/view-products');
  } catch (e) {
    res.status(500).send(e.toString());
  }
});





/* ─────────── SALES & PROFIT REPORTING ─────────── */
// GET /sales
// ────────────────────────────────────────────────────────────────
// GET  /sales  – Sales + Expense report with optional filters
// ────────────────────────────────────────────────────────────────
app.get('/sales', isAuthenticated, restrictRoute('/sales'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { saleDate, month, status } = req.query;

    /* -------------------------------------------------- */
    /* 1. Build the two Firestore queries                 */
    /* -------------------------------------------------- */
    let salesQ    = db.collection('sales')   .where('accountId','==',accountId)
                      .orderBy('createdAt','desc');
    let expenseQ  = db.collection('expenses').where('accountId','==',accountId)
                      .orderBy('createdAt','desc');

    if (saleDate) {
      salesQ   = salesQ  .where('saleDate','==',saleDate);
      expenseQ = expenseQ.where('saleDate','==',saleDate);
    } else if (month) {
      const [y,m]  = month.split('-');
      const start  = `${month}-01`;
      let nextM    = parseInt(m,10)+1, nextY=parseInt(y,10);
      if (nextM>12) { nextM=1; nextY++; }
      const end = `${nextY}-${String(nextM).padStart(2,'0')}-01`;
      salesQ   = salesQ  .where('saleDate','>=',start).where('saleDate','<',end);
      expenseQ = expenseQ.where('saleDate','>=',start).where('saleDate','<',end);
    }

    if (status && status.trim() && status!=='All') {
      salesQ = salesQ.where('status','==',status);
    }

    /* -------------------------------------------------- */
    /* 2. Run them in parallel                            */
    /* -------------------------------------------------- */
    const [salesSnap, expSnap] = await Promise.all([salesQ.get(), expenseQ.get()]);
    const sales    = salesSnap.docs.map(d => ({ id:d.id, ...d.data() }));
    const expenses = expSnap .docs.map(d => ({ id:d.id, ...d.data() }));

    /* -------------------------------------------------- */
    /* 3. Gather every unique date we touched             */
    /* -------------------------------------------------- */
    const dateSet = new Set();
    sales.forEach(s   => dateSet.add(s.saleDate));
    expenses.forEach(e=> dateSet.add(e.saleDate));
    const allDates = Array.from(dateSet);

    /* -------------------------------------------------- */
    /* 4. Fetch opening / closing times for each date     */
    /* -------------------------------------------------- */
    const openingTimes = {};
    await Promise.all(allDates.map(async date => {                      //   ★ FIX
      const obDoc = await db.collection('openingBalances')
                            .doc(`${accountId}_${date}`)                //   ★ FIX
                            .get();
      openingTimes[date] = obDoc.exists
        ? { openingTime: obDoc.data().openingTime || '',
            closingTime: obDoc.data().closingTime || '' }
        : { openingTime:'', closingTime:'' };
    }));

    /* -------------------------------------------------- */
    /* 5. Profit & expense roll‑ups                       */
    /* -------------------------------------------------- */
    const profitWithoutExpenses = sales.reduce((sum,s)=>sum+s.profit,0);
    const totalExpensesAmount   = expenses.reduce((sum,e)=>sum+e.expenseCost,0);
    const profitAfterExpenses   = profitWithoutExpenses - totalExpensesAmount;

    /* -------------------------------------------------- */
    /* 6. Render                                          */
    /* -------------------------------------------------- */
    res.render('sales',{
      sales, expenses,
      saleDate, month, status,
      profitWithoutExpenses, totalExpensesAmount, profitAfterExpenses,
      openingTimes
    });

  } catch (err) {
    res.status(500).send(err.toString());
  }
});


// POST /api/edit-sale
app.post('/api/edit-sale', async (req, res) => {
  try {
    const {
      saleId,
      field,
      value,
      paymentDetail1,
      paymentDetail2
    } = req.body;

    const saleRef = db.collection('sales').doc(saleId);
    const saleSnap = await saleRef.get();
    if (!saleSnap.exists) return res.json({ success: false, error: 'Sale not found' });
    const data = saleSnap.data();

    // ─────────── Handle status + details ───────────
    if (field === 'status') {
      const updateData = { status: value };
      if (paymentDetail1 !== undefined) updateData.paymentDetail1 = parseFloat(paymentDetail1);
      if (paymentDetail2 !== undefined) updateData.paymentDetail2 = parseFloat(paymentDetail2);
      await saleRef.update(updateData);
    } else {
      // ─────────── Original quantity/retail inline‐edit logic ───────────

      // 1) Parse new values
      const oldQty    = data.saleQuantity;
      const oldRetail = data.retailPrice;
      const newQty    = field === 'saleQuantity' ? parseInt(value, 10) : oldQty;
      const newRetail = field === 'retailPrice'   ? parseFloat(value)   : oldRetail;

      // 2) Adjust stock batches by deltaQty
      const deltaQty = newQty - oldQty;
      const batchDb  = db.collection('stockBatches');
      const batchOps = db.batch();

      // clone existing usage array
      const updatedBatchesUsed = Array.isArray(data.batchesUsed)
        ? data.batchesUsed.map(u => ({ ...u }))
        : [];

      if (deltaQty > 0) {
        // consume extra units FIFO
        let toTake = deltaQty;
        const snap = await batchDb
          .where('productId','==', data.productId)
          .where('remainingQuantity','>', 0)
          .orderBy('batchDate','asc')
          .get();
        for (const b of snap.docs) {
          if (toTake <= 0) break;
          const d = b.data();
          const take = Math.min(d.remainingQuantity, toTake);
          batchOps.update(b.ref, { remainingQuantity: d.remainingQuantity - take });
          const idx = updatedBatchesUsed.findIndex(u => u.id === b.id);
          if (idx > -1) updatedBatchesUsed[idx].qtyUsed += take;
          else            updatedBatchesUsed.push({ id: b.id, qtyUsed: take });
          toTake -= take;
        }
        if (toTake > 0) return res.json({ success: false, error: 'Not enough stock to increase quantity' });

      } else if (deltaQty < 0) {
        // return units back to batches
        let toReturn = -deltaQty;
        for (const usage of updatedBatchesUsed.slice().reverse()) {
          if (toReturn <= 0) break;
          const ret = Math.min(usage.qtyUsed, toReturn);
          const batchRef2 = batchDb.doc(usage.id);
          const batchSnap2= await batchRef2.get();
          if (!batchSnap2.exists) continue;
          const currRem = batchSnap2.data().remainingQuantity || 0;
          batchOps.update(batchRef2, { remainingQuantity: currRem + ret });
          usage.qtyUsed -= ret;
          toReturn   -= ret;
        }
        // drop zero‐usage entries
        for (let i = updatedBatchesUsed.length - 1; i >= 0; i--) {
          if (updatedBatchesUsed[i].qtyUsed <= 0) updatedBatchesUsed.splice(i, 1);
        }
      }

      // commit batch updates
      await batchOps.commit();

      // 3) Recompute product.quantity
      const recalcSnap = await batchDb.where('productId','==', data.productId).get();
      let sumRemaining = 0;
      recalcSnap.docs.forEach(d => sumRemaining += (d.data().remainingQuantity || 0));
      await db.collection('products').doc(data.productId).update({ quantity: sumRemaining });

      // 4) Recalculate weighted average wholesale price
      let totalWholesale = 0;
      for (const u of updatedBatchesUsed) {
        const bdoc = await batchDb.doc(u.id).get();
        if (!bdoc.exists) continue;
        const pPrice = bdoc.data().purchasePrice;
        totalWholesale += pPrice * u.qtyUsed;
      }
      const avgWholesale = newQty > 0 ? (totalWholesale / newQty) : 0;

      // 5) Compute profit figures
      const profitPerUnit = newRetail - avgWholesale;
      const totalProfit   = profitPerUnit * newQty;
      const totalSale     = newRetail * newQty;

      // 6) Update the sale document
      const updatedName = (newQty !== oldQty || newRetail !== oldRetail) && !data.productName.includes('(updated)')
        ? data.productName + '(updated)'
        : data.productName;

      await saleRef.update({
        saleQuantity:   newQty,
        wholesalePrice: avgWholesale,
        retailPrice:    newRetail,
        totalSale,
        profitPerUnit,
        profit:         totalProfit,
        productName:    updatedName,
        batchesUsed:    updatedBatchesUsed
      });
    }

    // ─────────── Recompute daily summary ───────────
    const date = data.saleDate;
    const [salesSnap2, expSnap2] = await Promise.all([
      db.collection('sales').where('saleDate','==', date).get(),
      db.collection('expenses').where('saleDate','==', date).get()
    ]);
    let tS=0, tP=0, cS=0, oS=0, nS=0, cE=0, oE=0;
    salesSnap2.forEach(d => {
      const s = d.data(), amt = s.retailPrice * s.saleQuantity;
      tS += amt; tP += s.profit;
      switch(s.status){
        case 'Paid Cash': cS += amt; break;
        case 'Paid Online': oS += amt; break;
        case 'Not Paid': nS += amt; break;
        case 'Half Cash + Half Online':
          if(s.paymentDetail1) cS += parseFloat(s.paymentDetail1);
          if(s.paymentDetail2) oS += parseFloat(s.paymentDetail2);
          break;
        case 'Half Cash + Not Paid':
          if(s.paymentDetail1) cS += parseFloat(s.paymentDetail1);
          if(s.paymentDetail2) nS += parseFloat(s.paymentDetail2);
          break;
        case 'Half Online + Not Paid':
          if(s.paymentDetail1) oS += parseFloat(s.paymentDetail1);
          if(s.paymentDetail2) nS += parseFloat(s.paymentDetail2);
          break;
      }
    });
    expSnap2.forEach(d => {
      const e = d.data();
      switch(e.expenseStatus){
        case 'Paid Cash': cE += parseFloat(e.expenseCost); break;
        case 'Paid Online': oE += parseFloat(e.expenseCost); break;
        case 'Half Cash + Half Online':
          if(e.expenseDetail1) cE += parseFloat(e.expenseDetail1);
          if(e.expenseDetail2) oE += parseFloat(e.expenseDetail2);
          break;
        case 'Half Cash + Not Paid':
          if(e.expenseDetail1) cE += parseFloat(e.expenseDetail1);
          break;
        case 'Half Online + Not Paid':
          if(e.expenseDetail1) oE += parseFloat(e.expenseDetail1);
          break;
      }
    });
    const summary = {
      totalSales:          tS,
      totalProfit:         tP,
      totalCashSales:      cS,
      totalOnlineSales:    oS,
      totalNotPaidSales:   nS,
      totalCashExpenses:   cE,
      totalOnlineExpenses: oE,
      finalCash:           cS - cE
    };

    // 8) Return success + updatedRow + summary
    // For status edits, include the two details in updatedRow
    let updatedRow = {};
    if (req.body.field === 'status') {
      updatedRow.status = req.body.value;
      if (req.body.paymentDetail1 !== undefined)
        updatedRow.paymentDetail1 = parseFloat(req.body.paymentDetail1);
      if (req.body.paymentDetail2 !== undefined)
        updatedRow.paymentDetail2 = parseFloat(req.body.paymentDetail2);
    } else {
      // numeric edits already updated above; re-fetch if needed
      const fresh = await saleRef.get();
      const d = fresh.data();
      updatedRow = {
        saleQuantity:   d.saleQuantity,
        wholesalePrice: d.wholesalePrice,
        retailPrice:    d.retailPrice,
        totalSale:      d.totalSale,
        profitPerUnit:  d.profitPerUnit,
        profit:         d.profit,
        productName:    d.productName
      };
    }

    return res.json({ success: true, updatedRow, summary });
  } catch (error) {
    return res.json({ success: false, error: error.message });
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
app.get('/pricing', (req, res) => {
  const now = new Date();
  if (req.session.user?.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > now)
    return res.redirect('/');
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
    if (!expDoc.exists) throw new Error('Expense not found');
    const exp = expDoc.data();
    if (exp.accountId !== req.session.user.accountId) throw new Error('Access denied');

    // delete the expense
    await expRef.delete();

    // recompute summary for that date
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
app.post('/api/delete-sale', isAuthenticated, async (req, res) => {
  const { saleId } = req.body;
  try {
    // 0. pull the sale we’re undoing
    const saleRef = db.collection('sales').doc(saleId);
    const saleDoc = await saleRef.get();
    if (!saleDoc.exists) throw new Error('Sale not found');
    const sale = saleDoc.data();
    if (sale.accountId !== req.session.user.accountId) throw new Error('Access denied');

    // 1. restore product stock
    await db.collection('products')
      .doc(sale.productId)
      .update({
        // this line increments the product.quantity by the number you originally sold
        quantity: admin.firestore.FieldValue.increment(sale.saleQuantity)
      });

    // 2. restore every batch that the sale had pulled from
    if (Array.isArray(sale.batchesUsed) && sale.batchesUsed.length) {
      const batch = db.batch();
      sale.batchesUsed.forEach(bu => {
        batch.update(
          db.collection('stockBatches').doc(bu.id),
          { remainingQuantity: admin.firestore.FieldValue.increment(bu.qtyUsed) }
        );
      });
      await batch.commit();
    }

    // 3. delete the sale document
    await saleRef.delete();

    // 4. recompute today’s summary so the client stays in‑sync
    const { summary } = await computeDailySummary(
      req.session.user.accountId,
      sale.saleDate
    );
    res.json({ success: true, summary });
  } catch (e) {
    res.json({ success: false, error: e.toString() });
  }
});



// GET /tnc – Terms & Conditions
app.get('/tnc', (req, res) => {
  res.render('tnc', { host: req.get('host') });
});

// In app.js, after your documentation route for example:

// GET /privacy
app.get('/privacy', (req, res) => {
  res.render('privacy');
});

/* ─────────── START THE SERVER ─────────── */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

