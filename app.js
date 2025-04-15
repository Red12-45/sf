// app.js – Optimized version preserving all logic, routes, and features

const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { FirestoreStore } = require('@google-cloud/connect-firestore');
const favicon = require('serve-favicon');
const Razorpay = require('razorpay');
require('dotenv').config();

// Initialize Firebase Admin SDK (ensure serviceAccountKey.json is in your root directory)
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

const app = express();

// Use your environment variables securely.
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

// -----------------------------------------------------------------------------
// MIDDLEWARE & EXPRESS SETUP
// -----------------------------------------------------------------------------

// Serve static files and favicon.
app.use(express.static('public'));
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

// Setup session middleware with a one‑month duration.
app.use(session({
  store: new FirestoreStore({
    dataset: admin.firestore(),
    kind: 'express-sessions'     
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000  // 30 days cookie lifespan
  }
}));

// Use body‑parser middleware.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set view engine and views folder.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Global reCAPTCHA verification endpoint.
app.post('/verify-captcha', async (req, res) => {
  const token = req.body.token; // The token from your client‑side reCAPTCHA
  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`;
  try {
    const response = await fetch(verificationUrl, { method: 'POST' });
    const data = await response.json();
    if (data.success) {
      res.json({ message: 'Captcha verification successful!' });
    } else {
      res.status(400).json({ message: 'Captcha verification failed.', errors: data['error-codes'] });
    }
  } catch (error) {
    console.error('Error verifying reCAPTCHA:', error);
    res.status(500).json({ message: 'Server error verifying reCAPTCHA.' });
  }
});

// Global subscription check middleware.
// (Only routes outside the allowedPaths will be checked for an active subscription.)
app.use((req, res, next) => {
  if (!req.session || !req.session.user) return next();

  const allowedPaths = [
    '/', 
    '/login', 
    '/register', 
    '/documentation', 
    '/pricing',
    '/subscribe/monthly', 
    '/subscribe/half-yearly', 
    '/subscribe/yearly',
    '/payment-success',
    '/logout'
  ];
  if (allowedPaths.includes(req.path)) return next();

  const subscriptionExpiry = req.session.user.subscriptionExpiry;
  if (!subscriptionExpiry || new Date(subscriptionExpiry) <= new Date()) {
    return res.redirect('/pricing');
  }
  next();
});

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS & MIDDLEWARE
// -----------------------------------------------------------------------------

// Only master users can access.
const requireMaster = (req, res, next) =>
  req.session.user && req.session.user.isMaster ? next() : res.status(403).send("Access denied: Only master users can access this page.");

// Check for authentication.
const isAuthenticated = (req, res, next) =>
  req.session && req.session.user ? next() : res.redirect('/login');

// Get distinct product categories for a given account.
const getCategories = async (accountId) => {
  const snapshot = await db.collection('products').where('accountId', '==', accountId).get();
  const categorySet = new Set();
  snapshot.forEach(doc => {
    const { category } = doc.data();
    if (category) categorySet.add(category);
  });
  return Array.from(categorySet);
};

// Configurable restricted routes for sub‑users.
const availableRestrictedRoutes = [
  { path: '/profit', label: 'Profit Report' },
  { path: '/sales', label: 'Sales Report' },
  { path: '/expense', label: 'Expense Report' },
  { path: '/add-product', label: 'Add Product' },
  { path: '/view-products', label: 'View Products' }
];

// Middleware factory to restrict certain routes for sub‑users.
const restrictRoute = (routeIdentifier) => async (req, res, next) => {
  if (req.session.user.isMaster) return next();
  if (req.session.lockedRoutes && req.session.lockedRoutes.includes(routeIdentifier)) {
    return res.status(403).send("Access denied: You do not have permission to access this route.");
  }
  next();
};

// Initialize Razorpay instance.
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// -----------------------------------------------------------------------------
// AUTHENTICATION ROUTES
// -----------------------------------------------------------------------------

// GET /register – Render the registration form.
app.get('/register', async (req, res) => res.render('register'));

// POST /register – Process registration and create master account.
app.post('/register', async (req, res) => {
  try {
    const { name, email, phone, address, location, password, confirmPassword } = req.body;
    if (password !== confirmPassword) return res.status(400).send("Passwords do not match");

    const normalizedEmail = email.trim().toLowerCase();
    const userQuery = await db.collection('users').where('email', '==', normalizedEmail).get();
    if (!userQuery.empty) return res.status(400).send("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      name,
      email: normalizedEmail,
      phone,
      address,
      location,
      password: hashedPassword,
      isMaster: true,
      createdAt: new Date()
    };
    const newUserRef = await db.collection('users').add(newUser);
    // Set the accountId as the same as the new user's document ID.
    await db.collection('users').doc(newUserRef.id).update({ accountId: newUserRef.id });
    res.redirect('/login');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /login – Render the login form.
app.get('/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.render('login');
});

// GET /customerservice – Render customer service page.
app.get('/customerservice', (req, res) => {
  res.render('cs');
});

// POST /login – Process login, validate credentials, and check for subscription expiry.
app.post('/login', async (req, res) => {
  try {
    let { identifier, password } = req.body;
    let userDoc = null;
    if (identifier.includes('@')) identifier = identifier.trim().toLowerCase();

    // Execute multiple queries concurrently.
    const [emailQuery, subUserQuery, phoneQuery] = await Promise.all([
      db.collection('users').where('email', '==', identifier).get(),
      db.collection('users').where('subUserId', '==', identifier).get(),
      db.collection('users').where('phone', '==', identifier).get()
    ]);

    if (!emailQuery.empty) {
      userDoc = emailQuery.docs[0];
    } else if (!subUserQuery.empty) {
      userDoc = subUserQuery.docs[0];
    } else if (!phoneQuery.empty) {
      userDoc = phoneQuery.docs[0];
    }
    if (!userDoc) return res.status(400).send("User not found");

    const userData = userDoc.data();
    let subscriptionExpiry = null;
    if (userData.subscriptionExpiry) {
      subscriptionExpiry = (typeof userData.subscriptionExpiry.toDate === 'function') ?
                           userData.subscriptionExpiry.toDate() : new Date(userData.subscriptionExpiry);
    }
    if (!userData.isMaster) {
      const masterDoc = await db.collection('users').doc(userData.accountId).get();
      if (masterDoc.exists) {
        const masterData = masterDoc.data();
        if (masterData.subscriptionExpiry) {
          subscriptionExpiry = (typeof masterData.subscriptionExpiry.toDate === 'function') ?
                               masterData.subscriptionExpiry.toDate() : new Date(masterData.subscriptionExpiry);
        }
      }
    }
    const validPassword = await bcrypt.compare(password, userData.password);
    if (!validPassword) return res.status(400).send("Invalid password");

    // Save relevant user data in the session.
    req.session.user = {
      id: userDoc.id,
      name: userData.name,
      email: userData.email,
      isMaster: userData.isMaster || false,
      accountId: userData.accountId || userDoc.id,
      subscriptionExpiry
    };

    // For sub‑users, load restricted routes.
    if (!req.session.user.isMaster) {
      const permDoc = await db.collection('permissions').doc(req.session.user.accountId).get();
      req.session.lockedRoutes = permDoc.exists ? (permDoc.data().lockedRoutes || []) : [];
    }
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /logout – Log out the current user.
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// GET /documentation – Render the documentation page.
app.get('/documentation', (req, res) => {
  res.render('documentations');
});

// -----------------------------------------------------------------------------
// USER MANAGEMENT ROUTES (Master Only)
// -----------------------------------------------------------------------------

// GET /create-user – Render the create sub‑user form.
app.get('/create-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send("Access denied");
  try {
    const snapshot = await db.collection('users')
      .where('accountId', '==', req.session.user.accountId)
      .get();
    const users = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      users.push({
        id: doc.id,
        name: data.name,
        email: data.email,
        isMaster: data.isMaster,
        subUserId: data.subUserId
      });
    });
    res.render('createuser', { users });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /create-user – Create a sub‑user (master only).
app.post('/create-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send("Access denied");
  try {
    const subUsersQuery = await db.collection('users')
      .where('accountId', '==', req.session.user.accountId)
      .where('isMaster', '==', false)
      .get();
    if (subUsersQuery.size >= 2) return res.status(400).send("Sub‑user limit reached. Maximum 2 sub‑users allowed.");
    
    const { name, password, confirmPassword, subUserId } = req.body;
    if (password !== confirmPassword) return res.status(400).send("Passwords do not match");
    if (!subUserId || subUserId.trim() === "") return res.status(400).send("Sub‑user ID is required");

    const subUserQuery = await db.collection('users')
      .where('subUserId', '==', subUserId)
      .where('accountId', '==', req.session.user.accountId)
      .get();
    if (!subUserQuery.empty) return res.status(400).send("Sub‑user ID already exists. Please generate a new one.");

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').add({
      name,
      password: hashedPassword,
      isMaster: false,
      accountId: req.session.user.accountId,
      subUserId,
      createdAt: new Date()
    });
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /edit-user – Update a sub‑user's name and/or password (master only).
app.post('/edit-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send("Access denied");
  try {
    const { userId, name, password, confirmPassword } = req.body;
    if (password && password !== confirmPassword) return res.status(400).send("Passwords do not match");

    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId) {
      return res.status(403).send("Access denied");
    }
    const updateData = { name };
    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }
    await userRef.update(updateData);
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /delete-user – Delete a sub‑user account (master only).
app.post('/delete-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send("Access denied");
  try {
    const { userId } = req.body;
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId) {
      return res.status(403).send("Access denied");
    }
    await userRef.delete();
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /delete-product/:productId – Delete a product if its quantity is zero and it has no batches.
app.post('/delete-product/:productId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const productId = req.params.productId;
    const productRef = db.collection('products').doc(productId);
    const productDoc = await productRef.get();
    if (!productDoc.exists) return res.status(404).send("Product not found");

    const productData = productDoc.data();
    if (productData.accountId !== accountId) return res.status(403).send("Access denied");
    if (productData.quantity !== 0) return res.status(400).send("Product cannot be deleted because its quantity is not zero");
    
    const batchesSnapshot = await db.collection('stockBatches')
      .where('productId', '==', productId)
      .get();
    if (!batchesSnapshot.empty) return res.status(400).send("Product cannot be deleted because it has associated batches");
    
    await productRef.delete();
    res.redirect('/view-products');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// PERMISSION MANAGEMENT ROUTES (Master Only)
// -----------------------------------------------------------------------------

// GET /permission – Render the permission management page.
app.get('/permission', isAuthenticated, restrictRoute('/permission'), async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send("Access denied");
  try {
    const permDoc = await db.collection('permissions').doc(req.session.user.accountId).get();
    const lockedRoutes = permDoc.exists ? (permDoc.data().lockedRoutes || []) : [];
    res.render('permission', { lockedRoutes, availableRoutes: availableRestrictedRoutes, success: req.query.success });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /permission – Save new permissions configuration.
app.post('/permission', isAuthenticated, restrictRoute('/permission'), async (req, res) => {
  if (!req.session.user.isMaster) return res.status(403).send("Access denied");
  try {
    let lockedRoutes = req.body.lockedRoutes;
    if (!lockedRoutes) lockedRoutes = [];
    else if (!Array.isArray(lockedRoutes)) lockedRoutes = [lockedRoutes];
    
    await db.collection('permissions').doc(req.session.user.accountId).set({ lockedRoutes }, { merge: true });
    res.redirect('/permission?success=1');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// PROTECTED APP ROUTES (Require Authentication)
// -----------------------------------------------------------------------------

// GET / – Homepage.
app.get('/', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const today = new Date();
    const pad = num => String(num).padStart(2, '0');
    const defaultDate = `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;
    const saleDate = req.query.saleDate || defaultDate;

    // Execute queries concurrently.
    const [productsSnapshot, salesSnapshot, expenseSnapshot, categories, obDoc] = await Promise.all([
      db.collection('products').where('accountId', '==', accountId).get(),
      db.collection('sales').where('accountId', '==', accountId).where('saleDate', '==', saleDate).orderBy('createdAt', 'desc').get(),
      db.collection('expenses').where('accountId', '==', accountId).where('saleDate', '==', saleDate).orderBy('createdAt', 'desc').get(),
      getCategories(accountId),
      db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get()
    ]);

    // Process products and fetch their batches concurrently.
    const products = await Promise.all(productsSnapshot.docs.map(async doc => {
      let product = { id: doc.id, ...doc.data() };
      const batchesSnapshot = await db.collection('stockBatches')
        .where('productId', '==', doc.id)
        .where('remainingQuantity', '>', 0)
        .orderBy('batchDate', 'asc')
        .get();
      product.batches = batchesSnapshot.docs.map(batchDoc => {
        const { purchasePrice: wholesale, salePrice: retail, remainingQuantity: qty } = batchDoc.data();
        return { wholesale, retail, qty };
      });
      return product;
    }));

    // Process sales and expenses.
    let sales = [];
    salesSnapshot.forEach(doc => sales.push({ id: doc.id, ...doc.data() }));
    let expenses = [];
    expenseSnapshot.forEach(doc => expenses.push(doc.data()));

    // Opening balance information.
    let openingBalance = 0, openingTime = "", closingTime = "";
    if (obDoc.exists) {
      const obData = obDoc.data();
      openingBalance = obData.balance || 0;
      openingTime = obData.openingTime || "";
      closingTime = obData.closingTime || "";
    }

    // Calculate summary data.
    let totalProfit = 0, totalSales = 0, totalCashSales = 0, totalOnlineSales = 0, totalNotPaidSales = 0;
    for (const sale of sales) {
      totalProfit += sale.profit;
      const saleAmount = sale.retailPrice * sale.saleQuantity;
      totalSales += saleAmount;
      switch(sale.status) {
        case 'Paid Cash':
          totalCashSales += saleAmount;
          break;
        case 'Paid Online':
          totalOnlineSales += saleAmount;
          break;
        case 'Not Paid':
          totalNotPaidSales += saleAmount;
          break;
        case 'Half Cash + Half Online':
          if (sale.paymentDetail1) totalCashSales += sale.paymentDetail1;
          if (sale.paymentDetail2) totalOnlineSales += sale.paymentDetail2;
          break;
        case 'Half Cash + Not Paid':
          if (sale.paymentDetail1) totalCashSales += sale.paymentDetail1;
          if (sale.paymentDetail2) totalNotPaidSales += sale.paymentDetail2;
          break;
        case 'Half Online + Not Paid':
          if (sale.paymentDetail1) totalOnlineSales += sale.paymentDetail1;
          if (sale.paymentDetail2) totalNotPaidSales += sale.paymentDetail2;
          break;
        default:
          break;
      }
    }

    let totalCashExpenses = 0, totalOnlineExpenses = 0;
    for (const exp of expenses) {
      const expenseAmount = exp.expenseCost;
      switch(exp.expenseStatus) {
        case 'Paid Cash':
          totalCashExpenses += expenseAmount;
          break;
        case 'Paid Online':
          totalOnlineExpenses += expenseAmount;
          break;
        case 'Half Cash + Half Online':
          if (exp.expenseDetail1) totalCashExpenses += exp.expenseDetail1;
          if (exp.expenseDetail2) totalOnlineExpenses += exp.expenseDetail2;
          break;
        case 'Half Cash + Not Paid':
          if (exp.expenseDetail1) totalCashExpenses += exp.expenseDetail1;
          break;
        case 'Half Online + Not Paid':
          if (exp.expenseDetail1) totalOnlineExpenses += exp.expenseDetail1;
          break;
        default:
          break;
      }
    }
    const finalCash = parseFloat(openingBalance) + totalCashSales - totalCashExpenses;

    // Calculate remaining subscription days.
    let subscriptionRemaining = 0;
    if (req.session.user.subscriptionExpiry) {
      const diffTime = new Date(req.session.user.subscriptionExpiry) - new Date();
      subscriptionRemaining = Math.max(Math.ceil(diffTime / (1000 * 60 * 60 * 24)), 0);
    }
    
    res.render('index', { 
      products, 
      sales, 
      expenses, 
      saleDate, 
      categories, 
      openingBalance,
      openingTime,
      closingTime,
      totalProfit,
      totalSales,
      totalCashSales,
      totalOnlineSales,
      totalNotPaidSales,
      totalCashExpenses,
      totalOnlineExpenses,
      finalCash,
      subscriptionRemaining,
      user: req.session.user
    });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /expense – Show expenses for a selected month.
app.get('/expense', isAuthenticated, restrictRoute('/expense'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const today = new Date();
    const currentYear = today.getFullYear();
    const currentMonth = String(today.getMonth() + 1).padStart(2, '0');
    const defaultMonth = `${currentYear}-${currentMonth}`;
    const monthParam = req.query.month || defaultMonth;
    const startDate = monthParam + '-01';
    const [year, mon] = monthParam.split('-');
    let nextMonthNum = parseInt(mon, 10) + 1;
    let nextYear = parseInt(year, 10);
    if (nextMonthNum > 12) { nextMonthNum = 1; nextYear++; }
    const nextMonth = `${nextYear}-${String(nextMonthNum).padStart(2, '0')}-01`;

    const expenseSnapshot = await db.collection('expenses')
      .where('accountId', '==', accountId)
      .where('saleDate', '>=', startDate)
      .where('saleDate', '<', nextMonth)
      .orderBy('createdAt', 'desc')
      .get();
    const expenses = expenseSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    const totalExpense = expenses.reduce((sum, exp) => sum + exp.expenseCost, 0);

    const groupedExpenses = {};
    expenses.forEach(exp => {
      let createdAt = (exp.createdAt && typeof exp.createdAt.toDate === 'function')
                      ? exp.createdAt.toDate() : new Date(exp.createdAt);
      if (!isNaN(createdAt.getTime())) {
        const dateStr = createdAt.toISOString().substring(0, 10);
        groupedExpenses[dateStr] = groupedExpenses[dateStr] || [];
        groupedExpenses[dateStr].push(exp);
      }
    });

    res.render('expense', { month: monthParam, groupedExpenses, totalExpense });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /expense – Process expense transactions.
app.post('/expense', isAuthenticated, restrictRoute('/expense'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const saleDate = req.body.saleDate;
    const { redirectTo } = req.body;
    let { expenseReason, expenseCost, expenseStatus, expenseDetail1, expenseDetail2 } = req.body;
    if (!Array.isArray(expenseReason)) {
      expenseReason = [expenseReason];
      expenseCost = [expenseCost];
      expenseStatus = [expenseStatus];
      expenseDetail1 = [expenseDetail1];
      expenseDetail2 = [expenseDetail2];
    }
    await Promise.all(expenseReason.map(async (reason, i) => {
      const cost = parseFloat(expenseCost[i]);
      const status = expenseStatus[i] || 'Paid Cash';
      const detail1 = expenseDetail1[i];
      const detail2 = expenseDetail2[i];
      let expenseData = {
        expenseReason: reason,
        expenseCost: cost,
        expenseStatus: status,
        saleDate,
        accountId,
        createdAt: new Date()
      };
      if (detail1 !== undefined && detail1 !== "") expenseData.expenseDetail1 = parseFloat(detail1);
      if (detail2 !== undefined && detail2 !== "") expenseData.expenseDetail2 = parseFloat(detail2);
      await db.collection('expenses').add(expenseData);
    }));
    const selectedMonth = saleDate.substring(0, 7);
    res.redirect(redirectTo === 'expense' ? (`/expense?month=${selectedMonth}`) : (`/?saleDate=${saleDate}`));
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /sale – Process sale transactions with FIFO and weighted average.
app.post('/sale', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    let { productId, customProductId, retailPrice, saleQuantity, saleDate, status, extraInfo, paymentDetail1, paymentDetail2 } = req.body;
    const selectedProductId = (customProductId && customProductId.trim()) ? customProductId : productId;
    
    saleQuantity = parseInt(saleQuantity);
    const chosenRetailPrice = parseFloat(retailPrice);

    const productRef = db.collection('products').doc(selectedProductId);
    const productDoc = await productRef.get();
    if (!productDoc.exists) return res.status(404).send("Product not found");
    const product = productDoc.data();
    if (product.accountId !== accountId) return res.status(403).send("Unauthorized");

    const batchesSnapshot = await db.collection('stockBatches')
      .where('productId', '==', selectedProductId)
      .where('remainingQuantity', '>', 0)
      .orderBy('batchDate', 'asc')
      .get();
    let remainingToSell = saleQuantity;
    let totalWholesaleCost = 0;
    let weightedRetailTotal = 0;
    let updatedBatches = [];
    batchesSnapshot.forEach(batchDoc => {
      if (remainingToSell <= 0) return;
      const batchData = batchDoc.data();
      const available = batchData.remainingQuantity;
      if (available <= 0) return;
      const qtyFromBatch = Math.min(available, remainingToSell);
      totalWholesaleCost += batchData.purchasePrice * qtyFromBatch;
      weightedRetailTotal += batchData.salePrice * qtyFromBatch;
      remainingToSell -= qtyFromBatch;
      updatedBatches.push({ id: batchDoc.id, newRemaining: available - qtyFromBatch });
    });
    if (remainingToSell > 0) return res.status(400).send("Not enough quantity in stock (batches)");
    
    const avgWholesale = totalWholesaleCost / saleQuantity;
    const avgRetailDefault = weightedRetailTotal / saleQuantity;
    const profitPerUnit = chosenRetailPrice - avgWholesale;
    const totalProfit = profitPerUnit * saleQuantity;
    const totalSale = chosenRetailPrice * saleQuantity;
    
    await Promise.all(updatedBatches.map(b =>
      db.collection('stockBatches').doc(b.id).update({ remainingQuantity: b.newRemaining })
    ));
    
    const newProductQuantity = product.quantity - saleQuantity;
    if (newProductQuantity < 0) return res.status(400).send("Not enough quantity in product stock");
    await productRef.update({ quantity: newProductQuantity });

    const obDoc = await db.collection('openingBalances').doc(`${accountId}_${saleDate}`).get();
    const openingBalance = obDoc.exists ? obDoc.data().balance : 0;

    let saleData = {
      productId: selectedProductId,
      productName: product.productName,
      wholesalePrice: avgWholesale,
      retailPrice: chosenRetailPrice,
      defaultRetail: avgRetailDefault,
      saleQuantity,
      profit: totalProfit,
      profitPerUnit,
      totalSale,
      saleDate,
      status,
      extraInfo,
      openingBalance,
      createdAt: new Date(),
      accountId,
      customProductId: (product.productId && product.productId.trim() !== "") ? product.productId.trim() : "-"
    };
    if (paymentDetail1 !== undefined && paymentDetail1 !== "") saleData.paymentDetail1 = parseFloat(paymentDetail1);
    if (paymentDetail2 !== undefined && paymentDetail2 !== "") saleData.paymentDetail2 = parseFloat(paymentDetail2);
    
    await db.collection('sales').add(saleData);
    res.redirect(`/?saleDate=${saleDate}`);
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /update-opening-balance – Update the opening balance.
app.post('/update-opening-balance', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { saleDate, openingBalance, openingTime, closingTime } = req.body;
    const balance = parseFloat(openingBalance);
    await db.collection('openingBalances').doc(`${accountId}_${saleDate}`).set({
      balance,
      openingTime: openingTime || "",
      closingTime: closingTime || "",
      updatedAt: new Date(),
      accountId
    }, { merge: true });
    res.redirect(`/?saleDate=${saleDate}`);
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /add-product – Render the add product (or stock batch) form.
app.get('/add-product', isAuthenticated, restrictRoute('/add-product'), async (req, res) => {
  try {
    const categories = await getCategories(req.session.user.accountId);
    const selectedCategory = req.query.category || '';
    const sortOrder = req.query.sortOrder || 'asc';
    
    let productsQuery = db.collection('products').where('accountId', '==', req.session.user.accountId);
    if (selectedCategory.trim() !== "") productsQuery = productsQuery.where('category', '==', selectedCategory);
    productsQuery = productsQuery.orderBy('productName', sortOrder);
    const productsSnapshot = await productsQuery.get();
    const existingProducts = productsSnapshot.docs.map(doc => ({ id: doc.id, name: doc.data().productName }));
    
    res.render('addProduct', { 
      success: req.query.success,
      errorMessage: null,
      categories,
      existingProducts,
      selectedCategory,
      sortOrder
    });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /add-product – Process new product (or stock batch) submission.
app.post('/add-product', isAuthenticated, restrictRoute('/add-product'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { existingProduct, productName, wholesalePrice, retailPrice, quantity, productId, selectedCategory, newCategory } = req.body;
    const chosenWholesale = parseFloat(wholesalePrice);
    const chosenRetail = parseFloat(retailPrice);
    const chosenQuantity = parseFloat(quantity);
    const category = (newCategory && newCategory.trim() !== "") ? newCategory.trim() : (selectedCategory || "");
    const enteredProductId = (productId && productId.trim() !== "") ? productId.trim() : '-';
    
    let productDoc;
    if (existingProduct && existingProduct !== "new") {
      const prodRef = db.collection('products').doc(existingProduct);
      const prodSnapshot = await prodRef.get();
      if (!prodSnapshot.exists) return res.status(404).send("Selected product not found");
      productDoc = prodSnapshot;
      const productData = productDoc.data();
      const currentQuantity = productData.quantity || 0;
      const newQuantityTotal = currentQuantity + chosenQuantity;
      const currentWholesale = productData.wholesalePrice || chosenWholesale;
      const currentRetail = productData.retailPrice || chosenRetail;
      const weightedWholesale = ((currentQuantity * currentWholesale) + (chosenQuantity * chosenWholesale)) / newQuantityTotal;
      const weightedRetail = ((currentQuantity * currentRetail) + (chosenQuantity * chosenRetail)) / newQuantityTotal;
      const weightedProfitMargin = weightedRetail - weightedWholesale;
      
      const oldestWholesale = (productData.oldestWholesale !== undefined) ? productData.oldestWholesale : chosenWholesale;
      const oldestBatchQty = (productData.oldestBatchQty !== undefined) ? productData.oldestBatchQty : currentQuantity;
      const oldestRetail = (productData.oldestRetail !== undefined) ? productData.oldestRetail : chosenRetail;
      const secondWholesale = chosenWholesale;
      
      await db.collection('products').doc(productDoc.id).update({
        quantity: newQuantityTotal,
        wholesalePrice: weightedWholesale,
        retailPrice: weightedRetail,
        profitMargin: weightedProfitMargin,
        updatedAt: new Date(),
        oldestWholesale,
        oldestBatchQty,
        secondWholesale,
        oldestRetail,
        secondRetail: chosenRetail,
        category: category || productData.category
      });
    } else {
      const productQuery = await db.collection('products')
        .where('accountId', '==', accountId)
        .where('productName', '==', productName)
        .limit(1)
        .get();
      if (!productQuery.empty) {
        productDoc = productQuery.docs[0];
        const productData = productDoc.data();
        const currentQuantity = productData.quantity || 0;
        const newQuantityTotal = currentQuantity + chosenQuantity;
        const currentWholesale = productData.wholesalePrice || chosenWholesale;
        const currentRetail = productData.retailPrice || chosenRetail;
        const weightedWholesale = ((currentQuantity * currentWholesale) + (chosenQuantity * chosenWholesale)) / newQuantityTotal;
        const weightedRetail = ((currentQuantity * currentRetail) + (chosenQuantity * chosenRetail)) / newQuantityTotal;
        const weightedProfitMargin = weightedRetail - weightedWholesale;
        
        const oldestWholesale = (productData.oldestWholesale !== undefined) ? productData.oldestWholesale : chosenWholesale;
        const oldestBatchQty = (productData.oldestBatchQty !== undefined) ? productData.oldestBatchQty : currentQuantity;
        const oldestRetail = (productData.oldestRetail !== undefined) ? productData.oldestRetail : chosenRetail;
        const secondWholesale = chosenWholesale;
        
        await db.collection('products').doc(productDoc.id).update({
          quantity: newQuantityTotal,
          wholesalePrice: weightedWholesale,
          retailPrice: weightedRetail,
          profitMargin: weightedProfitMargin,
          updatedAt: new Date(),
          oldestWholesale,
          oldestBatchQty,
          secondWholesale,
          oldestRetail,
          secondRetail: chosenRetail,
          category: category || productData.category
        });
      } else {
        const newProductData = {
          productName,
          wholesalePrice: chosenWholesale,
          retailPrice: chosenRetail,
          quantity: chosenQuantity,
          profitMargin: chosenRetail - chosenWholesale,
          category,
          createdAt: new Date(),
          productId: enteredProductId,
          accountId,
          oldestWholesale: chosenWholesale,
          oldestBatchQty: chosenQuantity,
          secondWholesale: null,
          oldestRetail: chosenRetail,
          secondRetail: null
        };
        const docRef = await db.collection('products').add(newProductData);
        productDoc = { id: docRef.id, data: () => newProductData };
      }
    }
    
    const stockBatchData = {
      productId: productDoc.id,
      productName: (existingProduct && existingProduct !== "new") ? productDoc.data().productName : productName,
      purchasePrice: chosenWholesale,
      salePrice: chosenRetail,
      quantity: chosenQuantity,
      remainingQuantity: chosenQuantity,
      batchDate: new Date(),
      accountId,
      batchProductId: enteredProductId
    };
    await db.collection('stockBatches').add(stockBatchData);
    
    res.redirect('/add-product?success=1');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// VIEW & MANAGE PRODUCTS
// -----------------------------------------------------------------------------

// GET /view-products – View all products with optional category filter.
app.get('/view-products', isAuthenticated, restrictRoute('/view-products'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const filterCategory = req.query.filterCategory || '';
    const stockThreshold = req.query.stockThreshold || '';
    const sortOrder = req.query.sortOrder || 'asc';
    
    let productsQuery = db.collection('products').where('accountId', '==', accountId);
    if (filterCategory.trim() !== '') productsQuery = productsQuery.where('category', '==', filterCategory);
    if (stockThreshold.trim() !== '') productsQuery = productsQuery.where('quantity', '<', parseInt(stockThreshold));
    productsQuery = productsQuery.orderBy('productName', sortOrder);
    const productsSnapshot = await productsQuery.get();
    
    const products = await Promise.all(productsSnapshot.docs.map(async doc => {
      let product = { id: doc.id, ...doc.data() };
      const batchesSnapshot = await db.collection('stockBatches')
        .where('productId', '==', doc.id)
        .get();
      product.batches = batchesSnapshot.docs.map(batchDoc => {
        let batchData = batchDoc.data();
        batchData.profitMargin = batchData.salePrice - batchData.purchasePrice;
        return { id: batchDoc.id, ...batchData };
      });
      return product;
    }));
    const categories = await getCategories(accountId);
    res.render('viewProducts', { products, categories, filterCategory, stockThreshold, sortOrder });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// STOCK BATCH MANAGEMENT
// -----------------------------------------------------------------------------

// NEW ROUTE: Delete a stock batch.
app.post('/delete-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const batchId = req.params.batchId;
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchDoc = await batchRef.get();
    if (!batchDoc.exists) return res.status(404).send("Stock batch not found");

    const batchData = batchDoc.data();
    if (batchData.accountId !== accountId) return res.status(403).send("Access denied: You do not have permission to delete this batch");

    await batchRef.delete();
    await recalcProductFromBatches(batchData.productId);
    res.redirect('/view-products');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// Helper: Recalculate product values based on stock batches.
async function recalcProductFromBatches(productId) {
  const snapshot = await db.collection('stockBatches').where('productId', '==', productId).get();
  let totalRemaining = 0, totalWholesale = 0, totalRetail = 0;
  snapshot.forEach(doc => {
    const data = doc.data();
    totalRemaining += data.remainingQuantity;
    totalWholesale += data.remainingQuantity * data.purchasePrice;
    totalRetail += data.remainingQuantity * data.salePrice;
  });
  let newWholesale = 0, newRetail = 0, profitMargin = 0;
  if (totalRemaining > 0) {
    newWholesale = totalWholesale / totalRemaining;
    newRetail = totalRetail / totalRemaining;
    profitMargin = newRetail - newWholesale;
  }
  await db.collection('products').doc(productId).update({
    quantity: totalRemaining,
    wholesalePrice: newWholesale,
    retailPrice: newRetail,
    profitMargin: profitMargin,
    updatedAt: new Date()
  });
}

// GET /edit-stock-batch/:batchId – Render the edit form for a stock batch.
app.get('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const batchId = req.params.batchId;
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchDoc = await batchRef.get();
    if (!batchDoc.exists) return res.status(404).send("Stock batch not found");

    const batchData = batchDoc.data();
    if (batchData.accountId !== accountId) return res.status(403).send("Access denied");

    const productDoc = await db.collection('products').doc(batchData.productId).get();
    if (!productDoc.exists) return res.status(404).send("Parent product not found");
    const productData = productDoc.data();
    const categories = await getCategories(accountId);

    res.render('editStockBatch', { 
      batch: { id: batchDoc.id, ...batchData }, 
      product: { id: productDoc.id, ...productData },
      categories
    });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /edit-stock-batch/:batchId – Process stock batch update.
app.post('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const batchId = req.params.batchId;
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchDoc = await batchRef.get();
    if (!batchDoc.exists) return res.status(404).send("Stock batch not found");
    const batchData = batchDoc.data();
    if (batchData.accountId !== accountId) return res.status(403).send("Access denied");

    const newProductName = (req.body.productName && req.body.productName.trim() !== "") ? req.body.productName.trim() : batchData.productName;
    const purchasePrice = parseFloat(req.body.purchasePrice);
    const salePrice = parseFloat(req.body.salePrice);
    const quantity = parseInt(req.body.quantity, 10);
    const batchProductId = (req.body.productId && req.body.productId.trim() !== "") ? req.body.productId.trim() : "-";
    const selectedCategory = req.body.selectedCategory;
    const newCategory = (req.body.newCategory && req.body.newCategory.trim() !== "") ? req.body.newCategory.trim() : "";
    const category = newCategory || selectedCategory;

    await batchRef.update({
      purchasePrice,
      salePrice,
      quantity,
      remainingQuantity: quantity,
      batchProductId,
      updatedAt: new Date(),
      productName: newProductName
    });

    const productRef = db.collection('products').doc(batchData.productId);
    const productDoc = await productRef.get();
    if (!productDoc.exists) return res.status(404).send("Parent product not found");

    await productRef.update({
      productName: newProductName,
      category: category,
      updatedAt: new Date()
    });
    await recalcProductFromBatches(batchData.productId);
    res.redirect('/view-products');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// SALES & PROFIT REPORTING
// -----------------------------------------------------------------------------

// GET /sales – Sales Report and Filtering Route.
app.get('/sales', isAuthenticated, restrictRoute('/sales'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { saleDate, month, status } = req.query;
    let salesQuery = db.collection('sales').where('accountId', '==', accountId).orderBy('createdAt', 'desc');
    let expenseQuery = db.collection('expenses').where('accountId', '==', accountId).orderBy('createdAt', 'desc');

    if (saleDate) {
      salesQuery = salesQuery.where('saleDate', '==', saleDate);
      expenseQuery = expenseQuery.where('saleDate', '==', saleDate);
    } else if (month) {
      const [year, monthNum] = month.split('-');
      const startDate = `${month}-01`;
      let nextMonthNum = parseInt(monthNum) + 1;
      let nextYear = parseInt(year);
      if (nextMonthNum > 12) { nextMonthNum = 1; nextYear++; }
      const nextMonth = `${nextYear}-${String(nextMonthNum).padStart(2, '0')}-01`;
      salesQuery = salesQuery.where('saleDate', '>=', startDate).where('saleDate', '<', nextMonth);
      expenseQuery = expenseQuery.where('saleDate', '>=', startDate).where('saleDate', '<', nextMonth);
    }
    if (status && status.trim() !== "" && status !== "All") {
      salesQuery = salesQuery.where('status', '==', status);
    }

    const [salesSnapshot, expenseSnapshot] = await Promise.all([salesQuery.get(), expenseQuery.get()]);

    const sales = salesSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    const expenses = expenseSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    const allDatesSet = new Set();
    sales.forEach(sale => allDatesSet.add(sale.saleDate));
    expenses.forEach(exp => allDatesSet.add(exp.saleDate));
    const allDates = Array.from(allDatesSet);

    const openingTimes = {};
    await Promise.all(allDates.map(async (date) => {
      const obDoc = await db.collection('openingBalances').doc(`${accountId}_${date}`).get();
      openingTimes[date] = obDoc.exists ? {
        openingTime: obDoc.data().openingTime || "",
        closingTime: obDoc.data().closingTime || ""
      } : { openingTime: "", closingTime: "" };
    }));

    const profitWithoutExpenses = sales.reduce((sum, sale) => sum + sale.profit, 0);
    const totalExpensesAmount = expenses.reduce((sum, exp) => sum + exp.expenseCost, 0);
    const profitAfterExpenses = profitWithoutExpenses - totalExpensesAmount;

    res.render('sales', { 
      sales, 
      expenses, 
      saleDate, 
      month, 
      status,
      profitWithoutExpenses,
      totalExpensesAmount,
      profitAfterExpenses,
      openingTimes
    });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /profit – Profit Report Route.
app.get('/profit', isAuthenticated, restrictRoute('/profit'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const { month, year } = req.query;
    let salesQuery = db.collection('sales').where('accountId', '==', accountId);
    let expenseQuery = db.collection('expenses').where('accountId', '==', accountId);
    
    if (month) {
      const [y, m] = month.split('-');
      const startDate = `${month}-01`;
      let nextMonthNum = parseInt(m) + 1;
      let nextYear = parseInt(y);
      if (nextMonthNum > 12) { nextMonthNum = 1; nextYear++; }
      const nextMonth = `${nextYear}-${String(nextMonthNum).padStart(2, '0')}-01`;
      salesQuery = salesQuery.where('saleDate', '>=', startDate).where('saleDate', '<', nextMonth);
      expenseQuery = expenseQuery.where('saleDate', '>=', startDate).where('saleDate', '<', nextMonth);
    } else if (year) {
      const startDate = `${year}-01-01`;
      const endDate = `${parseInt(year)+1}-01-01`;
      salesQuery = salesQuery.where('saleDate', '>=', startDate).where('saleDate', '<', endDate);
      expenseQuery = expenseQuery.where('saleDate', '>=', startDate).where('saleDate', '<', endDate);
    } else {
      const currentYear = new Date().getFullYear();
      const startDate = `${currentYear}-01-01`;
      const endDate = `${currentYear+1}-01-01`;
      salesQuery = salesQuery.where('saleDate', '>=', startDate).where('saleDate', '<', endDate);
      expenseQuery = expenseQuery.where('saleDate', '>=', startDate).where('saleDate', '<', endDate);
    }
    
    const [salesSnapshot, expenseSnapshot] = await Promise.all([salesQuery.get(), expenseQuery.get()]);
    const sales = salesSnapshot.docs.map(doc => doc.data());
    const expenses = expenseSnapshot.docs.map(doc => doc.data());
    
    const totalProfit = sales.reduce((sum, sale) => sum + sale.profit, 0);
    const totalExpenses = expenses.reduce((sum, exp) => sum + exp.expenseCost, 0);
    const netProfit = totalProfit - totalExpenses;
    
    const profitByMonth = {};
    sales.forEach(sale => {
      const saleMonth = sale.saleDate.substring(0,7);
      if (!profitByMonth[saleMonth]) profitByMonth[saleMonth] = { profit: 0, expenses: 0, netProfit: 0 };
      profitByMonth[saleMonth].profit += sale.profit;
    });
    expenses.forEach(exp => {
      const expMonth = exp.saleDate.substring(0,7);
      if (!profitByMonth[expMonth]) profitByMonth[expMonth] = { profit: 0, expenses: 0, netProfit: 0 };
      profitByMonth[expMonth].expenses += exp.expenseCost;
    });
    Object.keys(profitByMonth).forEach(m => {
      profitByMonth[m].netProfit = profitByMonth[m].profit - profitByMonth[m].expenses;
    });
    
    res.render('profit', { 
      sales, 
      expenses, 
      totalProfit, 
      totalExpenses, 
      netProfit, 
      profitByMonth,
      monthFilter: month || '',
      yearFilter: req.query.year || ''
    });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// SUBSCRIPTION & PAYMENT ROUTES
// -----------------------------------------------------------------------------

// GET /pricing – Render subscription plans page.
app.get('/pricing', isAuthenticated, (req, res) => {
  const now = new Date();
  if (req.session.user.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > now) return res.redirect('/');
  res.render('pricing', { user: req.session.user });
});

// Subscription routes – Create Razorpay order and render payment page.
app.get('/subscribe/monthly', isAuthenticated, async (req, res) => {
  const amount = 400 * 100;
  const currency = 'INR';
  const receipt = `receipt_monthly_${Date.now()}`;
  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });
    res.render('payment', { order, plan: 'Monthly', amount: 400, user: req.session.user });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

app.get('/subscribe/half-yearly', isAuthenticated, async (req, res) => {
  const amount = 4599 * 100;
  const currency = 'INR';
  const receipt = `receipt_halfyearly_${Date.now()}`;
  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });
    res.render('payment', { order, plan: 'Half-Yearly', amount: 4599, user: req.session.user });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

app.get('/subscribe/yearly', isAuthenticated, async (req, res) => {
  const amount = 8599 * 100;
  const currency = 'INR';
  const receipt = `receipt_yearly_${Date.now()}`;
  try {
    const order = await razorpay.orders.create({ amount, currency, receipt });
    res.render('payment', { order, plan: 'Yearly', amount: 8599, user: req.session.user });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// Payment success callback.
app.post('/payment-success', isAuthenticated, async (req, res) => {
  try {
    const { plan } = req.body;
    let subscriptionDurationDays;
    if (plan === 'Monthly') subscriptionDurationDays = 30;
    else if (plan === 'Half-Yearly') subscriptionDurationDays = 182;
    else if (plan === 'Yearly') subscriptionDurationDays = 365;
    else return res.status(400).send("Invalid subscription plan");
    
    const currentTime = new Date();
    let newExpiry = req.session.user.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > currentTime
                    ? new Date(req.session.user.subscriptionExpiry) : currentTime;
    newExpiry.setDate(newExpiry.getDate() + subscriptionDurationDays);
    
    await db.collection('users').doc(req.session.user.id).update({ subscriptionExpiry: newExpiry });
    req.session.user.subscriptionExpiry = newExpiry;
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /profile – Render the profile page (master only).
app.get('/profile', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.session.user.id).get();
    if (!userDoc.exists) return res.status(404).send("User not found");
    let userData = userDoc.data();
    if (userData.subscriptionExpiry) {
      userData.subscriptionExpiry = (typeof userData.subscriptionExpiry.toDate === 'function') ?
                                    userData.subscriptionExpiry.toDate() : new Date(userData.subscriptionExpiry);
    }
    res.render('profile', { user: userData });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /billing – Render billing/subscription details page (master only).
app.get('/billing', isAuthenticated, requireMaster, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.session.user.id).get();
    if (!userDoc.exists) return res.status(404).send("User not found");
    let userData = userDoc.data();
    if (userData.subscriptionExpiry) {
      userData.subscriptionExpiry = (typeof userData.subscriptionExpiry.toDate === 'function') ?
                                    userData.subscriptionExpiry.toDate() : new Date(userData.subscriptionExpiry);
    }
    res.render('billing', { user: userData });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// -----------------------------------------------------------------------------
// START THE SERVER
// -----------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
