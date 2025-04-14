// app.js
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

// Store your secret key in an environment variable for security.
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

app.post('/verify-captcha', async (req, res) => {
  const token = req.body.token; // The token from your client-side reCAPTCHA

  // Verify the token with the reCAPTCHA server.
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

// Serve static files and favicon.
app.use(express.static('public'));
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

// Setup session middleware with one-month duration (30 days)
app.use(session({
  store: new FirestoreStore({
    dataset: admin.firestore(), // Alternatively, you can use 'db' if you prefer.
    kind: 'express-sessions'     // (Optional) Custom collection name in Firestore.
  }),
  secret: process.env.SESSION_SECRET, // Replace with a strong secret or use an environment variable for production.
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000  // 30 days cookie lifespan
  }
}));

// Use body-parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set view engine to EJS and set views directory
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ***********************
// NEW GLOBAL SUBSCRIPTION CHECK MIDDLEWARE
// ***********************
// This middleware ensures that if the user is logged in but their subscription is missing or expired,
// then if they try to access any route that is not in the allowed list, the payment page will be rendered.
//
// Allowed routes for non‑subscribed users (they can access these regardless of subscription status):
// - Homepage ("/")
// - Login page ("/login")
// - Registration page ("/register")
// - Documentation page ("/documentation")
// - Payment/Pricing and subscription related routes to allow the user to subscribe:
//     "/pricing", "/subscribe/monthly", "/subscribe/half-yearly", "/subscribe/yearly", "/payment-success"
app.use((req, res, next) => {
  // If not logged in, no subscription check is necessary.
  if (!req.session || !req.session.user) {
    return next();
  }

  // Define allowed routes.
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

  // If the current request path is in the allowedPaths, let it pass.
  if (allowedPaths.includes(req.path)) {
    return next();
  }

  // Check the subscription expiry stored in the session.
  const subscriptionExpiry = req.session.user.subscriptionExpiry;
  const now = new Date();
  if (!subscriptionExpiry || new Date(subscriptionExpiry) <= now) {
    // Render the payment view (payment.ejs) with null values for order, plan and amount.
    // This forces the non‑subscribed user to see the payment page on restricted routes.
    return res.redirect('/pricing');

  }

  // Otherwise, allow the request to proceed.
  next();
});

// ***********************
// END OF SUBSCRIPTION CHECK MIDDLEWARE
// ***********************

function requireMaster(req, res, next) {
  if (req.session.user && req.session.user.isMaster) {
    return next();
  }
  return res.status(403).send("Access denied: Only master users can access this page.");
}



// Initialize Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ----------------------
// HELPER FUNCTIONS
// ----------------------

// Middleware to check if a user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.redirect('/login');
}

// Function to get distinct categories from products for a given account
async function getCategories(accountId) {
  const productsSnapshot = await db.collection('products')
    .where('accountId', '==', accountId)
    .get();
  const categorySet = new Set();
  productsSnapshot.forEach(doc => {
    const data = doc.data();
    if (data.category) {
      categorySet.add(data.category);
    }
  });
  return Array.from(categorySet);
}

// A list of available (configurable) restricted routes for sub‑users.
const availableRestrictedRoutes = [
  { path: '/profit', label: 'Profit Report' },
  { path: '/sales', label: 'Sales Report' },
  { path: '/expense', label: 'Expense Report' },
  { path: '/add-product', label: 'Add Product' },
  { path: '/view-products', label: 'View Products' }
];

// Middleware factory to restrict certain routes for subusers based on their lockedRoutes.
function restrictRoute(routeIdentifier) {
  return async function(req, res, next) {
    // Allow master users.
    if (req.session.user.isMaster) {
      return next();
    }
    // For subusers check if the route is locked.
    if (req.session.lockedRoutes && req.session.lockedRoutes.includes(routeIdentifier)) {
      return res.status(403).send("Access denied: You do not have permission to access this route.");
    }
    next();
  }
}

// ----------------------
// AUTHENTICATION ROUTES
// ----------------------

// GET /register – Render the registration form.
app.get('/register', async (req, res) => {
  res.render('register');
});

// POST /register – Process registration and create master account.
app.post('/register', async (req, res) => {
  try {
    const { name, email, phone, address, location, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
    }
    // Normalize the email to lower case to prevent duplicate registrations with different cases.
    const normalizedEmail = email.trim().toLowerCase();
    // Check if a user with the same email already exists.
    const userQuery = await db.collection('users').where('email', '==', normalizedEmail).get();
    if (!userQuery.empty) {
      return res.status(400).send("User already exists");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create master account without accountId first.
    const newUserRef = await db.collection('users').add({
      name,
      email: normalizedEmail,
      phone,
      address,
      location,
      password: hashedPassword,
      isMaster: true,
      createdAt: new Date()
    });
    // Set accountId to be the user's own id for the master account.
    await db.collection('users').doc(newUserRef.id).update({ accountId: newUserRef.id });
    res.redirect('/login');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


// GET /login – Render the login form
app.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    // User is already authenticated, redirect to the dashboard/home page.
    return res.redirect('/');
  }
  res.render('login');
});

app.get('/customerservice', (req, res) => {
  res.render('cs');
});

// POST /login – Process login, validate credentials, and check for subscription expiry.
app.post('/login', async (req, res) => {
  try {
    let { identifier, password } = req.body;
    let userDoc;
    
    // If the identifier looks like an email, normalize it to lower case.
    if (identifier.includes('@')) {
      identifier = identifier.trim().toLowerCase();
    }
    
    // Try to find the user by email.
    const emailQuery = await db.collection('users').where('email', '==', identifier).get();
    if (!emailQuery.empty) {
      userDoc = emailQuery.docs[0];
    } else {
      // Try to find the user by sub‑user ID.
      const subUserQuery = await db.collection('users').where('subUserId', '==', identifier).get();
      if (!subUserQuery.empty) {
        userDoc = subUserQuery.docs[0];
      } else {
        // Lastly, try to find the user by phone.
        const phoneQuery = await db.collection('users').where('phone', '==', identifier).get();
        if (!phoneQuery.empty) {
          userDoc = phoneQuery.docs[0];
        }
      }
    }
    if (!userDoc) {
      return res.status(400).send("User not found");
    }
    const userData = userDoc.data();
    
    // Process subscription expiry.
    let subscriptionExpiry = null;
    if (userData.subscriptionExpiry) {
      if (typeof userData.subscriptionExpiry.toDate === 'function') {
        subscriptionExpiry = userData.subscriptionExpiry.toDate();
      } else {
        subscriptionExpiry = new Date(userData.subscriptionExpiry);
      }
    }
    
    // For sub‑users, fetch subscriptionExpiry from master account.
    if (!userData.isMaster) {
      const masterDoc = await db.collection('users').doc(userData.accountId).get();
      if (masterDoc.exists) {
        const masterData = masterDoc.data();
        if (masterData.subscriptionExpiry) {
          if (typeof masterData.subscriptionExpiry.toDate === 'function') {
            subscriptionExpiry = masterData.subscriptionExpiry.toDate();
          } else {
            subscriptionExpiry = new Date(masterData.subscriptionExpiry);
          }
        }
      }
    }
    
    // Validate the password.
    const validPassword = await bcrypt.compare(password, userData.password);
    if (!validPassword) {
      return res.status(400).send("Invalid password");
    }
    
    // Save user details (including subscription expiry) into the session.
    req.session.user = {
      id: userDoc.id,
      name: userData.name,
      email: userData.email,
      isMaster: userData.isMaster || false,
      accountId: userData.accountId || userDoc.id,
      subscriptionExpiry: subscriptionExpiry
    };
    
    // For sub‑users, load locked routes from Firestore.
    if (!req.session.user.isMaster) {
      const permDoc = await db.collection('permissions').doc(req.session.user.accountId).get();
      req.session.lockedRoutes = permDoc.exists ? (permDoc.data().lockedRoutes || []) : [];
    }
    
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});




// GET /logout – Log out the current user
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// GET /documentation – Render the documentation page.
app.get('/documentation', (req, res) => {
  res.render('documentations');
});

// ----------------------
// USER MANAGEMENT ROUTES (Master Only)
// ----------------------

// GET /create-user – Render the create sub‑user form (for master only)
// GET /create-user – Render the create sub‑user form (for master only)
app.get('/create-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) {
    return res.status(403).send("Access denied");
  }
  try {
    const usersSnapshot = await db.collection('users')
      .where('accountId', '==', req.session.user.accountId)
      .get();
    let users = [];
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      users.push({
        id: doc.id,
        name: userData.name,
        email: userData.email,
        isMaster: userData.isMaster,
        subUserId: userData.subUserId // Added to pass the sub-user id to the template.
      });
    });
    res.render('createuser', { users });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});




app.post('/create-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) {
    return res.status(403).send("Access denied");
  }
  try {
    // Count existing sub-users for the master account.
    const subUsersQuery = await db.collection('users')
      .where('accountId', '==', req.session.user.accountId)
      .where('isMaster', '==', false)
      .get();
    if (subUsersQuery.size >= 2) {
      return res.status(400).send("Sub‑user limit reached. Maximum 2 sub‑users allowed.");
    }

    // Only destructure the fields that exist in your EJS form.
    const { name, password, confirmPassword, subUserId } = req.body;
    if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
    }
    if (!subUserId || subUserId.trim() === "") {
      return res.status(400).send("Sub‑user ID is required");
    }

    // Check if the subUserId already exists for this account.
    const subUserQuery = await db.collection('users')
      .where('subUserId', '==', subUserId)
      .where('accountId', '==', req.session.user.accountId)
      .get();
    if (!subUserQuery.empty) {
      return res.status(400).send("Sub‑user ID already exists. Please generate a new one.");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').add({
      name,
      password: hashedPassword,
      isMaster: false,
      accountId: req.session.user.accountId,
      subUserId: subUserId,
      createdAt: new Date()
    });
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


// POST /edit-user – Update a sub‑user's name and/or password (master only)
app.post('/edit-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) {
    return res.status(403).send("Access denied");
  }
  try {
    // Now we expect 'userId', 'name', 'password', and 'confirmPassword'
    const { userId, name, password, confirmPassword } = req.body;
    
    if (password && password !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
    }
    
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists || userDoc.data().accountId !== req.session.user.accountId) {
      return res.status(403).send("Access denied");
    }
    
    // Prepare update data with the new name. Only update password if provided.
    const updateData = { name };
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }
    
    await userRef.update(updateData);
    res.redirect('/create-user');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


// POST /delete-user – Delete a sub‑user account (master only)
app.post('/delete-user', isAuthenticated, async (req, res) => {
  if (!req.session.user.isMaster) {
    return res.status(403).send("Access denied");
  }
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


// POST /delete-product/:productId – Delete a product if its quantity is zero and there are no batches.
app.post('/delete-product/:productId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const productId = req.params.productId;
    
    // Get the product document.
    const productRef = db.collection('products').doc(productId);
    const productDoc = await productRef.get();
    if (!productDoc.exists) {
      return res.status(404).send("Product not found");
    }
    
    const productData = productDoc.data();
    if (productData.accountId !== accountId) {
      return res.status(403).send("Access denied");
    }
    
    // Only allow deletion if quantity is zero.
    if (productData.quantity !== 0) {
      return res.status(400).send("Product cannot be deleted because its quantity is not zero");
    }
    
    // Check if there are any stock batches associated with this product.
    const batchesSnapshot = await db.collection('stockBatches')
      .where('productId', '==', productId)
      .get();
    if (!batchesSnapshot.empty) {
      return res.status(400).send("Product cannot be deleted because it has associated batches");
    }
    
    // Delete the product.
    await productRef.delete();
    res.redirect('/view-products');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


// ----------------------
// PERMISSION MANAGEMENT ROUTES (Master Only)
// ----------------------

// GET /permission – Render the permission management page (master only)
app.get('/permission', isAuthenticated, restrictRoute('/permission'), async (req, res) => {
  if (!req.session.user.isMaster) {
    return res.status(403).send("Access denied");
  }
  try {
    const permDoc = await db.collection('permissions').doc(req.session.user.accountId).get();
    let lockedRoutes = [];
    if (permDoc.exists) {
      lockedRoutes = permDoc.data().lockedRoutes || [];
    }
    res.render('permission', { lockedRoutes, availableRoutes: availableRestrictedRoutes, success: req.query.success });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /permission – Save the new permissions configuration (master only)
app.post('/permission', isAuthenticated, restrictRoute('/permission'), async (req, res) => {
  if (!req.session.user.isMaster) {
    return res.status(403).send("Access denied");
  }
  try {
    let lockedRoutes = req.body.lockedRoutes;
    if (!lockedRoutes) {
      lockedRoutes = [];
    } else if (!Array.isArray(lockedRoutes)) {
      lockedRoutes = [lockedRoutes];
    }
    await db.collection('permissions').doc(req.session.user.accountId).set({ lockedRoutes }, { merge: true });
    res.redirect('/permission?success=1');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// ----------------------
// PROTECTED APP ROUTES (Require Authentication)
// ----------------------

// Homepage: always available.
app.get('/', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const today = new Date();
    const pad = num => num.toString().padStart(2, '0');
    const defaultDate = `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;
    const saleDate = req.query.saleDate || defaultDate;

    // Fetch products for the current account.
    const productsSnapshot = await db.collection('products')
      .where('accountId', '==', accountId)
      .get();
    let products = [];
    for (const doc of productsSnapshot.docs) {
      let product = { id: doc.id, ...doc.data() };
      const batchesSnapshot = await db.collection('stockBatches')
        .where('productId', '==', doc.id)
        .where('remainingQuantity', '>', 0)
        .orderBy('batchDate', 'asc')
        .get();
      let batches = [];
      batchesSnapshot.forEach(batchDoc => {
        let batch = batchDoc.data();
        batches.push({
          wholesale: batch.purchasePrice,
          retail: batch.salePrice,
          qty: batch.remainingQuantity
        });
      });
      product.batches = batches;
      products.push(product);
    }

    const categories = await getCategories(accountId);

    // Fetch sales for the selected date.
    const salesSnapshot = await db.collection('sales')
      .where('accountId', '==', accountId)
      .where('saleDate', '==', saleDate)
      .orderBy('createdAt', 'desc')
      .get();
    let sales = [];
    salesSnapshot.forEach(doc => {
      sales.push({ id: doc.id, ...doc.data() });
    });

    // Fetch expenses for the selected date.
    const expenseSnapshot = await db.collection('expenses')
      .where('accountId', '==', accountId)
      .where('saleDate', '==', saleDate)
      .orderBy('createdAt', 'desc')
      .get();
    let expenses = [];
    expenseSnapshot.forEach(doc => {
      expenses.push(doc.data());
    });

    // Opening balance info.
    const openingDocId = `${accountId}_${saleDate}`;
    const obDoc = await db.collection('openingBalances').doc(openingDocId).get();
    let openingBalance = 0, openingTime = "", closingTime = "";
    if (obDoc.exists) {
      const obData = obDoc.data();
      openingBalance = obData.balance || 0;
      openingTime = obData.openingTime || "";
      closingTime = obData.closingTime || "";
    }

    // Calculate summary data.
    let totalProfit = 0, totalSales = 0, totalCashSales = 0, totalOnlineSales = 0, totalNotPaidSales = 0;
    sales.forEach(sale => {
      totalProfit += sale.profit;
      let saleAmount = sale.retailPrice * sale.saleQuantity;
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
    });

    let totalCashExpenses = 0, totalOnlineExpenses = 0;
    expenses.forEach(exp => {
      let expenseAmount = exp.expenseCost;
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
    });
    const finalCash = parseFloat(openingBalance) + totalCashSales - totalCashExpenses;
    
    // Calculate subscription remaining days.
    let subscriptionRemaining = 0;
    if (req.session.user.subscriptionExpiry) {
      let expiry = new Date(req.session.user.subscriptionExpiry);
      let now = new Date();
      let diffTime = expiry - now;
      subscriptionRemaining = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      if (subscriptionRemaining < 0) subscriptionRemaining = 0;
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
    const currentMonth = (today.getMonth() + 1).toString().padStart(2, '0');
    const defaultMonth = `${currentYear}-${currentMonth}`;
    const monthParam = req.query.month || defaultMonth;
    const startDate = monthParam + '-01';
    const [year, mon] = monthParam.split('-');
    let nextMonthNum = parseInt(mon, 10) + 1;
    let nextYear = parseInt(year, 10);
    if (nextMonthNum > 12) {
      nextMonthNum = 1;
      nextYear++;
    }
    const nextMonth = `${nextYear}-${nextMonthNum.toString().padStart(2, '0')}-01`;

    const expenseSnapshot = await db.collection('expenses')
      .where('accountId', '==', accountId)
      .where('saleDate', '>=', startDate)
      .where('saleDate', '<', nextMonth)
      .orderBy('createdAt', 'desc')
      .get();

    let expenses = [];
    expenseSnapshot.forEach(doc => {
      expenses.push({ id: doc.id, ...doc.data() });
    });

    let totalExpense = 0;
    expenses.forEach(exp => {
      totalExpense += exp.expenseCost;
    });

    // Group expenses by creation date.
    let groupedExpenses = {};
    expenses.forEach(exp => {
      let createdAt = exp.createdAt && typeof exp.createdAt.toDate === 'function'
                      ? exp.createdAt.toDate()
                      : new Date(exp.createdAt);
      if (isNaN(createdAt.getTime())) return;
      let expenseDate = createdAt.toISOString().substring(0, 10);
      if (!groupedExpenses[expenseDate]) {
        groupedExpenses[expenseDate] = [];
      }
      groupedExpenses[expenseDate].push(exp);
    });

    res.render('expense', { month: monthParam, groupedExpenses, totalExpense });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /expense – Process expense transaction.
app.post('/expense', isAuthenticated, restrictRoute('/expense'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const saleDate = req.body.saleDate;
    const { redirectTo } = req.body; // "expense" or "index"
    let { expenseReason, expenseCost, expenseStatus, expenseDetail1, expenseDetail2 } = req.body;
    if (!Array.isArray(expenseReason)) {
      expenseReason = [expenseReason];
      expenseCost = [expenseCost];
      expenseStatus = [expenseStatus];
      expenseDetail1 = [expenseDetail1];
      expenseDetail2 = [expenseDetail2];
    }
    for (let i = 0; i < expenseReason.length; i++) {
      const reason = expenseReason[i];
      const cost = parseFloat(expenseCost[i]);
      const status = expenseStatus[i] || 'Paid Cash';
      const detail1 = expenseDetail1[i];
      const detail2 = expenseDetail2[i];

      const expenseData = {
        expenseReason: reason,
        expenseCost: cost,
        expenseStatus: status,
        saleDate,
        accountId,
        createdAt: new Date()
      };

      if (detail1 !== undefined && detail1 !== "") {
        expenseData.expenseDetail1 = parseFloat(detail1);
      }
      if (detail2 !== undefined && detail2 !== "") {
        expenseData.expenseDetail2 = parseFloat(detail2);
      }
      await db.collection('expenses').add(expenseData);
    }
    if (redirectTo === 'expense') {
      const selectedMonth = saleDate.substring(0, 7);
      res.redirect('/expense?month=' + selectedMonth);
    } else {
      res.redirect('/?saleDate=' + saleDate);
    }
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// POST /sale – Process sale transaction with FIFO and weighted average.
app.post('/sale', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    let { productId, customProductId, retailPrice, saleQuantity, saleDate, status, extraInfo, paymentDetail1, paymentDetail2 } = req.body;
    // Use customProductId if provided.
    const selectedProductId = customProductId && customProductId.trim() !== "" ? customProductId : productId;
    
    saleQuantity = parseInt(saleQuantity);
    const chosenRetailPrice = parseFloat(retailPrice);

    // Retrieve the product.
    const productRef = db.collection('products').doc(selectedProductId);
    const productDoc = await productRef.get();
    if (!productDoc.exists) {
      return res.status(404).send("Product not found");
    }
    const product = productDoc.data();
    if (product.accountId !== accountId) {
      return res.status(403).send("Unauthorized");
    }

    // Retrieve stock batches in FIFO order.
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
      let batchData = batchDoc.data();
      let available = batchData.remainingQuantity;
      if (available <= 0) return;
      let qtyFromBatch = Math.min(available, remainingToSell);
      totalWholesaleCost += batchData.purchasePrice * qtyFromBatch;
      weightedRetailTotal += batchData.salePrice * qtyFromBatch;
      remainingToSell -= qtyFromBatch;
      updatedBatches.push({
        id: batchDoc.id,
        newRemaining: available - qtyFromBatch
      });
    });

    if (remainingToSell > 0) {
      return res.status(400).send("Not enough quantity in stock (batches)");
    }

    // Calculate weighted averages.
    let avgWholesale = totalWholesaleCost / saleQuantity;
    let avgRetailDefault = weightedRetailTotal / saleQuantity;
    let profitPerUnit = chosenRetailPrice - avgWholesale;
    let totalProfit = profitPerUnit * saleQuantity;
    let totalSale = chosenRetailPrice * saleQuantity;

    // Update stock batches.
    let batchUpdatePromises = updatedBatches.map(b =>
      db.collection('stockBatches').doc(b.id).update({ remainingQuantity: b.newRemaining })
    );
    await Promise.all(batchUpdatePromises);

    // Update overall product quantity.
    const newProductQuantity = product.quantity - saleQuantity;
    if (newProductQuantity < 0) {
      return res.status(400).send("Not enough quantity in product stock");
    }
    await productRef.update({ quantity: newProductQuantity });

    // Fetch opening balance.
    const openingDocId = `${accountId}_${saleDate}`;
    const obDoc = await db.collection('openingBalances').doc(openingDocId).get();
    let openingBalance = obDoc.exists ? obDoc.data().balance : 0;

    // Create the sale record.
    const saleData = {
      productId: selectedProductId,
      productName: product.productName,
      wholesalePrice: avgWholesale,
      retailPrice: chosenRetailPrice,
      defaultRetail: avgRetailDefault,
      saleQuantity: saleQuantity,
      profit: totalProfit,
      profitPerUnit: profitPerUnit,
      totalSale: totalSale,
      saleDate: saleDate,
      status: status,
      extraInfo: extraInfo,
      openingBalance: openingBalance,
      createdAt: new Date(),
      accountId: accountId,
      customProductId: (product.productId && product.productId.trim() !== "") ? product.productId.trim() : "-"
    };

    if (paymentDetail1 !== undefined && paymentDetail1 !== "") {
      saleData.paymentDetail1 = parseFloat(paymentDetail1);
    }
    if (paymentDetail2 !== undefined && paymentDetail2 !== "") {
      saleData.paymentDetail2 = parseFloat(paymentDetail2);
    }

    await db.collection('sales').add(saleData);
    res.redirect('/?saleDate=' + saleDate);
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
    const docId = `${accountId}_${saleDate}`;
    await db.collection('openingBalances').doc(docId).set({
      balance,
      openingTime: openingTime || "",
      closingTime: closingTime || "",
      updatedAt: new Date(),
      accountId
    }, { merge: true });
    res.redirect('/?saleDate=' + saleDate);
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /add-product – Render the add product (or stock batch) form.
// This version includes a dropdown for filtering existing products.
app.get('/add-product', isAuthenticated, restrictRoute('/add-product'), async (req, res) => {
  try {
    // Get available categories.
    const categories = await getCategories(req.session.user.accountId);

    // Retrieve query params for filtering and sorting.
    const selectedCategory = req.query.category || '';
    const sortOrder = req.query.sortOrder || 'asc'; // default ascending (A-Z)
    
    // Query existing products for this account.
    let productsQuery = db.collection('products')
      .where('accountId', '==', req.session.user.accountId);
    if (selectedCategory.trim() !== "") {
      productsQuery = productsQuery.where('category', '==', selectedCategory);
    }
    productsQuery = productsQuery.orderBy('productName', sortOrder);
    
    const productsSnapshot = await productsQuery.get();
    let existingProducts = [];
    productsSnapshot.forEach(doc => {
      existingProducts.push({ id: doc.id, name: doc.data().productName });
    });
    
    res.render('addProduct', { 
      success: req.query.success,
      errorMessage: null, // default value to prevent ReferenceError
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
// This version checks if an existing product is selected (via dropdown) or if new details are provided.
app.post('/add-product', isAuthenticated, restrictRoute('/add-product'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    // Destructure fields from the form:
    // "existingProduct" will be set if a product is selected from the dropdown.
    // If the dropdown value is "new", the master intends to create a new product.
    const { existingProduct, productName, wholesalePrice, retailPrice, quantity, productId, selectedCategory, newCategory } = req.body;
    const chosenWholesale = parseFloat(wholesalePrice);
    const chosenRetail = parseFloat(retailPrice);
    // Modified: using parseFloat to allow decimals for quantity received.
    const chosenQuantity = parseFloat(quantity);

    // Determine the category.
    // If a new category is provided, use that; otherwise use the dropdown selection.
    let category = (newCategory && newCategory.trim() !== "") ? newCategory.trim() : (selectedCategory || "");
    // Process product ID input – if none, default to '-'
    let enteredProductId = (productId && productId.trim() !== "") ? productId.trim() : '-';
    
    let productDoc;
    // If an existing product was selected (its value is not "new"),
    // then update that product’s record.
    if (existingProduct && existingProduct !== "new") {
      // Get the product document from Firestore.
      const prodRef = db.collection('products').doc(existingProduct);
      const prodSnapshot = await prodRef.get();
      if (!prodSnapshot.exists) {
        return res.status(404).send("Selected product not found");
      }
      productDoc = prodSnapshot;
      const productData = productDoc.data();
      
      // Update aggregated quantity and weighted average pricing.
      const currentQuantity = productData.quantity || 0;
      const newQuantityTotal = currentQuantity + chosenQuantity;
      const currentWholesale = productData.wholesalePrice || chosenWholesale;
      const currentRetail = productData.retailPrice || chosenRetail;
      const weightedWholesale = ((currentQuantity * currentWholesale) + (chosenQuantity * chosenWholesale)) / newQuantityTotal;
      const weightedRetail = ((currentQuantity * currentRetail) + (chosenQuantity * chosenRetail)) / newQuantityTotal;
      const weightedProfitMargin = weightedRetail - weightedWholesale;
      
      const oldestWholesale = productData.oldestWholesale !== undefined ? productData.oldestWholesale : chosenWholesale;
      const oldestBatchQty = productData.oldestBatchQty !== undefined ? productData.oldestBatchQty : currentQuantity;
      const oldestRetail = productData.oldestRetail !== undefined ? productData.oldestRetail : chosenRetail;
      const secondWholesale = chosenWholesale;
      
      await db.collection('products').doc(productDoc.id).update({
        quantity: newQuantityTotal,
        wholesalePrice: weightedWholesale,
        retailPrice: weightedRetail,
        profitMargin: weightedProfitMargin,
        updatedAt: new Date(),
        oldestWholesale: oldestWholesale,
        oldestBatchQty: oldestBatchQty,
        secondWholesale: secondWholesale,
        oldestRetail: oldestRetail,
        secondRetail: chosenRetail,
        // Optionally update the category if provided.
        category: category ? category : productData.category
      });
    } else {
      // Otherwise, no existing product was chosen.
      // Check if a product with the submitted name already exists.
      const productQuery = await db.collection('products')
        .where('accountId', '==', accountId)
        .where('productName', '==', productName)
        .limit(1)
        .get();
      if (!productQuery.empty) {
        // Product exists – update its quantity and averages.
        productDoc = productQuery.docs[0];
        const productData = productDoc.data();
        const currentQuantity = productData.quantity || 0;
        const newQuantityTotal = currentQuantity + chosenQuantity;
        const currentWholesale = productData.wholesalePrice || chosenWholesale;
        const currentRetail = productData.retailPrice || chosenRetail;
        const weightedWholesale = ((currentQuantity * currentWholesale) + (chosenQuantity * chosenWholesale)) / newQuantityTotal;
        const weightedRetail = ((currentQuantity * currentRetail) + (chosenQuantity * chosenRetail)) / newQuantityTotal;
        const weightedProfitMargin = weightedRetail - weightedWholesale;
        
        const oldestWholesale = productData.oldestWholesale !== undefined ? productData.oldestWholesale : chosenWholesale;
        const oldestBatchQty = productData.oldestBatchQty !== undefined ? productData.oldestBatchQty : currentQuantity;
        const oldestRetail = productData.oldestRetail !== undefined ? productData.oldestRetail : chosenRetail;
        const secondWholesale = chosenWholesale;
        
        await db.collection('products').doc(productDoc.id).update({
          quantity: newQuantityTotal,
          wholesalePrice: weightedWholesale,
          retailPrice: weightedRetail,
          profitMargin: weightedProfitMargin,
          updatedAt: new Date(),
          oldestWholesale: oldestWholesale,
          oldestBatchQty: oldestBatchQty,
          secondWholesale: secondWholesale,
          oldestRetail: oldestRetail,
          secondRetail: chosenRetail,
          category: category ? category : productData.category
        });
      } else {
        // Create a new product.
        const productData = {
          productName,
          wholesalePrice: chosenWholesale,
          retailPrice: chosenRetail,
          quantity: chosenQuantity,
          profitMargin: chosenRetail - chosenWholesale,
          category, // Use category as determined above.
          createdAt: new Date(),
          productId: enteredProductId,  // Save the entered product ID.
          accountId,
          oldestWholesale: chosenWholesale,
          oldestBatchQty: chosenQuantity,
          secondWholesale: null,
          oldestRetail: chosenRetail,
          secondRetail: null
        };
        const docRef = await db.collection('products').add(productData);
        // For later references, create a productDoc-like object.
        productDoc = { id: docRef.id, data: () => productData };
      }
    }
    
    // Create the stock batch record.
    // When an existing product was used, we get its name from Firestore.
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


// ----------------------
// GET /view-products – View all products with an optional category filter.
// GET /view-products – View all products with an optional category filter and sort order.
// GET /view-products – View all products with an optional category filter and sort order.
app.get('/view-products', isAuthenticated, restrictRoute('/view-products'), async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const filterCategory = req.query.filterCategory || '';
    const stockThreshold = req.query.stockThreshold || '';
    // New sortOrder query parameter; defaults to ascending order
    const sortOrder = req.query.sortOrder || 'asc';
    
    let productsQuery = db.collection('products').where('accountId', '==', accountId);

    if (filterCategory && filterCategory.trim() !== '') {
      productsQuery = productsQuery.where('category', '==', filterCategory);
    }
    if (stockThreshold && stockThreshold.trim() !== '') {
      productsQuery = productsQuery.where('quantity', '<', parseInt(stockThreshold));
    }
    
    // Add ordering by product name according to the specified sortOrder.
    productsQuery = productsQuery.orderBy('productName', sortOrder);

    const productsSnapshot = await productsQuery.get();
    let products = [];
    
    for (let doc of productsSnapshot.docs) {
      let product = { id: doc.id, ...doc.data() };
      const batchesSnapshot = await db.collection('stockBatches')
        .where('productId', '==', doc.id)
        .get();
      let batches = [];
      batchesSnapshot.forEach(batchDoc => {
        let batchData = batchDoc.data();
        // Compute the profit margin for the batch (salePrice minus purchasePrice)
        batchData.profitMargin = batchData.salePrice - batchData.purchasePrice;
        batches.push({ id: batchDoc.id, ...batchData });
      });
      product.batches = batches;
      products.push(product);
    }

    const categories = await getCategories(accountId);
    res.render('viewProducts', { products, categories, filterCategory, stockThreshold, sortOrder });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});



// NEW ROUTE: Delete a stock batch with zero remaining quantity.
// NEW ROUTE: Delete a stock batch with zero remaining quantity.
// Modified Route: Delete a stock batch regardless of remaining quantity.
app.post('/delete-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const batchId = req.params.batchId;
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchDoc = await batchRef.get();

    if (!batchDoc.exists) {
      return res.status(404).send("Stock batch not found");
    }

    const batchData = batchDoc.data();
    if (batchData.accountId !== accountId) {
      return res.status(403).send("Access denied: You do not have permission to delete this batch");
    }

    // Get the product ID before deleting the batch.
    const productId = batchData.productId;

    // Delete the stock batch.
    await batchRef.delete();

    // Recalculate the product aggregates automatically.
    await recalcProductFromBatches(productId);

    res.redirect('/view-products');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});




// Helper function to recalculate product values from its stock batches.
async function recalcProductFromBatches(productId) {
  const batchesSnapshot = await db.collection('stockBatches')
    .where('productId', '==', productId)
    .get();
  let totalRemaining = 0, totalWholesale = 0, totalRetail = 0;
  batchesSnapshot.forEach(doc => {
    const data = doc.data();
    // Use remainingQuantity for recalculation of current stock
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

    if (!batchDoc.exists) {
      return res.status(404).send("Stock batch not found");
    }

    const batchData = batchDoc.data();
    // Ensure the stock batch belongs to the current account.
    if (batchData.accountId !== accountId) {
      return res.status(403).send("Access denied");
    }

    // Fetch the parent product for additional context.
    const productDoc = await db.collection('products').doc(batchData.productId).get();
    if (!productDoc.exists) {
      return res.status(404).send("Parent product not found");
    }
    const productData = productDoc.data();

    // Get available categories for this account.
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
// POST /edit-stock-batch/:batchId – Process stock batch update.
app.post('/edit-stock-batch/:batchId', isAuthenticated, async (req, res) => {
  try {
    const accountId = req.session.user.accountId;
    const batchId = req.params.batchId;
    const batchRef = db.collection('stockBatches').doc(batchId);
    const batchDoc = await batchRef.get();

    if (!batchDoc.exists) {
      return res.status(404).send("Stock batch not found");
    }
    const batchData = batchDoc.data();
    if (batchData.accountId !== accountId) {
      return res.status(403).send("Access denied");
    }

    // Extract new values from the form.
    // Allow editing of product name:
    const newProductName = req.body.productName && req.body.productName.trim() !== "" 
                           ? req.body.productName.trim() 
                           : batchData.productName;
    const purchasePrice = parseFloat(req.body.purchasePrice);
    const salePrice = parseFloat(req.body.salePrice);
    const quantity = parseInt(req.body.quantity, 10);

    // Get the batch-specific Product ID from the form; if left empty, use default.
    const batchProductId = req.body.productId && req.body.productId.trim() !== ""
                           ? req.body.productId.trim()
                           : "-";

    // Category update: use the new category if provided; otherwise, use the selected category.
    const selectedCategory = req.body.selectedCategory;
    const newCategory = req.body.newCategory && req.body.newCategory.trim() !== ""
                        ? req.body.newCategory.trim()
                        : "";
    const category = newCategory !== "" ? newCategory : selectedCategory;

    // Update the stock batch record with the new details including productName.
    await batchRef.update({
      purchasePrice,
      salePrice,
      quantity,
      remainingQuantity: quantity, // reset remaining quantity to new quantity
      batchProductId,
      updatedAt: new Date(),
      productName: newProductName  // update the batch's stored product name
    });

    // Fetch the master product document to update its name and category.
    const productRef = db.collection('products').doc(batchData.productId);
    const productDoc = await productRef.get();
    if (!productDoc.exists) {
      return res.status(404).send("Parent product not found");
    }

    // Update the master product record with the new product name and category.
    await productRef.update({
      productName: newProductName,
      category: category,
      updatedAt: new Date()
    });

    // Recalculate the parent product's aggregates based on its batches.
    await recalcProductFromBatches(batchData.productId);

    res.redirect('/view-products');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});



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
      if (nextMonthNum > 12) {
        nextMonthNum = 1;
        nextYear++;
      }
      const nextMonth = `${nextYear}-${nextMonthNum.toString().padStart(2, '0')}-01`;
      salesQuery = salesQuery.where('saleDate', '>=', startDate)
                             .where('saleDate', '<', nextMonth);
      expenseQuery = expenseQuery.where('saleDate', '>=', startDate)
                                 .where('saleDate', '<', nextMonth);
    }

    if (status && status.trim() !== "" && status !== "All") {
      salesQuery = salesQuery.where('status', '==', status);
    }

    const salesSnapshot = await salesQuery.get();
    let sales = [];
    salesSnapshot.forEach(doc => {
      sales.push({ id: doc.id, ...doc.data() });
    });

    const expenseSnapshot = await expenseQuery.get();
    let expenses = [];
    expenseSnapshot.forEach(doc => {
      expenses.push({ id: doc.id, ...doc.data() });
    });

    const allDatesSet = new Set();
    sales.forEach(sale => allDatesSet.add(sale.saleDate));
    expenses.forEach(expense => allDatesSet.add(expense.saleDate));
    const allDates = Array.from(allDatesSet);

    const openingTimes = {};
    await Promise.all(allDates.map(async (date) => {
      const obDoc = await db.collection('openingBalances').doc(`${accountId}_${date}`).get();
      if (obDoc.exists) {
        const obData = obDoc.data();
        openingTimes[date] = {
          openingTime: obData.openingTime || "",
          closingTime: obData.closingTime || ""
        };
      } else {
        openingTimes[date] = { openingTime: "", closingTime: "" };
      }
    }));

    let profitWithoutExpenses = 0;
    sales.forEach(sale => {
      profitWithoutExpenses += sale.profit;
    });
    let totalExpensesAmount = 0;
    expenses.forEach(exp => {
      totalExpensesAmount += exp.expenseCost;
    });
    let profitAfterExpenses = profitWithoutExpenses - totalExpensesAmount;

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
        if (nextMonthNum > 12) {
          nextMonthNum = 1;
          nextYear++;
        }
        const nextMonth = `${nextYear}-${nextMonthNum.toString().padStart(2, '0')}-01`;
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
    
    const salesSnapshot = await salesQuery.get();
    let sales = [];
    salesSnapshot.forEach(doc => {
      sales.push(doc.data());
    });
    
    const expenseSnapshot = await expenseQuery.get();
    let expenses = [];
    expenseSnapshot.forEach(doc => {
      expenses.push(doc.data());
    });
    
    let totalProfit = 0;
    sales.forEach(sale => {
      totalProfit += sale.profit;
    });
    let totalExpenses = 0;
    expenses.forEach(exp => {
      totalExpenses += exp.expenseCost;
    });
    let netProfit = totalProfit - totalExpenses;
    
    let profitByMonth = {};
    sales.forEach(sale => {
      let saleMonth = sale.saleDate.substring(0,7);
      if (!profitByMonth[saleMonth]) {
         profitByMonth[saleMonth] = { profit: 0, expenses: 0, netProfit: 0 };
      }
      profitByMonth[saleMonth].profit += sale.profit;
    });
    expenses.forEach(exp => {
      let expMonth = exp.saleDate.substring(0,7);
      if (!profitByMonth[expMonth]) {
         profitByMonth[expMonth] = { profit: 0, expenses: 0, netProfit: 0 };
      }
      profitByMonth[expMonth].expenses += exp.expenseCost;
    });
    for (let m in profitByMonth) {
       profitByMonth[m].netProfit = profitByMonth[m].profit - profitByMonth[m].expenses;
    }
    
    res.render('profit', { 
      sales, 
      expenses, 
      totalProfit, 
      totalExpenses, 
      netProfit, 
      profitByMonth,
      monthFilter: req.query.month || '',
      yearFilter: req.query.year || ''
    });
    
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// ----------------------
// NEW SUBSCRIPTION & PAYMENT ROUTES
// ----------------------

// GET /pricing – Render subscription plans page.
app.get('/pricing', isAuthenticated, (req, res) => {
  const now = new Date();

  // Redirect subscribed users back to the homepage
  if (req.session.user.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > now) {
    return res.redirect('/');
  }

  // Only non-subscribed users can view the pricing page
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

// Payment success callback route.
app.post('/payment-success', isAuthenticated, async (req, res) => {
  try {
    const { plan } = req.body;
    let subscriptionDurationDays;
    if (plan === 'Monthly') {
      subscriptionDurationDays = 30;
    } else if (plan === 'Half-Yearly') {
      subscriptionDurationDays = 182;
    } else if (plan === 'Yearly') {
      subscriptionDurationDays = 365;
    } else {
      return res.status(400).send("Invalid subscription plan");
    }
    const currentTime = new Date();
    let newExpiry;
    if (req.session.user.subscriptionExpiry && new Date(req.session.user.subscriptionExpiry) > currentTime) {
      newExpiry = new Date(req.session.user.subscriptionExpiry);
    } else {
      newExpiry = currentTime;
    }
    newExpiry.setDate(newExpiry.getDate() + subscriptionDurationDays);
    
    await db.collection('users').doc(req.session.user.id).update({
      subscriptionExpiry: newExpiry
    });
    req.session.user.subscriptionExpiry = newExpiry;
    res.redirect('/');
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /profile – Render the profile page for the current user.
app.get('/profile', isAuthenticated, requireMaster, async (req, res) => {
  
  try {
    const userDoc = await db.collection('users').doc(req.session.user.id).get();
    if (!userDoc.exists) {
      return res.status(404).send("User not found");
    }
    let userData = userDoc.data();
    if (userData.subscriptionExpiry) {
      if (typeof userData.subscriptionExpiry.toDate === 'function') {
        userData.subscriptionExpiry = userData.subscriptionExpiry.toDate();
      } else {
        userData.subscriptionExpiry = new Date(userData.subscriptionExpiry);
      }
    }
    res.render('profile', { user: userData });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


// GET /billing – Render the billing/subscription details page.
app.get('/billing', isAuthenticated, requireMaster, async (req, res) => {
  try {
    // Fetch the latest user details from Firestore.
    const userDoc = await db.collection('users').doc(req.session.user.id).get();
    if (!userDoc.exists) {
      return res.status(404).send("User not found");
    }
    let userData = userDoc.data();
    
    // Convert subscriptionExpiry to a JavaScript Date object if needed.
    if (userData.subscriptionExpiry) {
      if (typeof userData.subscriptionExpiry.toDate === 'function') {
        userData.subscriptionExpiry = userData.subscriptionExpiry.toDate();
      } else {
        userData.subscriptionExpiry = new Date(userData.subscriptionExpiry);
      }
    }
    
    // Render the billing.ejs template and pass the userData.
    res.render('billing', { user: userData });
  } catch (error) {
    res.status(500).send(error.toString());
  }
});


// Start the server.
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
