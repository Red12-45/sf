// helmetConfig.js
module.exports = function setupHelmet(app) {
  const helmet = require('helmet');

  /* ─── Hide Express fingerprint ─── */
  app.disable('x-powered-by');
  app.use(helmet.hidePoweredBy());

  /* ─── Strict Content-Security-Policy ─── */
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
            "https://checkout.razorpay.com"
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
            "https://*.razorpay.com"
          ],
          imgSrc : ["'self'", "data:", "blob:"],
          fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
          frameSrc: [
            "'self'",
            "https://checkout.razorpay.com",
            "https://api.razorpay.com"
          ],
          childSrc: [
            "'self'",
            "https://checkout.razorpay.com",
            "https://api.razorpay.com"
          ]
        }
      }
    })
  );

  /* ─── HSTS (2 years) ─── */
  app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true }));
};
