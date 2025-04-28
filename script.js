// one-off back-fill: add nameKey for legacy rows
const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

/* copy–paste the helper ↓ */
const normalizeName = s =>
  s.toLowerCase().replace(/\s+/g, ' ').trim();

(async () => {
  const snap = await db.collection('products').get();
  const batch = db.batch();
  snap.docs.forEach(doc => {
    const d = doc.data();
    if (!d.nameKey) batch.update(doc.ref, { nameKey: normalizeName(d.productName) });
  });
  await batch.commit();
  console.log('Back-fill complete');
  process.exit(0);
})();
