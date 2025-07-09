const admin = require('firebase-admin');

/* ───── load your service-account key ─────
   ①  Visit  ▸  Firebase console ▸ Project settings ▸ Service accounts
   ②  Click  “Generate new private key”  and save the JSON    */
const serviceAccount = require('./serviceAccountKey.json');   // ← exact path

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId : 'saleflow-63fb0'      // ← your project ID (keep the quotes)
});
(async () => {
  const db   = admin.firestore();
  const snap = await db.collection('users')
                       .where('password', '!=', null).get();
  const bat  = db.batch();
  snap.forEach(doc => bat.update(doc.ref, { password: admin.firestore.FieldValue.delete() }));
  await bat.commit();
  console.log(`Removed password field from ${snap.size} user documents`);
  process.exit();
})();
