/* ------------------------------------------------------------------
   removeInvoiceNo.js – standalone Firestore maintenance script
   ------------------------------------------------------------------
   Deletes the `invoiceNo` field from ***every*** document in the
   `sales` collection (for ALL accounts) using the Firebase Admin SDK.
   ------------------------------------------------------------------
   USAGE:
     1.  Install deps (once):   npm install firebase-admin
     2.  Run the script:        node removeInvoiceNo.js ./serviceAccountKey.json
         (pass the absolute or relative path to your service‑account key)
   ------------------------------------------------------------------ */

const admin = require('firebase-admin');
const fs    = require('fs');
const path  = require('path');

/* ---------------- sanity‑check CLI arg ---------------- */
if (process.argv.length < 3) {
  console.error('\n  Usage: node removeInvoiceNo.js <serviceAccountKey.json>\n');
  process.exit(1);
}

const keyPath = path.resolve(process.argv[2]);
if (!fs.existsSync(keyPath)) {
  console.error('❌  Service‑account key not found at:', keyPath);
  process.exit(1);
}

/* ---------------- Firebase Admin init ---------------- */
admin.initializeApp({
  credential: admin.credential.cert(require(keyPath))
});

const db = admin.firestore();

/* ------------------------------------------------------------------
   main() – stream through the entire collection in pages of 500 docs
   ------------------------------------------------------------------ */
async function main () {
  const PAGE = 500;           // Firestore max batch‑write size
  let last    = null;         // cursor
  let total   = 0;

  while (true) {
    let q = db.collectionGroup('sales')  // hits every /sales sub‑collection
               .orderBy('__name__')
               .limit(PAGE);
    if (last) q = q.startAfter(last);

    const snap = await q.get();
    if (snap.empty) break;    // done – no more docs

    const batch = db.batch();
    snap.docs.forEach(doc => {
      batch.update(doc.ref, { invoiceNo: admin.firestore.FieldValue.delete() });
    });
    await batch.commit();

    total += snap.size;
    last   = snap.docs[snap.docs.length - 1];
    console.log(`✔︎  Cleared invoiceNo in ${total} document${total===1?'':'s'} so far…`);
  }

  console.log(`\n🎉  All done – invoiceNo removed from ${total} document${total===1?'':'s'}.\n`);
  process.exit(0);
}

main().catch(err => {
  console.error('\n❌  Fatal error:', err, '\n');
  process.exit(1);
});
