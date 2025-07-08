/**
 * migrateFirestoreUsersToAuth.mjs
 * ────────────────────────────────────────────────────────────────────────────
 * PURPOSE
 *   • Create a Firebase-Auth user for every Firestore doc in collection `users`
 *   • Uses the SAME document ID as the Auth UID
 *   • Sets a default password  ResetMe123   (force users to reset later)
 *   • Safe to resume – skips anything that already exists in Auth
 *   • Never deletes / modifies Firestore
 *
 * HOW TO TEST JUST ONE USER FIRST
 *   node migrateFirestoreUsersToAuth.mjs 11LpNsRJIM6JznlSg72D
 *
 * RUN FOR *EVERYONE*
 *   node migrateFirestoreUsersToAuth.mjs
 *
 * REQUIREMENTS
 *   • Node 18+  (ESM syntax)
 *   • firebase-admin  v11+
 *   • A service-account key JSON file named  serviceAccountKey.json
 *     in the same folder, or set  GOOGLE_APPLICATION_CREDENTIALS
 */

import fs     from 'fs';
import path   from 'path';
import admin  from 'firebase-admin';

/* ────────────────────────────────────────────────────────────────────────────
   1.  Firebase Admin initialisation
   ────────────────────────────────────────────────────────────────────────── */
const keyPath = path.resolve('./serviceAccountKey.json');
if (!fs.existsSync(keyPath)) {
  console.error('❌  serviceAccountKey.json not found – aborting.');
  process.exit(1);
}

admin.initializeApp({ credential: admin.credential.cert(keyPath) });
const db   = admin.firestore();
const auth = admin.auth();

/* ────────────────────────────────────────────────────────────────────────────
   2.  Helper – create a single Auth user (idempotent)
   ────────────────────────────────────────────────────────────────────────── */
async function ensureAuthUser (uid, email) {
  try {
    await auth.createUser({ uid, email, password: 'Zxcv@123' });
    console.log(`✅  Created user  ${uid}  (${email})`);
  } catch (err) {
    if (err.code === 'auth/email-already-exists' ||
        err.code === 'auth/uid-already-exists') {
      console.log(`⚠️  Already exists  ${uid}`);
    } else {
      console.log(`❌  Failed for ${uid} → ${err.message}`);
    }
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   3.  Main
   ────────────────────────────────────────────────────────────────────────── */
const singleUid = (process.argv[2] || '').trim();   // optional CLI arg

(async () => {
  if (singleUid) {
    /* ── Safe single-user test ── */
    const doc = await db.collection('users').doc(singleUid).get();
    if (!doc.exists) {
      console.error(`❌  Firestore document ${singleUid} not found.`);
      process.exit(1);
    }
    const data = doc.data();
    if (!data.email) {
      console.log(`⚠️  Skipped ${singleUid} – document has no "email" field.`);
      return;
    }
    await ensureAuthUser(singleUid, data.email.toLowerCase());
    return;
  }

  /* ── Full migration ── */
  console.log('🔎  Fetching every document in collection "users"…');
  const snap = await db.collection('users').get();
  console.log(`ℹ️   Processing ${snap.size} user(s)…`);

  for (const doc of snap.docs) {
    const data = doc.data();
    if (!data.email) {
      console.log(`⚠️  Skipped ${doc.id} – document has no "email" field.`);
      continue;
    }
    await ensureAuthUser(doc.id, data.email.toLowerCase());
  }

  console.log('🏁  Migration complete.');
  process.exit(0);
})().catch(err => {
  console.error('🔥  Fatal error:', err);
  process.exit(1);
});
