/* ===========================================================
   SALESFLOW – Firestore client with ultra‑efficient caching
   Version: 2025‑05‑07‑lite‑fix1
   -----------------------------------------------------------
   ❖ Default helpers (`getDoc`,`getDocs`) are cache‑first and
     never trigger a background refresh → zero repeat reads.
   ❖ Opt‑in helpers (`getDocLive`,`getDocsLive`) implement the
     stale‑while‑revalidate logic (pays only deltas).
   ❖ Realtime listener renamed to `onSnapshotLive`.
   ❖ Unlimited multi‑tab persistent cache retained.
   =========================================================== */
/* ----------  Firebase v11.9.1  ---------- */
import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.9.1/firebase-app.js';
import {
  initializeFirestore,
  persistentLocalCache,
  persistentMultipleTabManager,
  CACHE_SIZE_UNLIMITED,

  /* ── read ops – network versions aliased so we can override names ── */
  getDoc              as getDocOnline,
  getDocs             as getDocsOnline,
  getDocFromCache,
  getDocsFromCache,
  collection, query, where, orderBy, limit,
  onSnapshot,

  /* ── write ops ── */
  setDoc, addDoc, updateDoc, deleteDoc,

  /* ── cache maintenance ── */
  clearIndexedDbPersistence, terminate
} from 'https://www.gstatic.com/firebasejs/11.9.1/firebase-firestore.js';

   
   /* ---------- PUBLIC CONFIG (safe to expose) ---------------- */
   export const firebaseConfig = {
     apiKey:            'AIzaSyDxiyCQx35omEQOJAVEcOT3Xfjsf5ANSac',
     authDomain:        'saleflow-63fb0.firebaseapp.com',
     projectId:         'saleflow-63fb0',
     storageBucket:     'saleflow-63fb0.appspot.com',
     messagingSenderId: '18857800436',
     appId:             '1:18857800436:web:58f3523b7e6f1764e6e4a1',
     measurementId:     'G-ZWZ7GLCH2D'
   };
   
   /* ---------- INIT APP + OFFLINE CACHE --------------------- */
   const app = initializeApp(firebaseConfig);
   
   export const db = initializeFirestore(app, {
     localCache: persistentLocalCache({
       cacheSizeBytes: CACHE_SIZE_UNLIMITED,
       tabManager    : persistentMultipleTabManager()
     })
   });
   
   console.log(
     '%cFirestore persistent cache ✓  (unlimited, shared)',
     'color:#4CAF50;font-weight:bold;'
   );
   
   /* ===========================================================
      ①  ZERO‑COST READ HELPERS  (cache‑first, no background net)
      =========================================================== */
   
   export async function getDoc(ref) {
     try { return await getDocFromCache(ref); }
     catch { return await getDocOnline(ref); }
   }
   
   export async function getDocs(q) {
     try { return await getDocsFromCache(q); }
     catch { return await getDocsOnline(q); }
   }
   
   /* ===========================================================
      ②  OPTIONAL “LIVE” HELPERS  (SWR – pay only for deltas)
      =========================================================== */
   
   export async function getDocLive(ref, onUpdated) {
     let cached = null;
     try { cached = await getDocFromCache(ref); } catch {}
   
     // always fire a background refresh
     getDocOnline(ref)
       .then(snap => {
         if (
           !cached ||
           JSON.stringify(cached.data()) !== JSON.stringify(snap.data())
         ) {
           onUpdated?.(snap);
         }
       })
       .catch(console.error);
   
     return cached ?? getDocOnline(ref);
   }
   
   export async function getDocsLive(q, onUpdated) {
     let cached = null;
     try { cached = await getDocsFromCache(q); } catch {}
   
     getDocsOnline(q)
       .then(snap => {
         if (!cached || snap.size !== cached.size) {
           onUpdated?.(snap);
           return;
         }
         const equal = snap.docs.every(
           (d, i) =>
             JSON.stringify(d.data()) ===
             JSON.stringify(cached.docs[i].data())
         );
         if (!equal) onUpdated?.(snap);
       })
       .catch(console.error);
   
     return cached ?? getDocsOnline(q);
   }
   
   /* ===========================================================
      ③  REAL‑TIME LISTENER (subscription – billed on every delta)
      =========================================================== */
   
   export function onSnapshotLive(target, cb, options = {}) {
     return onSnapshot(
       target,
       { includeMetadataChanges: true, ...options },
       cb,
       console.error
     );
   }
   
   /* ===========================================================
      ④  WRITES (unchanged – latency‑compensated by SDK)
      =========================================================== */
   export const setDocCF    = setDoc;
   export const addDocCF    = addDoc;
   export const updateDocCF = updateDoc;
   export const deleteDocCF = deleteDoc;
   
   /* ===========================================================
      ⑤  HOUSEKEEPING
      =========================================================== */
   export async function clearLocalCache() {
     try {
       await terminate(db);
       await clearIndexedDbPersistence(db);
       console.log('🧹 Firestore cache cleared');
     } catch (err) {
       console.warn('[clearLocalCache] failed:', err);
     }
   }
   
   /* ===========================================================
      Example usage
      -----------------------------------------------------------
      // Static list (no live updates)
      const snap = await getDocs(collection(db, 'products'));
      render(snap.docs);
   
      // Live dashboard
      const snap = await getDocsLive(
        query(collection(db, 'sales'), where('saleDate', '==', today)),
        fresh => render(fresh.docs)
      );
   
      // Full subscription
      const unsub = onSnapshotLive(
        query(collection(db, 'expenses'), where('saleDate', '==', today)),
        snap => render(snap.docs)
      );
      =========================================================== */
   