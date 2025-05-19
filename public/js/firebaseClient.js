/*  /public/js/firebaseClient.js
    Full client-side Firebase initialisation with App Check + Firestore
--------------------------------------------------------------------- */
import { initializeApp }       from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import {
  initializeAppCheck,
  ReCaptchaV3Provider,
  getToken                     // we’ll need this for the fetch wrapper
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app-check.js";
import {
  getFirestore,
  enableIndexedDbPersistence
} from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

/* The server injects the full config object at render-time */
const cfg = window.__FIREBASE_CFG__;
const app = initializeApp(cfg);

/* ————— APP CHECK ————— */
export const appCheck = initializeAppCheck(app, {
  provider: new ReCaptchaV3Provider(cfg.recaptchaKey),
  isTokenAutoRefreshEnabled: true          // keeps the token fresh
});

/* ————— FIRESTORE ————— */
export const db = getFirestore(app);
enableIndexedDbPersistence(db).catch(console.warn);

/* ————— fetch wrapper that auto-attaches the App Check token ————— */
export async function secureFetch(url, opts={}) {
  const { token } = await getToken(appCheck, /*forceRefresh*/ false);
  opts.headers = {
    ...(opts.headers || {}),
    "X-Firebase-AppCheck": token
  };
  return fetch(url, opts);
}
