// public/js/firebasePersistence.js
// Use type="module" in your script tag when importing this file.

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-app.js";
import { getFirestore, enableIndexedDbPersistence } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-firestore.js";
import { initializeAppCheck, ReCaptchaV3Provider } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-app-check.js";

// Your Firebase project config
const firebaseConfig = {
  apiKey: "AIzaSyDxiyCQx35omEQOJAVEcOT3Xfjsf5ANSac",
  authDomain: "saleflow-63fb0.firebaseapp.com",
  projectId: "saleflow-63fb0",
  storageBucket: "saleflow-63fb0.appspot.com",
  messagingSenderId: "18857800436",
  appId: "1:18857800436:web:58f3523b7e6f1764e6e4a1",
  measurementId: "G-ZWZ7GLCH2D"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// ✅ Initialize App Check with reCAPTCHA v3
const appCheck = initializeAppCheck(app, {
  provider: new ReCaptchaV3Provider('6LfftRYrAAAAABPCvK52DNLzdxpShOarzalncDbP'),
  isTokenAutoRefreshEnabled: true
});

// Initialize Firestore
export const db = getFirestore(app);

// Enable offline persistence
enableIndexedDbPersistence(db)
  .then(() => {
    console.log("Offline persistence enabled.");
  })
  .catch((err) => {
    if (err.code === "failed-precondition") {
      console.error("Persistence failed – multiple tabs open.");
    } else if (err.code === "unimplemented") {
      console.error("Persistence is not available in this browser.");
    } else {
      console.error("Error enabling persistence:", err);
    }
  });
