  // public/js/firebasePersistence.js
  // Use type="module" in your script tag when importing this file.

  import { initializeApp } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-app.js";
  import { getFirestore, enableIndexedDbPersistence } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-firestore.js";
  import { initializeAppCheck, ReCaptchaV3Provider } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-app-check.js";
  require('dotenv').config();

  // Your Firebase project config
  const firebaseConfig = {
    apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
    authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
    projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
    storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
    messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
    appId: import.meta.env.VITE_FIREBASE_APP_ID,
    measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID
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
