// public/js/firebasePersistence.js
// Use type="module" in your script tag when importing this file.

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-app.js";
import { getFirestore, enableIndexedDbPersistence } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-firestore.js";

// Replace the values below with your Firebase project configuration from the Firebase Console.
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

// Initialize Firestore
export const db = getFirestore(app);

// Enable offline persistence using IndexedDB.
enableIndexedDbPersistence(db)
  .then(() => {
    console.log("Offline persistence enabled.");
  })
  .catch((err) => {
    if (err.code === "failed-precondition") {
      // Multiple tabs open; persistence can only be enabled in one tab at a time.
      console.error("Persistence failed – multiple tabs open.");
    } else if (err.code === "unimplemented") {
      // The current browser does not support all features required.
      console.error("Persistence is not available in this browser.");
    } else {
      console.error("Error enabling persistence:", err);
    }
  });
