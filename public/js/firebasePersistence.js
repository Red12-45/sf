// public/js/firebasePersistence.js
// Make sure to use: <script type="module" src="/js/firebasePersistence.js?v=2"></script>

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.19.1/firebase-app.js";
import {
  initializeFirestore,
  persistentLocalCache
} from "https://www.gstatic.com/firebasejs/9.19.1/firebase-firestore.js";

// ✅ Safe to expose — this is the public Firebase config
const firebaseConfig = {
  apiKey: "AIzaSyDxiyCQx35omEQOJAVEcOT3Xfjsf5ANSac",
  authDomain: "saleflow-63fb0.firebaseapp.com",
  projectId: "saleflow-63fb0",
  storageBucket: "saleflow-63fb0.appspot.com",
  messagingSenderId: "18857800436",
  appId: "1:18857800436:web:58f3523b7e6f1764e6e4a1",
  measurementId: "G-ZWZ7GLCH2D"
};

// Initialize Firebase app
const app = initializeApp(firebaseConfig);

// Initialize Firestore with persistent local cache
export const db = initializeFirestore(app, {
  localCache: persistentLocalCache()
});

console.log("✅ Offline persistence enabled with persistentLocalCache.");
