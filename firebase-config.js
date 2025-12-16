// firebase-config.js
// Import Firebase modules
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js";
import { getStorage } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-storage.js";

// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyCrmVDlBwRkkzP_rYY3mXBKw_ihrkV3tVM",
  authDomain: "dialek-6a219.firebaseapp.com",
  databaseURL: "https://dialek-6a219-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "dialek-6a219",
  storageBucket: "dialek-6a219.firebasestorage.app",
  messagingSenderId: "423916223695",
  appId: "1:423916223695:web:449bd44c54cad998d8cbba",
  measurementId: "G-4SLBH47WTM"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const storage = getStorage(app);

export { auth, db, storage };