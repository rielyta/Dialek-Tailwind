/**
 * Firebase Integration for AES-ECC
 * 
 * Provides high-level Firebase Firestore operations with transparent encryption
 * using the AES-ECC hybrid encryption system.
 * 
 * Usage:
 * ------
 * const db = getFirestore(app);
 * const cryptoSystem = new AESECCSystem();
 * const firebaseManager = new FirebaseAESECC(db, cryptoSystem);
 * 
 * @version 1.1 (PRODUCTION READY - Global export fix)
 */

class FirebaseAESECC {
  constructor(db, cryptoSystem) {
    this.db = db;
    this.crypto = cryptoSystem;
  }

  /**
   * Store User's ECC Public Key
   * 
   * @param {string} userId - User's Firebase UID
   * @param {Object} publicKeyJWK - Public key in JWK format
   */
  async storePublicKey(userId, publicKeyJWK) {
    console.log(`🔑 Storing public key for user ${userId}...`);
    
    const { doc, setDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      await setDoc(doc(this.db, 'users', userId, 'keys', 'public'), {
        key: publicKeyJWK,
        algorithm: 'ECC-P256',
        usage: 'ECDH key agreement',
        createdAt: new Date().toISOString()
      });

      console.log(`✅ Public key stored`);
    } catch (error) {
      console.error('❌ Failed to store public key:', error);
      throw error;
    }
  }

  /**
   * Get User's Public Key
   * 
   * @param {string} userId - User's Firebase UID
   * @returns {Promise<CryptoKey>} - Imported public key ready for encryption
   */
  async getPublicKey(userId) {
    const { doc, getDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const publicKeyDoc = await getDoc(doc(this.db, 'users', userId, 'keys', 'public'));
      
      if (!publicKeyDoc.exists()) {
        throw new Error(`Public key not found for user ${userId}`);
      }

      const jwk = publicKeyDoc.data().key;
      const publicKey = await this.crypto.importPublicKeyFromJWK(jwk);

      return publicKey;
    } catch (error) {
      console.error('❌ Failed to get public key:', error);
      throw error;
    }
  }

  /**
   * Encrypt and Store User Profile
   * 
   * Encrypts sensitive profile data before storing in Firestore.
   * Public metadata (username, profile image) remains plain text for indexing.
   * 
   * @param {string} userId - User's Firebase UID
   * @param {Object} profileData - {name, email, phone, username, profileImage}
   * @param {CryptoKey} userPrivateKey - User's private key for encryption
   * @returns {Promise<Object>} - Encryption metadata
   */
  async storeUserProfile(userId, profileData, userPrivateKey) {
    const { doc, setDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(`👤 Encrypting and storing user profile...`);

    try {
      // Get user's public key
      const userPublicKey = await this.getPublicKey(userId);

      // Data to encrypt (sensitive fields)
      const dataToEncrypt = {
        name: profileData.name,
        email: profileData.email,
        phone: profileData.phone
      };

      // Encrypt
      const encrypted = await this.crypto.encryptCompleteWorkflow(
        JSON.stringify(dataToEncrypt),
        userPrivateKey,
        userPublicKey
      );

      // Store (combine encrypted + public data)
      await setDoc(doc(this.db, 'users', userId), {
        // Public data (searchable/indexable)
        username: profileData.username,
        profileImage: profileData.profileImage,

        // Encrypted data
        encryptedProfile: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion,
          workflowTime: encrypted.workflowTime
        }
      }, { merge: true });

      console.log(`✅ Profile stored securely`);
      return encrypted;
    } catch (error) {
      console.error('❌ Failed to store profile:', error);
      throw error;
    }
  }

  /**
   * Retrieve and Decrypt User Profile
   * 
   * @param {string} userId - User's Firebase UID
   * @param {CryptoKey} userPrivateKey - User's private key for decryption
   * @returns {Promise<Object>} - Decrypted profile data
   */
  async getUserProfile(userId, userPrivateKey) {
    const { doc, getDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(`👤 Retrieving and decrypting user profile...`);

    try {
      // Get user's public key
      const userPublicKey = await this.getPublicKey(userId);

      // Get encrypted profile
      const userDoc = await getDoc(doc(this.db, 'users', userId));
      if (!userDoc.exists()) {
        throw new Error(`User profile not found for ${userId}`);
      }

      const encryptedProfile = userDoc.data().encryptedProfile;
      if (!encryptedProfile) {
        throw new Error('No encrypted profile data found');
      }

      // Decrypt
      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedProfile,
        userPrivateKey,
        userPublicKey
      );

      const profileData = JSON.parse(decrypted.plaintext);

      console.log(`✅ Profile decrypted successfully`);
      return profileData;
    } catch (error) {
      console.error('❌ Failed to get profile:', error);
      throw error;
    }
  }

  /**
   * Encrypt and Store Forum Question
   * 
   * @param {string} userId - Question author's Firebase UID
   * @param {string} question - Question text to encrypt
   * @param {CryptoKey} userPrivateKey - Author's private key
   * @returns {Promise<Object>} - Encryption metadata
   */
  async postForumQuestion(userId, question, userPrivateKey) {
    const { doc, collection, addDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(`💬 Posting encrypted forum question...`);

    try {
      // Get user's public key
      const userPublicKey = await this.getPublicKey(userId);

      // Encrypt
      const encrypted = await this.crypto.encryptCompleteWorkflow(
        question,
        userPrivateKey,
        userPublicKey
      );

      // Store
      await addDoc(collection(this.db, 'forum'), {
        encryptedContent: encrypted.encryptedData,
        authorId: userId,
        category: 'Bahasa Batak Toba',
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion,
          workflowTime: encrypted.workflowTime
        },
        postedAt: new Date().toISOString()
      });

      console.log(`✅ Forum question posted securely`);
      return encrypted;
    } catch (error) {
      console.error('❌ Failed to post forum question:', error);
      throw error;
    }
  }

  /**
   * Get Forum Questions
   * 
   * Retrieves encrypted forum questions from Firestore.
   * Questions remain encrypted until explicitly decrypted by viewer.
   * 
   * @returns {Promise<Array>} - Array of forum questions with metadata
   */
  async getForumQuestions() {
    const { collection, getDocs } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(`📝 Fetching forum questions...`);

    try {
      const forumCollection = collection(this.db, 'forum');
      const snapshot = await getDocs(forumCollection);

      const questions = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      console.log(`✅ Retrieved ${questions.length} questions`);
      return questions;
    } catch (error) {
      console.error('❌ Failed to get forum questions:', error);
      throw error;
    }
  }

  /**
   * Decrypt Forum Question
   * 
   * Decrypts a question for viewing. Only the viewer's private key
   * and the author's public key are needed.
   * 
   * @param {string} encryptedQuestion - Base64 encrypted question
   * @param {CryptoKey} viewerPrivateKey - Viewer's private key
   * @param {string} authorId - Question author's Firebase UID
   * @returns {Promise<string>} - Decrypted plaintext question
   */
  async decryptForumQuestion(encryptedQuestion, viewerPrivateKey, authorId) {
    console.log(`🔓 Decrypting forum question...`);

    try {
      // Get author's public key
      const authorPublicKey = await this.getPublicKey(authorId);

      // Decrypt
      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedQuestion,
        viewerPrivateKey,
        authorPublicKey
      );

      console.log(`✅ Question decrypted`);
      return decrypted.plaintext;
    } catch (error) {
      console.error('❌ Failed to decrypt question:', error);
      throw error;
    }
  }

  /**
   * Send Encrypted Message between Users
   * 
   * Creates a shared message encrypted to both sender and recipient.
   * Stores copy in both users' message collections.
   * 
   * @param {string} senderUserId - Sender's Firebase UID
   * @param {string} recipientUserId - Recipient's Firebase UID
   * @param {string} message - Message text to encrypt
   * @param {CryptoKey} senderPrivateKey - Sender's private key
   * @returns {Promise<Object>} - Encryption metadata
   */
  async sendEncryptedMessage(senderUserId, recipientUserId, message, senderPrivateKey) {
    const { doc, collection, addDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(`💌 Sending encrypted message...`);

    try {
      // Get recipient's public key
      const recipientPublicKey = await this.getPublicKey(recipientUserId);

      // Encrypt to recipient
      const encrypted = await this.crypto.encryptCompleteWorkflow(
        message,
        senderPrivateKey,
        recipientPublicKey
      );

      // Store in sender's messages (outbox)
      await addDoc(collection(this.db, 'users', senderUserId, 'messages'), {
        type: 'sent',
        recipientId: recipientUserId,
        encryptedContent: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion,
          workflowTime: encrypted.workflowTime
        },
        sentAt: new Date().toISOString()
      });

      // Store in recipient's messages (inbox)
      await addDoc(collection(this.db, 'users', recipientUserId, 'messages'), {
        type: 'received',
        senderId: senderUserId,
        encryptedContent: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion,
          workflowTime: encrypted.workflowTime
        },
        receivedAt: new Date().toISOString()
      });

      console.log(`✅ Message sent securely`);
      return encrypted;
    } catch (error) {
      console.error('❌ Failed to send message:', error);
      throw error;
    }
  }

  /**
   * Get Received Messages
   * 
   * @param {string} userId - User's Firebase UID
   * @returns {Promise<Array>} - Array of encrypted messages
   */
  async getReceivedMessages(userId) {
    const { collection, getDocs } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const messagesCollection = collection(this.db, 'users', userId, 'messages');
      const snapshot = await getDocs(messagesCollection);

      const messages = snapshot.docs
        .filter(doc => doc.data().type === 'received')
        .map(doc => ({
          id: doc.id,
          ...doc.data()
        }));

      return messages;
    } catch (error) {
      console.error('❌ Failed to get messages:', error);
      throw error;
    }
  }

  /**
   * Decrypt Received Message
   * 
   * @param {string} encryptedMessage - Base64 encrypted message
   * @param {CryptoKey} receiverPrivateKey - Receiver's private key
   * @param {string} senderId - Sender's Firebase UID
   * @returns {Promise<string>} - Decrypted plaintext message
   */
  async decryptReceivedMessage(encryptedMessage, receiverPrivateKey, senderId) {
    console.log(`🔓 Decrypting received message...`);

    try {
      // Get sender's public key
      const senderPublicKey = await this.getPublicKey(senderId);

      // Decrypt
      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedMessage,
        receiverPrivateKey,
        senderPublicKey
      );

      console.log(`✅ Message decrypted`);
      return decrypted.plaintext;
    } catch (error) {
      console.error('❌ Failed to decrypt message:', error);
      throw error;
    }
  }
}

// ✅ Export for global access and module systems
if (typeof window !== 'undefined') {
    window.FirebaseAESECC = FirebaseAESECC;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = FirebaseAESECC;
}

// Named export for ES6 modules
export default FirebaseAESECC;