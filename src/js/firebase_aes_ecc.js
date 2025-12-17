/**
 * Firebase Integration for AES-ECC
 */

class FirebaseAESECC {
  constructor(db, cryptoSystem) {
    this.db = db;
    this.crypto = cryptoSystem;
  }

  /**
   * Store User's ECC Public Key
   */
  async storePublicKey(userId, publicKeyJWK) {
    console.log(` Storing public key for user ${userId}...`);
    
    const { doc, setDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      await setDoc(doc(this.db, 'users', userId, 'keys', 'public'), {
        key: publicKeyJWK,
        algorithm: 'ECC-P256',
        usage: 'ECDH key agreement',
        createdAt: new Date().toISOString()
      });

      console.log(` Public key stored`);
    } catch (error) {
      console.error(' Failed to store public key:', error);
      throw error;
    }
  }

  /**
   * Get User's Public Key
   */
  async getPublicKey(userId) {
    const { doc, getDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const publicKeyDoc = await getDoc(doc(this.db, 'users', userId, 'keys', 'public'));
      
      if (!publicKeyDoc.exists()) {
        throw new Error(Public key not found for user ${userId});
      }

      const jwk = publicKeyDoc.data().key;
      const publicKey = await this.crypto.importPublicKeyFromJWK(jwk);

      return publicKey;
    } catch (error) {
      console.error(' Failed to get public key:', error);
      throw error;
    }
  }

  /**
   * Encrypt and Store User Profile
   */
  async storeUserProfile(userId, profileData, userPrivateKey) {
    const { doc, setDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(👤 Encrypting and storing user profile...);

    try {
      // Get user's public key
      const userPublicKey = await this.getPublicKey(userId);

      // Data to encrypt
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

      // Store
      await setDoc(doc(this.db, 'users', userId), {
        // Public data
        username: profileData.username,
        profileImage: profileData.profileImage,

        // Encrypted data
        encryptedProfile: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion,
          timestamp: encrypted.timestamp
        }
      }, { merge: true });

      console.log(` Profile stored securely`);
      return encrypted;
    } catch (error) {
      console.error(' Failed to store profile:', error);
      throw error;
    }
  }

  /**
   * Retrieve and Decrypt User Profile
   */
  async getUserProfile(userId, userPrivateKey) {
    const { doc, getDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(👤 Retrieving and decrypting user profile...);

    try {
      // Get user's public key
      const userPublicKey = await this.getPublicKey(userId);

      // Get encrypted profile
      const userDoc = await getDoc(doc(this.db, 'users', userId));
      const encryptedProfile = userDoc.data().encryptedProfile;

      // Decrypt
      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedProfile,
        userPrivateKey,
        userPublicKey
      );

      const profileData = JSON.parse(decrypted.plaintext);

      console.log(` Profile decrypted successfully`);
      return profileData;
    } catch (error) {
      console.error(' Failed to get profile:', error);
      throw error;
    }
  }

  /**
   * Encrypt and Store Forum Question
   */
  async postForumQuestion(userId, question, userPrivateKey) {
    const { doc, collection, addDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(Posting encrypted forum question...);

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
          expansion: encrypted.expansion
        },
        postedAt: new Date().toISOString()
      });

      console.log(` Forum question posted securely`);
      return encrypted;
    } catch (error) {
      console.error(' Failed to post forum question:', error);
      throw error;
    }
  }

  /**
   * Get Forum Questions
   */
  async getForumQuestions() {
    const { collection, getDocs } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(Fetching forum questions...);

    try {
      const forumCollection = collection(this.db, 'forum');
      const snapshot = await getDocs(forumCollection);

      const questions = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      console.log(Retrieved ${questions.length} questions);
      return questions;
    } catch (error) {
      console.error('Failed to get forum questions:', error);
      throw error;
    }
  }

  /**
   * Decrypt Forum Question (by viewer)
   */
  async decryptForumQuestion(encryptedQuestion, viewerPrivateKey, authorId) {
    console.log(Decrypting forum question...);

    try {
      // Get author's public key
      const authorPublicKey = await this.getPublicKey(authorId);

      // Decrypt
      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedQuestion,
        viewerPrivateKey,
        authorPublicKey
      );

      console.log(Question decrypted);
      return decrypted.plaintext;
    } catch (error) {
      console.error('Failed to decrypt question:', error);
      throw error;
    }
  }

  /**
   * Send Encrypted Message between Users
   */
  async sendEncryptedMessage(senderUserId, recipientUserId, message, senderPrivateKey) {
    const { doc, collection, addDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    console.log(Sending encrypted message...);

    try {
      // Get recipient's public key
      const recipientPublicKey = await this.getPublicKey(recipientUserId);

      // Encrypt
      const encrypted = await this.crypto.encryptCompleteWorkflow(
        message,
        senderPrivateKey,
        recipientPublicKey
      );

      // Store in sender's messages
      await addDoc(collection(this.db, 'users', senderUserId, 'messages'), {
        type: 'sent',
        recipientId: recipientUserId,
        encryptedContent: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion
        },
        sentAt: new Date().toISOString()
      });

      // Store in recipient's messages
      await addDoc(collection(this.db, 'users', recipientUserId, 'messages'), {
        type: 'received',
        senderId: senderUserId,
        encryptedContent: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion
        },
        receivedAt: new Date().toISOString()
      });

      console.log(Message sent securely);
      return encrypted;
    } catch (error) {
      console.error('Failed to send message:', error);
      throw error;
    }
  }

  /**
   * Get Received Messages
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
      console.error(' Failed to get messages:', error);
      throw error;
    }
  }

  /**
   * Decrypt Received Message
   */
  async decryptReceivedMessage(encryptedMessage, receiverPrivateKey, senderId) {
    console.log(Decrypting received message...);

    try {
      // Get sender's public key
      const senderPublicKey = await this.getPublicKey(senderId);

      // Decrypt
      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedMessage,
        receiverPrivateKey,
        senderPublicKey
      );

      console.log(Message decrypted);
      return decrypted.plaintext;
    } catch (error) {
      console.error('Failed to decrypt message:', error);
      throw error;
    }
  }
}

export default FirebaseAESECC;