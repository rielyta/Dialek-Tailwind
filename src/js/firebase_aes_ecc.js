class FirebaseAESECC {
  constructor(db, cryptoSystem) {
    this.db = db;
    this.crypto = cryptoSystem;
  }

  async storePublicKey(userId, publicKeyJWK) {
    const { doc, setDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      await setDoc(doc(this.db, 'users', userId, 'keys', 'public'), {
        key: publicKeyJWK,
        algorithm: 'ECC-P256',
        usage: 'ECDH key agreement',
        createdAt: new Date().toISOString()
      });
    } catch (error) {
      throw error;
    }
  }

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
      throw error;
    }
  }

  async storeUserProfile(userId, profileData, userPrivateKey) {
    const { doc, setDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const userPublicKey = await this.getPublicKey(userId);

      const dataToEncrypt = {
        name: profileData.name,
        email: profileData.email,
        phone: profileData.phone
      };

      const encrypted = await this.crypto.encryptCompleteWorkflow(
        JSON.stringify(dataToEncrypt),
        userPrivateKey,
        userPublicKey
      );

      await setDoc(doc(this.db, 'users', userId), {
        username: profileData.username,
        profileImage: profileData.profileImage,
        encryptedProfile: encrypted.encryptedData,
        encryptionMetadata: {
          algorithm: 'AES-256-GCM + ECDH-P256',
          plaintextSize: encrypted.plaintextSize,
          ciphertextSize: encrypted.ciphertextSize,
          expansion: encrypted.expansion,
          workflowTime: encrypted.workflowTime
        }
      }, { merge: true });

      return encrypted;
    } catch (error) {
      throw error;
    }
  }

  async getUserProfile(userId, userPrivateKey) {
    const { doc, getDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const userPublicKey = await this.getPublicKey(userId);
      const userDoc = await getDoc(doc(this.db, 'users', userId));
      if (!userDoc.exists()) {
        throw new Error(`User profile not found for ${userId}`);
      }

      const encryptedProfile = userDoc.data().encryptedProfile;
      if (!encryptedProfile) {
        throw new Error('No encrypted profile data found');
      }

      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedProfile,
        userPrivateKey,
        userPublicKey
      );

      const profileData = JSON.parse(decrypted.plaintext);

      return profileData;
    } catch (error) {
      throw error;
    }
  }

  async postForumQuestion(userId, question, userPrivateKey) {
    const { doc, collection, addDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const userPublicKey = await this.getPublicKey(userId);

      const encrypted = await this.crypto.encryptCompleteWorkflow(
        question,
        userPrivateKey,
        userPublicKey
      );

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

      return encrypted;
    } catch (error) {
      throw error;
    }
  }

  async getForumQuestions() {
    const { collection, getDocs } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const forumCollection = collection(this.db, 'forum');
      const snapshot = await getDocs(forumCollection);

      const questions = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      return questions;
    } catch (error) {
      throw error;
    }
  }

  async decryptForumQuestion(encryptedQuestion, viewerPrivateKey, authorId) {
    try {
      const authorPublicKey = await this.getPublicKey(authorId);

      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedQuestion,
        viewerPrivateKey,
        authorPublicKey
      );

      return decrypted.plaintext;
    } catch (error) {
      throw error;
    }
  }

  async sendEncryptedMessage(senderUserId, recipientUserId, message, senderPrivateKey) {
    const { doc, collection, addDoc } = await import('https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js');

    try {
      const recipientPublicKey = await this.getPublicKey(recipientUserId);

      const encrypted = await this.crypto.encryptCompleteWorkflow(
        message,
        senderPrivateKey,
        recipientPublicKey
      );

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

      return encrypted;
    } catch (error) {
      throw error;
    }
  }

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
      throw error;
    }
  }

  async decryptReceivedMessage(encryptedMessage, receiverPrivateKey, senderId) {
    try {
      const senderPublicKey = await this.getPublicKey(senderId);

      const decrypted = await this.crypto.decryptCompleteWorkflow(
        encryptedMessage,
        receiverPrivateKey,
        senderPublicKey
      );

      return decrypted.plaintext;
    } catch (error) {
      throw error;
    }
  }
}

if (typeof window !== 'undefined') {
    window.FirebaseAESECC = FirebaseAESECC;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = FirebaseAESECC;
}

export default FirebaseAESECC;