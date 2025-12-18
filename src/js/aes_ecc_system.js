/**
 * AES-ECC Cryptographic System
 * 
 * Provides hybrid encryption using:
 * - ECC (Elliptic Curve Cryptography) for key agreement
 * - AES-256-GCM for symmetric encryption
 * 
 * @version 1.0
 * @exports {class} AESECCSystem
 */

export class AESECCSystem {

  constructor() {
    this.curve = "P-256";
  }

  /**
   * Generate ECC Key Pair
   * @returns {Promise<CryptoKeyPair>} Public and Private keys
   */
  async generateECCKeyPair() {
    return crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: this.curve
      },
      true, // extractable
      ["deriveKey", "deriveBits"]
    );
  }

  /**
   * Export Public Key to JWK format
   * @param {CryptoKey} publicKey
   * @returns {Promise<Object>} JWK format
   */
  async exportPublicKeyToJWK(publicKey) {
    return crypto.subtle.exportKey("jwk", publicKey);
  }

  /**
   * Export Private Key to JWK format
   * @param {CryptoKey} privateKey
   * @returns {Promise<Object>} JWK format
   */
  async exportPrivateKey(privateKey) {
    return crypto.subtle.exportKey("jwk", privateKey);
  }

  /**
   * Import Public Key from JWK
   * @param {Object} jwk - Public key in JWK format
   * @returns {Promise<CryptoKey>}
   */
  async importPublicKeyFromJWK(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: this.curve },
      true,
      []
    );
  }

  /**
   * Import Private Key from JWK
   * @param {Object} jwk - Private key in JWK format
   * @returns {Promise<CryptoKey>}
   */
  async importPrivateKeyFromJWK(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: this.curve },
      true,
      ["deriveKey", "deriveBits"]
    );
  }

  /**
   * Derive shared secret using ECDH
   * @param {CryptoKey} privateKey
   * @param {CryptoKey} publicKey
   * @returns {Promise<Uint8Array>}
   */
  async deriveSharedSecret(privateKey, publicKey) {
    return crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: publicKey
      },
      privateKey,
      256 // 256 bits = 32 bytes
    );
  }

  /**
   * Derive AES Key from shared secret
   * @param {Uint8Array} sharedSecret
   * @returns {Promise<CryptoKey>}
   */
  async deriveAESKey(sharedSecret) {
    // First import the shared secret as HMAC key
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    // Then derive AES key using HMAC-based KDF (simplified)
    // In production, use proper HKDF or PBKDF2
    const derivedBits = await crypto.subtle.sign(
      "HMAC",
      hkdfKey,
      new TextEncoder().encode("AES-KEY-DERIVATION")
    );

    return crypto.subtle.importKey(
      "raw",
      derivedBits.slice(0, 32), // Take first 256 bits for AES-256
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Complete encryption workflow
   * Encrypts plaintext using hybrid AES-ECC encryption
   * 
   * @param {string} plaintext - Text to encrypt
   * @param {CryptoKey} senderPrivateKey - Sender's private key
   * @param {CryptoKey} recipientPublicKey - Recipient's public key
   * @returns {Promise<Object>} {encryptedData: string, plaintextSize, ciphertextSize, expansion, workflowTime}
   */
  async encryptCompleteWorkflow(plaintext, senderPrivateKey, recipientPublicKey) {
    const startTime = performance.now();

    try {
      // 1. Derive shared secret using ECDH
      const sharedSecret = await this.deriveSharedSecret(senderPrivateKey, recipientPublicKey);

      // 2. Derive AES key from shared secret
      const aesKey = await this.deriveAESKey(sharedSecret);

      // 3. Generate random IV
      const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits for GCM

      // 4. Encrypt plaintext with AES-256-GCM
      const plaintextBytes = new TextEncoder().encode(plaintext);
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        aesKey,
        plaintextBytes
      );

      // 5. Combine IV + Ciphertext + Authentication Tag
      const combined = new Uint8Array(iv.length + ciphertext.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(ciphertext), iv.length);

      // 6. Encode to Base64 for storage
      const encryptedData = btoa(String.fromCharCode(...combined));

      const endTime = performance.now();
      const workflowTime = endTime - startTime;

      return {
        encryptedData,
        plaintextSize: plaintextBytes.length,
        ciphertextSize: combined.length,
        expansion: ((combined.length - plaintextBytes.length) / plaintextBytes.length * 100).toFixed(2) + '%',
        workflowTime: workflowTime.toFixed(2) + 'ms'
      };

    } catch (error) {
      console.error('❌ Encryption failed:', error);
      throw error;
    }
  }

  /**
   * Complete decryption workflow
   * Decrypts AES-ECC encrypted data
   * 
   * @param {string} encryptedData - Base64 encrypted data
   * @param {CryptoKey} recipientPrivateKey - Recipient's private key
   * @param {CryptoKey} senderPublicKey - Sender's public key
   * @returns {Promise<Object>} {plaintext: string, workflowTime}
   */
  async decryptCompleteWorkflow(encryptedData, recipientPrivateKey, senderPublicKey) {
    const startTime = performance.now();

    try {
      // 1. Decode Base64
      const combined = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));

      // 2. Extract IV (first 12 bytes) and ciphertext
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);

      // 3. Derive shared secret using ECDH (same as encryption)
      const sharedSecret = await this.deriveSharedSecret(recipientPrivateKey, senderPublicKey);

      // 4. Derive AES key from shared secret
      const aesKey = await this.deriveAESKey(sharedSecret);

      // 5. Decrypt with AES-256-GCM
      const plaintextBytes = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        aesKey,
        ciphertext
      );

      // 6. Convert to string
      const plaintext = new TextDecoder().decode(plaintextBytes);

      const endTime = performance.now();
      const workflowTime = endTime - startTime;

      return {
        plaintext,
        workflowTime: workflowTime.toFixed(2) + 'ms'
      };

    } catch (error) {
      console.error('❌ Decryption failed:', error);
      throw error;
    }
  }
}

// 📤 Default export untuk compatibility
export default AESECCSystem;

// 🌍 Global export untuk non-module scripts
if (typeof window !== 'undefined') {
  window.AESECCSystem = AESECCSystem;
}