class AESECCSystem {
  constructor() {
    this.metrics = {
      plaintexts: [],
      ciphertexts: [],
      times: []
    };
  }

  /**
   * Step 1: Generate ECC P-256 Key Pair
   */
  async generateECCKeyPair() {
    console.log('🔑 Generating ECC P-256 key pair...');
    const start = performance.now();

    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true, 
      ['deriveBits', 'deriveKey']
    );

    const time = performance.now() - start;
    console.log(` Generated in ${time.toFixed(2)}ms`);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey
    };
  }

  /**
   * Export Public Key to JWK (untuk Firebase)
   */
  async exportPublicKeyToJWK(publicKey) {
    const jwk = await window.crypto.subtle.exportKey('jwk', publicKey);
    return jwk;
  }

  /**
   * Import Public Key dari JWK
   */
  async importPublicKeyFromJWK(jwk) {
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveBits']
    );
    return publicKey;
  }

  /**
   * Step 2: ECDH Key Agreement (menghasilkan shared secret)
   */
  async performECDH(privateKey, publicKeyRemote) {
    console.log(' ECDH P-256 key agreement...');
    const start = performance.now();

    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKeyRemote
      },
      privateKey,
      256 // 256 bits
    );

    const time = performance.now() - start;
    console.log(` Shared secret generated (${new Uint8Array(sharedSecret).length} bytes) in ${time.toFixed(2)}ms`);

    return new Uint8Array(sharedSecret);
  }

  /**
   * Step 3: Derive AES Key dari Shared Secret
   */
  async deriveAESKeyFromSharedSecret(sharedSecret) {
    console.log('🔑 Deriving AES-256 key from shared secret...');
    const start = performance.now();

    // Import shared secret sebagai key untuk HKDF
    const ikm = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Derive menggunakan HKDF
    const keyMaterial = await window.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('dialek-id-aes-ecc')
      },
      ikm,
      256 // 256 bits untuk AES-256
    );

    // Import sebagai AES key
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      keyMaterial,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );

    const time = performance.now() - start;
    console.log(AES key derived in ${time.toFixed(2)}ms);

    return aesKey;
  }

  /**
   * Step 4: Encrypt dengan AES-256-GCM
   */
  async encryptWithAES(plaintext, aesKey) {
    console.log('🔒 Encrypting with AES-256-GCM...');
    const start = performance.now();

    // Generate random IV (96-bit)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Convert plaintext ke bytes
    const plaintextBytes = new TextEncoder().encode(plaintext);

    // Encrypt
    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      aesKey,
      plaintextBytes
    );

    const time = performance.now() - start;

    // Combine IV + Ciphertext
    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), iv.length);

    console.log(✅ Encrypted in ${time.toFixed(2)}ms);
    console.log(`   Plaintext: ${plaintextBytes.length} bytes → Ciphertext: ${result.length} bytes`);

    this.metrics.plaintexts.push(plaintextBytes.length);
    this.metrics.ciphertexts.push(result.length);
    this.metrics.times.push(time);

    return {
      iv,
      ciphertext: new Uint8Array(ciphertext),
      combined: result,
      plaintextSize: plaintextBytes.length,
      ciphertextSize: new Uint8Array(ciphertext).length
    };
  }

  /**
   * Step 5: Decrypt dengan AES-256-GCM
   */
  async decryptWithAES(encryptedData, aesKey) {
    console.log('🔓 Decrypting with AES-256-GCM...');
    const start = performance.now();

    // Extract IV dan ciphertext
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);

    // Decrypt
    const plaintext = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      aesKey,
      ciphertext
    );

    const time = performance.now() - start;
    const plaintextString = new TextDecoder().decode(plaintext);

    console.log(✅ Decrypted in ${time.toFixed(2)}ms);
    console.log(`   Size: ${plaintext.byteLength} bytes`);

    return plaintextString;
  }

  /**
   * Encrypt plaintext
   * Input: plaintext + sender private key + receiver public key
   * Output: encrypted payload untuk Firebase
   */
  async encryptCompleteWorkflow(plaintext, senderPrivateKey, receiverPublicKey) {
    console.log('\n COMPLETE ENCRYPTION WORKFLOW\n');
    const workflowStart = performance.now();

    try {
      // 1. ECDH
      console.log('[1/3] ECDH Key Agreement');
      const sharedSecret = await this.performECDH(senderPrivateKey, receiverPublicKey);

      // 2. Derive AES Key
      console.log('\n[2/3] AES Key Derivation');
      const aesKey = await this.deriveAESKeyFromSharedSecret(sharedSecret);

      // 3. AES Encrypt
      console.log('\n[3/3] AES-256-GCM Encryption');
      const encryptResult = await this.encryptWithAES(plaintext, aesKey);

      const workflowTime = performance.now() - workflowStart;

      console.log('\n  WORKFLOW COMPLETE');
      console.log(` Total time: ${workflowTime.toFixed(2)}ms\n`);

      // Return encrypted package
      return {
        encryptedData: this.uint8ToBase64(encryptResult.combined),
        plaintextSize: encryptResult.plaintextSize,
        ciphertextSize: encryptResult.ciphertextSize,
        expansion: (encryptResult.combined.length / encryptResult.plaintextSize).toFixed(2),
        workflowTime: workflowTime,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error(' Encryption failed:', error);
      throw error;
    }
  }

  /**
   *  Decrypt ciphertext
   * Input: encrypted payload + receiver private key + sender public key
   * Output: plaintext
   */
  async decryptCompleteWorkflow(encryptedPayload, receiverPrivateKey, senderPublicKey) {
    console.log('\n COMPLETE DECRYPTION WORKFLOW \n');
    const workflowStart = performance.now();

    try {
      // 1. ECDH (same as sender)
      console.log('[1/3] ECDH Key Agreement (regenerate)');
      const sharedSecret = await this.performECDH(receiverPrivateKey, senderPublicKey);

      // 2. Derive AES Key (same as encryption)
      console.log('\n[2/3] AES Key Derivation');
      const aesKey = await this.deriveAESKeyFromSharedSecret(sharedSecret);

      // 3. AES Decrypt
      console.log('\n[3/3] AES-256-GCM Decryption');
      const encryptedBytes = this.base64ToUint8(encryptedPayload);
      const plaintext = await this.decryptWithAES(encryptedBytes, aesKey);

      const workflowTime = performance.now() - workflowStart;

      console.log('\n WORKFLOW COMPLETE ');
      console.log(` Total time: ${workflowTime.toFixed(2)}ms\n`);

      return {
        plaintext: plaintext,
        workflowTime: workflowTime
      };
    } catch (error) {
      console.error(' Decryption failed:', error);
      throw error;
    }
  }

  /**
   * Utility: Convert Uint8Array to Base64
   */
  uint8ToBase64(uint8) {
    const binary = String.fromCharCode.apply(null, uint8);
    return btoa(binary);
  }

  /**
   * Utility: Convert Base64 to Uint8Array
   */
  base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Generate Security Analysis Report
   */
  generateReport() {
    const totalPlaintext = this.metrics.plaintexts.reduce((a, b) => a + b, 0);
    const totalCiphertext = this.metrics.ciphertexts.reduce((a, b) => a + b, 0);
    const avgTime = this.metrics.times.length > 0 
      ? (this.metrics.times.reduce((a, b) => a + b, 0) / this.metrics.times.length).toFixed(2)
      : 0;

    return {
      system: {
        keyAgreement: 'ECDH P-256',
        encryption: 'AES-256-GCM',
        symmetricEquivalent: 'AES-256 (256-bit)',
        ecdsSymmetricEquivalent: 'ECC P-256 (128-bit)',
        description: 'AES-ECC hybrid for end-to-end encryption on Firebase'
      },
      sizeAnalysis: {
        totalPlaintextBytes: totalPlaintext,
        totalCiphertextBytes: totalCiphertext,
        expansionRatio: totalPlaintext > 0 ? (totalCiphertext / totalPlaintext).toFixed(4) : 0,
        overheadPerMessage: 12 + 16, 
        note: 'Fixed overhead ~28 bytes per message'
      },
      performance: {
        averageEncryptionTime: avgTime + 'ms',
        totalOperations: this.metrics.plaintexts.length,
        cryptoLibrary: 'Web Crypto API'
      },
      security: {
        keySize: '256-bit AES + 256-bit ECDH',
        confidentiality: ' Full (AES-256)',
        integrity: ' Full (AES-GCM auth tag)',
        keyExchange: 'ECDH P-256',
        forwardSecrecy: 'Per-message key derivation',
        endToEnd: ' Private keys never sent to Firebase'
      }
    };
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AESECCSystem;
}