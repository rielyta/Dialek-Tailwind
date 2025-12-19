class AESECCSystem {
  constructor() {
    this.curve = "P-256";
    this.metrics = {
      ecdhTimes: [],
      hkdfTimes: [],
      aesTimes: [],
      totalEncryptTimes: [],
      totalDecryptTimes: [],
      plaintextSizes: [],
      ciphertextSizes: []
    };
  }

  async generateECCKeyPair() {
    return crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: this.curve
      },
      true,
      ["deriveKey", "deriveBits"]
    );
  }

  async exportPublicKeyToJWK(publicKey) {
    return crypto.subtle.exportKey("jwk", publicKey);
  }

  async exportPrivateKey(privateKey) {
    return crypto.subtle.exportKey("jwk", privateKey);
  }

  async importPublicKeyFromJWK(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: this.curve },
      true,
      []
    );
  }

  async importPrivateKeyFromJWK(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: this.curve },
      true,
      ["deriveKey", "deriveBits"]
    );
  }

  async deriveSharedSecret(privateKey, publicKey) {
    const startTime = performance.now();
    
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: publicKey
      },
      privateKey,
      256
    );
    
    const endTime = performance.now();
    this.metrics.ecdhTimes.push(endTime - startTime);
    
    return new Uint8Array(sharedSecret);
  }

  async deriveAESKey(sharedSecret) {
    const startTime = performance.now();
    
    const importedKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveBits', 'deriveKey']
    );

    const keyMaterial = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('dialek-id-aes-ecc')
      },
      importedKey,
      256
    );

    const aesKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
    
    const endTime = performance.now();
    this.metrics.hkdfTimes.push(endTime - startTime);
    
    return aesKey;
  }

  async encryptWithAES(plaintext, aesKey) {
    const startTime = performance.now();
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintextBytes = new TextEncoder().encode(plaintext);

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      aesKey,
      plaintextBytes
    );

    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    const endTime = performance.now();
    this.metrics.aesTimes.push(endTime - startTime);
    this.metrics.plaintextSizes.push(plaintextBytes.length);
    this.metrics.ciphertextSizes.push(combined.length);

    return {
      iv,
      ciphertext: new Uint8Array(ciphertext),
      combined: combined,
      plaintextSize: plaintextBytes.length,
      ciphertextSize: combined.length
    };
  }

  async decryptWithAES(encryptedData, aesKey) {
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);

    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(plaintext);
  }

  async encryptCompleteWorkflow(plaintext, senderPrivateKey, receiverPublicKey) {
    const workflowStart = performance.now();

    try {
      const sharedSecret = await this.deriveSharedSecret(senderPrivateKey, receiverPublicKey);
      const aesKey = await this.deriveAESKey(sharedSecret);
      const encryptResult = await this.encryptWithAES(plaintext, aesKey);

      const workflowEnd = performance.now();
      const workflowTime = workflowEnd - workflowStart;
      this.metrics.totalEncryptTimes.push(workflowTime);

      return {
        encryptedData: this.uint8ToBase64(encryptResult.combined),
        plaintextSize: encryptResult.plaintextSize,
        ciphertextSize: encryptResult.ciphertextSize,
        expansion: (encryptResult.ciphertextSize / encryptResult.plaintextSize).toFixed(2),
        workflowTime: workflowTime.toFixed(2)
      };
    } catch (error) {
      console.error('Encryption failed:', error);
      throw error;
    }
  }

  async decryptCompleteWorkflow(encryptedPayload, receiverPrivateKey, senderPublicKey) {
    const workflowStart = performance.now();

    try {
      const combined = this.base64ToUint8(encryptedPayload);
      const sharedSecret = await this.deriveSharedSecret(receiverPrivateKey, senderPublicKey);
      const aesKey = await this.deriveAESKey(sharedSecret);
      const plaintext = await this.decryptWithAES(combined, aesKey);

      const workflowEnd = performance.now();
      const workflowTime = workflowEnd - workflowStart;
      this.metrics.totalDecryptTimes.push(workflowTime);

      return {
        plaintext,
        workflowTime: workflowTime.toFixed(2)
      };
    } catch (error) {
      console.error('Decryption failed:', error);
      throw error;
    }
  }

  uint8ToBase64(uint8) {
    return btoa(String.fromCharCode(...uint8));
  }

  base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  getPerformanceStats() {
    const calculateStats = (arr) => {
      if (arr.length === 0) return { avg: 0, min: 0, max: 0 };
      const sum = arr.reduce((a, b) => a + b, 0);
      return {
        avg: (sum / arr.length).toFixed(2),
        min: Math.min(...arr).toFixed(2),
        max: Math.max(...arr).toFixed(2)
      };
    };

    const encryptStats = calculateStats(this.metrics.totalEncryptTimes);
    const throughput = encryptStats.avg > 0 ? Math.floor(1000 / parseFloat(encryptStats.avg)) : 0;

    return {
      ecdhAgreement: calculateStats(this.metrics.ecdhTimes),
      hkdfDerivation: calculateStats(this.metrics.hkdfTimes),
      aesEncryption: calculateStats(this.metrics.aesTimes),
      totalEncryption: encryptStats,
      totalDecryption: calculateStats(this.metrics.totalDecryptTimes),
      throughput: throughput,
      avgExpansion: this.metrics.plaintextSizes.length > 0 
        ? (this.metrics.ciphertextSizes.reduce((a, b) => a + b, 0) / 
           this.metrics.plaintextSizes.reduce((a, b) => a + b, 0)).toFixed(2)
        : 0
    };
  }

  resetMetrics() {
    this.metrics = {
      ecdhTimes: [],
      hkdfTimes: [],
      aesTimes: [],
      totalEncryptTimes: [],
      totalDecryptTimes: [],
      plaintextSizes: [],
      ciphertextSizes: []
    };
  }
}

if (typeof window !== 'undefined') {
  window.AESECCSystem = AESECCSystem;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AESECCSystem;
}

export default AESECCSystem;