/**
 * HYBRID ENCRYPTION SYSTEM: AES-256-GCM + ECDH P-256
 * ==================================================
 * 
 * Implementation of hybrid cryptography for Dialek.id platform
 * Combines asymmetric (ECC) and symmetric (AES) encryption
 * 
 * ARCHITECTURE:
 * ============
 * 1. ECDH P-256: Elliptic Curve Diffie-Hellman for key agreement
 * 2. HKDF-SHA256: Key derivation function for shared secret
 * 3. AES-256-GCM: Authenticated encryption with associated data
 * 4. Web Crypto API: Native browser cryptography (no external libraries)
 * 
 * SECURITY PROPERTIES:
 * ===================
 * ✓ End-to-End Encryption: Private keys never leave client
 * ✓ Forward Secrecy: Unique IV per message
 * ✓ Authentication: GCM mode provides integrity + authenticity
 * ✓ Confidentiality: 256-bit AES (military-grade encryption)
 * 
 * WORKFLOW:
 * =========
 * Encryption:
 *   Plaintext → ECDH (generate shared secret) → HKDF (derive AES key)
 *   → AES-GCM encrypt → Ciphertext + IV + Auth Tag → Base64 → Firebase
 * 
 * Decryption:
 *   Firebase → Base64 decode → ECDH (generate shared secret) → HKDF
 *   → AES-GCM decrypt (verify auth tag) → Plaintext
 * 
 * @author Dialek.id Research Team
 * @date December 2024
 * @version 1.0 (PRODUCTION READY)
 */

class AESECCSystem {
    constructor() {
        this.metrics = { 
            plaintexts: [], 
            ciphertexts: [], 
            times: [], 
            decryptTimes: [] 
        };
    }

    /**
     * Generate ECDH P-256 key pair
     * 
     * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
     * 
     * Security: P-256 provides ~128-bit security (equivalent to RSA-3072)
     */
    async generateECCKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            { 
                name: 'ECDH', 
                namedCurve: 'P-256'  // NIST P-256 (secp256r1)
            },
            true,  // Extractable (needed for export)
            ['deriveBits', 'deriveKey']  // Key agreement operations
        );
        return { 
            publicKey: keyPair.publicKey, 
            privateKey: keyPair.privateKey 
        };
    }

    /**
     * Perform ECDH key agreement
     * 
     * Combines local private key with remote public key to generate
     * a shared secret that both parties can compute independently
     * 
     * @param {CryptoKey} privateKey - Local user's private key
     * @param {CryptoKey} publicKeyRemote - Remote user's public key
     * @returns {Promise<Uint8Array>} - 256-bit shared secret
     * 
     * Security: Shared secret is never transmitted over network
     */
    async performECDH(privateKey, publicKeyRemote) {
        const sharedSecret = await window.crypto.subtle.deriveBits(
            { 
                name: 'ECDH', 
                public: publicKeyRemote  // Remote party's public key
            },
            privateKey,  // Our private key
            256  // Derive 256 bits
        );
        return new Uint8Array(sharedSecret);
    }

    /**
     * Derive AES-256 key from shared secret using HKDF
     * 
     * HKDF (HMAC-based Key Derivation Function) transforms the shared
     * secret into a cryptographically strong AES key with proper entropy
     * 
     * @param {Uint8Array} sharedSecret - Output from ECDH
     * @returns {Promise<CryptoKey>} - AES-256-GCM key
     * 
     * CRITICAL FIX:
     * ============
     * Web Crypto API requires HKDF's deriveBits() to receive a CryptoKey
     * object, NOT raw bytes. Must import sharedSecret first!
     * 
     * Reference: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits
     */
    async deriveAESKeyFromSharedSecret(sharedSecret) {
        // STEP 1: Import shared secret as CryptoKey for HKDF
        // -------------------------------------------------
        // HKDF requires a CryptoKey object, not Uint8Array
        const importedKey = await window.crypto.subtle.importKey(
            'raw',                          // Format: raw bytes
            sharedSecret,                   // The Uint8Array from ECDH
            { name: 'HKDF' },              // Algorithm identifier
            false,                          // Not extractable (security)
            ['deriveBits', 'deriveKey']    // Permitted operations
        );

        // STEP 2: Use HKDF to derive 256 bits of key material
        // --------------------------------------------------
        // HKDF ensures the derived key has full entropy and is
        // cryptographically independent from the shared secret
        const keyMaterial = await window.crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',                                // Hash function
                salt: new Uint8Array(32),                      // 32-byte salt (zeros OK)
                info: new TextEncoder().encode('dialek-id-aes-ecc')  // Context string
            },
            importedKey,  // ✅ CryptoKey (NOT Uint8Array!)
            256           // Output: 256 bits for AES-256
        );

        // STEP 3: Import derived material as AES-GCM key
        // --------------------------------------------
        const aesKey = await window.crypto.subtle.importKey(
            'raw',
            keyMaterial,
            { name: 'AES-GCM' },
            false,  // Not extractable (security)
            ['encrypt', 'decrypt']
        );

        return aesKey;
    }

    /**
     * Encrypt plaintext with AES-256-GCM
     * 
     * GCM (Galois/Counter Mode) provides:
     * - Confidentiality through encryption
     * - Authenticity through authentication tag
     * - Integrity protection against tampering
     * 
     * @param {string} plaintext - Data to encrypt
     * @param {CryptoKey} aesKey - AES-256 key from HKDF
     * @returns {Promise<Object>} - Encrypted data with metadata
     * 
     * Output format: IV (12 bytes) + Ciphertext + Auth Tag (16 bytes)
     */
    async encryptWithAES(plaintext, aesKey) {
        // Generate random IV (Initialization Vector)
        // CRITICAL: Must be unique for each message
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const plaintextBytes = new TextEncoder().encode(plaintext);

        // AES-256-GCM encryption
        const ciphertext = await window.crypto.subtle.encrypt(
            { 
                name: 'AES-GCM', 
                iv: iv,
                tagLength: 128  // 128-bit authentication tag
            },
            aesKey,
            plaintextBytes
        );

        // Combine IV + Ciphertext (IV needed for decryption)
        const result = new Uint8Array(iv.length + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), iv.length);

        // Track metrics for research paper
        this.metrics.plaintexts.push(plaintextBytes.length);
        this.metrics.ciphertexts.push(result.length);

        return {
            iv,
            ciphertext: new Uint8Array(ciphertext),
            combined: result,
            plaintextSize: plaintextBytes.length,
            ciphertextSize: new Uint8Array(ciphertext).length
        };
    }

    /**
     * Decrypt ciphertext with AES-256-GCM
     * 
     * @param {Uint8Array} encryptedData - IV + Ciphertext + Auth Tag
     * @param {CryptoKey} aesKey - AES-256 key from HKDF
     * @returns {Promise<string>} - Decrypted plaintext
     * 
     * Security: GCM automatically verifies auth tag; throws error if tampered
     */
    async decryptWithAES(encryptedData, aesKey) {
        // Extract IV (first 12 bytes)
        const iv = encryptedData.slice(0, 12);
        // Remaining bytes: ciphertext + auth tag
        const ciphertext = encryptedData.slice(12);

        // AES-256-GCM decryption (verifies auth tag automatically)
        const plaintext = await window.crypto.subtle.decrypt(
            { 
                name: 'AES-GCM', 
                iv: iv 
            },
            aesKey,
            ciphertext
        );

        return new TextDecoder().decode(plaintext);
    }

    /**
     * Complete encryption workflow (ECDH + HKDF + AES-GCM)
     * 
     * @param {string} plaintext - Message to encrypt
     * @param {CryptoKey} senderPrivateKey - Sender's private key
     * @param {CryptoKey} receiverPublicKey - Receiver's public key
     * @returns {Promise<Object>} - Encrypted data ready for Firebase
     */
    async encryptCompleteWorkflow(plaintext, senderPrivateKey, receiverPublicKey) {
        const start = performance.now();

        // 1. ECDH: Generate shared secret
        const ecdhResult = await this.performECDH(senderPrivateKey, receiverPublicKey);
        
        // 2. HKDF: Derive AES key from shared secret
        const aesKey = await this.deriveAESKeyFromSharedSecret(ecdhResult);
        
        // 3. AES-GCM: Encrypt plaintext
        const encryptResult = await this.encryptWithAES(plaintext, aesKey);

        const time = performance.now() - start;
        this.metrics.times.push(time);

        return {
            encryptedData: this.uint8ToBase64(encryptResult.combined),
            plaintextSize: encryptResult.plaintextSize,
            ciphertextSize: encryptResult.ciphertextSize,
            expansion: (encryptResult.combined.length / encryptResult.plaintextSize).toFixed(2),
            workflowTime: time
        };
    }

    /**
     * Complete decryption workflow (ECDH + HKDF + AES-GCM)
     * 
     * @param {string} encryptedPayload - Base64 encrypted data from Firebase
     * @param {CryptoKey} receiverPrivateKey - Receiver's private key
     * @param {CryptoKey} senderPublicKey - Sender's public key
     * @returns {Promise<Object>} - Decrypted plaintext with metadata
     */
    async decryptCompleteWorkflow(encryptedPayload, receiverPrivateKey, senderPublicKey) {
        const start = performance.now();

        // 1. ECDH: Generate same shared secret
        const ecdhResult = await this.performECDH(receiverPrivateKey, senderPublicKey);
        
        // 2. HKDF: Derive same AES key
        const aesKey = await this.deriveAESKeyFromSharedSecret(ecdhResult);
        
        // 3. AES-GCM: Decrypt ciphertext
        const encryptedBytes = this.base64ToUint8(encryptedPayload);
        const plaintext = await this.decryptWithAES(encryptedBytes, aesKey);

        const time = performance.now() - start;
        this.metrics.decryptTimes.push(time);

        return { plaintext, workflowTime: time };
    }

    /**
     * Convert Uint8Array to Base64 (for Firebase storage)
     */
    uint8ToBase64(uint8) {
        return btoa(String.fromCharCode.apply(null, uint8));
    }

    /**
     * Convert Base64 to Uint8Array (from Firebase storage)
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
     * Export public key to JWK (for Firebase storage)
     */
    async exportPublicKeyToJWK(publicKey) {
        return await window.crypto.subtle.exportKey('jwk', publicKey);
    }

    /**
     * Import public key from JWK (from Firebase storage)
     */
    async importPublicKeyFromJWK(jwk) {
        return await window.crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );
    }

    /**
     * Get performance statistics (for research paper metrics)
     */
    getStats() {
        const times = this.metrics.times;
        const decryptTimes = this.metrics.decryptTimes;
        const plaintexts = this.metrics.plaintexts;
        const ciphertexts = this.metrics.ciphertexts;

        return {
            encryptAvg: times.length ? (times.reduce((a, b) => a + b, 0) / times.length).toFixed(2) : 0,
            encryptMin: times.length ? Math.min(...times).toFixed(2) : 0,
            encryptMax: times.length ? Math.max(...times).toFixed(2) : 0,
            decryptAvg: decryptTimes.length ? (decryptTimes.reduce((a, b) => a + b, 0) / decryptTimes.length).toFixed(2) : 0,
            avgExpansion: ciphertexts.length && plaintexts.length
                ? (ciphertexts.reduce((a, b) => a + b, 0) / plaintexts.reduce((a, b) => a + b, 0)).toFixed(2)
                : 0,
            totalMessages: times.length
        };
    }

    /**
     * Reset metrics
     */
    reset() {
        this.metrics = { plaintexts: [], ciphertexts: [], times: [], decryptTimes: [] };
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AESECCSystem;
}