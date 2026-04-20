/**
 * Obscura Crypto Module
 * Handles Identity generation, E2EE, and Persistence.
 */

const CRYPTO_CONFIG = {
    rsa: {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    },
    aes: {
        name: "AES-GCM",
        length: 256
    }
};

/**
 * Robust Base64 Helpers for Binary Data
 */
class Base64 {
    static fromBytes(bytes) {
        const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join("");
        return btoa(binString);
    }

    static toBytes(base64) {
        const binString = atob(base64);
        return Uint8Array.from(binString, (m) => m.codePointAt(0));
    }
}

/**
 * Identity Persistence using IndexedDB
 */
class IdentityStore {
    static DB_NAME = "ObscuraDB";
    static STORE_NAME = "identity";

    static async openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.DB_NAME, 1);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(this.STORE_NAME)) {
                    db.createObjectStore(this.STORE_NAME);
                }
            };
        });
    }

    static async saveIdentity(keyPair) {
        const db = await this.openDB();
        const tx = db.transaction(this.STORE_NAME, "readwrite");
        const store = tx.objectStore(this.STORE_NAME);
        store.put(keyPair.publicKey, "publicKey");
        store.put(keyPair.privateKey, "privateKey");
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    static async loadIdentity() {
        const db = await this.openDB();
        const tx = db.transaction(this.STORE_NAME, "readonly");
        const store = tx.objectStore(this.STORE_NAME);
        const pubReq = store.get("publicKey");
        const privReq = store.get("privateKey");

        return new Promise((resolve, reject) => {
            tx.oncomplete = () => {
                if (pubReq.result && privReq.result) {
                    resolve({ publicKey: pubReq.result, privateKey: privReq.result });
                } else {
                    resolve(null);
                }
            };
            tx.onerror = () => reject(tx.error);
        });
    }

    static async clearIdentity() {
        const db = await this.openDB();
        const tx = db.transaction(this.STORE_NAME, "readwrite");
        const store = tx.objectStore(this.STORE_NAME);
        store.clear();
        return new Promise((resolve) => {
            tx.oncomplete = () => resolve();
        });
    }
}

class ObscuraCrypto {
    /**
     * Generate a new RSA Key Pair for the user identity.
     */
    static async generateIdentity() {
        const keyPair = await window.crypto.subtle.generateKey(
            CRYPTO_CONFIG.rsa,
            false, // non-extractable (more secure, IndexedDB can still store them)
            ["encrypt", "decrypt"]
        );
        await IdentityStore.saveIdentity(keyPair);
        return keyPair;
    }

    /**
     * Try to load identity from persistence.
     */
    static async getPersistedIdentity() {
        return await IdentityStore.loadIdentity();
    }

    /**
     * Export a public key to Base64 SPKI format.
     */
    static async exportPublicKey(publicKey) {
        const exported = await window.crypto.subtle.exportKey("spki", publicKey);
        return Base64.fromBytes(new Uint8Array(exported));
    }

    /**
     * Import a public key from Base64 SPKI format.
     */
    static async importPublicKey(base64Key) {
        try {
            const binaryKey = Base64.toBytes(base64Key);
            return await window.crypto.subtle.importKey(
                "spki",
                binaryKey,
                CRYPTO_CONFIG.rsa,
                true,
                ["encrypt"]
            );
        } catch (e) {
            throw new Error("Invalid public key format.");
        }
    }

    /**
     * Encrypt a message for a specific recipient.
     */
    static async encryptMessage(recipientPublicKey, message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);

        // 1. Generate a temporary AES key
        const aesKey = await window.crypto.subtle.generateKey(
            CRYPTO_CONFIG.aes,
            true,
            ["encrypt", "decrypt"]
        );

        // 2. Encrypt the message with AES-GCM
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedMessage = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            data
        );

        // 3. Wrap (encrypt) the AES key with the recipient's RSA Public Key
        const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const wrappedKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" }, // Minimal param for encrypt/decrypt
            recipientPublicKey,
            exportedAesKey
        );

        // 4. Packetize the data
        return {
            payload: Base64.fromBytes(new Uint8Array(encryptedMessage)),
            key: Base64.fromBytes(new Uint8Array(wrappedKey)),
            iv: Base64.fromBytes(new Uint8Array(iv))
        };
    }

    /**
     * Decrypt a message using own private key.
     */
    static async decryptMessage(myPrivateKey, packet) {
        try {
            const encryptedMessage = Base64.toBytes(packet.payload);
            const wrappedKey = Base64.toBytes(packet.key);
            const iv = Base64.toBytes(packet.iv);

            // 1. Unwrap the AES key using our Private Key
            const unwrappedKeyBuffer = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                myPrivateKey,
                wrappedKey
            );

            const aesKey = await window.crypto.subtle.importKey(
                "raw",
                unwrappedKeyBuffer,
                CRYPTO_CONFIG.aes,
                true,
                ["decrypt"]
            );

            // 2. Decrypt the message
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                aesKey,
                encryptedMessage
            );

            const decoder = new TextDecoder();
            return decoder.decode(decryptedBuffer);
        } catch (error) {
            console.error("Internal Decryption Error:", error);
            throw error; // Re-throw to be caught by app logic
        }
    }

    static async clearIdentity() {
        await IdentityStore.clearIdentity();
    }

    /**
     * Helper to encode packet to a link-safe string.
     */
    static encodePacket(packet) {
        return btoa(JSON.stringify(packet));
    }

    /**
     * Helper to decode packet from a link-safe string.
     */
    static decodePacket(encoded) {
        return JSON.parse(atob(encoded));
    }
}

window.ObscuraCrypto = ObscuraCrypto;
