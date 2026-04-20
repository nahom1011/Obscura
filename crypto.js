/**
 * Obscura Crypto Module
 * Handles Identity generation and E2EE using Web Crypto API.
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

class ObscuraCrypto {
    /**
     * Generate a new RSA Key Pair for the user identity.
     */
    static async generateIdentity() {
        const keyPair = await window.crypto.subtle.generateKey(
            CRYPTO_CONFIG.rsa,
            true, // extractable
            ["encrypt", "decrypt"]
        );
        return keyPair;
    }

    /**
     * Export a public key to Base64 SPKI format.
     */
    static async exportPublicKey(publicKey) {
        const exported = await window.crypto.subtle.exportKey("spki", publicKey);
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    /**
     * Import a public key from Base64 SPKI format.
     */
    static async importPublicKey(base64Key) {
        const binaryKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
        return await window.crypto.subtle.importKey(
            "spki",
            binaryKey,
            CRYPTO_CONFIG.rsa,
            true,
            ["encrypt"]
        );
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
            CRYPTO_CONFIG.rsa,
            recipientPublicKey,
            exportedAesKey
        );

        // 4. Packetize the data
        return {
            payload: btoa(String.fromCharCode(...new Uint8Array(encryptedMessage))),
            key: btoa(String.fromCharCode(...new Uint8Array(wrappedKey))),
            iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
        };
    }

    /**
     * Decrypt a message using own private key.
     */
    static async decryptMessage(myPrivateKey, packet) {
        try {
            const encryptedMessage = Uint8Array.from(atob(packet.payload), c => c.charCodeAt(0));
            const wrappedKey = Uint8Array.from(atob(packet.key), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(packet.iv), c => c.charCodeAt(0));

            // 1. Unwrap the AES key using our Private Key
            const unwrappedKeyBuffer = await window.crypto.subtle.decrypt(
                CRYPTO_CONFIG.rsa,
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
            console.error("Decryption failed:", error);
            throw new Error("Could not decrypt message. Key mismatch or corrupted data.");
        }
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
