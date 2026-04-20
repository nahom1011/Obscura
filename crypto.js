/**
 * Obscura Crypto Module - Shared Identity System
 * Uses Symmetric AES-GCM with keys derived from a shared UUID.
 */

const CONFIG = {
    aes: {
        name: "AES-GCM",
        length: 256
    },
    hash: "SHA-256"
};

class ObscuraCrypto {
    /**
     * Get or Generate the shared User Identity (UUID).
     */
    static getUserId() {
        try {
            let id = localStorage.getItem('obscura_user_id');
            if (!id) {
                // Use randomUUID if available, otherwise use a fallback
                id = (crypto.randomUUID) ? crypto.randomUUID() : this.generateUUIDFallback();
                localStorage.setItem('obscura_user_id', id);
            }
            return id;
        } catch (e) {
            console.error("Identity retrieval failed:", e);
            return null;
        }
    }

    /**
     * Fallback UUID generator for older browsers.
     */
    static generateUUIDFallback() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    /**
     * Replace the current User Identity with a new one (Pairing).
     */
    static setUserId(id) {
        if (!id) return;
        localStorage.setItem('obscura_user_id', id);
    }

    /**
     * Clear the User Identity and generate a new one.
     */
    static resetUserId() {
        localStorage.removeItem('obscura_user_id');
        return this.getUserId();
    }

    /**
     * Derive a 256-bit AES key from the user_id using SHA-256.
     */
    static async deriveKey(userId) {
        const encoder = new TextEncoder();
        const data = encoder.encode(userId);
        
        // Hash the userId to get 32 bytes (256 bits)
        const hash = await crypto.subtle.digest(CONFIG.hash, data);
        
        // Import as an AES-GCM key
        return await crypto.subtle.importKey(
            "raw",
            hash,
            CONFIG.aes,
            false,
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Encrypt a message using the derived key.
     * Returns a base64 string of [IV (12) + Ciphertext].
     */
    static async encrypt(text, userId) {
        const key = await this.deriveKey(userId);
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );

        // Combine IV and Ciphertext for transport
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);
        
        return btoa(String.fromCharCode(...combined));
    }

    /**
     * Decrypt a message using the derived key.
     */
    static async decrypt(base64Data, userId) {
        try {
            const bytes = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
            if (bytes.length < 13) throw new Error("Invalid payload");

            const key = await this.deriveKey(userId);
            const iv = bytes.slice(0, 12);
            const ciphertext = bytes.slice(12);

            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                ciphertext
            );

            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            console.error("Decryption failed:", error);
            throw new Error("Cannot decrypt (wrong identity)");
        }
    }
}

window.ObscuraCrypto = ObscuraCrypto;
