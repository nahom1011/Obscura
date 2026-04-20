/**
 * Obscura App Logic - Shared Identity System
 */

document.addEventListener('DOMContentLoaded', async () => {
    // --- State & DOM Elements ---
    let currentUserId = ObscuraCrypto.getUserId();

    const elements = {
        displayUserId: document.getElementById('display-user-id'),
        btnCopyId: document.getElementById('btn-copy-id'),
        btnResetId: document.getElementById('btn-reset-id'),
        
        importInput: document.getElementById('import-id-input'),
        btnImportId: document.getElementById('btn-import-id'),
        
        inboxSection: document.getElementById('inbox-section'),
        decryptedOutput: document.getElementById('decrypted-output'),
        
        messageInput: document.getElementById('message-input'),
        btnEncrypt: document.getElementById('btn-encrypt'),
        linkContainer: document.getElementById('link-container'),
        shareLinkOutput: document.getElementById('share-link-output'),
        btnCopyLink: document.getElementById('btn-copy-link')
    };

    /**
     * Boostrap the application
     */
    async function init() {
        elements.displayUserId.innerText = currentUserId;
        await checkUrlForData();
    }

    /**
     * Check URL hash for message data and attempt decryption
     */
    async function checkUrlForData() {
        const hash = window.location.hash;
        if (!hash.startsWith('#data=')) return;

        const base64Data = hash.replace('#data=', '');
        try {
            const decrypted = await ObscuraCrypto.decrypt(base64Data, currentUserId);
            
            elements.inboxSection.classList.remove('hidden');
            elements.decryptedOutput.innerHTML = `<div class="message-bubble message-incoming">${escapeHtml(decrypted)}</div>`;
            
            // Scroll to inbox
            elements.inboxSection.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            elements.inboxSection.classList.remove('hidden');
            elements.decryptedOutput.innerHTML = `<div class="message-error">⚠️ ${error.message}</div>`;
        }
    }

    /**
     * UI Action Handlers
     */

    elements.btnCopyId.addEventListener('click', () => {
        copyToClipboard(currentUserId, elements.btnCopyId, '📋 Identity Copied!');
    });

    elements.btnImportId.addEventListener('click', () => {
        const newId = elements.importInput.value.trim();
        if (newId) {
            ObscuraCrypto.setUserId(newId);
            location.reload();
        }
    });

    elements.btnResetId.addEventListener('click', () => {
        if (confirm("Resetting will change your identity. You will lose access to messages shared with your current identity. Continue?")) {
            ObscuraCrypto.resetUserId();
            location.hash = "";
            location.reload();
        }
    });

    elements.btnEncrypt.addEventListener('click', async () => {
        const message = elements.messageInput.value.trim();
        if (!message) return alert("Please enter a message to encrypt.");

        elements.btnEncrypt.innerText = "Encrypting...";
        try {
            const encryptedBase64 = await ObscuraCrypto.encrypt(message, currentUserId);
            const shareUrl = `${window.location.origin}${window.location.pathname}#data=${encryptedBase64}`;
            
            elements.shareLinkOutput.value = shareUrl;
            elements.linkContainer.classList.remove('hidden');
            elements.btnEncrypt.innerText = "Lock & Generate Link";
            
            elements.linkContainer.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            console.error(error);
            alert("Encryption failed.");
            elements.btnEncrypt.innerText = "Encrypt & Generate Link";
        }
    });

    elements.btnCopyLink.addEventListener('click', () => {
        copyToClipboard(elements.shareLinkOutput.value, elements.btnCopyLink, '📋 Link Copied!');
    });

    /**
     * Helpers
     */

    function copyToClipboard(text, btnElement, successText) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.innerText;
            btnElement.innerText = successText;
            btnElement.classList.add('btn-success');
            setTimeout(() => {
                btnElement.innerText = originalText;
                btnElement.classList.remove('btn-success');
            }, 2000);
        });
    }

    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // Auto-refresh decryption if hash changes manually
    window.addEventListener('hashchange', checkUrlForData);

    // Initial run
    init();
});
