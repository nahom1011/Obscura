/**
 * Obscura App Logic
 */

document.addEventListener('DOMContentLoaded', async () => {
    // --- State & DOM Elements ---
    let myIdentity = null;

    const views = {
        setup: document.getElementById('setup-view'),
        dashboard: document.getElementById('dashboard-view'),
        messaging: document.getElementById('messaging-view')
    };

    const elements = {
        btnGenerate: document.getElementById('btn-generate'),
        btnStartChat: document.getElementById('btn-start-chat'),
        btnEncrypt: document.getElementById('btn-encrypt-share'),
        btnBack: document.getElementById('btn-back'),
        btnReset: document.getElementById('btn-reset'),
        btnCopyMyKey: document.getElementById('btn-copy-my-key'),
        
        qrContainer: document.getElementById('identity-qr-container'),
        myPublicKeyDisplay: document.getElementById('my-public-key'),
        recipientInput: document.getElementById('recipient-key-input'),
        
        messageInput: document.getElementById('message-input'),
        shareLinkContainer: document.getElementById('share-link-container'),
        shareLinkOutput: document.getElementById('share-link-output'),
        
        decryptionSection: document.getElementById('decryption-section'),
        inboxContainer: document.getElementById('inbox-container')
    };

    // --- Bootstrapping ---
    async function init() {
        try {
            const persisted = await ObscuraCrypto.getPersistedIdentity();
            if (persisted) {
                myIdentity = persisted;
                await renderIdentityUI();
                showView('dashboard');
                // Check if message in URL
                handleIncomingMessage();
            }
        } catch (e) {
            console.error("Initialization failed", e);
        }
    }

    // --- Navigation Helpers ---
    function showView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        views[viewName].classList.remove('hidden');
    }

    // --- Core Logic ---

    /**
     * Render the UI associated with the current identity
     */
    async function renderIdentityUI() {
        if (!myIdentity) return;
        const pubKeyBase64 = await ObscuraCrypto.exportPublicKey(myIdentity.publicKey);
        
        // Render QR Code
        elements.qrContainer.innerHTML = "";
        new QRCode(elements.qrContainer, {
            text: pubKeyBase64,
            width: 200,
            height: 200,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });

        elements.myPublicKeyDisplay.innerText = pubKeyBase64;
    }

    /**
     * Create identity and update UI
     */
    async function createIdentity() {
        elements.btnGenerate.innerText = "Securing Identity...";
        elements.btnGenerate.classList.add('generating');

        try {
            myIdentity = await ObscuraCrypto.generateIdentity();
            await renderIdentityUI();
            
            // Transition
            setTimeout(() => {
                showView('dashboard');
                handleIncomingMessage();
            }, 800);

        } catch (error) {
            console.error("Identity generation failed", error);
            alert("Security Error: Identity generation failed.");
        } finally {
            elements.btnGenerate.innerText = "Generate My Identity";
            elements.btnGenerate.classList.remove('generating');
        }
    }

    /**
     * Copy key to clipboard
     */
    function copyMyKey() {
        const key = elements.myPublicKeyDisplay.innerText;
        if (!key || key === "...") return;
        
        navigator.clipboard.writeText(key).then(() => {
            const originalText = elements.btnCopyMyKey.innerHTML;
            elements.btnCopyMyKey.innerHTML = "<span>✅</span> Copied!";
            setTimeout(() => elements.btnCopyMyKey.innerHTML = originalText, 2000);
        });
    }

    /**
     * Check URL for incoming encrypted message payload
     */
    async function handleIncomingMessage() {
        const hash = window.location.hash;
        if (!hash.startsWith('#msg=')) return;

        if (!myIdentity) {
            // Wait for user to have an identity before trying to decrypt
            return;
        }

        const encodedPacket = hash.replace('#msg=', '');
        try {
            const packet = ObscuraCrypto.decodePacket(encodedPacket);
            const decrypted = await ObscuraCrypto.decryptMessage(myIdentity.privateKey, packet);
            
            elements.decryptionSection.classList.remove('hidden');
            elements.inboxContainer.innerHTML = `<div class="message-bubble message-incoming">${decrypted}</div>`;
            
            showView('messaging');
            document.getElementById('chat-title').innerText = "Received Message";
            
        } catch (error) {
            console.error("Decryption Error:", error);
            alert("Could not decrypt message. This link was likely intended for a different identity.");
        }
    }

    // --- Event Listeners ---

    elements.btnGenerate.addEventListener('click', createIdentity);
    elements.btnCopyMyKey.addEventListener('click', copyMyKey);

    elements.btnStartChat.addEventListener('click', () => {
        const input = elements.recipientInput.value.trim();
        if (!input) return alert("Please paste the recipient's public key first.");
        
        if (input.length < 100) return alert("Invalid public key format. Ensure you copied the full identity hash.");

        showView('messaging');
        elements.shareLinkContainer.classList.add('hidden');
        elements.btnEncrypt.innerText = "Encrypt & Generate Share Link";
        elements.btnEncrypt.removeAttribute('style');
    });

    elements.btnEncrypt.addEventListener('click', async () => {
        const msg = elements.messageInput.value;
        // Clean up key input (remove hidden whitespace/newlines)
        const recipientPubKeyRaw = elements.recipientInput.value.trim().replace(/\s/g, '');

        if (!msg) return alert("Please enter a message.");
        if (!recipientPubKeyRaw) return alert("Please provide a recipient public key.");

        elements.btnEncrypt.innerText = "Processing...";

        try {
            const recipientPubKey = await ObscuraCrypto.importPublicKey(recipientPubKeyRaw);
            const packet = await ObscuraCrypto.encryptMessage(recipientPubKey, msg);
            
            const encodedPacket = ObscuraCrypto.encodePacket(packet);
            const shareUrl = `${window.location.origin}${window.location.pathname}#msg=${encodedPacket}`;
            
            elements.shareLinkOutput.value = shareUrl;
            elements.shareLinkContainer.classList.remove('hidden');
            
            elements.btnEncrypt.innerText = "Encrypted!";
            elements.btnEncrypt.style.background = "var(--accent-secondary)";
            elements.btnEncrypt.style.color = "black";
            
        } catch (error) {
            console.error("Encryption Details:", error);
            alert(`Encryption failed: ${error.message || "Invalid public key"}`);
            elements.btnEncrypt.innerText = "Encrypt & Generate Share Link";
        }
    });

    elements.btnBack.addEventListener('click', () => showView('dashboard'));

    elements.btnReset.addEventListener('click', async () => {
        const warning = "DANGER: This will permanently destroy your current keys.\n\nYou will NOT be able to read any messages sent to this identity ever again.\n\nProceed?";
        if(confirm(warning)) {
            await ObscuraCrypto.clearIdentity();
            myIdentity = null;
            location.hash = "";
            location.reload();
        }
    });

    window.addEventListener('hashchange', handleIncomingMessage);

    // Start boot sequence
    init();
});
