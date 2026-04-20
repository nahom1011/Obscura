/**
 * Obscura App Logic
 */

document.addEventListener('DOMContentLoaded', async () => {
    // --- State & DOM Elements ---
    let myIdentity = null;
    let recipientKey = null;

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
        
        qrContainer: document.getElementById('identity-qr-container'),
        myPublicKeyDisplay: document.getElementById('my-public-key'),
        recipientInput: document.getElementById('recipient-key-input'),
        
        messageInput: document.getElementById('message-input'),
        shareLinkContainer: document.getElementById('share-link-container'),
        shareLinkOutput: document.getElementById('share-link-output'),
        
        decryptionSection: document.getElementById('decryption-section'),
        inboxContainer: document.getElementById('inbox-container')
    };

    // --- Navigation Helpers ---
    function showView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        views[viewName].classList.remove('hidden');
    }

    // --- Core Logic ---

    /**
     * Create identity, update UI, and save to session (non-persistent as per requirement)
     */
    async function createIdentity() {
        elements.btnGenerate.innerText = "Generating security layer...";
        elements.btnGenerate.classList.add('generating');

        try {
            const keyPair = await ObscuraCrypto.generateIdentity();
            myIdentity = keyPair;
            
            const pubKeyBase64 = await ObscuraCrypto.exportPublicKey(keyPair.publicKey);
            
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
            
            // Transition
            setTimeout(() => {
                showView('dashboard');
                // Check if there was a message waiting in the URL
                handleIncomingMessage();
            }, 800);

        } catch (error) {
            console.error("Identity generation failed", error);
            alert("Security Error: Identity generation failed. Check browser support.");
        } finally {
            elements.btnGenerate.innerText = "Generate My Identity";
            elements.btnGenerate.classList.remove('generating');
        }
    }

    /**
     * Handle composing and encryption
     */
    async function handleEncryption() {
        const msg = elements.messageInput.value;
        const recipientPubKeyRaw = elements.recipientInput.value;

        if (!msg) return alert("Please enter a message.");
        if (!recipientPubKeyRaw) return alert("Please provide a recipient public key.");

        try {
            const recipientPubKey = await ObscuraCrypto.importPublicKey(recipientPubKeyRaw);
            const packet = await ObscuraCrypto.encryptMessage(recipientPubKey, msg);
            
            const encodedPacket = ObscuraCrypto.encodePacket(packet);
            const shareUrl = `${window.location.origin}${window.location.pathname}#msg=${encodedPacket}`;
            
            elements.shareLinkOutput.value = shareUrl;
            elements.shareLinkContainer.classList.remove('hidden');
            
            // Visual feedback
            elements.btnEncrypt.innerText = "Encrypted!";
            elements.btnEncrypt.style.background = "var(--accent-secondary)";
            elements.btnEncrypt.style.color = "black";
            
        } catch (error) {
            console.error(error);
            alert("Encryption failed. Verify the recipient's public key.");
        }
    }

    /**
     * Check URL for incoming encrypted message payload
     */
    async function handleIncomingMessage() {
        const hash = window.location.hash;
        if (!hash.startsWith('#msg=')) return;

        if (!myIdentity) {
            alert("Incoming message detected! Please generate your identity first to attempt decryption.");
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
            console.error(error);
            alert("Could not decrypt message. It might be intended for a different recipient.");
        }
    }

    // --- Event Listeners ---

    elements.btnGenerate.addEventListener('click', createIdentity);

    elements.btnStartChat.addEventListener('click', () => {
        if (!elements.recipientInput.value) {
            alert("Enter a recipient key first.");
            return;
        }
        showView('messaging');
        elements.shareLinkContainer.classList.add('hidden');
        elements.btnEncrypt.innerText = "Encrypt & Generate Share Link";
        elements.btnEncrypt.removeAttribute('style');
    });

    elements.btnEncrypt.addEventListener('click', handleEncryption);

    elements.btnBack.addEventListener('click', () => showView('dashboard'));

    elements.btnReset.addEventListener('click', () => {
        if(confirm("This will destroy your current identity. Any messages intended for this key will be permanently unreadable. Proceed?")) {
            myIdentity = null;
            location.hash = "";
            location.reload();
        }
    });

    // Handle incoming message even if page is already open (hash change)
    window.addEventListener('hashchange', handleIncomingMessage);
});
