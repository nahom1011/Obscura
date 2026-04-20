# Obscura

**Obscura** is a fully client-side, serverless encrypted messaging application designed for maximum privacy. It enables secure communication without accounts, servers, or manual key exchanges.

## 🔐 Key Features

- **Zero-Server Architecture**: Everything happens in your browser. No data is sent to a central server.
- **No Accounts Required**: Generate a unique identity without providing personal information.
- **End-to-End Encryption (E2EE)**: Messages are encrypted using the **Web Crypto API** (AES-GCM, RSA-OAEP).
- **QR Code Pairing**: Securely pair two devices by scanning a QR code to exchange public keys.
- **Persistent-Free**: Messages exist only in the browser session or within the URL hash for sharing.

## 🚀 How it Works

1. **Identity Generation**: Create a local key pair (Public/Private) on your device.
2. **Pairing**: Scan a QR code from a friend to exchange identities.
3. **Messaging**: Type a message, which is encrypted locally.
4. **Sharing**: Share the encrypted payload via a secure link. Only the paired partner with the corresponding private key can decrypt it.

## 🛠️ Tech Stack

- **HTML5/CSS3** (Vanilla)
- **JavaScript** (Web Crypto API)
- **QR Code Library** (for pairing)

## 🛡️ Security

Obscura follows a **Zero Trust** model. The application code is served statically, and all cryptographic operations occur in a secure browser context. Your private keys never leave your device.

---
*Ensuring privacy in a connected world.*
