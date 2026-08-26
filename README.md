# 🔐 SECURE FILE VAULT

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.1-black.svg)](https://flask.palletsprojects.com/)
[![Cryptography](https://img.shields.io/badge/Cryptography-44.0.3-red.svg)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)](#license)

An enterprise-grade **Hybrid Cryptographic File Encryption & Decryption Web Application** built with **Python Flask**, featuring **Two-Factor File Protection** via password-based key wrapping, authenticated encryption, and real-time tampering detection.

---

## 📌 OVERVIEW

**Secure File Vault** solves the classic key distribution and speed limitations of encryption systems by combining **symmetric** and **asymmetric** cryptography into a unified hybrid pipeline:

1. **AES-256-GCM** provides high-speed, authenticated file encryption.
2. **RSA-3072-OAEP** protects the ephemeral AES session key using public-key cryptography.
3. **PBKDF2-HMAC-SHA256** derives a cryptographic key from a user-defined password to lock the RSA block (Key Wrapping).
4. **SHA-256** provides an independent, secondary integrity verification hash.

To decrypt any file, **two factors are strictly required**:
- 🔑 **Something the server HAS:** The RSA Private Key
- 🧠 **Something the user KNOWS:** The File Password

---

## 🛡️ CRYPTOGRAPHIC ARCHITECTURE

```
                  ┌─────────────────────────────────┐
                  │          Original File          │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │    AES-256-GCM Encryption       │◄── Fresh Random AES Key (32B)
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │     RSA-3072-OAEP Encrypt       │◄── Server RSA Public Key
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │   PBKDF2 Password Lock (AES)    │◄── User Password + Salt (100k rounds)
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │     Encrypted Package (.enc)    │
                  └─────────────────────────────────┘
```

| Layer | Algorithm | Key Length / Parameter | Purpose |
| :--- | :--- | :--- | :--- |
| **Symmetric Cipher** | AES-256-GCM | 256 bits (32 bytes) | Bulk file payload encryption & authentication |
| **Key Encapsulation** | RSA-3072-OAEP | 3072 bits (MGF1 SHA-256) | Protects the ephemeral AES key |
| **Key Wrapping** | PBKDF2-HMAC-SHA256 | 100,000 iterations | Locks the RSA block with the user's password |
| **Integrity Verification** | SHA-256 | 256 bits | Independent pre/post decryption hash comparison |

---

## ✨ KEY FEATURES

- 🚀 **Universal File Support:** Encrypt any file type (`.pdf`, `.docx`, `.jpg`, `.mp4`, `.zip`, `.exe`, etc.).
- 🔒 **Two-Factor File Protection:** Dual security using server-side RSA keys + user passwords.
- ⚡ **Authenticated Encryption:** AES-GCM built-in 128-bit authentication tag detects any data modification.
- 🔑 **Automatic Key Management:** RSA-3072 key pairs are auto-generated on first app launch if missing.
- 🧪 **Live Tampering Demo Module:** Built-in security testing tool to demonstrate bit-flip tampering detection.
- 🎨 **Modern Cyber-Red UI:** Dark-themed, responsive dashboard built with FontAwesome 6 and Rajdhani/Inter typography.
- 📊 **Real-Time Password Strength Meter:** Dynamic client-side rule checklist enforcing strong password policies.
- 📁 **Drag & Drop Interface:** Simple file selection with upload size safeguards (50 MB limit).
- 🧪 **Automated Testing Suite:** Comprehensive unit tests covering cryptographic edge cases using `pytest`.

---

## 🔒 PASSWORD POLICY

When encrypting a file, the password must satisfy **all 5 security rules**:

- [x] At least **12 characters** in length
- [x] At least **one lowercase letter** (`a-z`)
- [x] At least **one uppercase letter** (`A-Z`)
- [x] At least **one number** (`0-9`)
- [x] At least **one special character** (`!@#$%^&*` etc.)
- [x] Confirmation password must match

> **Example Valid Password:** `College@Secure1`

---

## 📁 PROJECT STRUCTURE

```text
secure-file-vault/
│
├── app/
│   ├── __init__.py          # Flask application factory
│   ├── routes.py            # Route handlers & HTTP endpoints
│   ├── crypto.py            # Cryptographic primitives (AES, RSA, PBKDF2, SHA-256)
│   ├── encryption.py        # High-level encryption/decryption workflows
│   ├── key_manager.py       # RSA key generation, loading, and persistence
│   └── utils.py             # Utilities, password validation, file sanitization
│
├── templates/
│   ├── base.html            # Base HTML wrapper & navigation
│   ├── index.html           # Main dashboard
│   ├── encrypt.html         # File encryption page with live strength meter
│   ├── decrypt.html         # File decryption page
│   ├── result.html          # Success, wrong-password & failure views
│   └── security.html        # Tampering demonstration page
│
├── static/
│   ├── css/
│   │   └── style.css        # Responsive dark cyber-red theme stylesheet
│   └── js/
│       └── app.js           # Drag-and-drop, password toggles, dynamic rules
│
├── storage/
│   ├── encrypted/           # Saved .enc package files
│   ├── decrypted/           # Output decrypted files
│   ├── keys/                # Server RSA PEM keys (private_key.pem, public_key.pem)
│   └── temp/                # Working directory
│
├── tests/
│   └── test_crypto.py       # Pytest unit tests for all crypto functions
│
├── app.py                   # Main application entry point
├── requirements.txt         # Dependencies file
├── .gitignore               # Excludes keys, temp files, and virtualenvs
└── README.md                # Project documentation
```

---

## 🚀 INSTALLATION & QUICK START

### 1. Prerequisites

Ensure you have **Python 3.11+** installed on your system.

### 2. Clone / Extract the Repository

```bash
cd secure-file-vault
```

### 3. Set Up Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Application

```bash
python app.py
```

### 6. Open in Browser

Navigate to **`http://127.0.0.1:5000`** in your web browser.

> ℹ️ **Note:** On first startup, the app will automatically generate an RSA-3072 key pair in `storage/keys/`.

---

## 🧪 RUNNING AUTOMATED TESTS

Execute the test suite using `pytest` to verify cryptographic integrity:

```bash
pytest tests/test_crypto.py -v
```

### Test Coverage Includes:
- [x] AES-256 key generation (256-bit validation)
- [x] AES-256-GCM encryption & decryption correctness
- [x] Detection of wrong AES key / wrong nonce
- [x] Detection of tampered ciphertext via `InvalidTag`
- [x] RSA-3072 key pair generation and PEM serialization
- [x] RSA-OAEP encryption and decryption of session keys
- [x] SHA-256 hash consistency and verification
- [x] End-to-end full encryption/decryption integration
- [x] Password key-derivation correctness

---

## 🧪 TAMPERING DEMONSTRATION WORKFLOW

1. Go to **Encrypt File**, upload any document, set a strong password, and download the `.enc` file.
2. Go to **Security** page.
3. Upload the `.enc` file and enter its password.
4. Click **RUN TAMPER TEST**.
5. The server flips **1 byte** of the ciphertext (`ct_bytes[0] ^= 0xFF`).
6. AES-GCM detects the change via the authentication tag, raises an `InvalidTag` exception, and **aborts decryption**.
7. No output file is generated, demonstrating complete data integrity protection.

---

## 🎓 VIVA & EVALUATION Q&A

### Q1: Why hybrid cryptography?
> AES is fast for large files but faces a key distribution problem. RSA solves key distribution using public/private keys but is too slow for large files. Hybrid cryptography combines both: **AES encrypts the file data quickly**, and **RSA securely protects the AES key**.

### Q2: Why AES-256-GCM instead of CBC or ECB?
> GCM (Galois/Counter Mode) provides **Authenticated Encryption (AEAD)**. It provides both confidentiality (encryption) AND integrity (authentication tag). ECB and CBC do not provide built-in authentication, making them vulnerable to padding oracle and bit-flipping attacks.

### Q3: Why add a password layer on top of RSA?
> If an attacker steals the server's RSA private key, traditional hybrid systems are completely compromised. By locking the RSA block with a **PBKDF2-derived password key**, we enforce **Two-Factor File Protection**. An attacker needs both the server's private key AND the user's password.

### Q4: What happens if a file is tampered with?
> AES-GCM calculates a 128-bit authentication tag during encryption. During decryption, the tag is recalculated. If even a single byte of ciphertext is altered, tag verification fails and decryption is aborted immediately before any plaintext is released.

### Q5: What is PBKDF2 and why use 100,000 iterations?
> PBKDF2 (Password-Based Key Derivation Function 2) stretches a weak human password into a strong 256-bit key using HMAC-SHA256. Running 100,000 iterations makes password verification computationally expensive, defending against offline GPU brute-force attacks.

---

## 👤 AUTHOR

**Athul Raj S**  
*Alias:* **alpha007-cmd**

- **GitHub:** [@alpha007-cmd](https://github.com/alpha007-cmd)
- **Role:** Lead Developer & Security Architect
- **Focus:** Hybrid Cryptography · Applied Security · Full-Stack Web Development

---

## 📄 LICENSE

This project is created for **academic and educational evaluation purposes**.
