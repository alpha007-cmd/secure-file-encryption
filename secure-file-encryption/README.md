# Secure File Encryption and Decryption Using Hybrid Cryptography

A Python Flask web application demonstrating **hybrid cryptography** for secure file encryption and decryption.

## Introduction

This project implements a secure file encryption system that combines **symmetric** and **asymmetric** encryption techniques. It uses AES-256-GCM for fast file encryption and RSA-3072-OAEP for secure key protection, demonstrating how modern cryptographic systems protect data confidentiality and integrity.

## Objectives

- **Confidentiality** – Encrypt files so only authorised users can read them
- **Integrity** – Detect any tampering or modification of encrypted data
- **Secure Key Management** – Protect encryption keys using asymmetric cryptography
- **Hybrid Cryptography** – Combine the strengths of symmetric and asymmetric encryption

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.11+ | Backend programming language |
| Flask | Web framework |
| AES-256-GCM | Symmetric file encryption |
| RSA-3072-OAEP | Asymmetric key protection |
| SHA-256 | Integrity hashing |
| HTML/CSS/JS | Frontend user interface |
| `cryptography` | Python cryptographic library |

## System Architecture

```
Frontend (Browser)
       ↓
Flask Routes (routes.py)
       ↓
Encryption Service (encryption.py)
       ↓
Cryptographic Functions (crypto.py)
       ↓
File Storage (storage/)
```

## Encryption Process

1. User uploads a file through the web interface
2. A **random AES-256 key** (32 bytes) is generated
3. A **random 12-byte nonce** is generated
4. The file is encrypted using **AES-256-GCM**
5. **SHA-256 hash** of the original file is calculated
6. The AES key is encrypted using **RSA-3072-OAEP** with the public key
7. All components are packaged into a JSON `.enc` file

## Decryption Process

1. User uploads the `.enc` encrypted package
2. The **RSA private key** decrypts the protected AES key
3. **AES-GCM authentication** verifies data hasn't been tampered with
4. The file is **decrypted** using the recovered AES key
5. **SHA-256** of the decrypted file is calculated and compared with the stored hash
6. Only if **all checks pass**, the decrypted file is made available

## Integrity Verification

The system uses **two layers** of integrity protection:

1. **AES-GCM Authentication Tag** – Built into the encryption algorithm. Any modification to the ciphertext causes authentication failure and decryption is aborted.
2. **SHA-256 Hash Comparison** – An independent hash of the original file is stored and compared after decryption for additional verification.

## Security Demonstration

The application includes a **Tampering Demo** feature:
- Upload a valid encrypted file
- The system modifies one byte of the ciphertext
- Decryption is attempted on the tampered data
- **AES-GCM detects the modification** and refuses to decrypt
- No output file is produced

This demonstrates that even a single-byte change is detected.

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd secure-file-encryption
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

**Windows:**
```bash
venv\Scripts\activate
```

**macOS/Linux:**
```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

### 5. Open in browser

```
http://127.0.0.1:5000
```

On first startup, RSA-3072 keys will be generated automatically.

## Running Tests

```bash
pytest tests/test_crypto.py -v
```

## Project Structure

```
secure-file-encryption/
├── app/
│   ├── __init__.py        # Flask app factory
│   ├── routes.py          # URL routes
│   ├── crypto.py          # Cryptographic primitives
│   ├── encryption.py      # Encrypt/decrypt workflows
│   ├── key_manager.py     # RSA key management
│   └── utils.py           # Helper utilities
├── templates/             # HTML templates
├── static/                # CSS and JavaScript
├── storage/               # File storage (encrypted, decrypted, keys)
├── tests/                 # Unit tests
├── app.py                 # Entry point
├── requirements.txt       # Dependencies
└── README.md              # This file
```

## Viva Q&A Guide

### Why AES?
AES (Advanced Encryption Standard) is a symmetric encryption algorithm that is very efficient for encrypting large amounts of data. It's the industry standard for symmetric encryption.

### Why RSA?
RSA is an asymmetric encryption algorithm that uses a public/private key pair. It's used to securely protect the AES key so it can be safely stored alongside the encrypted data.

### Why use both? (Hybrid Cryptography)
- **AES alone**: Fast encryption, but how do you securely share/store the key?
- **RSA alone**: Secure key management, but too slow for large files and has size limits
- **Together**: AES encrypts the file quickly, RSA protects the AES key securely

### Why AES-GCM specifically?
AES-GCM (Galois/Counter Mode) provides both **confidentiality** (encryption) and **authentication** (integrity). If even one bit of the encrypted data is modified, GCM detects it and refuses to decrypt. Other modes like ECB or CBC don't provide this authentication.

### Why RSA-3072?
RSA-3072 provides approximately 128 bits of security strength, which is considered secure for current and near-future use. It's the minimum recommended size by NIST for new applications.

### What is OAEP padding?
OAEP (Optimal Asymmetric Encryption Padding) adds randomized padding to RSA encryption, preventing various attacks that are possible with older padding schemes (like PKCS#1 v1.5).

### What happens if the encrypted file is modified?
AES-GCM maintains an authentication tag during encryption. During decryption, this tag is verified. If even a single byte of the ciphertext has been modified, the authentication check fails, and the application **refuses to decrypt** the file. No output is produced.

### What is the role of SHA-256?
SHA-256 provides an additional independent integrity check. After decryption, the SHA-256 hash of the decrypted file is calculated and compared with the hash of the original file that was stored during encryption.

### Why not encrypt the file directly with RSA?
RSA can only encrypt data smaller than its key size (roughly 384 bytes for RSA-3072 with OAEP). Files are typically much larger. Also, RSA encryption is significantly slower than AES.

## License

This project is for educational/academic purposes.