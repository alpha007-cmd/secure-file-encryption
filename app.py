"""
Secure File Encryption & Decryption System
Using Hybrid Cryptography: AES-256-GCM + RSA-3072-OAEP

Main entry point for the Flask application.
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SECURE FILE VAULT")
    print("  Hybrid Cryptography: AES-256-GCM + RSA-3072-OAEP")
    print("=" * 60)
    print("  Server: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)