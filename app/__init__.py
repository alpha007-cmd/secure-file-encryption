"""
Application factory for the Secure File Vault.
"""

import os
import secrets
from flask import Flask
from app.utils import ensure_storage_directories
from app.key_manager import generate_keys_if_missing


def create_app():
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )

    # --- Configuration ---
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
    max_mb = int(os.environ.get("MAX_FILE_SIZE_MB", 50))
    app.config["MAX_CONTENT_LENGTH"] = max_mb * 1024 * 1024  # Convert MB to bytes

    # Storage paths
    base_dir = os.path.dirname(os.path.dirname(__file__))
    app.config["STORAGE_DIR"] = os.path.join(base_dir, "storage")
    app.config["ENCRYPTED_DIR"] = os.path.join(base_dir, "storage", "encrypted")
    app.config["DECRYPTED_DIR"] = os.path.join(base_dir, "storage", "decrypted")
    app.config["KEYS_DIR"] = os.path.join(base_dir, "storage", "keys")
    app.config["TEMP_DIR"] = os.path.join(base_dir, "storage", "temp")

    # --- Initialization ---
    ensure_storage_directories(app.config["STORAGE_DIR"])
    generate_keys_if_missing(app.config["KEYS_DIR"])

    # --- Register routes ---
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app