"""
Flask routes for the Secure File Vault.
Includes strong password policy and password-based key wrapping.
"""

import os
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    current_app,
)
from app.encryption import encrypt_file, decrypt_file, create_tampered_package
from app.utils import (
    safe_filename,
    generate_unique_filename,
    format_file_size,
    cleanup_temp_files,
    validate_password,
)

main_bp = Blueprint("main", __name__)


# ──────────────────────────────────────────────
#  Home / Dashboard
# ──────────────────────────────────────────────

@main_bp.route("/")
def index():
    """Dashboard page."""
    return render_template("index.html")


# ──────────────────────────────────────────────
#  Encrypt
# ──────────────────────────────────────────────

@main_bp.route("/encrypt", methods=["GET"])
def encrypt_page():
    """Show the encryption upload form."""
    return render_template("encrypt.html")


@main_bp.route("/encrypt", methods=["POST"])
def encrypt_action():
    """Handle file encryption with strong password protection."""
    # Check if a file was uploaded
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("main.encrypt_page"))

    uploaded = request.files["file"]
    if uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.encrypt_page"))

    # Get passwords from form
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # Validate password strength
    # Rules: min 12 chars, upper, lower, number, special character
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for("main.encrypt_page"))

    # Confirm passwords match
    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for("main.encrypt_page"))

    try:
        # Read file data
        file_data = uploaded.read()
        if len(file_data) == 0:
            flash("The uploaded file is empty.", "error")
            return redirect(url_for("main.encrypt_page"))

        original_filename = safe_filename(uploaded.filename)
        keys_dir = current_app.config["KEYS_DIR"]

        # Encrypt with password
        package_json, metadata = encrypt_file(
            file_data, original_filename, keys_dir, password
        )

        # Save encrypted package
        enc_filename = generate_unique_filename(".enc")
        enc_path = os.path.join(current_app.config["ENCRYPTED_DIR"], enc_filename)
        with open(enc_path, "w", encoding="utf-8") as f:
            f.write(package_json)

        # Prepare metadata for result page
        metadata["enc_filename"] = enc_filename
        metadata["enc_size"] = len(package_json)
        metadata["formatted_original_size"] = format_file_size(metadata["original_size"])
        metadata["formatted_enc_size"] = format_file_size(len(package_json))

        return render_template("result.html", mode="encrypt", meta=metadata)

    except Exception as e:
        flash(f"Encryption error: {str(e)}", "error")
        return redirect(url_for("main.encrypt_page"))


# ──────────────────────────────────────────────
#  Decrypt
# ──────────────────────────────────────────────

@main_bp.route("/decrypt", methods=["GET"])
def decrypt_page():
    """Show the decryption upload form."""
    return render_template("decrypt.html")


@main_bp.route("/decrypt", methods=["POST"])
def decrypt_action():
    """Handle file decryption with password verification."""
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("main.decrypt_page"))

    uploaded = request.files["file"]
    if uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.decrypt_page"))

    # Get password (no strength rules on decrypt — just must be correct)
    password = request.form.get("password", "").strip()
    if not password:
        flash("Password is required to decrypt the file.", "error")
        return redirect(url_for("main.decrypt_page"))

    try:
        package_data = uploaded.read()
        if len(package_data) == 0:
            flash("The uploaded file is empty.", "error")
            return redirect(url_for("main.decrypt_page"))

        keys_dir = current_app.config["KEYS_DIR"]

        # Decrypt with password
        plaintext, metadata = decrypt_file(package_data, keys_dir, password)

        # Save decrypted file
        dec_filename = safe_filename(metadata["original_filename"])
        # Prepend UUID to avoid collisions
        unique_dec = generate_unique_filename("") + "_" + dec_filename
        dec_path = os.path.join(current_app.config["DECRYPTED_DIR"], unique_dec)
        with open(dec_path, "wb") as f:
            f.write(plaintext)

        metadata["dec_filename"] = unique_dec
        metadata["formatted_size"] = format_file_size(len(plaintext))

        return render_template("result.html", mode="decrypt", meta=metadata)

    except ValueError as e:
        error_msg = str(e)

        # Wrong password error
        if "INCORRECT PASSWORD" in error_msg or "Access Denied" in error_msg:
            return render_template(
                "result.html", mode="wrong_password", error=error_msg
            )

        # Tampering / integrity error
        if (
            "INTEGRITY" in error_msg
            or "authentication" in error_msg.lower()
            or "MISMATCH" in error_msg
        ):
            return render_template(
                "result.html", mode="tamper_failed", error=error_msg
            )

        # Generic errors
        flash(f"Decryption error: {error_msg}", "error")
        return redirect(url_for("main.decrypt_page"))

    except Exception as e:
        flash(f"Decryption error: {str(e)}", "error")
        return redirect(url_for("main.decrypt_page"))


# ──────────────────────────────────────────────
#  Download
# ──────────────────────────────────────────────

@main_bp.route("/download/encrypted/<filename>")
def download_encrypted(filename):
    """Download an encrypted package."""
    filename = safe_filename(filename)
    path = os.path.join(current_app.config["ENCRYPTED_DIR"], filename)
    if not os.path.isfile(path):
        flash("File not found.", "error")
        return redirect(url_for("main.index"))
    return send_file(path, as_attachment=True, download_name=filename)


@main_bp.route("/download/decrypted/<filename>")
def download_decrypted(filename):
    """Download a decrypted file."""
    filename = safe_filename(filename)
    path = os.path.join(current_app.config["DECRYPTED_DIR"], filename)
    if not os.path.isfile(path):
        flash("File not found.", "error")
        return redirect(url_for("main.index"))
    # Try to use original name (part after UUID_)
    original = filename.split("_", 1)[1] if "_" in filename else filename
    return send_file(path, as_attachment=True, download_name=original)


# ──────────────────────────────────────────────
#  Security / Tampering Demo
# ──────────────────────────────────────────────

@main_bp.route("/security")
def security_page():
    """Security architecture and demonstration page."""
    return render_template("security.html")


@main_bp.route("/demo/tamper", methods=["POST"])
def demo_tamper():
    """
    Demonstration: tamper with an encrypted file and attempt decryption.
    Shows that AES-GCM detects modifications even with the correct password.
    """
    if "file" not in request.files:
        flash("No file selected for tampering demo.", "error")
        return redirect(url_for("main.security_page"))

    uploaded = request.files["file"]
    if uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.security_page"))

    # Get password for the demo file
    password = request.form.get("password", "").strip()
    if not password:
        flash("Provided File is password protected.", "error")
        return redirect(url_for("main.security_page"))

    try:
        package_data = uploaded.read()
        if len(package_data) == 0:
            flash("The uploaded file is empty.", "error")
            return redirect(url_for("main.security_page"))

        # Create tampered version (modifies one byte of ciphertext)
        tampered = create_tampered_package(package_data)

        # Attempt decryption of tampered data
        keys_dir = current_app.config["KEYS_DIR"]
        try:
            decrypt_file(tampered, keys_dir, password)
            # Should NOT reach here — tampering must fail
            return render_template(
                "result.html",
                mode="tamper_failed",
                error="Unexpected: decryption should have failed on tampered data.",
            )
        except ValueError as e:
            error_msg = str(e)

            # Wrong password given for the demo file
            if "INCORRECT PASSWORD" in error_msg or "Access Denied" in error_msg:
                flash(
                    "Wrong password. Please enter the password used to encrypt this file.",
                    "error",
                )
                return redirect(url_for("main.security_page"))

            # Expected – tampering detected!
            return render_template(
                "result.html", mode="tamper_detected", error=error_msg
            )

    except Exception as e:
        flash(f"Demo error: {str(e)}", "error")
        return redirect(url_for("main.security_page"))


# ──────────────────────────────────────────────
#  Error handlers
# ──────────────────────────────────────────────

@main_bp.app_errorhandler(413)
def file_too_large(e):
    flash("File is too large. Maximum size is 50 MB.", "error")
    return redirect(url_for("main.index"))


@main_bp.app_errorhandler(404)
def not_found(e):
    return render_template("base.html", error_404=True), 404


@main_bp.app_errorhandler(500)
def server_error(e):
    return render_template("base.html", error_500=True), 500