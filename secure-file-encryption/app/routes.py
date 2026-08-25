"""
Flask routes for the Secure File Vault.
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
    session,
)
from app.encryption import encrypt_file, decrypt_file, create_tampered_package
from app.utils import safe_filename, generate_unique_filename, format_file_size, cleanup_temp_files

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
    """Handle file encryption."""
    # Check if a file was uploaded
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("main.encrypt_page"))

    uploaded = request.files["file"]
    if uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.encrypt_page"))

    try:
        # Read file data
        file_data = uploaded.read()
        if len(file_data) == 0:
            flash("The uploaded file is empty.", "error")
            return redirect(url_for("main.encrypt_page"))

        original_filename = safe_filename(uploaded.filename)
        keys_dir = current_app.config["KEYS_DIR"]

        # Encrypt
        package_json, metadata = encrypt_file(file_data, original_filename, keys_dir)

        # Save encrypted package
        enc_filename = generate_unique_filename(".enc")
        enc_path = os.path.join(current_app.config["ENCRYPTED_DIR"], enc_filename)
        with open(enc_path, "w", encoding="utf-8") as f:
            f.write(package_json)

        # Store result in session for the result page
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
    """Handle file decryption."""
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("main.decrypt_page"))

    uploaded = request.files["file"]
    if uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.decrypt_page"))

    try:
        package_data = uploaded.read()
        if len(package_data) == 0:
            flash("The uploaded file is empty.", "error")
            return redirect(url_for("main.decrypt_page"))

        keys_dir = current_app.config["KEYS_DIR"]

        # Decrypt
        plaintext, metadata = decrypt_file(package_data, keys_dir)

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
        # Check if it's a tampering / integrity error
        if "INTEGRITY" in error_msg or "authentication" in error_msg.lower() or "MISMATCH" in error_msg:
            return render_template("result.html", mode="tamper_failed", error=error_msg)
        flash(f"Decryption error: {error_msg}", "error")
        return redirect(url_for("main.decrypt_page"))

    except Exception as e:
        flash(f"Decryption error: {str(e)}", "error")
        return redirect(url_for("main.decrypt_page"))


@main_bp.route("/download/encrypted/<filename>")
def download_encrypted(filename):
    filename = safe_filename(filename)
    path = os.path.join(current_app.config["ENCRYPTED_DIR"], filename)
    if not os.path.isfile(path):
        flash("File not found.", "error")
        return redirect(url_for("main.index"))
    return send_file(path, as_attachment=True, download_name=filename)


@main_bp.route("/download/decrypted/<filename>")
def download_decrypted(filename):
    filename = safe_filename(filename)
    path = os.path.join(current_app.config["DECRYPTED_DIR"], filename)
    if not os.path.isfile(path):
        flash("File not found.", "error")
        return redirect(url_for("main.index"))
    original = filename.split("_", 1)[1] if "_" in filename else filename
    return send_file(path, as_attachment=True, download_name=original)


@main_bp.route("/security")
def security_page():
    return render_template("security.html")


@main_bp.route("/demo/tamper", methods=["POST"])
def demo_tamper():

    if "file" not in request.files:
        flash("No file selected for tampering demo.", "error")
        return redirect(url_for("main.security_page"))

    uploaded = request.files["file"]
    if uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.security_page"))

    try:
        package_data = uploaded.read()

        # Create tampered version
        tampered = create_tampered_package(package_data)

        # Attempt decryption of tampered data
        keys_dir = current_app.config["KEYS_DIR"]
        try:
            decrypt_file(tampered, keys_dir)
            return render_template(
                "result.html",
                mode="tamper_failed",
                error="Unexpected: decryption should have failed on tampered data.",
            )
        except ValueError as e:
            # Expected – tampering detected!
            return render_template("result.html", mode="tamper_detected", error=str(e))

    except Exception as e:
        flash(f"Demo error: {str(e)}", "error")
        return redirect(url_for("main.security_page"))



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