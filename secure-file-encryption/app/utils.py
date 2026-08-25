import os
import uuid
import hashlib
from werkzeug.utils import secure_filename


def ensure_storage_directories(storage_dir: str) -> None:
    subdirs = ["encrypted", "decrypted", "keys", "temp"]
    for sub in subdirs:
        path = os.path.join(storage_dir, sub)
        os.makedirs(path, exist_ok=True)
        gitkeep = os.path.join(path, ".gitkeep")
        if not os.path.exists(gitkeep):
            open(gitkeep, "w").close()


def safe_filename(filename: str) -> str:
    return secure_filename(filename) or "untitled"


def generate_unique_filename(extension: str = ".enc") -> str:
    return f"{uuid.uuid4().hex}{extension}"


def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def cleanup_temp_files(temp_dir: str) -> None:
    if not os.path.isdir(temp_dir):
        return
    for fname in os.listdir(temp_dir):
        fpath = os.path.join(temp_dir, fname)
        if os.path.isfile(fpath) and fname != ".gitkeep":
            try:
                os.remove(fpath)
            except OSError:
                pass