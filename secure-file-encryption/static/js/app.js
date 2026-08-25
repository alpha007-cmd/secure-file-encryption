/**
 * Secure File Vault – Client-side interactivity
 */

document.addEventListener("DOMContentLoaded", () => {
    setupFileInputs();
    setupDragAndDrop();
    setupFormLoading();
});

/**
 * Handle file input changes – show file info and enable submit button.
 */
function setupFileInputs() {
    // Encrypt & Decrypt pages
    const configs = [
        { inputId: "fileInput",        infoId: "fileInfo",        nameId: "fileName",        sizeId: "fileSize",     btnId: "encryptBtn" },
        { inputId: "fileInput",        infoId: "fileInfo",        nameId: "fileName",        sizeId: "fileSize",     btnId: "decryptBtn" },
        { inputId: "tamperFileInput",  infoId: "tamperFileInfo",  nameId: "tamperFileName",  sizeId: null,           btnId: "tamperBtn"  },
    ];

    configs.forEach(cfg => {
        const input = document.getElementById(cfg.inputId);
        const btn   = document.getElementById(cfg.btnId);
        if (!input || !btn) return;

        input.addEventListener("change", () => {
            if (input.files.length > 0) {
                const file = input.files[0];
                btn.disabled = false;

                const info = document.getElementById(cfg.infoId);
                const name = document.getElementById(cfg.nameId);
                if (info) info.style.display = "flex";
                if (name) name.textContent = file.name;

                const size = document.getElementById(cfg.sizeId);
                if (size) size.textContent = formatSize(file.size);
            }
        });
    });
}

/**
 * Drag-and-drop support for upload areas.
 */
function setupDragAndDrop() {
    document.querySelectorAll(".upload-area").forEach(zone => {
        ["dragenter", "dragover"].forEach(evt => {
            zone.addEventListener(evt, e => {
                e.preventDefault();
                zone.classList.add("drag-over");
            });
        });

        ["dragleave", "drop"].forEach(evt => {
            zone.addEventListener(evt, e => {
                e.preventDefault();
                zone.classList.remove("drag-over");
            });
        });

        zone.addEventListener("drop", e => {
            const input = zone.querySelector("input[type=file]");
            if (input && e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                input.dispatchEvent(new Event("change"));
            }
        });
    });
}

/**
 * Show a loading overlay when forms are submitted.
 */
function setupFormLoading() {
    // Create loading overlay
    const overlay = document.createElement("div");
    overlay.className = "loading-overlay";
    overlay.innerHTML = `
        <div class="spinner"></div>
        <div class="loading-text">Processing...</div>
    `;
    document.body.appendChild(overlay);

    // Attach to all forms
    document.querySelectorAll("form").forEach(form => {
        form.addEventListener("submit", () => {
            const btn = form.querySelector("button[type=submit]");
            if (btn) btn.disabled = true;

            // Choose label
            let label = "Processing...";
            if (form.id === "encryptForm")  label = "Encrypting file...";
            if (form.id === "decryptForm")  label = "Decrypting file...";
            if (form.id === "tamperForm")   label = "Running tampering test...";
            overlay.querySelector(".loading-text").textContent = label;

            overlay.classList.add("active");
        });
    });
}

/**
 * Format bytes to human-readable string.
 */
function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}