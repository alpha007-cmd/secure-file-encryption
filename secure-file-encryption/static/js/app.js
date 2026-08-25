document.addEventListener("DOMContentLoaded", () => {
    setupFileInputs();
    setupDragAndDrop();
});

function setupFileInputs() {
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
                const nameSpan = document.getElementById(cfg.nameId);
                
                if (info) info.style.display = "flex";
                if (nameSpan) {
                    // Update only the text span, keep the fontawesome icon
                    const textNode = nameSpan.querySelector('span');
                    if(textNode) textNode.textContent = file.name;
                }

                const size = document.getElementById(cfg.sizeId);
                if (size) size.textContent = formatSize(file.size);
            }
        });
    });
}

function setupDragAndDrop() {
    document.querySelectorAll(".upload-box").forEach(zone => {
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

function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}