document.addEventListener("DOMContentLoaded", () => {
    setupFileInputs();
    setupDragAndDrop();
    setupPasswordToggles();
    setupEncryptPasswordUI();
    setupDecryptPasswordUI();
});

/* ───────── File inputs ───────── */
function setupFileInputs() {
    const configs = [
        { inputId: "fileInput", infoId: "fileInfo", nameId: "fileName", sizeId: "fileSize", btnId: "encryptBtn" },
        { inputId: "fileInput", infoId: "fileInfo", nameId: "fileName", sizeId: "fileSize", btnId: "decryptBtn" },
        { inputId: "tamperFileInput", infoId: "tamperFileInfo", nameId: "tamperFileName", sizeId: null, btnId: "tamperBtn" },
    ];

    configs.forEach(cfg => {
        const input = document.getElementById(cfg.inputId);
        const btn = document.getElementById(cfg.btnId);
        if (!input || !btn) return;

        input.addEventListener("change", () => {
            if (input.files.length > 0) {
                const file = input.files[0];
                const info = document.getElementById(cfg.infoId);
                const nameSpan = document.getElementById(cfg.nameId);

                if (info) info.style.display = "flex";
                if (nameSpan) {
                    const textNode = nameSpan.querySelector("span");
                    if (textNode) textNode.textContent = file.name;
                    else nameSpan.textContent = file.name;
                }

                const size = document.getElementById(cfg.sizeId);
                if (size) size.textContent = formatSize(file.size);

                updateEncryptButtonState();
                updateDecryptButtonState();
                if (cfg.btnId === "tamperBtn") btn.disabled = false;
            }
        });
    });
}

/* ───────── Drag & drop ───────── */
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

/* ───────── Show / hide password ───────── */
function setupPasswordToggles() {
    document.querySelectorAll(".toggle-pass").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const input = document.getElementById(targetId);
            if (!input) return;
            const icon = btn.querySelector("i");
            if (input.type === "password") {
                input.type = "text";
                if (icon) icon.className = "fa-solid fa-eye-slash";
            } else {
                input.type = "password";
                if (icon) icon.className = "fa-solid fa-eye";
            }
        });
    });
}

/* ═══════════════════════════════════════
   ENCRYPT PAGE — strength + strict rules
   ═══════════════════════════════════════ */
function setupEncryptPasswordUI() {
    const password = document.getElementById("password");
    const confirm = document.getElementById("confirm_password");
    const panel = document.getElementById("passwordStrength");
    const rulesList = document.getElementById("passwordRules");

    // Only run on encrypt page
    if (!password || !confirm || !panel || !rulesList) return;

    const onType = () => {
        const val = password.value;
        const conf = confirm.value;

        if (val.length === 0 && conf.length === 0) {
            panel.style.display = "none";
        } else {
            panel.style.display = "block";
            updateStrengthMeter(val);
            validatePasswordRules(val, conf);
        }
        updateEncryptButtonState();
    };

    password.addEventListener("input", onType);
    confirm.addEventListener("input", onType);
}

function validatePasswordRules(password, confirmPassword) {
    const rules = {
        "rule-length":  password.length >= 12,
        "rule-lower":   /[a-z]/.test(password),
        "rule-upper":   /[A-Z]/.test(password),
        "rule-number":  /[0-9]/.test(password),
        "rule-special": /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password),
        "rule-match":   password.length > 0 && password === confirmPassword,
    };

    let allValid = true;
    Object.keys(rules).forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        const ok = rules[id];
        el.classList.toggle("valid", ok);
        const icon = el.querySelector("i");
        if (icon) icon.className = ok ? "fa-solid fa-circle-check" : "fa-solid fa-circle";
        if (!ok) allValid = false;
    });
    return allValid;
}

function updateStrengthMeter(password) {
    const checks = [
        password.length >= 12,
        /[a-z]/.test(password),
        /[A-Z]/.test(password),
        /[0-9]/.test(password),
        /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password),
    ];

    let score = checks.filter(Boolean).length;
    if (password.length >= 16) score++;

    const bar = document.getElementById("strengthBar");
    const label = document.getElementById("strengthLabel");
    if (!bar || !label) return;

    bar.className = "strength-bar-fill";
    label.className = "strength-label";

    let level, width, cls;
    if (score <= 2) {
        level = "Weak";   width = "25%";  cls = "weak";
    } else if (score === 3) {
        level = "Fair";   width = "50%";  cls = "fair";
    } else if (score === 4) {
        level = "Good";   width = "75%";  cls = "good";
    } else {
        level = "Strong"; width = "100%"; cls = "strong";
    }

    bar.style.width = width;
    bar.classList.add(cls);
    label.textContent = level;
    label.classList.add(cls);
}

function updateEncryptButtonState() {
    const btn = document.getElementById("encryptBtn");
    const fileInput = document.getElementById("fileInput");
    const password = document.getElementById("password");
    const confirm = document.getElementById("confirm_password");
    if (!btn || !password || !confirm) return;

    const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
    const passOk = validatePasswordRules(password.value, confirm.value);
    btn.disabled = !(hasFile && passOk);
}

/* ═══════════════════════════════════════
   DECRYPT PAGE — just enable button
   ═══════════════════════════════════════ */
function setupDecryptPasswordUI() {
    const password = document.getElementById("password");
    const btn = document.getElementById("decryptBtn");
    // decrypt page has decryptBtn but NO passwordRules / confirm_password
    if (!password || !btn) return;
    if (document.getElementById("passwordRules")) return; // encrypt page, skip

    password.addEventListener("input", updateDecryptButtonState);
}

function updateDecryptButtonState() {
    const btn = document.getElementById("decryptBtn");
    const fileInput = document.getElementById("fileInput");
    const password = document.getElementById("password");
    if (!btn) return;

    const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
    const hasPass = password && password.value.length > 0;
    btn.disabled = !(hasFile && hasPass);
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}