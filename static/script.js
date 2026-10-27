/**
 * script.js - AegisAuth Client-Side Security & UX Interactions
 * Handles password visibility toggling, real-time password strength calculation,
 * policy checklist updates, and match verification.
 */

document.addEventListener("DOMContentLoaded", () => {
    initPasswordToggles();
    initPasswordValidation();
    initFlashAutoDismiss();
});

/**
 * Initialize visibility toggles for password fields
 */
function initPasswordToggles() {
    setupToggle("togglePasswordBtn", "password", "passwordEyeIcon");
    setupToggle("toggleConfirmBtn", "confirm_password", "confirmEyeIcon");
}

function setupToggle(buttonId, inputId, iconId) {
    const btn = document.getElementById(buttonId);
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);

    if (!btn || !input || !icon) return;

    btn.addEventListener("click", () => {
        const isPassword = input.getAttribute("type") === "password";
        input.setAttribute("type", isPassword ? "text" : "password");

        if (isPassword) {
            icon.classList.remove("fa-eye");
            icon.classList.add("fa-eye-slash");
            btn.setAttribute("aria-label", "Hide password");
        } else {
            icon.classList.remove("fa-eye-slash");
            icon.classList.add("fa-eye");
            btn.setAttribute("aria-label", "Show password");
        }
    });
}

/**
 * Real-time Password Strength and Requirements Checklist Evaluator
 */
function initPasswordValidation() {
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm_password");
    const strengthBar = document.getElementById("strengthBar");
    const strengthText = document.getElementById("strengthText");
    const matchIndicator = document.getElementById("matchIndicator");

    // Only run on pages with registration form
    if (!passwordInput || !strengthBar || !strengthText) return;

    const reqLength = document.getElementById("req-length");
    const reqUpper = document.getElementById("req-upper");
    const reqLower = document.getElementById("req-lower");
    const reqNumber = document.getElementById("req-number");
    const reqSpecial = document.getElementById("req-special");

    const updateRequirement = (element, isValid) => {
        if (!element) return;
        const icon = element.querySelector("i");
        if (isValid) {
            element.classList.add("valid");
            if (icon) {
                icon.className = "fa-solid fa-circle-check";
            }
        } else {
            element.classList.remove("valid");
            if (icon) {
                icon.className = "fa-solid fa-circle-xmark";
            }
        }
    };

    const evaluatePassword = () => {
        const val = passwordInput.value;

        const hasLength = val.length >= 8;
        const hasUpper = /[A-Z]/.test(val);
        const hasLower = /[a-z]/.test(val);
        const hasNumber = /[0-9]/.test(val);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>\-_+=\[\]\\/`~]/.test(val);

        updateRequirement(reqLength, hasLength);
        updateRequirement(reqUpper, hasUpper);
        updateRequirement(reqLower, hasLower);
        updateRequirement(reqNumber, hasNumber);
        updateRequirement(reqSpecial, hasSpecial);

        // Calculate score
        let score = 0;
        if (hasLength) score++;
        if (hasUpper) score++;
        if (hasLower) score++;
        if (hasNumber) score++;
        if (hasSpecial) score++;

        // Bonus for length
        if (val.length >= 14 && score >= 4) {
            score = 5;
        }

        // Render strength meter
        if (val.length === 0) {
            strengthBar.style.width = "0%";
            strengthBar.style.backgroundColor = "transparent";
            strengthText.textContent = "Strength: None";
            strengthText.style.color = "var(--text-muted)";
        } else if (score <= 2) {
            strengthBar.style.width = "30%";
            strengthBar.style.backgroundColor = "var(--accent-danger)";
            strengthText.textContent = "Strength: Weak (Vulnerable)";
            strengthText.style.color = "#f87171";
        } else if (score === 3) {
            strengthBar.style.width = "60%";
            strengthBar.style.backgroundColor = "var(--accent-warning)";
            strengthText.textContent = "Strength: Medium (Acceptable)";
            strengthText.style.color = "#fbbf24";
        } else if (score === 4) {
            strengthBar.style.width = "85%";
            strengthBar.style.backgroundColor = "var(--primary-blue)";
            strengthText.textContent = "Strength: Strong (Robust)";
            strengthText.style.color = "#38bdf8";
        } else {
            strengthBar.style.width = "100%";
            strengthBar.style.backgroundColor = "var(--accent-emerald)";
            strengthText.textContent = "Strength: Maximum Security (Argon2id Ready)";
            strengthText.style.color = "#34d399";
        }

        checkMatch();
    };

    const checkMatch = () => {
        if (!confirmInput || !matchIndicator) return;
        const p1 = passwordInput.value;
        const p2 = confirmInput.value;

        if (p2.length === 0) {
            matchIndicator.textContent = "";
            matchIndicator.className = "password-match-indicator";
            return;
        }

        if (p1 === p2) {
            matchIndicator.textContent = "✓ Passwords match successfully.";
            matchIndicator.className = "password-match-indicator valid";
        } else {
            matchIndicator.textContent = "✕ Passwords do not match.";
            matchIndicator.className = "password-match-indicator invalid";
        }
    };

    passwordInput.addEventListener("input", evaluatePassword);
    if (confirmInput) {
        confirmInput.addEventListener("input", checkMatch);
    }
}

/**
 * Auto-dismiss flash messages after 8 seconds
 */
function initFlashAutoDismiss() {
    const alerts = document.querySelectorAll(".flash-alert");
    alerts.forEach((alert) => {
        setTimeout(() => {
            alert.style.transition = "opacity 0.5s ease, transform 0.5s ease";
            alert.style.opacity = "0";
            alert.style.transform = "translateY(-10px)";
            setTimeout(() => alert.remove(), 500);
        }, 8000);
    });
}
