/* FLANG local access flow: email lookup, registration, and login. */

const AUTH_STORAGE_KEY = "flang.auth.user";
const ACTIVE_EMAIL_KEY = "flang.auth.activeEmail";
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;
let authMode = "lookup";

const authScreen = document.getElementById("auth-screen");
const appShell = document.querySelector(".app-shell");
const authForm = document.getElementById("auth-form");
const authEmail = document.getElementById("auth-email");
const authNameField = document.getElementById("auth-name-field");
const authName = document.getElementById("auth-name");
const authConfirmEmailField = document.getElementById("auth-confirm-email-field");
const authConfirmEmail = document.getElementById("auth-confirm-email");
const authPasswordField = document.getElementById("auth-password-field");
const authPassword = document.getElementById("auth-password");
const authConfirmPasswordField = document.getElementById("auth-confirm-password-field");
const authConfirmPassword = document.getElementById("auth-confirm-password");
const authTitle = document.getElementById("auth-title");
const authDescription = document.getElementById("auth-description");
const authSubmit = document.getElementById("auth-submit");
const authMessage = document.getElementById("auth-message");
const authReset = document.getElementById("auth-reset");

function storedUser() {
  const raw = localStorage.getItem(AUTH_STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

async function passwordDigest(password) {
  const bytes = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function setMessage(text, kind = "") {
  authMessage.textContent = text;
  authMessage.className = `auth-message${kind ? ` ${kind}` : ""}`;
}

function showField(field, visible) {
  field.classList.toggle("hidden", !visible);
}

function setMode(mode) {
  authMode = mode;
  const isLookup = mode === "lookup";
  const isRegister = mode === "register";
  showField(authNameField, isRegister);
  showField(authConfirmEmailField, isRegister);
  showField(authPasswordField, !isLookup);
  showField(authConfirmPasswordField, isRegister);
  authEmail.autocomplete = isRegister ? "email" : "username";
  authPassword.autocomplete = isRegister ? "new-password" : "current-password";
  authTitle.textContent = isLookup ? "Welcome back" : isRegister ? "Create your access" : "Sign in";
  authDescription.textContent = isLookup
    ? "Enter your email to continue to the FLANG workbench."
    : isRegister
      ? "Register a new investigator account to continue."
      : "Enter your password to continue to the FLANG workbench.";
  authSubmit.textContent = isLookup ? "Continue" : isRegister ? "Create account" : "Sign in";
  authReset.classList.toggle("hidden", isLookup);
  setMessage("");
}

function showWorkbench() {
  const user = storedUser();
  if (user) localStorage.setItem(ACTIVE_EMAIL_KEY, user.email);
  authScreen.classList.add("hidden");
  appShell.classList.remove("hidden");
  document.querySelectorAll(".tab-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === "compiler-lang");
  });
  document.querySelectorAll(".page").forEach((page) => {
    page.classList.toggle("active", page.id === "page-compiler-lang");
  });
}

function showCompilerAuth() {
  authScreen.classList.remove("hidden");
  appShell.classList.add("hidden");
  const user = storedUser();
  setMode(user ? "login" : "lookup");
  authEmail.value = user ? user.email : "";
  authEmail.focus();
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = authEmail.value.trim().toLowerCase();
  const user = storedUser();

  if (!EMAIL_PATTERN.test(email)) {
    setMessage("Enter a valid email address, for example investigator@example.com.", "error");
    authEmail.focus();
    return;
  }

  if (authMode === "lookup") {
    if (user && user.email === email) {
      setMode("login");
      authPassword.focus();
    } else {
      setMode("register");
      authConfirmEmail.focus();
    }
    return;
  }

  if (authMode === "register") {
    if (!authName.value.trim()) {
      setMessage("Enter your full name.", "error");
      authName.focus();
      return;
    }
    if (authConfirmEmail.value.trim().toLowerCase() !== email) {
      setMessage("The email addresses do not match.", "error");
      authConfirmEmail.focus();
      return;
    }
    if (authPassword.value.length < 8) {
      setMessage("Use a password with at least 8 characters.", "error");
      authPassword.focus();
      return;
    }
    if (authPassword.value !== authConfirmPassword.value) {
      setMessage("The passwords do not match.", "error");
      authConfirmPassword.focus();
      return;
    }
    const passwordHash = await passwordDigest(authPassword.value);
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({
      email,
      name: authName.value.trim(),
      passwordHash,
    }));
    localStorage.setItem(ACTIVE_EMAIL_KEY, email);
    showWorkbench();
    return;
  }

  if (!user || user.email !== email) {
    setMessage("No account was found for this email. Use a different email to register.", "error");
    return;
  }
  if (await passwordDigest(authPassword.value) !== user.passwordHash) {
    setMessage("Incorrect password.", "error");
    authPassword.focus();
    return;
  }
  localStorage.setItem(ACTIVE_EMAIL_KEY, email);
  showWorkbench();
});

authReset.addEventListener("click", () => {
  authForm.reset();
  setMode("lookup");
  authEmail.focus();
});

authScreen.classList.add("hidden");
setMode("lookup");
