const messageBox = document.querySelector("#authMessage");

function setMessage(message, isError = false) {
  if (!messageBox) return;
  messageBox.textContent = message;
  messageBox.classList.add("visible");
  messageBox.classList.toggle("error", isError);
}

function setFieldError(id, message = "") {
  const node = document.querySelector(`#${id}`);
  if (node) node.textContent = message;
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || data.message || "Request failed.");
  }
  return data;
}

function passwordScore(password) {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(score, 4);
}

function updateStrength(input) {
  const bar = document.querySelector("#passwordStrengthBar");
  const text = document.querySelector("#passwordStrengthText");
  if (!bar || !text || !input) return;
  const score = passwordScore(input.value);
  const labels = ["Too short", "Basic", "Fair", "Strong", "Hard to guess"];
  bar.style.width = `${Math.max(8, score * 25)}%`;
  bar.dataset.score = String(score);
  text.textContent = input.value ? labels[score] : "Use at least 8 characters.";
}

document.querySelectorAll("input[type='password']").forEach(input => {
  if (input.autocomplete === "new-password") {
    input.addEventListener("input", () => updateStrength(input));
  }
});

const loginForm = document.querySelector("#loginPageForm");
if (loginForm) {
  loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    setFieldError("loginNicknameError");
    setFieldError("loginPasswordError");
    const nickname = document.querySelector("#loginNickname").value.trim();
    const password = document.querySelector("#loginPassword").value;
    if (!nickname) return setFieldError("loginNicknameError", "Nickname is required.");
    if (!password) return setFieldError("loginPasswordError", "Password is required.");
    try {
      await postJson("/api/auth/login", { nickname, password });
      setMessage("Access granted. Opening workspace.");
      window.location.assign("/");
    } catch (error) {
      document.querySelector("#loginPassword").value = "";
      setMessage(error.message, true);
    }
  });
}

const registerForm = document.querySelector("#registerPageForm");
if (registerForm) {
  registerForm.addEventListener("submit", async event => {
    event.preventDefault();
    setFieldError("registerNicknameError");
    setFieldError("registerPasswordError");
    const nickname = document.querySelector("#registerNickname").value.trim();
    const password = document.querySelector("#registerPassword").value;
    if (!/^[a-zA-Z0-9._-]{2,32}$/.test(nickname)) {
      return setFieldError("registerNicknameError", "Use 2-32 valid nickname characters.");
    }
    if (password.length < 8) {
      return setFieldError("registerPasswordError", "Password must be at least 8 characters.");
    }
    try {
      await postJson("/api/auth/register", { nickname, password });
      setMessage("Workspace created. Opening dashboard.");
      window.location.assign("/");
    } catch (error) {
      document.querySelector("#registerPassword").value = "";
      setMessage(error.message, true);
    }
  });
}

const forgotForm = document.querySelector("#forgotPageForm");
if (forgotForm) {
  forgotForm.addEventListener("submit", async event => {
    event.preventDefault();
    setFieldError("forgotIdentifierError");
    const identifier = document.querySelector("#forgotIdentifier").value.trim();
    if (!identifier) return setFieldError("forgotIdentifierError", "Nickname or email is required.");
    try {
      const data = await postJson("/api/auth/forgot-password", { identifier });
      setMessage(data.message || "If recovery is available, a reset link has been sent.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });
}

const resetForm = document.querySelector("#resetPageForm");
if (resetForm) {
  resetForm.addEventListener("submit", async event => {
    event.preventDefault();
    setFieldError("resetPasswordError");
    setFieldError("resetConfirmPasswordError");
    const token = decodeURIComponent(window.location.pathname.split("/").pop() || "");
    const password = document.querySelector("#resetPassword").value;
    const confirm = document.querySelector("#resetConfirmPassword").value;
    if (password.length < 8) return setFieldError("resetPasswordError", "Password must be at least 8 characters.");
    if (password !== confirm) return setFieldError("resetConfirmPasswordError", "Passwords do not match.");
    try {
      await postJson("/api/auth/reset-password", { token, password });
      setMessage("Password updated. Return to login.");
      window.setTimeout(() => window.location.assign("/login"), 900);
    } catch (error) {
      setMessage(error.message, true);
    }
  });
}

const securityForm = document.querySelector("#securityPageForm");
if (securityForm) {
  securityForm.addEventListener("submit", async event => {
    event.preventDefault();
    setFieldError("currentPasswordError");
    setFieldError("newPasswordError");
    setFieldError("confirmPasswordError");
    const currentPassword = document.querySelector("#currentPassword").value;
    const newPassword = document.querySelector("#newPassword").value;
    const confirmPassword = document.querySelector("#confirmPassword").value;
    if (!currentPassword) return setFieldError("currentPasswordError", "Current password is required.");
    if (newPassword.length < 8) return setFieldError("newPasswordError", "Password must be at least 8 characters.");
    if (newPassword !== confirmPassword) return setFieldError("confirmPasswordError", "Passwords do not match.");
    try {
      await postJson("/api/auth/change-password", {
        current_password: currentPassword,
        new_password: newPassword
      });
      securityForm.reset();
      updateStrength(document.querySelector("#newPassword"));
      setMessage("Password changed.");
    } catch (error) {
      document.querySelector("#currentPassword").value = "";
      setMessage(error.message, true);
    }
  });
}
