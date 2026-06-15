const dashboard = document.querySelector("#adminDashboard");

function showMessage(message, isError = false) {
  const box = document.querySelector("#adminMessage");
  box.textContent = message;
  box.classList.add("visible");
  box.classList.toggle("error", isError);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function adminApi(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Admin operation failed");
  return data;
}

function statusCard(label, value, tone = "ok") {
  return `
    <div class="admin-status-card ${tone}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function renderAdmin(data) {
  const admin = data.admin || data;
  dashboard.hidden = false;

  const production = admin.production || {};
  const totals = admin.totals || {};
  const database = production.database || {};
  document.querySelector("#adminStatusGrid").innerHTML = [
    statusCard("Users", totals.users || 0),
    statusCard("Domain reports", totals.reports || 0),
    statusCard("Social reports", totals.social_reports || 0),
    statusCard("Wallet reports", totals.wallet_reports || 0),
    statusCard("Monitor", totals.monitors || 0),
    statusCard("Stripe link Pro", production.stripe_pro_link ? "OK" : "Missing", production.stripe_pro_link ? "ok" : "warn"),
    statusCard("Stripe link Agency", production.stripe_agency_link ? "OK" : "Missing", production.stripe_agency_link ? "ok" : "warn"),
    statusCard("Stripe webhook", production.stripe_webhook ? "OK" : "Missing", production.stripe_webhook ? "ok" : "warn"),
    statusCard("Cron secret", production.cron_secret ? "OK" : "Missing", production.cron_secret ? "ok" : "warn"),
    statusCard("Alert webhook", production.alert_webhook ? "Active" : "Optional", production.alert_webhook ? "ok" : "muted"),
    statusCard("Database", database.persistent_hint ? "Custom path" : "Default", database.persistent_hint ? "ok" : "warn"),
    statusCard("Anti-abuse", production.registration_limit ? `${production.registration_limit}/connection` : "Off", production.registration_limit ? "ok" : "warn"),
    statusCard("Backup DB", database.backup_count ? `${database.backup_count} snapshot` : "None", database.backup_count ? "ok" : "warn")
  ].join("");

  const users = admin.users || [];
  document.querySelector("#adminUsers").innerHTML = users.length ? `
    <div class="admin-row header">
      <span>Nickname</span><span>Plan</span><span>Credits</span><span>Report</span><span>Monitor</span>
    </div>
    ${users.map(user => `
      <button class="admin-row user-row" type="button" data-user="${escapeHtml(user.nickname)}" data-plan="${escapeHtml(user.plan)}">
        <span>${escapeHtml(user.nickname)}</span>
        <span>${escapeHtml(user.plan)}</span>
        <span>${escapeHtml(user.credits)}</span>
        <span>${escapeHtml((user.report_count || 0) + (user.social_report_count || 0) + (user.wallet_report_count || 0))}</span>
        <span>${escapeHtml(user.monitor_count || 0)}</span>
      </button>
    `).join("")}
  ` : `<div class="empty">No registered users.</div>`;

  const events = admin.stripe_events || [];
  document.querySelector("#adminEvents").innerHTML = events.length ? `
    <div class="admin-row header">
      <span>Type</span><span>Status</span><span>Plan</span><span>Date</span>
    </div>
    ${events.map(event => `
      <div class="admin-row">
        <span>${escapeHtml(event.type)}</span>
        <span>${escapeHtml(event.status)}</span>
        <span>${escapeHtml(event.plan || "-")}</span>
        <span>${escapeHtml(event.created_at)}</span>
      </div>
    `).join("")}
  ` : `<div class="empty">No Stripe events recorded.</div>`;

  const backups = admin.backups || [];
  document.querySelector("#adminBackups").innerHTML = backups.length ? `
    <div class="admin-row backup-row header">
      <span>File</span><span>Size</span><span>Created</span><span>Action</span>
    </div>
    ${backups.map(backup => `
      <div class="admin-row backup-row">
        <span>${escapeHtml(backup.name)}</span>
        <span>${escapeHtml(Math.max(1, Math.round((backup.size || 0) / 1024)))} KB</span>
        <span>${escapeHtml(backup.created_at)}</span>
        <span><a href="/api/admin/backups/${encodeURIComponent(backup.name)}">Download</a></span>
      </div>
    `).join("")}
  ` : `<div class="empty">No backups created.</div>`;
}

async function loadAdminStatus() {
  try {
    const data = await adminApi("/api/admin/status");
    renderAdmin(data);
    showMessage("Admin dashboard loaded.");
  } catch {
    dashboard.hidden = true;
  }
}

document.querySelector("#adminForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  const code = document.querySelector("#adminCode").value;
  button.disabled = true;
  button.textContent = "Verifying...";

  try {
    const data = await adminApi("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ code })
    });
    renderAdmin(data);
    showMessage("Admin access enabled. Private dashboard ready.");
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    document.querySelector("#adminCode").value = "";
    button.disabled = false;
    button.textContent = "Unlock Admin";
  }
});

document.querySelector("#planForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  const nickname = document.querySelector("#planNickname").value;
  const plan = document.querySelector("#planValue").value;
  button.disabled = true;
  button.textContent = "Updating...";
  try {
    const data = await adminApi("/api/admin/users/plan", {
      method: "POST",
      body: JSON.stringify({ nickname, plan })
    });
    renderAdmin(data);
    showMessage(`Plan updated for ${nickname}.`);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Update plan";
  }
});

document.querySelector("#backupButton").addEventListener("click", async event => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = "Creating backup...";
  try {
    const data = await adminApi("/api/admin/backups", { method: "POST" });
    renderAdmin(data);
    showMessage(`Backup created: ${data.backup.name}`);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Create DB backup";
  }
});

document.querySelector("#restoreForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  const file = document.querySelector("#restoreFile").files[0];
  if (!file) {
    showMessage("Select a SQLite snapshot to restore.", true);
    return;
  }
  const confirmation = window.prompt("Type RESTORE to replace the current database.");
  if (confirmation !== "RESTORE") return;
  button.disabled = true;
  button.textContent = "Restoring...";
  try {
    const response = await fetch("/api/admin/restore", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-OSINTPRO-RESTORE": "RESTORE"
      },
      body: file
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Restore failed");
    renderAdmin(data);
    document.querySelector("#restoreFile").value = "";
    showMessage(`Restore completed: ${data.restored.users} users, ${data.restored.reports + data.restored.social_reports} reports.`);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Restore backup";
  }
});

document.addEventListener("click", event => {
  const row = event.target.closest("[data-user]");
  if (!row) return;
  document.querySelector("#planNickname").value = row.dataset.user;
  document.querySelector("#planValue").value = row.dataset.plan;
});

loadAdminStatus();
