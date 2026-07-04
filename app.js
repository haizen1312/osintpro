const state = {
  user: { plan: "Free", credits: 0, free_credits: 5, monitor_limit: 1 },
  reports: [],
  socialReports: [],
  walletReports: [],
  monitors: [],
  folders: [],
  playbooks: [],
  apiKeys: [],
  currentRepoAudit: null,
  repoConfidenceThreshold: 0.35,
  workspace: null,
  checkoutConfigured: false,
  currentWallet: null,
  currentWebAuditReportId: null,
  graphFilter: "all",
  featureFlags: {},
  metrics: null,
  shownUpsells: new Set(),
  trackedSections: new Set()
};

if (localStorage.getItem("op-performance-mode") === "on") {
  document.body.classList.add("performance-mode");
}

function startSignalCanvas() {
  const canvas = document.querySelector("#signalCanvas");
  if (!canvas) return;
  if (document.body.classList.contains("performance-mode")) {
    canvas.remove();
    return;
  }
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    canvas.remove();
    return;
  }
  const context = canvas.getContext("2d");
  const particles = Array.from({ length: 30 }, () => ({
    x: Math.random(),
    y: Math.random(),
    vx: (Math.random() - .5) * .0008,
    vy: (Math.random() - .5) * .0008,
    r: Math.random() * 1.4 + .7
  }));
  let dpr = Math.min(window.devicePixelRatio || 1, 1.25);
  let isScrolling = false;
  let scrollTimer = 0;
  let lastFrame = 0;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 1.25);
    canvas.width = Math.floor(window.innerWidth * dpr);
    canvas.height = Math.floor(window.innerHeight * dpr);
  }

  function draw(timestamp = 0) {
    requestAnimationFrame(draw);
    if (document.hidden || isScrolling || timestamp - lastFrame < 42) return;
    lastFrame = timestamp;
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = "rgba(57, 255, 184, .42)";
    context.strokeStyle = "rgba(57, 255, 184, .08)";
    particles.forEach(point => {
      point.x += point.vx;
      point.y += point.vy;
      if (point.x < 0 || point.x > 1) point.vx *= -1;
      if (point.y < 0 || point.y > 1) point.vy *= -1;
      const x = point.x * canvas.width;
      const y = point.y * canvas.height;
      context.beginPath();
      context.arc(x, y, point.r * dpr, 0, Math.PI * 2);
      context.fill();
    });
    for (let index = 0; index < particles.length; index += 1) {
      for (let next = index + 1; next < particles.length; next += 1) {
        const a = particles[index];
        const b = particles[next];
        const dx = (a.x - b.x) * canvas.width;
        const dy = (a.y - b.y) * canvas.height;
        const distance = Math.hypot(dx, dy);
        const threshold = 120 * dpr;
        if (distance < threshold) {
          context.globalAlpha = 1 - distance / threshold;
          context.beginPath();
          context.moveTo(a.x * canvas.width, a.y * canvas.height);
          context.lineTo(b.x * canvas.width, b.y * canvas.height);
          context.stroke();
        }
      }
    }
    context.globalAlpha = 1;
  }

  window.addEventListener("resize", resize);
  window.addEventListener("scroll", () => {
    isScrolling = true;
    window.clearTimeout(scrollTimer);
    scrollTimer = window.setTimeout(() => {
      isScrolling = false;
    }, 130);
  }, { passive: true });
  resize();
  requestAnimationFrame(draw);
}

function setLiveSignal(text) {
  const node = document.querySelector("#liveSignal");
  if (node) node.textContent = text;
}

let toastTimer = 0;

function showToast(message, isError = false) {
  const toast = document.querySelector("#appToast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 4200);
}

function downloadFilename(response, fallback) {
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return match?.[1] || fallback;
}

async function downloadExport(url, fallbackName = "osintpro-export") {
  setLiveSignal("preparing secure export");
  try {
    const response = await fetch(url, { credentials: "same-origin" });
    if (!response.ok) {
      const contentType = response.headers.get("Content-Type") || "";
      const payload = contentType.includes("application/json") ? await response.json() : {};
      throw new Error(payload.error || `Export failed with HTTP ${response.status}.`);
    }
    const blob = await response.blob();
    if (!blob.size) throw new Error("The export was empty.");
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = downloadFilename(response, fallbackName);
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    showToast(`Downloaded ${anchor.download}`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    setLiveSignal("passive sensors idle");
  }
}

function freeReportsUnlimited() {
  return state.user.plan === "Free" && state.user.free_credits === null;
}

function freeCreditsExhausted() {
  return state.user.plan === "Free" && !freeReportsUnlimited() && Number(state.user.credits || 0) <= 0;
}

function closeMobileNavigation() {
  document.body.classList.remove("nav-open");
  const button = document.querySelector("#mobileMenuButton");
  if (button) {
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-label", "Open navigation");
  }
}

function toggleMobileNavigation() {
  const button = document.querySelector("#mobileMenuButton");
  if (!button) return;
  const open = !document.body.classList.contains("nav-open");
  document.body.classList.toggle("nav-open", open);
  button.setAttribute("aria-expanded", String(open));
  button.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
}

function setSection(id) {
  document.querySelectorAll(".section").forEach(section => section.classList.toggle("active", section.id === id));
  document.querySelectorAll(".nav-btn").forEach(button => button.classList.toggle("active", button.dataset.section === id));
  closeMobileNavigation();
  if (id === "billing" && !state.trackedSections.has("billing")) {
    state.trackedSections.add("billing");
    trackEvent("billing_view", { source: "navigation", plan: state.user?.plan || "Free" });
  }
  if (id === "api-preview") {
    loadApiKeys();
  }
}

function redactClient(value) {
  return String(value ?? "")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted]")
    .replace(/\b(?:sk|pk|rk|whsec|ghp|github_pat|xox[baprs])[_-][-A-Za-z0-9_]{12,}\b/g, "[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[redacted]")
    .replace(/\b[A-Za-z0-9_=-]{24,}\.[A-Za-z0-9_=-]{12,}\.[A-Za-z0-9_=-]{12,}\b/g, "[redacted]")
    .replace(/(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*)[^\s,;"'<>]+/gi, "$1[redacted]")
    .replace(/(\bauthorization\s*[:=]\s*(?:bearer|basic)\s+)[a-z0-9._~+/=-]+/gi, "$1[redacted]");
}

function escapeHtml(value) {
  return redactClient(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

function formatDate(value) {
  if (!value) return "not yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", { dateStyle: "short", timeStyle: "short" });
}

const REPO_IGNORED_SEGMENTS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", "coverage", ".next",
  ".nuxt", ".venv", "venv", "__pycache__", "target", "bin", "obj"
]);

const REPO_TEXT_EXTENSIONS = new Set([
  "", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".php", ".rb",
  ".go", ".rs", ".java", ".cs", ".html", ".htm", ".css", ".scss", ".sql",
  ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".yml", ".yaml", ".md",
  ".txt", ".sh", ".zsh", ".bash", ".env", ".example", ".lock"
]);

function repositoryFileAllowed(file) {
  const path = String(file.webkitRelativePath || file.name || "").replaceAll("\\", "/");
  const parts = path.split("/").filter(Boolean);
  if (parts.some(part => REPO_IGNORED_SEGMENTS.has(part))) return false;
  if (file.size > 180000) return false;
  const name = parts.at(-1)?.toLowerCase() || "";
  if (name === ".gitignore") return true;
  const extensionIndex = name.lastIndexOf(".");
  const extension = extensionIndex >= 0 ? name.slice(extensionIndex) : "";
  return REPO_TEXT_EXTENSIONS.has(extension)
    || ["dockerfile", "gemfile", "procfile", "makefile", "license"].includes(name);
}

function repoSeverityTone(severity) {
  return ["critical", "high", "medium", "low"].includes(severity) ? severity : "info";
}

function repoConfidenceValue(item) {
  if (Number.isFinite(Number(item.confidence_score))) return Number(item.confidence_score);
  return { high: 0.95, medium: 0.7, low: 0.45 }[String(item.confidence || "").toLowerCase()] || 0.5;
}

function updateRepoConfidenceFilter() {
  const threshold = Number(state.repoConfidenceThreshold || 0.35);
  const findings = [...document.querySelectorAll("[data-repo-finding]")];
  let visible = 0;
  findings.forEach(item => {
    const confidence = Number(item.dataset.confidence || "0");
    const show = confidence >= threshold;
    item.hidden = !show;
    if (show) visible += 1;
  });
  const count = document.querySelector("#repoConfidenceCount");
  if (count) count.textContent = `${visible} of ${findings.length} findings visible`;
}

function renderRepoAudit(audit) {
  state.currentRepoAudit = audit;
  const holder = document.querySelector("#repoAuditResult");
  const findings = audit.findings || [];
  const dependencyAdvisories = audit.dependency_advisories || [];
  const counts = audit.counts || {};
  holder.className = "result";
  holder.innerHTML = `
    <div class="report-top">
      <div>
        <span class="pill">Static repository review</span>
        <h2>${escapeHtml(audit.repository)}</h2>
        <p>${escapeHtml(audit.files_scanned)} text files reviewed without executing code. ${escapeHtml(audit.ignored_files || 0)} files ignored by dependency/build/.gitignore rules.</p>
      </div>
      <div class="score">
        <div><span>Code posture</span><strong>${escapeHtml(audit.score)}</strong></div>
      </div>
    </div>
    <div class="summary-strip">
      <div><strong>${escapeHtml(counts.critical || 0)}</strong><span>critical</span></div>
      <div><strong>${escapeHtml(counts.high || 0)}</strong><span>high</span></div>
      <div><strong>${escapeHtml(counts.medium || 0)}</strong><span>medium</span></div>
      <div><strong>${escapeHtml(counts.low || 0)}</strong><span>low</span></div>
      <div><strong>${escapeHtml(audit.files_scanned)}</strong><span>files</span></div>
    </div>
    <section class="repo-context">
      <div>
        <span class="pill">Detected context</span>
        <strong>${escapeHtml((audit.languages || []).join(", ") || "Configuration/text repository")}</strong>
        <p>${Object.entries(audit.context || {}).filter(([, enabled]) => enabled).map(([name]) => escapeHtml(name)).join(" · ") || "No application capability confidently detected."}</p>
      </div>
      <div>
        <span class="pill">Manifests</span>
        <strong>${escapeHtml((audit.manifests || []).join(", ") || "None detected")}</strong>
        <p>${escapeHtml(Math.round((audit.bytes_scanned || 0) / 1024))} KB of source text analyzed.</p>
      </div>
    </section>
    <section class="repo-findings">
      <div class="mini-head">
        <span class="pill">Prioritized review</span>
        <h3>${escapeHtml(audit.total_findings ?? findings.length)} findings</h3>
      </div>
      <div class="repo-toolbar">
        <label for="repoConfidenceSlider">
          Confidence threshold
          <strong id="repoConfidenceValue">${escapeHtml(Number(state.repoConfidenceThreshold).toFixed(2))}</strong>
        </label>
        <input id="repoConfidenceSlider" type="range" min="0.35" max="1" step="0.05" value="${escapeHtml(state.repoConfidenceThreshold)}">
        <span class="tag neutral" id="repoConfidenceCount">${escapeHtml(findings.length)} findings visible</span>
      </div>
      ${audit.suppressed_findings ? `<p class="muted">${escapeHtml(audit.suppressed_findings)} repeated occurrences were compacted to keep the review readable.</p>` : ""}
      ${findings.length ? findings.map(item => `
        <article class="repo-finding ${repoSeverityTone(item.severity)}" data-repo-finding data-confidence="${escapeHtml(repoConfidenceValue(item))}">
          <div class="repo-finding-head">
            <span class="severity ${repoSeverityTone(item.severity)}">${escapeHtml(item.severity)}</span>
            <strong>${escapeHtml(item.title)}</strong>
            <span class="tag">${escapeHtml(item.confidence)} · ${escapeHtml(repoConfidenceValue(item).toFixed(2))}</span>
          </div>
          <code>${escapeHtml(item.path)}:${escapeHtml(item.line)}</code>
          <pre>${escapeHtml(item.evidence || "Evidence redacted")}</pre>
          <p><strong>Why:</strong> ${escapeHtml(item.why)}</p>
          ${item.abuse_path ? `
            <div class="abuse-brief">
              <p><b>How an attacker may abuse it:</b> ${escapeHtml(item.abuse_path)}</p>
              <p><b>Business impact:</b> ${escapeHtml(item.business_impact || "Impact depends on reachability and privilege.")}</p>
              <p><b>Owner action:</b> ${escapeHtml(item.owner_action || "Confirm applicability and assign remediation ownership.")}</p>
            </div>
          ` : ""}
          <p><strong>Applies when:</strong> ${escapeHtml(item.applicability)}</p>
          <p><strong>Fix:</strong> ${escapeHtml(item.remediation)}</p>
        </article>
      `).join("") : `<div class="finding"><span class="tag">Review complete</span><strong>No rule match found</strong><p>This does not prove the repository is vulnerability-free. Continue with dependency, architecture and runtime testing.</p></div>`}
    </section>
    ${dependencyAdvisories.length ? `
      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Dependency advisory</span>
          <h3>${escapeHtml(dependencyAdvisories.length)} package review leads</h3>
        </div>
        <div class="repo-dependencies">
          ${dependencyAdvisories.map(item => `
            <article class="repo-finding ${repoSeverityTone(item.severity)}">
              <div class="repo-finding-head">
                <span class="severity ${repoSeverityTone(item.severity)}">${escapeHtml(item.severity)}</span>
                <strong>${escapeHtml(item.ecosystem)} · ${escapeHtml(item.package)}</strong>
                <span class="tag">fix &gt;= ${escapeHtml(item.fixed_version)}</span>
              </div>
              <code>${escapeHtml(item.path)}</code>
              <p>${escapeHtml(item.advisory)}</p>
              ${item.abuse_path ? `
                <div class="abuse-brief">
                  <p><b>How an attacker may abuse it:</b> ${escapeHtml(item.abuse_path)}</p>
                  <p><b>Business impact:</b> ${escapeHtml(item.business_impact || "Impact depends on whether the dependency is reachable.")}</p>
                  <p><b>Owner action:</b> ${escapeHtml(item.owner_action || "Upgrade, redeploy and verify the package is not loaded from stale artifacts.")}</p>
                </div>
              ` : ""}
              <p><strong>Fix:</strong> ${escapeHtml(item.remediation)}</p>
            </article>
          `).join("")}
        </div>
      </section>
    ` : ""}
    <section class="lab-panel disclaimer-panel">
      <div class="mini-head">
        <span class="pill">Limitations</span>
        <h3>What this result means</h3>
      </div>
      <ul class="step-list">${(audit.limitations || []).map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>
  `;
  const jsonExport = document.querySelector("#downloadRepoAudit");
  const sarifExport = document.querySelector("#downloadRepoSarif");
  if (jsonExport) {
    jsonExport.href = `/api/reports/${encodeURIComponent(audit.id)}/repository.json`;
    jsonExport.hidden = false;
  }
  if (sarifExport) {
    sarifExport.href = `/api/reports/${encodeURIComponent(audit.id)}/sarif`;
    sarifExport.hidden = false;
    const sarifFlag = state.featureFlags?.repo_audit_sarif;
    sarifExport.textContent = sarifFlag && !sarifFlag.allowed ? "Export SARIF · Pro" : "Export SARIF";
  }
  const slider = document.querySelector("#repoConfidenceSlider");
  if (slider) {
    slider.addEventListener("input", event => {
      state.repoConfidenceThreshold = Number(event.target.value);
      document.querySelector("#repoConfidenceValue").textContent = state.repoConfidenceThreshold.toFixed(2);
      updateRepoConfidenceFilter();
    });
  }
  updateRepoConfidenceFilter();
}

async function buildRepoAudit(files, repository) {
  if (freeCreditsExhausted()) {
    setSection("billing");
    trackEvent("free_credits_exhausted", { plan: "Pro", source: "repository_audit", metadata: { current_plan: state.user.plan } });
    showBillingMessage("You have used all Free credits. Repository Audit Lab continues on Pro/Agency.");
    return;
  }
  const eligible = [...files].filter(repositoryFileAllowed).slice(0, 180);
  if (!eligible.length) {
    throw new Error("No eligible text source files found in this folder.");
  }
  let totalBytes = 0;
  const payloadFiles = [];
  for (const file of eligible) {
    if (totalBytes + file.size > 1500000) break;
    const content = await file.text();
    totalBytes += new TextEncoder().encode(content).length;
    payloadFiles.push({
      path: file.webkitRelativePath || file.name,
      content
    });
  }
  if (!payloadFiles.length) {
    throw new Error("The selected source files exceed the audit size limit.");
  }
  const data = await api("/api/repository/audit", {
    method: "POST",
    body: JSON.stringify({ repository, files: payloadFiles })
  });
  state.user = data.user;
  updateAccount();
  renderRepoAudit(data.audit);
}

function nicknameInitials(nickname) {
  const clean = String(nickname || "").replace(/[^a-z0-9]/gi, "");
  return (clean.slice(0, 2) || "?").toUpperCase();
}

function list(items) {
  if (!items || !items.length) return "<span class=\"mono\">no data</span>";
  return `<div class="mono lines">${items.map(item => `<span>${escapeHtml(item)}</span>`).join("")}</div>`;
}

function flag(value) {
  return `<span class="tag ${value ? "" : "missing"}">${value ? "OK" : "Missing"}</span>`;
}

function optionalFlag(value, presentLabel = "Observed", absentLabel = "Not declared") {
  return `<span class="tag neutral">${value ? presentLabel : absentLabel}</span>`;
}

function scopedFlag(value, applicable) {
  return applicable ? flag(value) : `<span class="tag neutral">N/A</span>`;
}

function folderOptions(selected = "") {
  return `<option value="">No client folder</option>${state.folders.map(folder => `
    <option value="${escapeHtml(folder.id)}" ${folder.id === selected ? "selected" : ""}>${escapeHtml(folder.name)}</option>
  `).join("")}`;
}

function activeFolderId() {
  const node = document.querySelector("#activeFolder");
  return node ? node.value : "";
}

function probeLabel(probe) {
  if (!probe) return "not available";
  if (probe.available === false) return "assessment unavailable";
  return probe.present ? `HTTP ${probe.status}` : (probe.status ? `HTTP ${probe.status}` : "not found");
}

function renderFindings(findings = []) {
  if (!findings.length) {
    return `<div class="finding"><span class="tag">OK</span><strong>No priority finding</strong><p>Passive sources do not show major issues.</p></div>`;
  }
  return findings.map(item => `
    <div class="finding ${escapeHtml(item.level)}">
      <span class="tag ${item.level === "high" ? "missing" : ""}">${escapeHtml(item.level)}</span>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.detail)}</p>
      ${item.abuse_path ? `
        <div class="abuse-brief">
          <p><b>How an attacker may abuse it:</b> ${escapeHtml(item.abuse_path)}</p>
          <p><b>Business impact:</b> ${escapeHtml(item.business_impact || "Impact depends on reachability, privilege and exposed data.")}</p>
          <p><b>Owner action:</b> ${escapeHtml(item.owner_action || "Confirm applicability, assign an owner and track remediation.")}</p>
          <p><b>Evidence to collect:</b> ${escapeHtml(item.evidence_to_collect || "Collect logs, ownership context and current configuration.")}</p>
        </div>
      ` : ""}
    </div>
  `).join("");
}

function renderVulnerabilities(items = []) {
  if (!items.length) {
    return `<div class="ops-row"><span class="tag">OK</span><strong>No priority hypothesis</strong><p>No vulnerability hypotheses emerged from passive sources.</p></div>`;
  }
  return items.map(item => `
    <div class="ops-row ${escapeHtml(item.severity)}">
      <span class="tag ${item.severity === "high" ? "missing" : ""}">${escapeHtml(item.severity)}</span>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.evidence)}</p>
      ${item.attacker_path ? `
        <div class="abuse-brief">
          <p><b>Likely attacker path:</b> ${escapeHtml(item.attacker_path)}</p>
          <p><b>Likely impact:</b> ${escapeHtml(item.likely_impact || "Impact depends on asset exposure and authenticated surface.")}</p>
          <p><b>Defensive priority:</b> ${escapeHtml(item.defensive_priority || "Validate safely, then assign an owner and deadline.")}</p>
        </div>
      ` : ""}
      <small>${escapeHtml(item.next_step)}</small>
    </div>
  `).join("");
}

function renderOpsRows(items = [], titleKey, bodyKey, metaKey) {
  return items.map(item => `
    <div class="ops-row">
      <strong>${escapeHtml(item[titleKey])}</strong>
      <p>${escapeHtml(item[bodyKey])}</p>
      <small>${escapeHtml(item[metaKey])}</small>
    </div>
  `).join("");
}

function shellCommand(command) {
  return `<pre class="command-block"><code>${escapeHtml(command)}</code></pre>`;
}

function renderTerm(term, definition) {
  return `
    <article class="term-card">
      <strong>${escapeHtml(term)}</strong>
      <p>${escapeHtml(definition)}</p>
    </article>
  `;
}

function webAuditCommands(domain) {
  const safe = String(domain || "example.com").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return [
    {
      title: "Headers baseline",
      command: `curl -I https://${safe}`,
      explain: "Reads only response headers. It does not submit forms, fuzz parameters or attack the server."
    },
    {
      title: "Security disclosure file",
      command: `curl https://${safe}/.well-known/security.txt`,
      explain: "Checks whether researchers have a responsible disclosure contact."
    },
    {
      title: "Crawler hints",
      command: `curl https://${safe}/robots.txt && curl https://${safe}/sitemap.xml`,
      explain: "Shows public crawler instructions and URLs intentionally exposed for indexing."
    },
    {
      title: "TLS certificate dates",
      command: `echo | openssl s_client -servername ${safe} -connect ${safe}:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates`,
      explain: "Reads certificate metadata so you can verify issuer, subject and expiry."
    },
    {
      title: "Email spoofing posture",
      command: `dig TXT ${safe} +short && dig TXT _dmarc.${safe} +short`,
      explain: "Checks SPF and DMARC DNS records without sending any email."
    },
    {
      title: "Certificate authority policy",
      command: `dig CAA ${safe} +short`,
      explain: "Checks whether the domain restricts which certificate authorities can issue TLS certificates."
    }
  ];
}

function webAuditStatus(report) {
  const headers = report.https?.security_headers || [];
  const web = report.web_presence || {};
  const required = headers.map(item => ({
    label: item.name,
    ok: Boolean(item.present),
    applicable: item.assessed !== false,
    optional: false,
    detail: item.present ? item.value : item.reason
  }));
  [
    ["security.txt", web.security_txt],
    ["robots.txt", web.robots_txt],
    ["sitemap.xml", web.sitemap_xml]
  ].forEach(([label, value]) => {
    required.push({
      label,
      ok: Boolean(value?.present),
      applicable: value?.available !== false,
      optional: label !== "security.txt",
      detail: value?.status ? `HTTP ${value.status}` : value?.error || "not observed"
    });
  });
  return required;
}

function networkLabCommands(domain) {
  const safe = String(domain || "example.com").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return [
    {
      title: "Resolve the host",
      command: `dig A ${safe} +short`,
      explain: "Shows the IP addresses your machine may connect to before HTTPS starts."
    },
    {
      title: "Read the HTTPS response headers",
      command: `curl -I https://${safe}`,
      explain: "Creates one normal request and prints readable response headers."
    },
    {
      title: "Inspect the certificate",
      command: `echo | openssl s_client -servername ${safe} -connect ${safe}:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates`,
      explain: "Shows certificate issuer, subject and expiry without logging into the site."
    }
  ];
}

function networkLabFilters(domain, ips = []) {
  const safe = String(domain || "example.com");
  const firstIp = ips[0] || "203.0.113.10";
  return [
    { filter: `dns.qry.name == "${safe}"`, use: "Find DNS questions for the domain." },
    { filter: `ip.addr == ${firstIp}`, use: "Show packets between your device and the resolved server IP." },
    { filter: `tcp.port == 443`, use: "Focus on HTTPS transport traffic." },
    { filter: `tls.handshake.extensions_server_name == "${safe}"`, use: "Find the TLS Client Hello that contains the public SNI host name." },
    { filter: `http.host == "${safe}"`, use: "Useful only for plain HTTP traffic. HTTPS content stays encrypted." }
  ];
}

function networkPackets(report) {
  const domain = report.domain;
  const ips = report.dns?.addresses || [];
  const firstIp = ips[0] || "resolved server";
  const cert = report.https?.certificate || {};
  const headers = report.https?.security_headers || [];
  const presentHeaders = headers.filter(item => item.present).map(item => item.name);
  const missingHeaders = headers
    .filter(item => item.assessed !== false && !item.present)
    .map(item => item.name);
  const rows = [
    {
      no: 1,
      protocol: "DNS",
      source: "analyst workstation",
      destination: "recursive resolver",
      summary: `Query A record for ${domain}`,
      detail: "The browser needs an IP address before it can connect to a domain."
    },
    {
      no: 2,
      protocol: "DNS",
      source: "recursive resolver",
      destination: "analyst workstation",
      summary: ips.length ? `Answer: ${ips.join(", ")}` : "No A answer observed",
      detail: "These are the public addresses OSINTPRO resolved from passive DNS lookup."
    },
    {
      no: 3,
      protocol: "TCP",
      source: "analyst workstation",
      destination: `${firstIp}:443`,
      summary: "HTTPS connection opens on TCP/443",
      detail: "Wireshark would show SYN, SYN-ACK and ACK packets before encrypted TLS begins."
    },
    {
      no: 4,
      protocol: "TLS",
      source: "analyst workstation",
      destination: domain,
      summary: `Client Hello with SNI ${domain}`,
      detail: "SNI tells the server which certificate to present. It is host metadata, not a password."
    },
    {
      no: 5,
      protocol: "TLS",
      source: domain,
      destination: "analyst workstation",
      summary: cert.issuer ? `Certificate issuer: ${cert.issuer}` : "Certificate metadata not available",
      detail: cert.expires ? `Subject: ${cert.subject || "not available"}. Expires: ${cert.expires}.` : "Certificate details could not be collected from the public endpoint."
    },
    {
      no: 6,
      protocol: "HTTP",
      source: "analyst workstation",
      destination: domain,
      summary: "HEAD / request for public headers",
      detail: "This is equivalent to curl -I. It reads headers without submitting forms or sending credentials."
    },
    {
      no: 7,
      protocol: "HTTP",
      source: domain,
      destination: "analyst workstation",
      summary: `Response ${report.https?.status || "n/a"}${report.https?.server ? ` from ${report.https.server}` : ""}`,
      detail: report.https?.available === false
        ? "The public HTTPS response could not be assessed in this run."
        : presentHeaders.length
          ? `Observed security headers: ${presentHeaders.join(", ")}.`
          : "No major browser security headers were observed."
    },
    {
      no: 8,
      protocol: "Security",
      source: "OSINTPRO parser",
      destination: "case report",
      summary: missingHeaders.length ? `Missing headers: ${missingHeaders.join(", ")}` : "No priority missing security headers",
      detail: "This is a readable interpretation layer, not an exploit or invasive scan."
    }
  ];
  const mx = report.dns?.mx || [];
  if (mx.length) {
    rows.push({
      no: rows.length + 1,
      protocol: "DNS",
      source: "recursive resolver",
      destination: "case report",
      summary: `MX records: ${mx.slice(0, 3).join(", ")}`,
      detail: "Mail exchange records explain which public systems receive email for the domain."
    });
  }
  return rows;
}

function renderNetworkLab(report) {
  const domain = report.domain;
  const ips = report.dns?.addresses || [];
  const packets = networkPackets(report);
  const filters = networkLabFilters(domain, ips);
  const commands = networkLabCommands(domain);
  const glossary = [
    ["Packet", "A small unit of network data. Wireshark lists packets in the order they were observed."],
    ["DNS", "The lookup step that turns a domain name into one or more IP addresses."],
    ["TCP", "The transport protocol that opens a reliable connection before HTTPS data moves."],
    ["TLS", "The encryption layer used by HTTPS. It protects page content and credentials."],
    ["SNI", "Server Name Indication. A TLS field that tells the server which public host name is being requested."],
    ["HTTP header", "Readable metadata sent before the page body, such as security policy and server hints."],
    ["Display filter", "A Wireshark search expression that hides unrelated packets without changing the capture."]
  ];

  document.querySelector("#networkLabResult").className = "result";
  document.querySelector("#networkLabResult").innerHTML = `
    <div class="result-head">
      <div>
        <span class="pill">Network Traffic Lab</span>
        <h2>${escapeHtml(domain)}</h2>
        <p>${escapeHtml(report.summary)}</p>
      </div>
      <strong class="score">${escapeHtml(report.score)}/100</strong>
    </div>

    <div class="lab-grid">
      <article class="lab-card lab-hero">
        <span class="pill">Wireshark simple mode</span>
        <h3>Readable traffic story</h3>
        <ol class="step-list">
          <li><strong>DNS:</strong> the domain is translated into public IP addresses.</li>
          <li><strong>TCP:</strong> the browser opens a connection to port 443.</li>
          <li><strong>TLS:</strong> certificate metadata confirms who presented HTTPS.</li>
          <li><strong>HTTP:</strong> response headers show browser-side security posture.</li>
          <li><strong>Report:</strong> OSINTPRO turns the evidence into plain-language findings.</li>
        </ol>
      </article>
      <article class="lab-card">
        <span>Resolved IPs</span>
        <strong>${ips.length}</strong>
        <p>${ips.length ? ips.join(", ") : "No public A records observed."}</p>
      </article>
      <article class="lab-card">
        <span>HTTP status</span>
        <strong>${escapeHtml(report.https?.status || "n/a")}</strong>
        <p>${escapeHtml(report.https?.server || "Server header not observed.")}</p>
      </article>
    </div>

    <section class="lab-panel disclaimer-panel">
      <div class="mini-head">
        <span class="pill">Authorized use only</span>
        <h3>Capture boundary</h3>
      </div>
      <p>This lab explains what Wireshark would help you understand when you inspect your own traffic. Do not capture traffic from networks, devices, accounts or users you do not own or have explicit permission to monitor.</p>
    </section>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Packet list</span>
        <h3>Human-readable packets</h3>
      </div>
      <div class="packet-table">
        ${packets.map(packet => `
          <article class="packet-row">
            <span class="mono">#${packet.no}</span>
            <strong>${escapeHtml(packet.protocol)}</strong>
            <span>${escapeHtml(packet.source)} → ${escapeHtml(packet.destination)}</span>
            <p>${escapeHtml(packet.summary)}</p>
            <small>${escapeHtml(packet.detail)}</small>
          </article>
        `).join("")}
      </div>
    </section>

    <div class="lab-columns">
      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Display filters</span>
          <h3>Copy into Wireshark</h3>
        </div>
        <div class="command-list">
          ${filters.map(item => `
            <article class="command-card">
              ${shellCommand(item.filter)}
              <p>${escapeHtml(item.use)}</p>
            </article>
          `).join("")}
        </div>
      </section>

      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Safe terminal checks</span>
          <h3>Readable evidence</h3>
        </div>
        <div class="command-list">
          ${commands.map(item => `
            <article class="command-card">
              <strong>${escapeHtml(item.title)}</strong>
              ${shellCommand(item.command)}
              <p>${escapeHtml(item.explain)}</p>
            </article>
          `).join("")}
        </div>
      </section>
    </div>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Glossary</span>
        <h3>Network terms explained</h3>
      </div>
      <div class="term-grid">
        ${glossary.map(([term, definition]) => renderTerm(term, definition)).join("")}
      </div>
    </section>
  `;
}

function setNetworkMode(mode) {
  document.querySelectorAll("[data-network-mode]").forEach(button => {
    button.classList.toggle("active", button.dataset.networkMode === mode);
  });
  document.querySelector("#networkWebsiteMode").classList.toggle("active", mode === "website");
  document.querySelector("#networkLocalMode").classList.toggle("active", mode === "local");
  if (mode === "local") {
    document.querySelector("#networkLabResult").className = "result empty";
    document.querySelector("#networkLabResult").innerHTML = `<h2>Own-network lab</h2><p>Run OSINTPRO locally, then build a readable view of your own machine's network context and safe Wireshark filters.</p>`;
  }
}

function renderLocalNetworkLab(data) {
  const network = data.network || {};
  if (!data.available) {
    document.querySelector("#networkLabResult").className = "result";
    document.querySelector("#networkLabResult").innerHTML = `
      <div class="result-head">
        <div>
          <span class="pill">Own Network</span>
          <h2>Local capture requires local runtime</h2>
          <p>${escapeHtml(data.message)}</p>
        </div>
      </div>
      <section class="lab-panel disclaimer-panel">
        <div class="mini-head">
          <span class="pill">Safe next steps</span>
          <h3>How to use it correctly</h3>
        </div>
        <ol class="step-list">
          ${(data.safe_next_steps || []).map(item => `<li>${escapeHtml(item)}</li>`).join("")}
        </ol>
      </section>
    `;
    return;
  }

  const addresses = network.addresses || [];
  const filters = network.capture_filters || [];
  const timeline = network.timeline || [];
  document.querySelector("#networkLabResult").className = "result";
  document.querySelector("#networkLabResult").innerHTML = `
    <div class="result-head">
      <div>
        <span class="pill">Own Network Lab</span>
        <h2>${escapeHtml(network.hostname || "local machine")}</h2>
        <p>Readable local network context for a Wireshark capture on your own device or lab network.</p>
      </div>
      <strong class="score">${addresses.length}</strong>
    </div>

    <div class="lab-grid">
      <article class="lab-card lab-hero">
        <span class="pill">Local capture workflow</span>
        <h3>What to do in Wireshark</h3>
        <ol class="step-list">
          <li><strong>Select interface:</strong> choose your Wi-Fi or Ethernet adapter, not a random interface.</li>
          <li><strong>Start capture:</strong> capture only your own device or authorized lab traffic.</li>
          <li><strong>Filter:</strong> use DNS, ARP, TLS and mDNS filters below to hide noise.</li>
          <li><strong>Read:</strong> focus on endpoint, port, protocol and certificate metadata.</li>
          <li><strong>Stop:</strong> stop capture before storing or sharing evidence.</li>
        </ol>
      </article>
      <article class="lab-card">
        <span>Local addresses</span>
        <strong>${addresses.length}</strong>
        <p>${addresses.map(item => item.ip).join(", ") || "No local IPv4 address observed."}</p>
      </article>
      <article class="lab-card">
        <span>DNS resolvers</span>
        <strong>${(network.resolvers || []).length}</strong>
        <p>${(network.resolvers || []).join(", ") || "Resolver not observed from runtime."}</p>
      </article>
    </div>

    <section class="lab-panel disclaimer-panel">
      <div class="mini-head">
        <span class="pill">Authorized use only</span>
        <h3>LAN capture boundary</h3>
      </div>
      <p>Capture only your own traffic or traffic you are explicitly authorized to inspect. Do not capture roommates, clients, public Wi-Fi users or third-party devices without permission.</p>
    </section>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Local context</span>
        <h3>Readable interface clues</h3>
      </div>
      <div class="packet-table">
        ${addresses.map((item, index) => `
          <article class="packet-row">
            <span class="mono">#${index + 1}</span>
            <strong>IPv4</strong>
            <span>${escapeHtml(item.ip)} · ${escapeHtml(item.type)}${item.loopback ? " · loopback" : ""}</span>
            <p>${item.loopback ? "Local-only address used by your own machine." : "Candidate address for your local capture interface."}</p>
            <small>Use this only to orient your own Wireshark capture.</small>
          </article>
        `).join("")}
      </div>
    </section>

    <div class="lab-columns">
      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Display filters</span>
          <h3>Copy into Wireshark</h3>
        </div>
        <div class="command-list">
          ${filters.map(item => `
            <article class="command-card">
              ${shellCommand(item.filter)}
              <p>${escapeHtml(item.use)}</p>
            </article>
          `).join("")}
        </div>
      </section>

      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Protocol timeline</span>
          <h3>What common LAN packets mean</h3>
        </div>
        <div class="packet-table">
          ${timeline.map((item, index) => `
            <article class="packet-row">
              <span class="mono">#${index + 1}</span>
              <strong>${escapeHtml(item.protocol)}</strong>
              <span>${escapeHtml(item.summary)}</span>
              <p>${escapeHtml(item.plain)}</p>
              <small>Readable evidence, not a secret or credential.</small>
            </article>
          `).join("")}
        </div>
      </section>
    </div>
  `;
}

const gameSecurityScopes = {
  auth: {
    title: "Account and session auth",
    risk: "Account takeover, weak session lifecycle or unsafe launcher tokens.",
    attacker: "A real attacker would usually start with reused credentials, stolen launcher tokens, weak recovery flows or session persistence on shared machines, then try to convert account access into trades, refunds, moderation abuse or resale.",
    impact: "Player account loss, support overload, refund fraud, streamer/community reputational damage and possible regulatory complaints when recovery is weak.",
    checks: [
      "Review password reset, device login and launcher token expiry.",
      "Confirm session tokens rotate after privilege changes and logout.",
      "Separate game client identity from admin, support and moderation access."
    ],
    fixes: [
      "Use short-lived access tokens with server-side revocation.",
      "Require step-up checks for trading, purchases, refunds and account recovery.",
      "Log suspicious login changes without exposing secrets to the client."
    ]
  },
  economy: {
    title: "Inventory and economy",
    risk: "Client-side trust can allow item duplication, forged rewards or currency drift.",
    attacker: "A motivated abuser looks for any place where the client can claim rewards, repeat a transaction, replay a request or create race conditions around purchases, loot, crafting, trades or refunds.",
    impact: "Inflation, marketplace collapse, chargeback disputes, rare-item devaluation and loss of trust from legitimate players.",
    checks: [
      "Confirm rewards, inventory mutations and purchases are decided server-side.",
      "Review idempotency keys for purchases, trades, crafting and loot claims.",
      "Reconcile wallet/currency balances from append-only server events."
    ],
    fixes: [
      "Move economic authority to a server ledger with immutable event IDs.",
      "Add replay protection to every inventory-changing request.",
      "Alert on impossible currency deltas, duplicate claims and out-of-order events."
    ]
  },
  netcode: {
    title: "Netcode trust boundaries",
    risk: "Authoritative gaps can enable impossible movement, invalid hits or state desync.",
    attacker: "An abuser tries to discover which match outcomes the client can influence, then looks for impossible movement, timing, targeting, cooldown or state claims that the server accepts too easily.",
    impact: "Competitive integrity loss, churn from honest players, tournament disputes and expensive moderation review.",
    checks: [
      "List which game-state decisions are client-authoritative versus server-authoritative.",
      "Validate movement, firing, cooldowns and match events against server time.",
      "Look for inputs that the client can send without rate, state or map validation."
    ],
    fixes: [
      "Keep match-critical state authoritative on dedicated or trusted servers.",
      "Validate client actions against server-side physics windows and cooldowns.",
      "Record compact server replays for dispute review and anti-cheat triage."
    ]
  },
  anticheat: {
    title: "Anti-cheat telemetry",
    risk: "Telemetry gaps make cheating hard to detect and easy to dispute.",
    attacker: "Cheat developers look for blind spots between client telemetry, server truth and review evidence, then tune behavior to stay below detection or create plausible deniability.",
    impact: "Longer cheat lifetime, noisy ban appeals, false-positive risk and weaker confidence in enforcement decisions.",
    checks: [
      "Define which signals are collected from client, server and match replay.",
      "Verify telemetry is privacy-scoped and cannot leak secrets or personal data.",
      "Check that moderation actions have evidence IDs and appeal context."
    ],
    fixes: [
      "Prefer server-side anomaly detection for impossible outcomes.",
      "Keep client anti-cheat as one signal, not the only source of truth.",
      "Build analyst review queues with redacted evidence and clear retention."
    ]
  },
  backend: {
    title: "Backend APIs",
    risk: "Game APIs often expose unsafe debug routes, missing authorization or weak rate controls.",
    attacker: "An attacker maps public launcher, game, store, chat and telemetry endpoints, then looks for missing object-level authorization, weak rate limits or internal routes exposed by mistake.",
    impact: "Profile data leakage, inventory manipulation, chat abuse, matchmaking disruption and moderation bypass.",
    checks: [
      "Inventory public API routes used by launcher, game client, store and telemetry.",
      "Review object-level authorization for profiles, guilds, inventories and match results.",
      "Check rate limits and abuse controls for matchmaking, chat and trade endpoints."
    ],
    fixes: [
      "Apply object-level authorization on every player-owned resource.",
      "Separate production, staging and internal admin API surfaces.",
      "Use structured audit logs for moderation, inventory and economy changes."
    ]
  },
  builds: {
    title: "Build pipeline and patching",
    risk: "Unsigned builds, leaked debug symbols or slow patching can make abuse response harder.",
    attacker: "Abusers inspect public builds and update channels for leaked configuration, stale debug flags, predictable patch manifests or slow server-side kill switches.",
    impact: "Faster abuse research, delayed incident response, leaked secrets in client assets and forced emergency releases.",
    checks: [
      "Confirm build signing, launcher update integrity and rollback policy.",
      "Review how debug flags, staging endpoints and secrets are stripped from client builds.",
      "Measure time from critical bug report to forced client/server patch."
    ],
    fixes: [
      "Sign builds and validate patch manifests before install.",
      "Keep environment secrets out of client assets and crash logs.",
      "Prepare emergency server-side feature flags for risky systems."
    ]
  }
};

function architectureNotes(architecture) {
  const notes = {
    "client-server": [
      "Good baseline for online games when match-critical state is server-authoritative.",
      "Focus review effort on what the client can still claim: movement, rewards, purchases and telemetry."
    ],
    "peer-to-peer": [
      "Higher trust-boundary risk because one player machine may influence match state.",
      "Focus on host migration, tamper-resistant validation, replay review and dispute handling."
    ],
    "dedicated-server": [
      "Best fit for competitive integrity if servers validate timing, state and economy events.",
      "Focus on operational hardening, replay retention and backend authorization."
    ],
    "hybrid": [
      "Unknown or hybrid systems need a trust-boundary map before individual findings matter.",
      "Start by documenting which system has authority for each player-visible outcome."
    ]
  };
  return notes[architecture] || notes.hybrid;
}

function renderGameSecurityLab() {
  const title = document.querySelector("#gameTitle").value.trim() || "Online game";
  const architecture = document.querySelector("#gameArchitecture").value;
  const selected = Array.from(document.querySelectorAll(".game-scope-grid input:checked")).map(input => input.value);
  const scopes = selected.length ? selected : ["auth", "economy", "netcode", "backend"];
  const notes = architectureNotes(architecture);
  const rows = scopes.map(scope => gameSecurityScopes[scope]).filter(Boolean);
  const result = document.querySelector("#gameSecurityResult");

  result.className = "result";
  result.innerHTML = `
    <div class="result-head">
      <div>
        <span class="pill">Game Security Lab</span>
        <h2>${escapeHtml(title)}</h2>
        <p>Defensive review plan for ${escapeHtml(architecture.replace("-", " "))} online game engineering.</p>
      </div>
      <strong class="score">${rows.length}</strong>
    </div>

    <section class="lab-panel disclaimer-panel">
      <div class="mini-head">
        <span class="pill">Boundary</span>
        <h3>For authorized game teams only</h3>
      </div>
      <p>This lab helps engineers find and fix risk areas in games they own or are paid to review. No cheats, no bypasses, no exploit chains, no packet tampering steps and no offensive automation.</p>
    </section>

    <div class="lab-grid">
      <article class="lab-card lab-hero">
        <span class="pill">Architecture notes</span>
        <h3>Trust model first</h3>
        <ol class="step-list">
          ${notes.map(note => `<li>${escapeHtml(note)}</li>`).join("")}
          <li>Write down which system is authoritative for identity, inventory, economy, movement, matchmaking and moderation.</li>
        </ol>
      </article>
      <article class="lab-card">
        <span>Review areas</span>
        <strong>${rows.length}</strong>
        <p>${rows.map(row => escapeHtml(row.title)).join(", ")}</p>
      </article>
      <article class="lab-card">
        <span>Output</span>
        <strong>Dossier</strong>
        <p>Use the checklist below as engineering tickets, not as exploit instructions.</p>
      </article>
    </div>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Risk matrix</span>
        <h3>What to review and fix</h3>
      </div>
      <div class="risk-matrix">
        ${rows.map(row => `
          <article class="risk-row">
            <strong>${escapeHtml(row.title)}</strong>
            <div>
              <p><b>Risk:</b> ${escapeHtml(row.risk)}</p>
              <p><b>How an attacker may act:</b> ${escapeHtml(row.attacker)}</p>
              <p><b>Business impact:</b> ${escapeHtml(row.impact)}</p>
              <p><b>Checks:</b> ${row.checks.map(escapeHtml).join(" ")}</p>
              <p><b>Fix direction:</b> ${row.fixes.map(escapeHtml).join(" ")}</p>
            </div>
          </article>
        `).join("")}
      </div>
    </section>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Engineering tickets</span>
        <h3>Convert review into work</h3>
      </div>
      <ol class="step-list">
        <li>Create one ticket per trust boundary: identity, inventory, economy, match state, telemetry and moderation.</li>
        <li>Attach evidence from server logs, replay review, API route inventory or repository audit findings.</li>
        <li>Mark every fix as prevention, detection or response so production owners know what changed.</li>
        <li>Retest with authorized QA accounts and keep the results in the case folder.</li>
      </ol>
    </section>
  `;
  showToast("Game security review ready.");
}

function renderWebAuditLab(report) {
  const domain = report.domain;
  state.currentWebAuditReportId = report.id;
  const missingHeaders = (report.https?.security_headers || [])
    .filter(item => item.assessed !== false && !item.present);
  const findings = report.findings || [];
  const commands = webAuditCommands(domain);
  const statuses = webAuditStatus(report);
  const burpFeatures = [
    ["Target", "Builds a site map and scope. In OSINTPRO this becomes a clear list of authorized domains and public evidence."],
    ["Proxy", "Captures browser traffic so a tester can understand requests and responses before changing anything."],
    ["Repeater", "Lets a tester manually resend one request. OSINTPRO recommends it for safe GET requests and evidence capture only."],
    ["Decoder", "Helps read encoded values such as URL encoding or base64. Useful for understanding, not bypassing."],
    ["Comparer", "Shows differences between two responses, for example before and after a security header fix."],
    ["Logger", "Keeps a timeline of requests and responses. OSINTPRO maps this idea to report evidence."],
    ["Sequencer", "Evaluates randomness of tokens. OSINTPRO explains the concept but does not collect sensitive tokens."],
    ["Scanner", "Automates checks in Burp Suite. OSINTPRO does not run invasive scanning; it converts passive signals into a manual checklist."],
    ["Intruder", "Repeats requests with many inputs. OSINTPRO does not provide payload automation because it can become brute force or abuse."],
    ["Collaborator", "Detects out-of-band interactions. OSINTPRO does not run callback-based tests on third-party systems."]
  ];
  const exploitConcepts = [
    {
      title: "Cross-Site Scripting (XSS)",
      risk: "Untrusted input can run script in a user's browser.",
      safe: "Check whether CSP exists, identify input surfaces manually, and document where output encoding should be reviewed.",
      blocked: "No ready-to-run script payloads or automated injection."
    },
    {
      title: "SQL Injection",
      risk: "Untrusted input can alter database queries.",
      safe: "List forms, filters and API parameters that need server-side validation and prepared statements.",
      blocked: "No database error probing, UNION payloads or automated parameter fuzzing."
    },
    {
      title: "Access Control / IDOR",
      risk: "A user may access another user's object by changing an identifier.",
      safe: "Create a checklist for role boundaries, object ownership checks and audit evidence to collect in an authorized test account.",
      blocked: "No attempts against real user data or unauthorized accounts."
    },
    {
      title: "Authentication And Sessions",
      risk: "Weak login, cookies or session handling can expose accounts.",
      safe: "Review cookie flags, rate limits, logout behavior and password-change flows.",
      blocked: "No password guessing, credential stuffing or token theft."
    },
    {
      title: "Server-Side Request Forgery (SSRF)",
      risk: "A server may fetch attacker-controlled URLs or internal resources.",
      safe: "Identify features that accept URLs and document allowlist, timeout and metadata-IP protections to verify.",
      blocked: "No internal network probes or callback exploitation."
    },
    {
      title: "File Upload Risk",
      risk: "Unsafe uploads can lead to malware hosting or code execution.",
      safe: "Checklist allowed MIME types, extension validation, storage isolation, antivirus hooks and download headers.",
      blocked: "No malicious file generation or upload bypass payloads."
    },
    {
      title: "Command Injection",
      risk: "User input may reach shell commands on the server.",
      safe: "Identify input paths that trigger backend operations and require strict allowlists and no-shell execution.",
      blocked: "No shell metacharacter payloads or execution attempts."
    },
    {
      title: "CSRF",
      risk: "A third-party site may trigger state-changing actions in a logged-in browser.",
      safe: "Check SameSite cookies, CSRF tokens and whether state-changing routes require POST plus server-side validation.",
      blocked: "No cross-site proof-of-concept pages."
    }
  ];
  const glossary = [
    ["Proxy", "A tool that sits between your browser and the website so you can inspect requests and responses."],
    ["Request", "The message your browser sends to a server, usually containing a method, path, headers and sometimes a body."],
    ["Response", "The message the server sends back, including status code, headers and page/API content."],
    ["Header", "A key-value line that controls browser behavior, caching, security policy or metadata."],
    ["Cookie", "A small value stored by the browser and sent back to the same site, often used for sessions."],
    ["CSP", "Content-Security-Policy. A browser rule that limits where scripts, frames, images and connections can load from."],
    ["HSTS", "Strict-Transport-Security. A rule telling browsers to always use HTTPS for the domain."],
    ["Repeater", "A Burp Suite feature for manually resending one request to understand how the server responds."],
    ["Scanner", "An automated testing feature. OSINTPRO does not run invasive scanner traffic; it turns passive evidence into a checklist."],
    ["Intruder", "A Burp Suite feature often used for repeated payloads. OSINTPRO does not include this because it can become brute force."]
  ];

  document.querySelector("#webAuditResult").className = "result";
  document.querySelector("#webAuditResult").innerHTML = `
    <div class="result-head">
      <div>
        <span class="pill">Web Audit Lab</span>
        <h2>${escapeHtml(domain)}</h2>
        <p>${escapeHtml(report.summary)}</p>
        <div class="actions">
          <a class="secondary button-link" href="/api/reports/${escapeHtml(report.id)}/web-audit.csv" data-download>Export checklist CSV</a>
          <button class="secondary" type="button" data-save-playbook="${escapeHtml(report.id)}">Save playbook</button>
        </div>
      </div>
      <strong class="score">${escapeHtml(report.score)}/100</strong>
    </div>

    <div class="lab-grid">
      <article class="lab-card lab-hero">
        <span class="pill">Burp-style map</span>
        <h3>Beginner workflow</h3>
        <ol class="step-list">
          <li><strong>Scope:</strong> write down the exact domain you are allowed to test.</li>
          <li><strong>Proxy:</strong> inspect one normal browser request before changing anything.</li>
          <li><strong>Repeater:</strong> resend only safe GET requests such as the homepage or public metadata files.</li>
          <li><strong>Evidence:</strong> save headers, status codes and screenshots for the client report.</li>
          <li><strong>Fix:</strong> prioritize missing headers, disclosure files, TLS expiry and email spoofing posture.</li>
        </ol>
      </article>

      <article class="lab-card">
        <span>Header posture</span>
        <strong>${missingHeaders.length ? `${missingHeaders.length} missing` : "ready"}</strong>
        <p>${missingHeaders.length ? missingHeaders.map(item => item.name).join(", ") : "Main browser security headers are present."}</p>
      </article>

      <article class="lab-card">
        <span>Findings</span>
        <strong>${findings.length}</strong>
        <p>${findings.length ? "Review the prioritized issues below before touching any tooling." : "No priority passive findings."}</p>
      </article>
    </div>

    <section class="lab-panel disclaimer-panel">
      <div class="mini-head">
        <span class="pill">Authorized use only</span>
        <h3>Legal and safety boundary</h3>
      </div>
      <p>Use this lab only on domains, apps and accounts you own or are explicitly authorized to test. OSINTPRO provides passive evidence, beginner education and documentation workflows. Misuse against third-party systems is prohibited and remains the responsibility of the operator.</p>
    </section>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Burp Suite map</span>
        <h3>What each Burp-style feature means</h3>
      </div>
      <div class="feature-grid">
        ${burpFeatures.map(([name, detail]) => `
          <article class="feature-card">
            <strong>${escapeHtml(name)}</strong>
            <p>${escapeHtml(detail)}</p>
          </article>
        `).join("")}
      </div>
    </section>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Exploit concepts</span>
        <h3>Vulnerability classes explained safely</h3>
      </div>
      <div class="concept-grid">
        ${exploitConcepts.map(item => `
          <article class="concept-card">
            <strong>${escapeHtml(item.title)}</strong>
            <p><b>Risk:</b> ${escapeHtml(item.risk)}</p>
            <p><b>Beginner-safe review:</b> ${escapeHtml(item.safe)}</p>
            <p><b>Not automated here:</b> ${escapeHtml(item.blocked)}</p>
          </article>
        `).join("")}
      </div>
    </section>

    <div class="lab-columns">
      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Evidence checklist</span>
          <h3>What to verify</h3>
        </div>
        <div class="check-list">
          ${statuses.map(item => `
            <div class="check">
              <span>${item.optional ? optionalFlag(item.ok, "Public", "Not published") : scopedFlag(item.ok, item.applicable)}</span>
              <strong>${escapeHtml(item.label)}</strong>
              <em>${escapeHtml(item.detail || "")}</em>
            </div>
          `).join("")}
        </div>
      </section>

      <section class="lab-panel">
        <div class="mini-head">
          <span class="pill">Safe commands</span>
          <h3>Copy-friendly terminal checks</h3>
        </div>
        <div class="command-list">
          ${commands.map(item => `
            <article class="command-card">
              <strong>${escapeHtml(item.title)}</strong>
              ${shellCommand(item.command)}
              <p>${escapeHtml(item.explain)}</p>
            </article>
          `).join("")}
        </div>
      </section>
    </div>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Passive findings</span>
        <h3>What the lab found</h3>
      </div>
      <div class="ops-grid">
        ${renderFindings(findings)}
      </div>
    </section>

    <section class="lab-panel">
      <div class="mini-head">
        <span class="pill">Glossary</span>
        <h3>Technical terms explained</h3>
      </div>
      <div class="term-grid">
        ${glossary.map(([term, definition]) => renderTerm(term, definition)).join("")}
      </div>
    </section>
  `;
}

function updateAccount() {
  const isPaid = state.user.plan !== "Free";
  const isAuthenticated = Boolean(state.user.authenticated);
  const nickname = state.user.nickname || "Guest";
  const maxCredits = state.user.free_credits || 5;
  const label = isPaid || freeReportsUnlimited() ? "∞" : state.user.credits;
  const width = isPaid || freeReportsUnlimited() ? 100 : Math.max(0, Math.min(100, (state.user.credits / maxCredits) * 100));

  document.querySelector("#credits").textContent = label;
  document.querySelector("#creditBar").style.width = `${width}%`;
  document.querySelector("#workspacePlan").textContent = `${state.user.plan} workspace`;
  document.querySelector("#monitorUsage").textContent = `${state.monitors.length}/${state.user.monitor_limit}`;
  document.querySelector("#userAvatar").textContent = isAuthenticated ? nicknameInitials(nickname) : "?";
  document.querySelector("#userNickname").textContent = isAuthenticated ? `@${nickname}` : "Guest";
  document.querySelector("#userChip").classList.toggle("guest", !isAuthenticated);
  document.querySelector("#logoutButton").hidden = !isAuthenticated;
  document.querySelector("#deleteAccountButton").disabled = !isAuthenticated || state.user.plan === "Admin";
  document.querySelector("#accountState").textContent = state.user.authenticated
    ? `Signed in as @${state.user.nickname}`
    : "Anonymous session: create a nickname account to keep credits, reports and purchases.";
  document.querySelector("#accountMeta").textContent = `Plan ${state.user.plan} · Credits ${label} · Monitor ${state.monitors.length}/${state.user.monitor_limit}`;
  const historyNotice = document.querySelector("#historyNotice");
  if (historyNotice) {
    historyNotice.classList.toggle("guest-only", !isAuthenticated);
  }
  updateDashboard();
}

function updateDashboard() {
  const creditLabel = state.user.plan === "Free" && !freeReportsUnlimited() ? `${state.user.credits} credits available` : "Unlimited reports";
  const nodes = state.workspace?.nodes?.length || 0;
  const edges = state.workspace?.edges?.length || 0;
  const dashPlan = document.querySelector("#dashPlan");
  if (!dashPlan) return;
  dashPlan.textContent = state.user.plan || "Free";
  document.querySelector("#dashCredits").textContent = creditLabel;
  document.querySelector("#dashGraph").textContent = `${nodes} nodes / ${edges} edges`;
  document.querySelector("#dashMonitors").textContent = `${state.monitors.length}/${state.user.monitor_limit}`;
}

function reportActions(report) {
  return `
    <div class="row-actions">
      <a class="secondary small button-link" href="/api/reports/${report.id}/pdf" data-download>PDF</a>
      <a class="secondary small button-link" href="/api/reports/${report.id}/findings.csv" data-download>Findings CSV</a>
      <button class="secondary small" type="button" data-compare-domain="${escapeHtml(report.domain)}">Compare</button>
    </div>
  `;
}

function renderComparison(data) {
  const box = document.querySelector("#comparisonMessage");
  if (!box) return;
  box.classList.add("visible");
  if (!data.available) {
    box.innerHTML = `<strong>${escapeHtml(data.domain || "Domain")}</strong><br>${escapeHtml(data.message)}`;
    return;
  }
  const tone = data.delta > 0 ? "improved" : data.delta < 0 ? "declined" : "unchanged";
  box.innerHTML = `
    <strong>${escapeHtml(data.domain)} comparison: ${escapeHtml(tone)} ${data.delta > 0 ? "+" : ""}${escapeHtml(data.delta)} points</strong>
    <div class="comparison-grid">
      <span>Latest <b>${escapeHtml(data.latest.score)}/100</b> · ${escapeHtml(formatDate(data.latest.generated_at))}</span>
      <span>Previous <b>${escapeHtml(data.previous.score)}/100</b> · ${escapeHtml(formatDate(data.previous.generated_at))}</span>
      <span>Fixed headers: <b>${escapeHtml((data.fixed_headers || []).join(", ") || "none")}</b></span>
      <span>New missing headers: <b>${escapeHtml((data.new_missing_headers || []).join(", ") || "none")}</b></span>
      <span>Resolved findings: <b>${escapeHtml((data.resolved_findings || []).join(", ") || "none")}</b></span>
      <span>New findings: <b>${escapeHtml((data.new_findings || []).join(", ") || "none")}</b></span>
    </div>
  `;
}

function renderFolders() {
  const caseSummaryList = document.querySelector("#caseSummaryList");
  if (caseSummaryList) {
    const summaries = state.workspace?.case_summaries || [];
    if (!state.user.authenticated) {
      caseSummaryList.innerHTML = `<div class="result empty"><h2>Sign in to build case summaries</h2><p>Client summaries are generated from account-scoped folders.</p></div>`;
    } else if (!summaries.length) {
      caseSummaryList.innerHTML = `<div class="result empty"><h2>No case summary yet</h2><p>Create a folder and run domain, social or wallet investigations inside it.</p></div>`;
    } else {
      caseSummaryList.innerHTML = summaries.map(item => `
        <article class="dossier-card ${scoreTone(item.average_score)}">
          <div>
            <span class="pill">Case summary</span>
            <strong>${escapeHtml(item.name)}</strong>
            <span class="tag">${escapeHtml(item.average_score)}/100 avg</span>
          </div>
          <p>${escapeHtml(item.assets)} assets · ${escapeHtml(item.findings)} findings · ${escapeHtml(item.high_risk)} high-priority assets</p>
          <div class="dossier-meta">
            <span>Domains <strong>${escapeHtml(item.domains)}</strong></span>
            <span>People <strong>${escapeHtml(item.people)}</strong></span>
            <span>Wallets <strong>${escapeHtml(item.wallets)}</strong></span>
            <span>Latest <strong>${escapeHtml(formatDate(item.latest_activity))}</strong></span>
          </div>
          <div class="mini-list">
            ${(item.top_signals || []).map(signal => `<span>${escapeHtml(signal)}</span>`).join("") || "<span>No priority signal yet</span>"}
          </div>
        </article>
      `).join("");
    }
  }
  const select = document.querySelector("#activeFolder");
  if (select) {
    const current = select.value;
    select.innerHTML = folderOptions(current);
  }
  const folderList = document.querySelector("#folderList");
  if (folderList) {
    if (!state.user.authenticated) {
      folderList.innerHTML = `<div class="report-row"><span>Sign in to create agency client folders</span><span></span><span></span><span></span></div>`;
    } else if (!state.folders.length) {
      folderList.innerHTML = `<div class="report-row"><span>No client folders yet</span><span>Create one for each client or investigation.</span><span></span><span></span></div>`;
    } else {
      folderList.innerHTML = state.folders.map(folder => `
        <div class="report-row">
          <strong>${escapeHtml(folder.name)}</strong>
          <span class="tag">${folder.domain_reports} domains · ${folder.social_reports} social · ${folder.wallet_reports} wallets</span>
          <span class="mono">${escapeHtml(formatDate(folder.created_at))}</span>
          <button class="secondary small" type="button" data-delete-folder="${escapeHtml(folder.id)}">Remove</button>
        </div>
      `).join("");
    }
  }
  const playbookList = document.querySelector("#playbookList");
  if (playbookList) {
    if (!state.user.authenticated) {
      playbookList.innerHTML = `<div class="report-row"><span>Sign in to save Web Audit Lab playbooks</span><span></span><span></span><span></span></div>`;
    } else if (!state.playbooks.length) {
      playbookList.innerHTML = `<div class="report-row"><span>No saved playbooks</span><span>Build a Web Audit Lab and save it.</span><span></span><span></span></div>`;
    } else {
      playbookList.innerHTML = state.playbooks.map(item => `
        <div class="report-row">
          <strong>${escapeHtml(item.title)}</strong>
          <span class="tag">${escapeHtml(item.domain)}</span>
          <span class="mono">${escapeHtml(formatDate(item.updated_at))}</span>
          <a class="secondary small button-link" href="/api/reports/${escapeHtml(item.report_id)}/web-audit.csv" data-download>CSV</a>
        </div>
      `).join("");
    }
  }
}

function renderReport(report) {
  const scoreClass = report.score >= 80 ? "" : report.score >= 55 ? "warn" : "bad";
  const cert = report.https?.certificate || {};
  const headers = report.https?.security_headers || [];
  const missingHeaders = headers
    .filter(item => item.assessed !== false && !item.present)
    .map(item => item.name);
  const email = report.email_security || {};
  const flags = email.flags || {};
  const web = report.web_presence || {};
  const rdap = report.rdap || {};
  const ct = report.certificate_transparency || {};
  const advanced = report.advanced_intel || {};
  const dnssec = advanced.dnssec || {};
  const bimi = advanced.bimi || {};
  const wellKnown = advanced.well_known || {};
  const takeoverHints = advanced.takeover_hints || [];
  const subdomains = ct.subdomains || [];
  const tech = report.technology || [];
  const vulns = report.vulnerability_hypotheses || [];
  const redPaths = report.red_team_paths || [];
  const purpleControls = report.purple_team_controls || [];

  document.querySelector("#result").className = "result";
  document.querySelector("#result").innerHTML = `
    <div class="report-top">
      <div>
        <span class="pill">Sellable report</span>
        <h2>${escapeHtml(report.domain)}</h2>
        <p>${escapeHtml(report.summary)}</p>
        <div class="actions">
          <a class="secondary button-link" href="/api/reports/${report.id}/pdf" data-download>Download PDF</a>
          <a class="secondary button-link" href="/api/reports/${report.id}/findings.csv" data-download>Findings CSV</a>
          <a class="secondary button-link" href="/api/reports/${report.id}/html" target="_blank" rel="noreferrer">HTML report</a>
          <button class="secondary" type="button" data-monitor-domain="${escapeHtml(report.domain)}">Monitor domain</button>
        </div>
      </div>
      <div class="score ${scoreClass}">
        <div>
          <span>Score</span>
          <strong>${report.score}</strong>
        </div>
      </div>
    </div>

    <div class="summary-strip">
      <div><strong>${report.dns.addresses?.length || 0}</strong><span>IP</span></div>
      <div><strong>${email.applicable ? email.score ?? 0 : "N/A"}</strong><span>email posture</span></div>
      <div><strong>${subdomains.length}</strong><span>CT names</span></div>
    </div>

    <div class="grid">
      <article class="card">
        <strong>Resolved IPs</strong>
        ${list(report.dns.addresses)}
      </article>
      <article class="card">
        <strong>Mail exchange</strong>
        ${list(report.dns.mx)}
      </article>
      <article class="card">
        <strong>Nameserver</strong>
        ${list(report.dns.ns)}
      </article>
      <article class="card">
        <strong>CAA</strong>
        ${list(report.dns.caa)}
      </article>
      <article class="card">
        <strong>SOA</strong>
        ${list(report.dns.soa)}
      </article>
      <article class="card">
        <strong>TLS certificate</strong>
        <p class="mono">${cert.subject ? escapeHtml(cert.subject) : "not available"}<br>${cert.expires ? `Expires: ${escapeHtml(cert.expires)}` : ""}<br>${cert.days_remaining !== null && cert.days_remaining !== undefined ? `${cert.days_remaining} days remaining` : ""}</p>
      </article>
      <article class="card">
        <strong>HTTP status</strong>
        <p class="mono">${report.https?.status || "not available"} ${escapeHtml(report.https?.server || "")}</p>
      </article>
      <article class="card">
        <strong>Analysis time</strong>
        <p class="mono">${escapeHtml(formatDate(report.generated_at))}</p>
      </article>
    </div>

    <div class="deep-grid">
      <article class="intel-card">
        <div><span class="pill">Email Security</span><strong>${email.applicable ? `${email.score ?? 0}/100` : "N/A"}</strong></div>
        <p>${escapeHtml(email.scope_note || "Email scope could not be determined.")}</p>
        <div class="flag-grid">
          <span>${scopedFlag(flags.spf_present, email.applicable)} SPF</span>
          <span>${scopedFlag(flags.dmarc_present, email.applicable)} DMARC</span>
          <span>${scopedFlag(flags.dmarc_reject || flags.dmarc_quarantine, email.applicable)} Policy strict</span>
          <span>${scopedFlag(flags.mta_sts_present, email.applicable && flags.mx_present)} MTA-STS</span>
          <span>${scopedFlag(flags.tls_rpt_present, email.applicable && flags.mx_present)} TLS-RPT</span>
        </div>
        ${list([...(email.dmarc || []), ...(email.mta_sts || []), ...(email.tls_rpt || [])])}
      </article>

      <article class="intel-card">
        <div><span class="pill">Registry Intel</span><strong>${rdap.available ? "RDAP" : "n/a"}</strong></div>
        <p class="mono">Registrar: ${escapeHtml(rdap.registrar || "not available")}<br>Created: ${escapeHtml(formatDate(rdap.created))}<br>Expires: ${escapeHtml(formatDate(rdap.expires))}</p>
      </article>

      <article class="intel-card">
        <div><span class="pill">Web Exposure</span><strong>${[web.security_txt, web.robots_txt, web.sitemap_xml].filter(item => item?.present).length}/3</strong></div>
        <div class="flag-grid">
          <span>${scopedFlag(web.security_txt?.present, web.security_txt?.available !== false)} security.txt <em>${escapeHtml(probeLabel(web.security_txt))}</em></span>
          <span>${optionalFlag(web.robots_txt?.present, "Public", "Not published")} robots.txt <em>${escapeHtml(probeLabel(web.robots_txt))}</em></span>
          <span>${optionalFlag(web.sitemap_xml?.present, "Public", "Not published")} sitemap.xml <em>${escapeHtml(probeLabel(web.sitemap_xml))}</em></span>
          <span>${scopedFlag(web.mta_sts_policy?.present, email.applicable && flags.mx_present)} mta-sts policy <em>${escapeHtml(probeLabel(web.mta_sts_policy))}</em></span>
        </div>
      </article>

      <article class="intel-card">
        <div><span class="pill">Certificate Transparency</span><strong>${subdomains.length}</strong></div>
        ${list(subdomains.slice(0, 18))}
      </article>

      <article class="intel-card">
        <div><span class="pill">Tech Signals</span><strong>${tech.length}</strong></div>
        ${list(tech)}
      </article>

      <article class="intel-card">
        <div><span class="pill">Advanced OSINT</span><strong>${takeoverHints.length}</strong></div>
        <div class="flag-grid">
          <span>${flag(dnssec.enabled)} DNSSEC <em>${dnssec.score ?? 0}/100</em></span>
          <span>${scopedFlag(bimi.present, email.applicable)} BIMI</span>
          <span>${optionalFlag(wellKnown.change_password?.present)} change-password <em>${escapeHtml(probeLabel(wellKnown.change_password))}</em></span>
          <span>${optionalFlag(wellKnown.openid_configuration?.present)} OpenID config <em>${escapeHtml(probeLabel(wellKnown.openid_configuration))}</em></span>
          <span>${optionalFlag(wellKnown.assetlinks?.present)} Android assetlinks <em>${escapeHtml(probeLabel(wellKnown.assetlinks))}</em></span>
          <span>${optionalFlag(wellKnown.apple_app_site_association?.present)} Apple app association <em>${escapeHtml(probeLabel(wellKnown.apple_app_site_association))}</em></span>
        </div>
        ${takeoverHints.length ? renderOpsRows(takeoverHints, "provider", "subdomain", "cname") : `<span class="mono">no priority SaaS/cloud CNAME observed</span>`}
      </article>

      <article class="intel-card">
        <div><span class="pill">Findings</span><strong>${(report.findings || []).length}</strong></div>
        <div class="findings">${renderFindings(report.findings)}</div>
      </article>
    </div>

    <div class="ops-grid">
      <article class="ops-card priority">
        <div><span class="pill">Possible Vulnerabilities</span><strong>${vulns.length}</strong></div>
        ${renderVulnerabilities(vulns)}
      </article>
      <article class="ops-card">
        <div><span class="pill">Red Team Paths</span><strong>${redPaths.length}</strong></div>
        ${renderOpsRows(redPaths, "name", "objective", "signal")}
      </article>
      <article class="ops-card">
        <div><span class="pill">Purple Team Controls</span><strong>${purpleControls.length}</strong></div>
        ${renderOpsRows(purpleControls, "control", "why", "cadence")}
      </article>
    </div>

    <div class="checks">
      ${headers.map(item => `
        <div class="check">
          ${item.assessed === false ? `<span class="tag neutral">N/A</span>` : `<span class="tag ${item.present ? "" : "missing"}">${item.present ? "OK" : "Missing"}</span>`}
          <span><strong>${escapeHtml(item.name)}</strong><br><span class="mono">${escapeHtml(item.value || item.reason)}</span></span>
        </div>
      `).join("")}
    </div>
  `;
}

function renderReports() {
  const holder = document.querySelector("#reportList");
  if (!state.user.authenticated) {
    holder.innerHTML = `<div class="report-row"><span>Sign in to view your private account history</span><span></span><span></span><span></span></div>`;
    return;
  }
  if (!state.reports.length) {
    holder.innerHTML = `<div class="report-row"><span>No saved reports</span><span></span><span></span><span></span></div>`;
    return;
  }
  holder.innerHTML = state.reports.map(item => `
    <div class="report-row">
      <strong>${escapeHtml(item.domain)}</strong>
      <span class="tag">${item.score}/100</span>
      <span class="mono">${escapeHtml(formatDate(item.generated_at))}</span>
      ${reportActions(item)}
    </div>
  `).join("");
}

function renderSocialReports() {
  const holder = document.querySelector("#socialReportList");
  if (!state.user.authenticated) {
    holder.innerHTML = `<div class="report-row"><span>Sign in to view your social history</span><span></span><span></span><span></span></div>`;
    return;
  }
  if (!state.socialReports.length) {
    holder.innerHTML = `<div class="report-row"><span>No usernames analyzed</span><span></span><span></span><span></span></div>`;
    return;
  }
  holder.innerHTML = state.socialReports.map(item => `
    <div class="report-row">
      <strong>@${escapeHtml(item.username)}</strong>
      <span class="tag">${item.score}/100</span>
      <span class="mono">${escapeHtml(formatDate(item.generated_at))}</span>
      <span></span>
    </div>
  `).join("");
}

function renderSocialReport(report) {
  const found = report.profiles.filter(item => item.present === true);
  const uncertain = report.profiles.filter(item => item.present === null);
  const absent = report.profiles.filter(item => item.present === false);
  document.querySelector("#socialResult").className = "result";
  document.querySelector("#socialResult").innerHTML = `
    <div class="report-top">
      <div>
        <span class="pill">Nickname intelligence</span>
        <h2>@${escapeHtml(report.username)}</h2>
        <p>${escapeHtml(report.summary)}</p>
      </div>
      <div class="score">
        <div><span>Presence</span><strong>${report.score}</strong></div>
      </div>
    </div>

    <div class="summary-strip">
      <div><strong>${found.length}</strong><span>likely profiles</span></div>
      <div><strong>${uncertain.length}</strong><span>uncertain</span></div>
      <div><strong>${absent.length}</strong><span>not observed</span></div>
    </div>

    <div class="social-grid">
      ${report.profiles.map(item => `
        <a class="profile-card" href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer">
          <span class="tag ${item.present ? "" : "missing"}">${item.present === true ? "found" : item.present === null ? "uncertain" : "missing"}</span>
          <strong>${escapeHtml(item.platform)}</strong>
          <span class="mono">HTTP ${escapeHtml(item.status || "n/a")} · ${escapeHtml(item.confidence)}</span>
        </a>
      `).join("")}
    </div>

    <div class="ops-grid social-ops">
      <article class="ops-card">
        <div><span class="pill">Social Findings</span><strong>${report.findings.length}</strong></div>
        ${renderFindings(report.findings)}
      </article>
      <article class="ops-card">
        <div><span class="pill">Red Team Paths</span><strong>${report.red_team_paths.length}</strong></div>
        ${renderOpsRows(report.red_team_paths, "name", "objective", "signal")}
      </article>
      <article class="ops-card">
        <div><span class="pill">Purple Controls</span><strong>${report.purple_team_controls.length}</strong></div>
        ${renderOpsRows(report.purple_team_controls, "control", "why", "cadence")}
      </article>
    </div>
  `;
}

function renderWalletReports() {
  const holder = document.querySelector("#walletReportList");
  if (!holder) return;
  if (!state.user.authenticated) {
    holder.innerHTML = `<div class="report-row"><span>Sign in to save and view wallet history</span><span></span><span></span><span></span></div>`;
    return;
  }
  if (!state.walletReports.length) {
    holder.innerHTML = `<div class="report-row"><span>No wallets analyzed</span><span></span><span></span><span></span></div>`;
    return;
  }
  holder.innerHTML = state.walletReports.map(item => `
    <div class="report-row">
      <strong>${escapeHtml(item.address)}</strong>
      <span class="tag ${item.risk_score >= 65 ? "missing" : ""}">${escapeHtml(item.chain)} · ${item.risk_score}/100</span>
      <span class="mono">${escapeHtml(formatDate(item.generated_at))}</span>
      <span></span>
    </div>
  `).join("");
}

function renderWalletReport(report) {
  const counterparties = report.counterparties || [];
  const transactions = report.transactions || [];
  const findings = report.findings || [];
  state.currentWallet = { chain: report.chain, address: report.address };
  document.querySelector("#walletResult").className = "result";
  document.querySelector("#walletResult").innerHTML = `
    <div class="report-top">
      <div>
        <span class="pill">Blockchain report</span>
        <h2>${escapeHtml(report.address)}</h2>
        <p>${escapeHtml(report.summary)}</p>
        <div class="actions">
          <a class="secondary button-link" href="${escapeHtml(report.explorer_url)}" target="_blank" rel="noreferrer">Open explorer</a>
          <button class="secondary" type="button" data-section-jump="schema">View in graph</button>
        </div>
      </div>
      <div class="score ${report.risk_score >= 65 ? "bad" : report.risk_score >= 35 ? "warn" : ""}">
        <div><span>Risk</span><strong>${report.risk_score}</strong></div>
      </div>
    </div>

    <div class="summary-strip">
      <div><strong>${escapeHtml(report.balance ?? "n/a")}</strong><span>${escapeHtml(report.asset || report.chain)}</span></div>
      <div><strong>${escapeHtml(report.tx_count ?? transactions.length)}</strong><span>observed tx</span></div>
      <div><strong>${counterparties.length}</strong><span>counterparties</span></div>
    </div>

    <div class="ops-grid wallet-ops">
      <article class="ops-card priority">
        <div><span class="pill">Findings</span><strong>${findings.length}</strong></div>
        ${renderFindings(findings)}
      </article>
      <article class="ops-card">
        <div><span class="pill">Top counterparties</span><strong>${counterparties.length}</strong></div>
        ${counterparties.map(item => `
          <div class="ops-row">
            <strong>${escapeHtml(item.short || item.address)}</strong>
            <p>${escapeHtml(item.direction)} · ${escapeHtml(item.tx_count)} tx · ${escapeHtml(item.total_value)} ${escapeHtml(report.asset || "")}</p>
            <small>${escapeHtml((item.labels || []).join(", ") || item.address)}</small>
            <button class="secondary small" type="button" data-expand-wallet="${escapeHtml(item.address)}">Expand</button>
          </div>
        `).join("") || `<div class="ops-row"><strong>No counterparties</strong><p>No relationship in the recent window.</p></div>`}
      </article>
      <article class="ops-card">
        <div><span class="pill">Reconstruction</span><strong>${(report.reconstruction_notes || []).length}</strong></div>
        ${(report.reconstruction_notes || []).map(note => `
          <div class="ops-row"><strong>Next step</strong><p>${escapeHtml(note)}</p></div>
        `).join("")}
      </article>
    </div>

    <section class="lab-panel wallet-notes-panel">
      <div class="mini-head">
        <span class="pill">Case notes</span>
        <h3>Manual tags and notes</h3>
      </div>
      <form id="walletAnnotationForm" class="auth-form">
        <label for="walletTags">Tags</label>
        <input id="walletTags" type="text" placeholder="exchange, victim, scam, bridge, mixer, service" spellcheck="false">
        <label for="walletNotes">Notes</label>
        <textarea id="walletNotes" rows="4" placeholder="Case notes, evidence links, hypothesis and next passive checks"></textarea>
        <button class="secondary" type="submit">Save wallet notes</button>
      </form>
    </section>

    <div class="checks">
      ${transactions.map(tx => `
        <a class="check wallet-tx" href="${escapeHtml(tx.url)}" target="_blank" rel="noreferrer">
          <span class="tag ${tx.direction === "outgoing" ? "missing" : ""}">${escapeHtml(tx.direction)}</span>
          <span><strong>${escapeHtml(tx.short || tx.hash)}</strong><br><span class="mono">${escapeHtml(tx.value)} ${escapeHtml(report.asset || "")} · fee ${escapeHtml(tx.fee ?? "n/a")} · ${escapeHtml(formatDate(tx.timestamp))}</span></span>
        </a>
      `).join("") || `<div class="check"><span class="tag">n/a</span><span>No recent transactions from the public source.</span></div>`}
    </div>
  `;
}

function renderMonitors() {
  const holder = document.querySelector("#monitorList");
  updateAccount();
  if (!state.monitors.length) {
    holder.innerHTML = `<div class="monitor-row"><span>No monitored domains</span><span></span><span></span><span></span></div>`;
    return;
  }
  holder.innerHTML = state.monitors.map(item => `
    <div class="monitor-row">
      <strong>${escapeHtml(item.domain)}</strong>
      <span class="tag ${item.status === "changed" ? "missing" : ""}">${escapeHtml(item.status)}</span>
      <span class="mono">${item.last_score === null ? "not yet" : `${item.last_score}/100`}<br>${escapeHtml(formatDate(item.last_checked_at))}</span>
      <button class="secondary small" type="button" data-remove-monitor="${escapeHtml(item.id)}">Remove</button>
    </div>
  `).join("");
}

function scoreTone(score) {
  if (score >= 80) return "ok";
  if (score >= 55) return "warn";
  return "bad";
}

function nodeColor(type) {
  return {
    site: "#c44536",
    person: "#234757",
    profile: "#5e655f",
    ip: "#4a8a5c",
    nameserver: "#4a8a5c",
    mail: "#ffbd59",
    email: "#ffbd59",
    wallet: "#4a8a5c",
    counterparty: "#234757",
    transaction: "#ffbd59",
    registry: "#5e655f",
    technology: "#6f4c0f",
    subdomain: "#234757",
    folder: "#ffbd59",
    tag: "#5e655f",
    risk: "#ff5d6c",
    finding: "#ffbd59"
  }[type] || "#0d1117";
}

function renderGraph(nodes = [], edges = []) {
  if (!nodes.length) {
    return `<div class="graph-empty"><strong>No nodes</strong><span>Generate domain, social or wallet reports to populate the graph.</span></div>`;
  }
  const width = 920;
  const height = 520;
  const centerX = width / 2;
  const centerY = height / 2;
  const roots = nodes.filter(node => node.type === "site" || node.type === "person");
  const others = nodes.filter(node => node.type !== "site" && node.type !== "person");
  const ordered = [...roots, ...others];
  const positions = new Map();

  ordered.forEach((node, index) => {
    const isRoot = node.type === "site" || node.type === "person";
    const ring = isRoot ? 112 : 210 + ((index % 3) * 36);
    const angle = (Math.PI * 2 * index) / Math.max(ordered.length, 1) - Math.PI / 2;
    positions.set(node.id, {
      x: Math.round(centerX + Math.cos(angle) * ring),
      y: Math.round(centerY + Math.sin(angle) * ring)
    });
  });

  const edgeMarkup = edges.map(edge => {
    const a = positions.get(edge.from);
    const b = positions.get(edge.to);
    if (!a || !b) return "";
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="graph-edge ${escapeHtml(edge.kind)}"><title>${escapeHtml(edge.label)}</title></line>`;
  }).join("");

  const nodeMarkup = ordered.map(node => {
    const pos = positions.get(node.id);
    const radius = node.type === "site" || node.type === "person" ? 20 : 12;
    const label = node.label.length > 24 ? `${node.label.slice(0, 21)}...` : node.label;
    return `
      <g class="graph-node ${escapeHtml(node.type)}">
        <circle cx="${pos.x}" cy="${pos.y}" r="${radius}" fill="${nodeColor(node.type)}">
          <title>${escapeHtml(node.label)} · ${escapeHtml(node.type)} ${node.score !== null && node.score !== undefined ? `· ${node.score}/100` : ""}</title>
        </circle>
        <text x="${pos.x}" y="${pos.y + radius + 16}" text-anchor="middle">${escapeHtml(label)}</text>
      </g>
    `;
  }).join("");

  return `
    <svg class="entity-graph" viewBox="0 0 ${width} ${height}" role="img" aria-label="OSINT graph of collected data">
      <rect width="${width}" height="${height}" rx="10"></rect>
      ${edgeMarkup}
      ${nodeMarkup}
    </svg>
  `;
}

function renderDossierCard(item, type) {
  if (type === "wallet") {
    return `
      <article class="dossier-card ${scoreTone(100 - item.risk_score)}">
        <div>
          <span class="pill">Wallet dossier</span>
          <strong>${escapeHtml(item.short || item.address)}</strong>
          <span class="tag ${item.risk_score >= 65 ? "missing" : ""}">risk ${item.risk_score}/100</span>
        </div>
        <p>${escapeHtml(item.summary)}</p>
        <div class="dossier-meta">
          <span>Chain <strong>${escapeHtml(item.chain)}</strong></span>
          <span>Balance <strong>${escapeHtml(item.balance ?? "n/a")} ${escapeHtml(item.asset || "")}</strong></span>
          <span>Tx <strong>${escapeHtml(item.tx_count ?? "n/a")}</strong></span>
          <span>Counterparties <strong>${(item.counterparties || []).length}</strong></span>
        </div>
        <div class="mini-list">
          ${(item.findings || []).slice(0, 3).map(finding => `<span>${escapeHtml(finding.title || "finding")}</span>`).join("") || "<span>No priority finding</span>"}
        </div>
        <div class="mini-list">
          ${(item.annotation?.tags || []).map(tag => `<span>#${escapeHtml(tag)}</span>`).join("") || "<span>No manual tag</span>"}
          ${item.annotation?.notes ? `<span>${escapeHtml(item.annotation.notes.slice(0, 120))}</span>` : ""}
        </div>
        <div class="timeline-list">
          ${(item.timeline || []).slice(0, 4).map(tx => `
            <a href="${escapeHtml(tx.url || "#")}" target="_blank" rel="noreferrer">
              <strong>${escapeHtml(tx.direction || "tx")}</strong>
              <span>${escapeHtml(tx.value ?? "n/a")} ${escapeHtml(item.asset || "")}</span>
              <small>${escapeHtml(formatDate(tx.timestamp))} · ${escapeHtml(tx.short || "")}</small>
            </a>
          `).join("") || "<span class=\"mono\">No transaction timeline from source.</span>"}
        </div>
        ${item.explorer_url ? `<a class="secondary button-link small" href="${escapeHtml(item.explorer_url)}" target="_blank" rel="noreferrer">Open explorer</a>` : ""}
      </article>
    `;
  }
  if (type === "site") {
    return `
      <article class="dossier-card ${scoreTone(item.score)}">
        <div>
          <span class="pill">Site dossier</span>
          <strong>${escapeHtml(item.domain)}</strong>
          <span class="tag">${item.score}/100</span>
        </div>
        <p>${escapeHtml(item.summary)}</p>
        <div class="dossier-meta">
          <span>Registrar <strong>${escapeHtml(item.registrar)}</strong></span>
          <span>IP <strong>${(item.ips || []).length}</strong></span>
          <span>MX <strong>${(item.mx || []).length}</strong></span>
          <span>CT names <strong>${(item.subdomains || []).length}</strong></span>
          <span>Monitor <strong>${item.monitored ? "active" : "off"}</strong></span>
        </div>
        <div class="mini-list">
          ${(item.findings || []).slice(0, 3).map(finding => `<span>${escapeHtml(finding.title || "finding")}</span>`).join("") || "<span>No priority finding</span>"}
        </div>
      </article>
    `;
  }
  return `
    <article class="dossier-card ${scoreTone(item.score)}">
      <div>
        <span class="pill">Person dossier</span>
        <strong>@${escapeHtml(item.username)}</strong>
        <span class="tag">${item.score}/100</span>
      </div>
      <p>${escapeHtml(item.summary)}</p>
      <div class="dossier-meta">
        <span>Profiles <strong>${item.profiles_found}</strong></span>
        <span>Last check <strong>${escapeHtml(formatDate(item.generated_at))}</strong></span>
      </div>
      <div class="mini-list">
        ${(item.profiles || []).slice(0, 5).map(profile => `<span>${escapeHtml(profile.platform)} · ${escapeHtml(profile.confidence)}</span>`).join("") || "<span>No confirmed profile</span>"}
      </div>
    </article>
  `;
}

function renderWorkspace() {
  const schemaHolder = document.querySelector("#schemaResult");
  const walletResultHolder = document.querySelector("#walletResult");
  const data = state.workspace;
  if (!data || !data.authenticated) {
    schemaHolder.innerHTML = `<div class="result empty"><h2>Sign in to build the graph</h2><p>The graph only uses reports and history from your account.</p></div>`;
    if (walletResultHolder?.classList.contains("empty")) {
      walletResultHolder.innerHTML = `<h2>Private wallet history</h2><p>Login is required to save reconstructions and wallet history.</p>`;
    }
    return;
  }

  const sites = data.dossiers?.sites || [];
  const people = data.dossiers?.people || [];
  const wallets = data.dossiers?.wallets || [];
  const filter = state.graphFilter || "all";
  const sourceNodes = data.nodes || [];
  const sourceEdges = data.edges || [];
  const visibleNodes = filter === "all"
    ? sourceNodes
    : sourceNodes.filter(node => {
      if (filter === "risk") return ["risk", "finding", "tag"].includes(node.type);
      if (filter === "wallet") return ["wallet", "counterparty", "transaction", "tag", "finding"].includes(node.type);
      if (filter === "site") return ["site", "ip", "nameserver", "mail", "email", "registry", "technology", "subdomain", "risk", "finding"].includes(node.type);
      if (filter === "person") return ["person", "profile", "finding"].includes(node.type);
      return true;
    });
  const visibleIds = new Set(visibleNodes.map(node => node.id));
  const visibleEdges = sourceEdges.filter(edge => visibleIds.has(edge.from) && visibleIds.has(edge.to));
  const visibleSites = filter === "all" || filter === "site" || filter === "risk" ? sites : [];
  const visiblePeople = filter === "all" || filter === "person" || filter === "risk" ? people : [];
  const visibleWallets = filter === "all" || filter === "wallet" || filter === "risk" ? wallets : [];
  state.folders = data.folders || state.folders;
  state.playbooks = data.playbooks || state.playbooks;
  const wallet = data.wallet || {};
  schemaHolder.innerHTML = `
    <div class="schema-grid">
      <article class="graph-panel">
        ${renderGraph(visibleNodes, visibleEdges)}
      </article>
      <aside class="schema-summary">
        <article><span>Filter</span><strong>${escapeHtml(filter)}</strong></article>
        <article><span>Nodes</span><strong>${visibleNodes.length}</strong></article>
        <article><span>Edges</span><strong>${visibleEdges.length}</strong></article>
        <article><span>Sites</span><strong>${visibleSites.length}</strong></article>
        <article><span>People</span><strong>${visiblePeople.length}</strong></article>
        <article><span>Wallet</span><strong>${visibleWallets.length}</strong></article>
      </aside>
    </div>
    <div class="dossier-grid">
      ${visibleSites.map(item => renderDossierCard(item, "site")).join("")}
      ${visiblePeople.map(item => renderDossierCard(item, "person")).join("")}
      ${visibleWallets.map(item => renderDossierCard(item, "wallet")).join("")}
      ${!visibleSites.length && !visiblePeople.length && !visibleWallets.length ? `<div class="result empty"><h2>No dossier for this filter</h2><p>Switch graph filter or generate more reports.</p></div>` : ""}
    </div>
  `;

  const creditLabel = wallet.plan === "Free" && wallet.credits !== null ? wallet.credits : "∞";
  renderFolders();
  renderWalletReports();
  const walletStats = document.querySelector("#walletResult");
  if (walletStats && walletStats.classList.contains("empty")) {
    walletStats.innerHTML = `
    <div class="wallet-grid">
      <article class="wallet-card hero-wallet">
        <span class="pill">Current plan</span>
        <strong>${escapeHtml(wallet.plan || "Free")}</strong>
        <p>Credits: <b>${escapeHtml(creditLabel)}</b>. Wallet report: <b>${wallet.wallet_reports || 0}</b>. Domain monitors: <b>${wallet.monitor_used || 0}/${wallet.monitor_limit ?? 0}</b>.</p>
      </article>
      <article class="wallet-card"><span>Exposure index</span><strong>${wallet.exposure_index || 0}/100</strong><p>Average score across collected assets.</p></article>
      <article class="wallet-card"><span>Domain report</span><strong>${wallet.domain_reports || 0}</strong><p>Analyzed sites and brands.</p></article>
      <article class="wallet-card"><span>Wallet report</span><strong>${wallet.wallet_reports || 0}</strong><p>Traced blockchain addresses.</p></article>
    </div>
    `;
  }
}

async function loadWorkspace() {
  const data = await api("/api/intel/workspace");
  state.workspace = data;
  renderWorkspace();
  updateDashboard();
}

function showBillingMessage(message) {
  const box = document.querySelector("#billingMessage");
  box.textContent = message;
  box.classList.add("visible");
}

function featureEnabled(name) {
  const feature = state.featureFlags?.[name];
  return !feature || feature.allowed;
}

function maybeShowUpsell() {
  if (!state.metrics || state.user.plan !== "Free") return;
  const suggestion = (state.metrics.upsell || []).find(item => !state.shownUpsells.has(item.feature));
  if (!suggestion) return;
  state.shownUpsells.add(suggestion.feature);
  showBillingMessage(`${suggestion.message} Upgrade to ${suggestion.plan} when you are ready.`);
}

async function loadFeatureFlags() {
  try {
    const data = await api("/api/feature-flags");
    state.featureFlags = data.features || {};
  } catch {
    state.featureFlags = {};
  }
}

async function loadMetrics() {
  if (!state.user.authenticated) {
    state.metrics = null;
    return;
  }
  try {
    state.metrics = await api("/api/metrics");
    maybeShowUpsell();
  } catch {
    state.metrics = null;
  }
}

function showAccountMessage(message, isError = false) {
  const box = document.querySelector("#accountMessage");
  box.textContent = message;
  box.classList.add("visible");
  box.classList.toggle("error", isError);
}

function showApiKeyMessage(message, isError = false) {
  const box = document.querySelector("#apiKeyMessage");
  if (!box) return;
  box.textContent = message;
  box.classList.add("visible");
  box.classList.toggle("error", isError);
}

function renderApiKeys() {
  const holder = document.querySelector("#apiKeyList");
  if (!holder) return;
  const keys = state.apiKeys || [];
  if (!["Agency", "Admin"].includes(state.user.plan)) {
    holder.innerHTML = `<div class="empty">API keys are available on Agency accounts. Upgrade when you need workflow integrations.</div>`;
    return;
  }
  holder.innerHTML = keys.length ? `
    <div class="admin-row header">
      <span>Name</span><span>Prefix</span><span>Created</span><span>Last used</span><span>Action</span>
    </div>
    ${keys.map(item => `
      <div class="admin-row">
        <span>${escapeHtml(item.name)}</span>
        <span>${escapeHtml(item.prefix)}</span>
        <span>${escapeHtml(formatDate(item.created_at))}</span>
        <span>${escapeHtml(item.last_used_at ? formatDate(item.last_used_at) : "Never")}</span>
        <span>${item.revoked_at ? "Revoked" : `<button class="secondary small" type="button" data-revoke-api-key="${escapeHtml(item.id)}">Revoke</button>`}</span>
      </div>
    `).join("")}
  ` : `<div class="empty">No API keys yet.</div>`;
}

async function loadApiKeys() {
  if (!["Agency", "Admin"].includes(state.user.plan)) {
    renderApiKeys();
    return;
  }
  try {
    const data = await api("/api/api-keys");
    state.apiKeys = data.api_keys || [];
    renderApiKeys();
  } catch (error) {
    showApiKeyMessage(error.message, true);
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error || "Request failed");
    error.status = response.status;
    throw error;
  }
  return data;
}

function trackEvent(event, { plan = null, source = "app", metadata = {} } = {}) {
  fetch("/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event, plan, source, metadata })
  }).catch(() => {});
}

async function loadSession() {
  const data = await api("/api/session");
  state.user = data.user;
  state.reports = data.reports;
  state.socialReports = data.social_reports;
  state.walletReports = data.wallet_reports || [];
  state.monitors = data.monitors;
  state.folders = data.folders || [];
  state.playbooks = data.playbooks || [];
  state.checkoutConfigured = data.checkout_configured;
  await loadFeatureFlags();
  await loadMetrics();
  updateAccount();
  renderFolders();
  renderReports();
  renderSocialReports();
  renderWalletReports();
  renderMonitors();
  await loadWorkspace();
}

async function checkApi() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    document.querySelector("#apiStatus").textContent = data.ok ? "online" : "offline";
  } catch {
    document.querySelector("#apiStatus").textContent = "offline";
  }
}

async function analyze(target) {
  if (freeCreditsExhausted()) {
    setSection("billing");
    trackEvent("free_credits_exhausted", { plan: "Pro", source: "domain_intel", metadata: { current_plan: state.user.plan } });
    showBillingMessage("You have used all Free credits. Upgrade to Pro to continue.");
    return;
  }

  const button = document.querySelector("#scanButton");
  button.disabled = true;
  button.textContent = "Analyzing...";
  setLiveSignal(`collecting passive intel for ${target}`);
  document.querySelector("#result").className = "result empty";
  document.querySelector("#result").innerHTML = `<h2>Analysis in progress</h2><p>Querying passive sources from the backend.</p>`;

  try {
    const data = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ target, folder_id: activeFolderId() })
    });

    state.user = data.user;
    state.reports.unshift({
      id: data.report.id,
      domain: data.report.domain,
      score: data.report.score,
      summary: data.report.summary,
      generated_at: data.report.generated_at
    });
    state.reports = state.reports.slice(0, 50);
    updateAccount();
    renderReport(data.report);
    renderReports();
    await loadWorkspace();
  } catch (error) {
    document.querySelector("#result").className = "result empty";
    document.querySelector("#result").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Run intel";
    setLiveSignal("passive sensors idle");
  }
}

async function buildWebAuditLab(target) {
  if (freeCreditsExhausted()) {
    setSection("billing");
    trackEvent("free_credits_exhausted", { plan: "Pro", source: "web_audit_lab", metadata: { current_plan: state.user.plan } });
    showBillingMessage("You have used all Free credits. Web Audit Lab continues on Pro/Agency.");
    return;
  }

  const button = document.querySelector("#webAuditButton");
  button.disabled = true;
  button.textContent = "Building...";
  setLiveSignal(`building beginner web audit lab for ${target}`);
  document.querySelector("#webAuditResult").className = "result empty";
  document.querySelector("#webAuditResult").innerHTML = `<h2>Building Web Audit Lab</h2><p>Collecting passive evidence and converting it into a beginner-friendly workflow.</p>`;

  try {
    const data = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ target, folder_id: activeFolderId() })
    });
    state.user = data.user;
    state.reports.unshift({
      id: data.report.id,
      domain: data.report.domain,
      score: data.report.score,
      summary: data.report.summary,
      generated_at: data.report.generated_at
    });
    state.reports = state.reports.slice(0, 50);
    updateAccount();
    renderWebAuditLab(data.report);
    renderReports();
    await loadWorkspace();
  } catch (error) {
    document.querySelector("#webAuditResult").className = "result empty";
    document.querySelector("#webAuditResult").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Build lab";
    setLiveSignal("passive sensors idle");
  }
}

async function buildNetworkLab(target) {
  if (freeCreditsExhausted()) {
    setSection("billing");
    trackEvent("free_credits_exhausted", { plan: "Pro", source: "network_lab", metadata: { current_plan: state.user.plan } });
    showBillingMessage("You have used all Free credits. Network Traffic Lab continues on Pro/Agency.");
    return;
  }

  const button = document.querySelector("#networkLabButton");
  button.disabled = true;
  button.textContent = "Building...";
  setLiveSignal(`building readable network traffic view for ${target}`);
  document.querySelector("#networkLabResult").className = "result empty";
  document.querySelector("#networkLabResult").innerHTML = `<h2>Building Network Traffic Lab</h2><p>Converting DNS, TLS and HTTP evidence into a Wireshark-style packet timeline.</p>`;

  try {
    const data = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ target, folder_id: activeFolderId() })
    });
    state.user = data.user;
    state.reports.unshift({
      id: data.report.id,
      domain: data.report.domain,
      score: data.report.score,
      summary: data.report.summary,
      generated_at: data.report.generated_at
    });
    state.reports = state.reports.slice(0, 50);
    updateAccount();
    renderNetworkLab(data.report);
    renderReports();
    await loadWorkspace();
  } catch (error) {
    document.querySelector("#networkLabResult").className = "result empty";
    document.querySelector("#networkLabResult").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Build traffic view";
    setLiveSignal("passive sensors idle");
  }
}

async function buildLocalNetworkLab() {
  const button = document.querySelector("#localNetworkButton");
  button.disabled = true;
  button.textContent = "Building...";
  setLiveSignal("building own-network traffic view");
  document.querySelector("#networkLabResult").className = "result empty";
  document.querySelector("#networkLabResult").innerHTML = `<h2>Building Own Network Lab</h2><p>Reading safe local runtime network context.</p>`;
  try {
    const data = await api("/api/network/local");
    renderLocalNetworkLab(data);
  } catch (error) {
    document.querySelector("#networkLabResult").className = "result empty";
    document.querySelector("#networkLabResult").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Build own-network view";
    setLiveSignal("passive sensors idle");
  }
}

async function analyzeSocial(username) {
  if (freeCreditsExhausted()) {
    setSection("billing");
    trackEvent("free_credits_exhausted", { plan: "Pro", source: "social_intel", metadata: { current_plan: state.user.plan } });
    showBillingMessage("You have used all Free credits. Social OSINT continues on Pro/Agency.");
    return;
  }
  const button = document.querySelector("#socialButton");
  button.disabled = true;
  button.textContent = "Searching...";
  setLiveSignal(`probing public handles for ${username}`);
  document.querySelector("#socialResult").className = "result empty";
  document.querySelector("#socialResult").innerHTML = `<h2>Social lookup in progress</h2><p>Checking public profiles and impersonation signals.</p>`;
  try {
    const data = await api("/api/social/analyze", {
      method: "POST",
      body: JSON.stringify({ username, folder_id: activeFolderId() })
    });
    state.user = data.user;
    state.socialReports.unshift({
      id: data.report.id,
      username: data.report.username,
      score: data.report.score,
      summary: data.report.summary,
      generated_at: data.report.generated_at
    });
    state.socialReports = state.socialReports.slice(0, 50);
    updateAccount();
    renderSocialReport(data.report);
    renderSocialReports();
    await loadWorkspace();
  } catch (error) {
    document.querySelector("#socialResult").className = "result empty";
    document.querySelector("#socialResult").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Run social OSINT";
    setLiveSignal("passive sensors idle");
  }
}

async function analyzeWallet(address) {
  if (freeCreditsExhausted()) {
    setSection("billing");
    trackEvent("free_credits_exhausted", { plan: "Pro", source: "wallet_trace", metadata: { current_plan: state.user.plan } });
    showBillingMessage("You have used all Free credits. Wallet OSINT continues on Pro/Agency.");
    return;
  }
  const button = document.querySelector("#walletButton");
  button.disabled = true;
  button.textContent = "Tracing...";
  setLiveSignal(`tracing public blockchain wallet ${address}`);
  document.querySelector("#walletResult").className = "result empty";
  document.querySelector("#walletResult").innerHTML = `<h2>Wallet reconstruction running</h2><p>Reading public blockchain sources and preparing the counterparty graph.</p>`;
  try {
    const data = await api("/api/wallet/analyze", {
      method: "POST",
      body: JSON.stringify({ address, folder_id: activeFolderId() })
    });
    state.user = data.user;
    state.walletReports.unshift({
      id: data.report.id,
      chain: data.report.chain,
      address: data.report.address,
      risk_score: data.report.risk_score,
      summary: data.report.summary,
      generated_at: data.report.generated_at
    });
    state.walletReports = state.walletReports.slice(0, 50);
    updateAccount();
    renderWalletReport(data.report);
    renderWalletReports();
    await loadWorkspace();
  } catch (error) {
    document.querySelector("#walletResult").className = "result empty";
    document.querySelector("#walletResult").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Trace wallet";
    setLiveSignal("passive sensors idle");
  }
}

async function addMonitor(domain) {
  try {
    const data = await api("/api/monitors", {
      method: "POST",
      body: JSON.stringify({ domain, folder_id: activeFolderId() })
    });
    state.monitors = data.monitors;
    renderMonitors();
    await loadWorkspace();
    setSection("monitoring");
  } catch (error) {
    if (error.status === 401) {
      setSection("account");
      showAccountMessage(error.message, true);
      return;
    }
    setSection("billing");
    trackEvent("monitor_limit_hit", { plan: "Pro", source: "monitoring", metadata: { current_plan: state.user.plan } });
    showBillingMessage(error.message);
  }
}

async function checkout(plan) {
  try {
    trackEvent("checkout_click", { plan, source: "pricing_card" });
    const data = await api("/api/billing/checkout", {
      method: "POST",
      body: JSON.stringify({ plan })
    });
    if (data.url) {
      trackEvent("checkout_redirect_client", { plan, source: "stripe" });
      showBillingMessage("Secure redirect to Stripe...");
      window.location.href = data.url;
      return;
    }
    showBillingMessage(data.message);
  } catch (error) {
    if (error.status === 401) {
      setSection("account");
      showAccountMessage("Create an account or sign in before buying Pro/Agency.", true);
      return;
    }
    showBillingMessage(error.message);
  }
}

document.querySelectorAll(".nav-btn").forEach(button => {
  button.addEventListener("click", () => setSection(button.dataset.section));
});

document.querySelector("#mobileMenuButton")?.addEventListener("click", toggleMobileNavigation);

document.addEventListener("keydown", event => {
  if (event.key === "Escape") closeMobileNavigation();
});

window.addEventListener("resize", () => {
  if (window.innerWidth > 640) closeMobileNavigation();
});

document.querySelector("#scanForm").addEventListener("submit", event => {
  event.preventDefault();
  const target = document.querySelector("#target").value.trim();
  if (!target) {
    document.querySelector("#target").focus();
    return;
  }
  analyze(target);
});

document.querySelector("#socialForm").addEventListener("submit", event => {
  event.preventDefault();
  const username = document.querySelector("#username").value.trim();
  if (!username) {
    document.querySelector("#username").focus();
    return;
  }
  analyzeSocial(username);
});

document.querySelector("#webAuditForm").addEventListener("submit", event => {
  event.preventDefault();
  const target = document.querySelector("#webAuditTarget").value.trim();
  if (!target) {
    document.querySelector("#webAuditTarget").focus();
    return;
  }
  buildWebAuditLab(target);
});

document.querySelector("#repoAuditFiles").addEventListener("change", event => {
  const files = [...event.target.files];
  const eligible = files.filter(repositoryFileAllowed);
  const root = String(files[0]?.webkitRelativePath || "").split("/")[0];
  if (root && !document.querySelector("#repoAuditName").value) {
    document.querySelector("#repoAuditName").value = root;
  }
  document.querySelector("#repoAuditSelection").textContent = files.length
    ? `${eligible.length} eligible text files selected from ${files.length} files.`
    : "No folder selected.";
});

document.querySelector("#repoAuditForm").addEventListener("submit", async event => {
  event.preventDefault();
  const fileInput = document.querySelector("#repoAuditFiles");
  const button = document.querySelector("#repoAuditButton");
  if (!fileInput.files.length) {
    fileInput.focus();
    return;
  }
  button.disabled = true;
  button.textContent = "Auditing...";
  setLiveSignal("reviewing repository source without executing it");
  document.querySelector("#repoAuditResult").className = "result empty";
  document.querySelector("#repoAuditResult").innerHTML = `<h2>Repository audit in progress</h2><p>Filtering source files and checking defensive static-analysis rules.</p>`;
  try {
    await buildRepoAudit(fileInput.files, document.querySelector("#repoAuditName").value.trim());
  } catch (error) {
    document.querySelector("#repoAuditResult").className = "result empty";
    document.querySelector("#repoAuditResult").innerHTML = `<h2 class="error">Audit failed</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Audit repository";
    setLiveSignal("passive sensors idle");
  }
});

document.querySelector("#downloadRepoAudit").addEventListener("click", () => {
  const link = document.querySelector("#downloadRepoAudit");
  if (link?.getAttribute("href") && link.getAttribute("href") !== "#") return;
  if (!state.currentRepoAudit) return;
  const blob = new Blob([JSON.stringify(state.currentRepoAudit, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${String(state.currentRepoAudit.repository || "repository").replace(/[^a-z0-9_-]+/gi, "-").toLowerCase()}-audit.json`;
  anchor.click();
  URL.revokeObjectURL(url);
});

document.querySelector("#loadOwnAudit").addEventListener("click", () => {
  document.querySelector("#webAuditTarget").value = "osintpro-48j4.onrender.com";
  buildWebAuditLab("osintpro-48j4.onrender.com");
});

document.querySelector("#networkLabForm").addEventListener("submit", event => {
  event.preventDefault();
  const target = document.querySelector("#networkLabTarget").value.trim();
  if (!target) {
    document.querySelector("#networkLabTarget").focus();
    return;
  }
  buildNetworkLab(target);
});

document.querySelector("#loadOwnNetworkLab").addEventListener("click", () => {
  document.querySelector("#networkLabTarget").value = "osintpro-48j4.onrender.com";
  setNetworkMode("website");
  buildNetworkLab("osintpro-48j4.onrender.com");
});

document.querySelectorAll("[data-network-mode]").forEach(button => {
  button.addEventListener("click", () => setNetworkMode(button.dataset.networkMode));
});

document.querySelector("#localNetworkButton").addEventListener("click", buildLocalNetworkLab);

document.querySelector("#gameSecurityForm").addEventListener("submit", event => {
  event.preventDefault();
  renderGameSecurityLab();
});

document.querySelector("#walletForm").addEventListener("submit", event => {
  event.preventDefault();
  const address = document.querySelector("#walletAddress").value.trim();
  if (!address) {
    document.querySelector("#walletAddress").focus();
    return;
  }
  analyzeWallet(address);
});

document.querySelector("#folderForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const data = await api("/api/client-folders", {
      method: "POST",
      body: JSON.stringify({ name: document.querySelector("#folderName").value })
    });
    state.folders = data.folders;
    document.querySelector("#folderName").value = "";
    renderFolders();
    showAccountMessage("Client folder created.");
  } catch (error) {
    showAccountMessage(error.message, true);
  }
});

async function logout() {
  await api("/api/auth/logout", { method: "POST" });
  window.location.reload();
}

document.querySelector("#logoutButton").addEventListener("click", logout);
document.querySelector("#chipLogoutButton").addEventListener("click", logout);

document.querySelector("#monitorForm").addEventListener("submit", event => {
  event.preventDefault();
  const domain = document.querySelector("#monitorDomain").value.trim();
  if (!domain) return;
  addMonitor(domain);
});

document.querySelectorAll("[data-example]").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelector("#target").value = button.dataset.example;
    analyze(button.dataset.example);
  });
});

document.addEventListener("click", async event => {
  const download = event.target.closest("[data-download]");
  if (download) {
    event.preventDefault();
    await downloadExport(download.href, download.getAttribute("download") || "osintpro-export");
    return;
  }

  const monitorDomain = event.target.closest("[data-monitor-domain]");
  if (monitorDomain) {
    await addMonitor(monitorDomain.dataset.monitorDomain);
    return;
  }

  const removeMonitor = event.target.closest("[data-remove-monitor]");
  if (removeMonitor) {
    const data = await api(`/api/monitors/${removeMonitor.dataset.removeMonitor}`, { method: "DELETE" });
    state.monitors = data.monitors;
    renderMonitors();
  }

  const deleteFolder = event.target.closest("[data-delete-folder]");
  if (deleteFolder) {
    const data = await api(`/api/client-folders/${deleteFolder.dataset.deleteFolder}`, { method: "DELETE" });
    state.folders = data.folders;
    renderFolders();
    await loadWorkspace();
    return;
  }

  const savePlaybook = event.target.closest("[data-save-playbook]");
  if (savePlaybook) {
    const data = await api("/api/web-audit/playbooks", {
      method: "POST",
      body: JSON.stringify({ report_id: savePlaybook.dataset.savePlaybook })
    });
    state.playbooks = data.playbooks;
    renderFolders();
    showBillingMessage("Web Audit Lab playbook saved in Cases.");
    return;
  }

  const compareDomain = event.target.closest("[data-compare-domain]");
  if (compareDomain) {
    try {
      const data = await api(`/api/reports/compare?domain=${encodeURIComponent(compareDomain.dataset.compareDomain)}`);
      renderComparison(data);
    } catch (error) {
      renderComparison({ available: false, domain: compareDomain.dataset.compareDomain, message: error.message });
    }
    return;
  }

  const expandWallet = event.target.closest("[data-expand-wallet]");
  if (expandWallet) {
    document.querySelector("#walletAddress").value = expandWallet.dataset.expandWallet;
    analyzeWallet(expandWallet.dataset.expandWallet);
    return;
  }

  const jump = event.target.closest("[data-section-jump]");
  if (jump) {
    setSection(jump.dataset.sectionJump);
  }

  const revokeApiKey = event.target.closest("[data-revoke-api-key]");
  if (revokeApiKey) {
    const data = await api(`/api/api-keys/${encodeURIComponent(revokeApiKey.dataset.revokeApiKey)}`, { method: "DELETE" });
    state.apiKeys = data.api_keys || [];
    renderApiKeys();
    showApiKeyMessage("API key revoked.");
  }
});

document.addEventListener("submit", async event => {
  if (event.target.id === "apiKeyForm") {
    event.preventDefault();
    try {
      const data = await api("/api/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: document.querySelector("#apiKeyName").value })
      });
      state.apiKeys = data.api_keys || [];
      renderApiKeys();
      showApiKeyMessage(`Copy now: ${data.credential}`);
      document.querySelector("#apiKeyName").value = "";
    } catch (error) {
      showApiKeyMessage(error.message, true);
    }
    return;
  }
  if (event.target.id !== "walletAnnotationForm") return;
  event.preventDefault();
  if (!state.currentWallet) return;
  try {
    const data = await api("/api/wallet/annotations", {
      method: "POST",
      body: JSON.stringify({
        address: state.currentWallet.address,
        tags: document.querySelector("#walletTags").value,
        notes: document.querySelector("#walletNotes").value
      })
    });
    state.workspace = data.workspace;
    renderWorkspace();
    showBillingMessage("Wallet notes saved to the investigation graph.");
  } catch (error) {
    showBillingMessage(error.message);
  }
});

document.querySelector("#runMonitors").addEventListener("click", async () => {
  const button = document.querySelector("#runMonitors");
  button.disabled = true;
  button.textContent = "Checking...";
  try {
    const data = await api("/api/monitors/run", { method: "POST" });
    state.monitors = data.monitors;
    state.reports = data.reports;
    renderMonitors();
    renderReports();
    await loadWorkspace();
  } finally {
    button.disabled = false;
    button.textContent = "Run checks";
  }
});

document.querySelector("#clearReports").addEventListener("click", async () => {
  const data = await api("/api/reports", { method: "DELETE" });
  state.reports = data.reports;
  renderReports();
  await loadWorkspace();
});

document.querySelector("#clearSocialReports").addEventListener("click", async () => {
  const data = await api("/api/social/reports", { method: "DELETE" });
  state.socialReports = data.social_reports;
  renderSocialReports();
  await loadWorkspace();
});

document.querySelector("#clearWalletReports").addEventListener("click", async () => {
  const data = await api("/api/wallet/reports", { method: "DELETE" });
  state.walletReports = data.wallet_reports;
  renderWalletReports();
  document.querySelector("#walletResult").className = "result empty";
  document.querySelector("#walletResult").innerHTML = `<h2>No wallets analyzed</h2><p>Enter a public Bitcoin or Ethereum/EVM address.</p>`;
  await loadWorkspace();
});

document.querySelector("#clearAllHistory").addEventListener("click", async () => {
  const data = await api("/api/history", { method: "DELETE" });
  state.reports = data.reports;
  state.socialReports = data.social_reports;
  state.walletReports = data.wallet_reports || [];
  renderReports();
  renderSocialReports();
  renderWalletReports();
  await loadWorkspace();
});

document.querySelector("#refreshWorkspace").addEventListener("click", loadWorkspace);
document.querySelectorAll("[data-graph-filter]").forEach(button => {
  button.addEventListener("click", () => {
    state.graphFilter = button.dataset.graphFilter;
    document.querySelectorAll("[data-graph-filter]").forEach(item => item.classList.toggle("active", item === button));
    renderWorkspace();
  });
});
document.querySelector("#refreshWallet").addEventListener("click", loadWorkspace);

document.querySelector("#deleteAccountButton").addEventListener("click", async () => {
  if (!state.user.authenticated) {
    showAccountMessage("Sign in before deleting your account.", true);
    return;
  }
  if (state.user.plan === "Admin") {
    showAccountMessage("The Admin account cannot be deleted here.", true);
    return;
  }
  const confirmation = window.prompt("Type DELETE to delete the account and data.");
  if (confirmation !== "DELETE") return;
  await api("/api/account", { method: "DELETE" });
  window.location.reload();
});

document.querySelectorAll("[data-checkout]").forEach(button => {
  button.addEventListener("click", () => checkout(button.dataset.checkout));
});

document.querySelector("#performanceToggle").addEventListener("click", () => {
  document.body.classList.toggle("performance-mode");
  const enabled = document.body.classList.contains("performance-mode");
  localStorage.setItem("op-performance-mode", enabled ? "on" : "off");
  document.querySelector("#performanceToggle").textContent = enabled ? "Visual mode" : "Eco mode";
  if (enabled) {
    document.querySelector("#signalCanvas")?.remove();
  } else if (!document.querySelector("#signalCanvas")) {
    window.location.reload();
  }
});

document.querySelector("#performanceToggle").textContent = document.body.classList.contains("performance-mode")
  ? "Visual mode"
  : "Eco mode";

startSignalCanvas();
checkApi();
loadSession().catch(error => {
  document.querySelector("#apiStatus").textContent = "offline";
  document.querySelector("#result").className = "result empty";
  document.querySelector("#result").innerHTML = `<h2 class="error">Error</h2><p>${escapeHtml(error.message)}</p>`;
});
