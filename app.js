const state = {
  user: { plan: "Free", credits: 0, free_credits: 5, monitor_limit: 1 },
  reports: [],
  socialReports: [],
  monitors: [],
  checkoutConfigured: false
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

function setSection(id) {
  document.querySelectorAll(".section").forEach(section => section.classList.toggle("active", section.id === id));
  document.querySelectorAll(".nav-btn").forEach(button => button.classList.toggle("active", button.dataset.section === id));
}

function redactClient(value) {
  return String(value ?? "")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted]")
    .replace(/\b(?:sk|pk|rk|whsec|ghp|github_pat|xox[baprs])-[-A-Za-z0-9_]{12,}\b/g, "[redacted]")
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
  if (!value) return "non ancora";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" });
}

function nicknameInitials(nickname) {
  const clean = String(nickname || "").replace(/[^a-z0-9]/gi, "");
  return (clean.slice(0, 2) || "?").toUpperCase();
}

function list(items) {
  if (!items || !items.length) return "<span class=\"mono\">nessun dato</span>";
  return `<div class="mono lines">${items.map(item => `<span>${escapeHtml(item)}</span>`).join("")}</div>`;
}

function flag(value) {
  return `<span class="tag ${value ? "" : "missing"}">${value ? "OK" : "Manca"}</span>`;
}

function probeLabel(probe) {
  if (!probe) return "non disponibile";
  return probe.present ? `HTTP ${probe.status}` : (probe.status ? `HTTP ${probe.status}` : "non trovato");
}

function renderFindings(findings = []) {
  if (!findings.length) {
    return `<div class="finding"><span class="tag">OK</span><strong>Nessun finding prioritario</strong><p>Le fonti passive non evidenziano problemi principali.</p></div>`;
  }
  return findings.map(item => `
    <div class="finding ${escapeHtml(item.level)}">
      <span class="tag ${item.level === "high" ? "missing" : ""}">${escapeHtml(item.level)}</span>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.detail)}</p>
    </div>
  `).join("");
}

function renderVulnerabilities(items = []) {
  if (!items.length) {
    return `<div class="ops-row"><span class="tag">OK</span><strong>Nessuna ipotesi prioritaria</strong><p>Non emergono ipotesi di vulnerabilita dalle fonti passive.</p></div>`;
  }
  return items.map(item => `
    <div class="ops-row ${escapeHtml(item.severity)}">
      <span class="tag ${item.severity === "high" ? "missing" : ""}">${escapeHtml(item.severity)}</span>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.evidence)}</p>
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

function updateAccount() {
  const isPaid = state.user.plan !== "Free";
  const isAuthenticated = Boolean(state.user.authenticated);
  const nickname = state.user.nickname || "Guest";
  const maxCredits = state.user.free_credits || 5;
  const label = isPaid ? "∞" : state.user.credits;
  const width = isPaid ? 100 : Math.max(0, Math.min(100, (state.user.credits / maxCredits) * 100));

  document.querySelector("#credits").textContent = label;
  document.querySelector("#creditBar").style.width = `${width}%`;
  document.querySelector("#workspacePlan").textContent = `${state.user.plan} workspace`;
  document.querySelector("#monitorUsage").textContent = `${state.monitors.length}/${state.user.monitor_limit}`;
  document.querySelector("#userAvatar").textContent = isAuthenticated ? nicknameInitials(nickname) : "?";
  document.querySelector("#userNickname").textContent = isAuthenticated ? `@${nickname}` : "Guest";
  document.querySelector("#userChip").classList.toggle("guest", !isAuthenticated);
  document.querySelector("#logoutButton").hidden = !isAuthenticated;
  document.querySelector("#accountState").textContent = state.user.authenticated
    ? `Loggato come @${state.user.nickname}`
    : "Sessione anonima: registra un account con nickname per conservare pack, crediti e acquisti.";
  document.querySelector("#accountMeta").textContent = `Piano ${state.user.plan} · Crediti ${label} · Monitor ${state.monitors.length}/${state.user.monitor_limit}`;
  const historyNotice = document.querySelector("#historyNotice");
  if (historyNotice) {
    historyNotice.classList.toggle("guest-only", !isAuthenticated);
  }
}

function reportActions(report) {
  return `
    <div class="row-actions">
      <a class="secondary small button-link" href="/api/reports/${report.id}/html" target="_blank" rel="noreferrer">PDF</a>
    </div>
  `;
}

function renderReport(report) {
  const scoreClass = report.score >= 80 ? "" : report.score >= 55 ? "warn" : "bad";
  const cert = report.https?.certificate || {};
  const headers = report.https?.security_headers || [];
  const missingHeaders = headers.filter(item => !item.present).map(item => item.name);
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
        <span class="pill">Report monetizzabile</span>
        <h2>${escapeHtml(report.domain)}</h2>
        <p>${escapeHtml(report.summary)}</p>
        <div class="actions">
          <a class="secondary button-link" href="/api/reports/${report.id}/html" target="_blank" rel="noreferrer">Apri PDF</a>
          <button class="secondary" type="button" data-monitor-domain="${escapeHtml(report.domain)}">Monitora dominio</button>
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
      <div><strong>${email.score ?? 0}</strong><span>email score</span></div>
      <div><strong>${subdomains.length}</strong><span>CT names</span></div>
    </div>

    <div class="grid">
      <article class="card">
        <strong>IP risolti</strong>
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
        <strong>Certificato TLS</strong>
        <p class="mono">${cert.subject ? escapeHtml(cert.subject) : "non disponibile"}<br>${cert.expires ? `Scade: ${escapeHtml(cert.expires)}` : ""}<br>${cert.days_remaining !== null && cert.days_remaining !== undefined ? `${cert.days_remaining} giorni rimanenti` : ""}</p>
      </article>
      <article class="card">
        <strong>HTTP status</strong>
        <p class="mono">${report.https?.status || "non disponibile"} ${escapeHtml(report.https?.server || "")}</p>
      </article>
      <article class="card">
        <strong>Tempo analisi</strong>
        <p class="mono">${escapeHtml(formatDate(report.generated_at))}</p>
      </article>
    </div>

    <div class="deep-grid">
      <article class="intel-card">
        <div><span class="pill">Email Security</span><strong>${email.score ?? 0}/100</strong></div>
        <div class="flag-grid">
          <span>${flag(flags.spf_present)} SPF</span>
          <span>${flag(flags.dmarc_present)} DMARC</span>
          <span>${flag(flags.dmarc_reject || flags.dmarc_quarantine)} Policy strict</span>
          <span>${flag(flags.mta_sts_present)} MTA-STS</span>
          <span>${flag(flags.tls_rpt_present)} TLS-RPT</span>
        </div>
        ${list([...(email.dmarc || []), ...(email.mta_sts || []), ...(email.tls_rpt || [])])}
      </article>

      <article class="intel-card">
        <div><span class="pill">Registry Intel</span><strong>${rdap.available ? "RDAP" : "n/a"}</strong></div>
        <p class="mono">Registrar: ${escapeHtml(rdap.registrar || "non disponibile")}<br>Creato: ${escapeHtml(formatDate(rdap.created))}<br>Scadenza: ${escapeHtml(formatDate(rdap.expires))}</p>
      </article>

      <article class="intel-card">
        <div><span class="pill">Web Exposure</span><strong>${[web.security_txt, web.robots_txt, web.sitemap_xml].filter(item => item?.present).length}/3</strong></div>
        <div class="flag-grid">
          <span>${flag(web.security_txt?.present)} security.txt <em>${escapeHtml(probeLabel(web.security_txt))}</em></span>
          <span>${flag(web.robots_txt?.present)} robots.txt <em>${escapeHtml(probeLabel(web.robots_txt))}</em></span>
          <span>${flag(web.sitemap_xml?.present)} sitemap.xml <em>${escapeHtml(probeLabel(web.sitemap_xml))}</em></span>
          <span>${flag(web.mta_sts_policy?.present)} mta-sts policy <em>${escapeHtml(probeLabel(web.mta_sts_policy))}</em></span>
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
          <span>${flag(bimi.present)} BIMI</span>
          <span>${flag(wellKnown.change_password?.present)} change-password <em>${escapeHtml(probeLabel(wellKnown.change_password))}</em></span>
          <span>${flag(wellKnown.openid_configuration?.present)} OpenID config <em>${escapeHtml(probeLabel(wellKnown.openid_configuration))}</em></span>
          <span>${flag(wellKnown.assetlinks?.present)} Android assetlinks <em>${escapeHtml(probeLabel(wellKnown.assetlinks))}</em></span>
          <span>${flag(wellKnown.apple_app_site_association?.present)} Apple app association <em>${escapeHtml(probeLabel(wellKnown.apple_app_site_association))}</em></span>
        </div>
        ${takeoverHints.length ? renderOpsRows(takeoverHints, "provider", "subdomain", "cname") : `<span class="mono">nessun CNAME SaaS/cloud prioritario osservato</span>`}
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
          <span class="tag ${item.present ? "" : "missing"}">${item.present ? "OK" : "Manca"}</span>
          <span><strong>${escapeHtml(item.name)}</strong><br><span class="mono">${escapeHtml(item.value || item.reason)}</span></span>
        </div>
      `).join("")}
    </div>
  `;
}

function renderReports() {
  const holder = document.querySelector("#reportList");
  if (!state.user.authenticated) {
    holder.innerHTML = `<div class="report-row"><span>Accedi per vedere lo storico privato del tuo account</span><span></span><span></span><span></span></div>`;
    return;
  }
  if (!state.reports.length) {
    holder.innerHTML = `<div class="report-row"><span>Nessun report salvato</span><span></span><span></span><span></span></div>`;
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
    holder.innerHTML = `<div class="report-row"><span>Accedi per vedere lo storico social del tuo account</span><span></span><span></span><span></span></div>`;
    return;
  }
  if (!state.socialReports.length) {
    holder.innerHTML = `<div class="report-row"><span>Nessun nickname analizzato</span><span></span><span></span><span></span></div>`;
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
      <div><strong>${found.length}</strong><span>profili probabili</span></div>
      <div><strong>${uncertain.length}</strong><span>incerti</span></div>
      <div><strong>${absent.length}</strong><span>non osservati</span></div>
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

function renderMonitors() {
  const holder = document.querySelector("#monitorList");
  updateAccount();
  if (!state.monitors.length) {
    holder.innerHTML = `<div class="monitor-row"><span>Nessun dominio monitorato</span><span></span><span></span><span></span></div>`;
    return;
  }
  holder.innerHTML = state.monitors.map(item => `
    <div class="monitor-row">
      <strong>${escapeHtml(item.domain)}</strong>
      <span class="tag ${item.status === "changed" ? "missing" : ""}">${escapeHtml(item.status)}</span>
      <span class="mono">${item.last_score === null ? "non ancora" : `${item.last_score}/100`}<br>${escapeHtml(formatDate(item.last_checked_at))}</span>
      <button class="secondary small" type="button" data-remove-monitor="${escapeHtml(item.id)}">Rimuovi</button>
    </div>
  `).join("");
}

function showBillingMessage(message) {
  const box = document.querySelector("#billingMessage");
  box.textContent = message;
  box.classList.add("visible");
}

function showAccountMessage(message, isError = false) {
  const box = document.querySelector("#accountMessage");
  box.textContent = message;
  box.classList.add("visible");
  box.classList.toggle("error", isError);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error || "Richiesta fallita");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function loadSession() {
  const data = await api("/api/session");
  state.user = data.user;
  state.reports = data.reports;
  state.socialReports = data.social_reports;
  state.monitors = data.monitors;
  state.checkoutConfigured = data.checkout_configured;
  updateAccount();
  renderReports();
  renderSocialReports();
  renderMonitors();
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
  if (state.user.plan === "Free" && state.user.credits <= 0) {
    setSection("billing");
    showBillingMessage("Hai finito i crediti Free. Passa a Pro per continuare.");
    return;
  }

  const button = document.querySelector("#scanButton");
  button.disabled = true;
  button.textContent = "Analyzing...";
  setLiveSignal(`collecting passive intel for ${target}`);
  document.querySelector("#result").className = "result empty";
  document.querySelector("#result").innerHTML = `<h2>Analisi in corso</h2><p>Sto interrogando fonti passive dal backend locale.</p>`;

  try {
    const data = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ target })
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
  } catch (error) {
    document.querySelector("#result").className = "result empty";
    document.querySelector("#result").innerHTML = `<h2 class="error">Errore</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Run intel";
    setLiveSignal("passive sensors idle");
  }
}

async function analyzeSocial(username) {
  if (state.user.plan === "Free" && state.user.credits <= 0) {
    setSection("billing");
    showBillingMessage("Hai finito i crediti Free. Social OSINT continua nei piani Pro/Agency.");
    return;
  }
  const button = document.querySelector("#socialButton");
  button.disabled = true;
  button.textContent = "Searching...";
  setLiveSignal(`probing public handles for ${username}`);
  document.querySelector("#socialResult").className = "result empty";
  document.querySelector("#socialResult").innerHTML = `<h2>Ricerca nickname in corso</h2><p>Sto controllando profili pubblici e segnali di impersonificazione.</p>`;
  try {
    const data = await api("/api/social/analyze", {
      method: "POST",
      body: JSON.stringify({ username })
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
  } catch (error) {
    document.querySelector("#socialResult").className = "result empty";
    document.querySelector("#socialResult").innerHTML = `<h2 class="error">Errore</h2><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Run social OSINT";
    setLiveSignal("passive sensors idle");
  }
}

async function addMonitor(domain) {
  try {
    const data = await api("/api/monitors", {
      method: "POST",
      body: JSON.stringify({ domain })
    });
    state.monitors = data.monitors;
    renderMonitors();
    setSection("monitoring");
  } catch (error) {
    if (error.status === 401) {
      setSection("account");
      showAccountMessage(error.message, true);
      return;
    }
    setSection("billing");
    showBillingMessage(error.message);
  }
}

async function checkout(plan) {
  try {
    const data = await api("/api/billing/checkout", {
      method: "POST",
      body: JSON.stringify({ plan })
    });
    if (data.url) {
      showBillingMessage("Redirect sicuro verso Stripe in corso...");
      window.location.href = data.url;
      return;
    }
    showBillingMessage(data.message);
  } catch (error) {
    if (error.status === 401) {
      setSection("account");
      showAccountMessage("Crea un account o accedi prima di acquistare Pro/Agency.", true);
      return;
    }
    showBillingMessage(error.message);
  }
}

document.querySelectorAll(".nav-btn").forEach(button => {
  button.addEventListener("click", () => setSection(button.dataset.section));
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

document.querySelector("#registerForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const data = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        nickname: document.querySelector("#registerNickname").value,
        password: document.querySelector("#registerPassword").value
      })
    });
    document.querySelector("#registerPassword").value = "";
    state.user = data.user;
    await loadSession();
    showAccountMessage("Account creato. Crediti, report e piani ora sono legati al tuo nickname.");
  } catch (error) {
    document.querySelector("#registerPassword").value = "";
    showAccountMessage(error.message, true);
  }
});

document.querySelector("#loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        nickname: document.querySelector("#loginNickname").value,
        password: document.querySelector("#loginPassword").value
      })
    });
    document.querySelector("#loginPassword").value = "";
    state.user = data.user;
    await loadSession();
    showAccountMessage("Login effettuato.");
  } catch (error) {
    document.querySelector("#loginPassword").value = "";
    showAccountMessage(error.message, true);
  }
});

document.querySelector("#passwordForm").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await api("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: document.querySelector("#currentPassword").value,
        new_password: document.querySelector("#newPassword").value
      })
    });
    document.querySelector("#currentPassword").value = "";
    document.querySelector("#newPassword").value = "";
    showAccountMessage("Password aggiornata.");
  } catch (error) {
    document.querySelector("#currentPassword").value = "";
    document.querySelector("#newPassword").value = "";
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
  } finally {
    button.disabled = false;
    button.textContent = "Run checks";
  }
});

document.querySelector("#clearReports").addEventListener("click", async () => {
  const data = await api("/api/reports", { method: "DELETE" });
  state.reports = data.reports;
  renderReports();
});

document.querySelector("#clearSocialReports").addEventListener("click", async () => {
  const data = await api("/api/social/reports", { method: "DELETE" });
  state.socialReports = data.social_reports;
  renderSocialReports();
});

document.querySelector("#clearAllHistory").addEventListener("click", async () => {
  const data = await api("/api/history", { method: "DELETE" });
  state.reports = data.reports;
  state.socialReports = data.social_reports;
  renderReports();
  renderSocialReports();
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
  document.querySelector("#result").innerHTML = `<h2 class="error">Errore</h2><p>${escapeHtml(error.message)}</p>`;
});
