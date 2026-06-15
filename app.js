const state = {
  user: { plan: "Free", credits: 0, free_credits: 5, monitor_limit: 1 },
  reports: [],
  socialReports: [],
  walletReports: [],
  monitors: [],
  workspace: null,
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
  if (!value) return "not yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", { dateStyle: "short", timeStyle: "short" });
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

function probeLabel(probe) {
  if (!probe) return "not available";
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
      detail: value?.status ? `HTTP ${value.status}` : "not observed"
    });
  });
  return required;
}

function renderWebAuditLab(report) {
  const domain = report.domain;
  const missingHeaders = (report.https?.security_headers || []).filter(item => !item.present);
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
              <span>${flag(item.ok)}</span>
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
  const creditLabel = state.user.plan === "Free" ? `${state.user.credits} credits available` : "Unlimited reports";
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
        <span class="pill">Sellable report</span>
        <h2>${escapeHtml(report.domain)}</h2>
        <p>${escapeHtml(report.summary)}</p>
        <div class="actions">
          <a class="secondary button-link" href="/api/reports/${report.id}/html" target="_blank" rel="noreferrer">Open PDF</a>
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
      <div><strong>${email.score ?? 0}</strong><span>email score</span></div>
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
        <p class="mono">Registrar: ${escapeHtml(rdap.registrar || "not available")}<br>Created: ${escapeHtml(formatDate(rdap.created))}<br>Expires: ${escapeHtml(formatDate(rdap.expires))}</p>
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
          <span class="tag ${item.present ? "" : "missing"}">${item.present ? "OK" : "Missing"}</span>
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
    site: "#39ffb8",
    person: "#62d8ff",
    profile: "#9de7ff",
    ip: "#d6f7ef",
    nameserver: "#7cffce",
    mail: "#ffbd59",
    email: "#ffbd59",
    wallet: "#39ffb8",
    counterparty: "#b9fff0",
    transaction: "#ffbd59",
    registry: "#b8ffdf",
    technology: "#a7b8ff",
    subdomain: "#62d8ff",
    risk: "#ff5d6c",
    finding: "#ffbd59"
  }[type] || "#e9fff7";
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
  const wallet = data.wallet || {};
  schemaHolder.innerHTML = `
    <div class="schema-grid">
      <article class="graph-panel">
        ${renderGraph(data.nodes || [], data.edges || [])}
      </article>
      <aside class="schema-summary">
        <article><span>Nodes</span><strong>${(data.nodes || []).length}</strong></article>
        <article><span>Edges</span><strong>${(data.edges || []).length}</strong></article>
        <article><span>Sites</span><strong>${sites.length}</strong></article>
        <article><span>People</span><strong>${people.length}</strong></article>
        <article><span>Wallet</span><strong>${wallets.length}</strong></article>
      </aside>
    </div>
    <div class="dossier-grid">
      ${sites.map(item => renderDossierCard(item, "site")).join("")}
      ${people.map(item => renderDossierCard(item, "person")).join("")}
      ${wallets.map(item => renderDossierCard(item, "wallet")).join("")}
      ${!sites.length && !people.length && !wallets.length ? `<div class="result empty"><h2>No dossier</h2><p>Generate a domain, social or wallet report to populate this section.</p></div>` : ""}
    </div>
  `;

  const creditLabel = wallet.plan === "Free" ? wallet.credits : "∞";
  renderWalletReports();
  const walletStats = document.querySelector("#walletResult");
  if (walletStats && walletStats.classList.contains("empty")) {
    walletStats.innerHTML = `
    <div class="wallet-grid">
      <article class="wallet-card hero-wallet">
        <span class="pill">Current plan</span>
        <strong>${escapeHtml(wallet.plan || "Free")}</strong>
        <p>Credits: <b>${escapeHtml(creditLabel)}</b>. Wallet report: <b>${wallet.wallet_reports || 0}</b>. Domain monitors: <b>${wallet.monitor_used || 0}/${wallet.monitor_limit || 1}</b>.</p>
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
    const error = new Error(data.error || "Request failed");
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
  state.walletReports = data.wallet_reports || [];
  state.monitors = data.monitors;
  state.checkoutConfigured = data.checkout_configured;
  updateAccount();
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
  if (state.user.plan === "Free" && state.user.credits <= 0) {
    setSection("billing");
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
  if (state.user.plan === "Free" && state.user.credits <= 0) {
    setSection("billing");
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

async function analyzeSocial(username) {
  if (state.user.plan === "Free" && state.user.credits <= 0) {
    setSection("billing");
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
  if (state.user.plan === "Free" && state.user.credits <= 0) {
    setSection("billing");
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
      body: JSON.stringify({ address })
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
      body: JSON.stringify({ domain })
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

document.querySelector("#loadOwnAudit").addEventListener("click", () => {
  document.querySelector("#webAuditTarget").value = "osintpro-48j4.onrender.com";
  buildWebAuditLab("osintpro-48j4.onrender.com");
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
    showAccountMessage("Account created. Credits, reports and plans are now tied to your nickname.");
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
    showAccountMessage("Signed in.");
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
    showAccountMessage("Password updated.");
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

  const jump = event.target.closest("[data-section-jump]");
  if (jump) {
    setSection(jump.dataset.sectionJump);
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
