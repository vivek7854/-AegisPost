/**
 * AegisPost | Modern Cybersecurity Posture & Phishing Detector
 * Frontend Application Controller
 */

const form = document.querySelector('#check-form');
const urlInput = document.querySelector('#url-input');
const submitButton = document.querySelector('#submit-button');
const errorMessage = document.querySelector('#error-message');
const loading = document.querySelector('#loading');
const results = document.querySelector('#results');
const progressText = document.querySelector('#progress-text');
const sampleChips = document.querySelectorAll('.sample-chip');

let busy = false;
let currentReport = null;
let currentFilter = 'all';

// HTML Entity Escaper for defense-in-depth XSS protection
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[c]));

// Quick Sample Click Handlers
sampleChips.forEach(chip => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.url;
    urlInput.focus();
  });
});

// Scan Step Animation Helper
function setScanStep(stepNumber, text) {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`step-${i}`);
    if (el) {
      if (i <= stepNumber) el.classList.add('active');
      else el.classList.remove('active');
    }
  }
  if (progressText) progressText.textContent = text;
}

// Map check status to human readable badge & class
function statusMeta(status) {
  switch (status) {
    case 'present':
      return { label: 'Observed / Safe', badgeClass: 'pass', textClass: 'present' };
    case 'not_present':
      return { label: 'Needs Review', badgeClass: 'warn', textClass: 'not_present' };
    case 'not_applicable':
      return { label: 'Not Applicable', badgeClass: 'neutral', textClass: 'not_applicable' };
    default:
      return { label: 'Unverified', badgeClass: 'neutral', textClass: 'unknown' };
  }
}

// Render Trust Status Gauge and Overview Banner
function renderOverviewBanner(summary, target, assessedAt) {
  const score = summary.score;
  const isScorePresent = score !== null && score !== undefined;
  const scoreVal = isScorePresent ? score : 0;
  
  // Radial gauge circumference: 2 * PI * 46 ≈ 289
  const circumference = 289;
  const offset = isScorePresent ? circumference - (scoreVal / 100) * circumference : circumference;
  
  const tier = isScorePresent 
    ? (scoreVal >= 80 ? 'safe' : scoreVal >= 50 ? 'warning' : 'danger')
    : 'unknown';
    
  const badgeText = isScorePresent
    ? (scoreVal >= 80 ? 'Safe Posture' : scoreVal >= 50 ? 'Needs Attention' : 'High Risk Gaps')
    : 'Indeterminate';

  return `
    <div class="overview-banner">
      <div class="score-gauge-wrap">
        <svg class="gauge-svg" viewBox="0 0 110 110">
          <circle class="gauge-bg" cx="55" cy="55" r="46"></circle>
          <circle class="gauge-progress ${tier}" cx="55" cy="55" r="46"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${offset}"></circle>
        </svg>
        <div class="gauge-label">
          <div class="gauge-number">${isScorePresent ? scoreVal : '—'}</div>
          <div class="gauge-total">/100</div>
        </div>
      </div>

      <div class="overview-content">
        <div class="trust-badge-row">
          <span class="trust-badge ${tier}">${escapeHtml(badgeText)}</span>
          <span class="results-time">Audited ${escapeHtml(new Date(assessedAt).toLocaleTimeString())}</span>
        </div>
        <h2 class="overview-title">${escapeHtml(summary.label || 'Posture Evaluation')}</h2>
        <p class="overview-desc">
          ${isScorePresent ? `Evaluated ${summary.completed} of ${summary.total} baseline cybersecurity signals. ` : ''}
          Passive inspection of cryptographic TLS presentation, defensive headers, and anti-phishing posture.
        </p>
      </div>

      <div class="overview-stats">
        <div class="stat-item">
          <strong>${summary.completed || 0} / ${summary.total || 0}</strong>
          <span>Checks Completed</span>
        </div>
        <div class="stat-item">
          <strong>${summary.applicable_weight || 0} pts</strong>
          <span>Assessed Weight</span>
        </div>
      </div>
    </div>
  `;
}

// Render 4-Pillar Breakdown Metric Cards
function renderPillarMetrics(report) {
  const checks = report.checks || [];
  
  // 1. SSL/TLS Status
  const httpsCheck = checks.find(c => c.id === 'https');
  const httpsPassed = httpsCheck && httpsCheck.status === 'present';

  // 2. Threat Intel
  const threat = report.threat_lookup || {};
  const isThreatMatch = threat.status === 'match';
  const isThreatClean = threat.status === 'no_match';

  // 3. Security Headers
  const headerChecks = checks.filter(c => c.category === 'Headers');
  const headersPassed = headerChecks.filter(c => c.status === 'present').length;
  const headersTotal = headerChecks.length || 1;
  const headersRatio = headersPassed / headersTotal;

  // 4. Cookies & Identity
  const cookieCheck = checks.find(c => c.id === 'cookies');
  const cookiePassed = cookieCheck && cookieCheck.status === 'present';
  const cookieNA = cookieCheck && cookieCheck.status === 'not_applicable';

  return `
    <div class="pillar-metrics-grid">
      <!-- SSL / TLS Metric -->
      <div class="metric-card">
        <div class="metric-header">
          <div class="metric-icon green">🔒</div>
          <span class="status-chip ${httpsPassed ? 'pass' : 'danger'}">
            ${httpsPassed ? 'HTTPS ACTIVE' : 'INSECURE HTTP'}
          </span>
        </div>
        <div class="metric-title">SSL / TLS Encryption</div>
        <div class="metric-summary">
          ${httpsPassed ? 'Secure encrypted transport with valid TLS handshake.' : 'Unencrypted plaintext connection.'}
        </div>
      </div>

      <!-- Phishing & Threat Intelligence -->
      <div class="metric-card">
        <div class="metric-header">
          <div class="metric-icon ${isThreatMatch ? 'rose' : 'cyan'}">🛡️</div>
          <span class="status-chip ${isThreatMatch ? 'danger' : isThreatClean ? 'pass' : 'neutral'}">
            ${isThreatMatch ? 'FLAGGED THREAT' : isThreatClean ? 'CLEAN RECORD' : 'UNVERIFIED'}
          </span>
        </div>
        <div class="metric-title">Phishing Intelligence</div>
        <div class="metric-summary">
          ${isThreatMatch ? 'Active threat listing reported in Google Safe Browsing!' : 'No matching phishing entries reported.'}
        </div>
      </div>

      <!-- Security Headers -->
      <div class="metric-card">
        <div class="metric-header">
          <div class="metric-icon ${headersRatio >= 0.75 ? 'green' : headersRatio >= 0.4 ? 'amber' : 'rose'}">📑</div>
          <span class="status-chip ${headersRatio >= 0.75 ? 'pass' : 'warn'}">
            ${headersPassed}/${headersTotal} OBSERVED
          </span>
        </div>
        <div class="metric-title">Defensive Headers</div>
        <div class="metric-summary">
          CSP, HSTS, X-Content-Type-Options &amp; Clickjacking framing rules.
        </div>
      </div>

      <!-- Cookies & Session Integrity -->
      <div class="metric-card">
        <div class="metric-header">
          <div class="metric-icon ${cookiePassed ? 'green' : cookieNA ? 'cyan' : 'amber'}">🍪</div>
          <span class="status-chip ${cookiePassed ? 'pass' : cookieNA ? 'neutral' : 'warn'}">
            ${cookiePassed ? 'HARDENED' : cookieNA ? 'NO COOKIES' : 'MISSING FLAGS'}
          </span>
        </div>
        <div class="metric-title">Session Hardening</div>
        <div class="metric-summary">
          ${cookiePassed ? 'Secure, HttpOnly, and SameSite flags verified.' : cookieNA ? 'No homepage cookies set.' : 'Cookies lack Secure or HttpOnly.'}
        </div>
      </div>
    </div>
  `;
}

// Render Threat Intelligence Details Card
function renderThreatIntelligence(threat) {
  const t = threat || { status: 'unknown', provider: 'Google Safe Browsing', evidence: 'Lookup unconfigured.' };
  const status = t.status === 'match' ? 'threat' : t.status === 'no_match' ? 'safe' : 'unknown';
  
  const icon = status === 'threat' ? '🚨' : status === 'safe' ? '✅' : 'ℹ️';
  const title = status === 'threat'
    ? 'Critical Alert: Known Threat or Phishing Match'
    : status === 'safe'
      ? 'Google Safe Browsing: No Threat Match Found'
      : 'Threat Intelligence Provider Offline or Unconfigured';

  const desc = status === 'threat'
    ? `Google Safe Browsing flagged this URL with match types: ${(t.threat_types || []).map(escapeHtml).join(', ') || 'Malware/Phishing'}. Do NOT enter sensitive credentials.`
    : status === 'safe'
      ? 'No active threat entries matched this domain at the time of lookup. (Newly created phishing domains may not yet be indexed).'
      : escapeHtml(t.evidence || 'Threat lookup was not completed.');

  return `
    <div class="threat-banner ${status}">
      <div class="threat-symbol">${icon}</div>
      <div class="threat-info">
        <div class="threat-title">${title}</div>
        <div class="threat-desc">${desc}</div>
      </div>
    </div>
  `;
}

// Render Interactive AI Security Advisor Section
function renderAiAdvisor() {
  return `
    <section class="ai-advisor-card" id="ai-section">
      <div class="ai-header">
        <div class="ai-header-left">
          <div class="ai-sparkle">✦</div>
          <div>
            <h3 class="ai-title">Automated AI Security Advisor</h3>
            <p class="ai-subtitle">Actionable defensive remediation &amp; server configuration generator</p>
          </div>
        </div>
        <div class="ai-provider-badge" id="ai-provider-badge">Free-Tier Multi-LLM</div>
      </div>

      <button type="button" class="ai-trigger-btn" id="ask-ai-btn">
        <span class="btn-spinner" id="ai-spinner" hidden></span>
        <span id="ai-btn-text">Generate AI Remediation Advice ⚡</span>
      </button>

      <!-- AI Advice Container -->
      <div id="ai-advice-output" class="ai-advice-container" hidden></div>

      <!-- Interactive Fix Snippets Tabs -->
      <div class="fix-tabs-container" id="fix-tabs-section">
        <div class="fix-tabs-header">
          <div class="tab-group">
            <button type="button" class="tab-btn active" data-server="nginx">Nginx</button>
            <button type="button" class="tab-btn" data-server="apache">Apache</button>
            <button type="button" class="tab-btn" data-server="cloudflare">Cloudflare</button>
            <button type="button" class="tab-btn" data-server="express">Express.js</button>
            <button type="button" class="tab-btn" data-server="meta">HTML Meta</button>
          </div>
          <button type="button" class="copy-btn" id="copy-snippet-btn">
            <span>📋 Copy Config</span>
          </button>
        </div>
        <pre class="code-snippet-box" id="snippet-code"># Click any tab above or "Generate AI Advice" to load custom server configuration rules.</pre>
      </div>
    </section>
  `;
}

// Render Detailed Check Findings List
function renderFindings(checks) {
  let filtered = checks;
  if (currentFilter === 'needs_review') {
    filtered = checks.filter(c => c.status === 'not_present');
  } else if (currentFilter === 'passed') {
    filtered = checks.filter(c => c.status === 'present');
  } else if (currentFilter === 'info') {
    filtered = checks.filter(c => ['not_applicable', 'unknown'].includes(c.status));
  }

  const reviewCount = checks.filter(c => c.status === 'not_present').length;
  const passedCount = checks.filter(c => c.status === 'present').length;

  return `
    <section class="findings-section">
      <div class="findings-toolbar">
        <div class="filter-pills">
          <button type="button" class="filter-pill ${currentFilter === 'all' ? 'active' : ''}" data-filter="all">
            All Checks (${checks.length})
          </button>
          <button type="button" class="filter-pill ${currentFilter === 'needs_review' ? 'active' : ''}" data-filter="needs_review">
            Needs Review (${reviewCount})
          </button>
          <button type="button" class="filter-pill ${currentFilter === 'passed' ? 'active' : ''}" data-filter="passed">
            Passed (${passedCount})
          </button>
          <button type="button" class="filter-pill ${currentFilter === 'info' ? 'active' : ''}" data-filter="info">
            Informational
          </button>
        </div>
      </div>

      <div class="findings-list">
        ${filtered.map(c => {
          const meta = statusMeta(c.status);
          return `
            <article class="finding-card ${escapeHtml(c.status)}">
              <div class="finding-top">
                <div>
                  <div class="category-tag">${escapeHtml(c.category)}</div>
                  <h4 class="finding-title">${escapeHtml(c.title)}</h4>
                </div>
                <span class="status-pill ${meta.textClass}">${meta.label}</span>
              </div>

              <div class="evidence-box">
                <strong>Observed Evidence:</strong> ${escapeHtml(c.evidence)}
              </div>

              ${c.impact || c.remediation ? `
                <div class="finding-cols">
                  ${c.impact ? `
                    <div>
                      <div class="finding-col-title">Potential Security Impact</div>
                      <p class="finding-col-text">${escapeHtml(c.impact)}</p>
                    </div>
                  ` : ''}
                  ${c.remediation ? `
                    <div>
                      <div class="finding-col-title">Actionable Recommendation</div>
                      <p class="finding-col-text">${escapeHtml(c.remediation)}</p>
                    </div>
                  ` : ''}
                </div>
              ` : ''}

              <div class="finding-footer">
                <span>Confidence: <strong>${escapeHtml(c.confidence || 'High')}</strong></span>
                <button type="button" class="explain-btn" data-concept="${escapeHtml(c.id)}">
                  💡 Explain in simple terms
                </button>
              </div>
            </article>
          `;
        }).join('')}
      </div>
    </section>
  `;
}

// Assemble and Render Entire Report
function renderReport(report) {
  currentReport = report;
  const s = report.summary || {};

  results.innerHTML = `
    <div class="results-header">
      <div>
        <div class="target-badge">
          <span class="badge-dot"></span> PASIVE POSTURE AUDIT
        </div>
        <h2 class="results-target">${escapeHtml(report.target)}</h2>
      </div>
      <div class="header-actions">
        <button class="action-btn secondary" id="download-json" type="button">JSON Export</button>
        <button class="action-btn primary" id="download-report" type="button">📄 Download PDF Report</button>
        <button class="action-btn secondary" id="re-check-btn" type="button">↻ New Scan</button>
      </div>
    </div>

    ${renderOverviewBanner(s, report.target, report.assessed_at)}
    ${renderPillarMetrics(report)}
    ${renderThreatIntelligence(report.threat_lookup)}
    ${renderAiAdvisor()}
    ${renderFindings(report.checks || [])}
  `;

  results.hidden = false;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Attach Listeners
  document.querySelector('#download-report').addEventListener('click', () => downloadReportPdf(report));
  document.querySelector('#download-json').addEventListener('click', () => downloadReportJson(report));
  document.querySelector('#re-check-btn').addEventListener('click', () => {
    results.hidden = true;
    urlInput.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // AI Button Listener
  const aiBtn = document.querySelector('#ask-ai-btn');
  if (aiBtn) {
    aiBtn.addEventListener('click', () => requestAiAdvice(report));
  }

  // Server Fix Snippet Tab Listeners
  document.querySelectorAll('.tab-btn').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      loadServerSnippet(tab.dataset.server, report);
    });
  });

  // Copy Snippet Button
  const copyBtn = document.querySelector('#copy-snippet-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', copyActiveSnippet);
  }

  // Filter Pills Listeners
  document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      currentFilter = pill.dataset.filter;
      renderReport(report);
    });
  });

  // Concept Explain Buttons
  document.querySelectorAll('.explain-btn').forEach(btn => {
    btn.addEventListener('click', () => explainConcept(btn.dataset.concept));
  });

  // Automatically fetch default Nginx fix snippet for convenience
  loadServerSnippet('nginx', report);
}

// Request AI Security Advice
async function requestAiAdvice(report) {
  const btn = document.querySelector('#ask-ai-btn');
  const btnText = document.querySelector('#ai-btn-text');
  const output = document.querySelector('#ai-advice-output');
  const badge = document.querySelector('#ai-provider-badge');

  if (!btn || btn.disabled) return;
  btn.disabled = true;
  btnText.textContent = 'Consulting AI Security Engine...';
  output.hidden = false;
  output.innerHTML = '<p><em>Synthesizing defensive guidance from observed security controls...</em></p>';

  try {
    const res = await fetch('/api/advice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report, allow_offline: true })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to generate AI advice.');

    if (badge && data.provider) badge.textContent = data.provider;
    
    // Format simple markdown into clean HTML paragraphs
    const formatted = data.advice
      .replace(/^### (.*$)/gim, '<h4>$1</h4>')
      .replace(/^## (.*$)/gim, '<h3>$1</h3>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/\n- /g, '<br>• ');

    output.innerHTML = `<p>${formatted}</p>`;
  } catch (err) {
    output.innerHTML = `<p style="color: var(--crimson);"><strong>Advisor Notice:</strong> ${escapeHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btnText.textContent = 'Refresh AI Advice ⚡';
  }
}

// Load Server Configuration Snippet
async function loadServerSnippet(serverType, report) {
  const codeBox = document.querySelector('#snippet-code');
  if (!codeBox) return;

  const missing = (report.checks || [])
    .filter(c => c.status === 'not_present')
    .map(c => c.id);

  try {
    const res = await fetch('/api/fix-snippet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server: serverType, missing })
    });
    const data = await res.json();
    codeBox.textContent = data.snippet;
  } catch (err) {
    codeBox.textContent = '# Error generating configuration snippet.';
  }
}

// Copy Code Snippet
function copyActiveSnippet() {
  const codeBox = document.querySelector('#snippet-code');
  const copyBtn = document.querySelector('#copy-snippet-btn');
  if (!codeBox || !copyBtn) return;

  navigator.clipboard.writeText(codeBox.textContent).then(() => {
    const original = copyBtn.innerHTML;
    copyBtn.innerHTML = '<span>✅ Copied!</span>';
    setTimeout(() => { copyBtn.innerHTML = original; }, 2000);
  });
}

// Explain Concept in Plain English Modal/Alert
async function explainConcept(conceptId) {
  try {
    const res = await fetch('/api/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: conceptId })
    });
    const data = await res.json();
    alert(`💡 ${data.title} (${data.analogy})\n\n${data.simple_explanation}\n\nSecurity Risk: ${data.risk}`);
  } catch (e) {
    alert('Security concept information is temporarily unavailable.');
  }
}

// Download PDF Attachment
async function downloadReportPdf(report) {
  const btn = document.querySelector('#download-report');
  if (!btn || btn.disabled) return;
  btn.disabled = true;
  btn.textContent = 'Generating PDF...';

  try {
    const res = await fetch('/api/report.pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'PDF creation failed.');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegispost-security-report-${Date.now()}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    alert(err.message || 'Could not download PDF report.');
  } finally {
    btn.disabled = false;
    btn.textContent = '📄 Download PDF Report';
  }
}

// Download JSON Report
function downloadReportJson(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `aegispost-audit-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Main Form Submission Handler
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;

  errorMessage.hidden = true;
  errorMessage.textContent = '';

  let inputVal = urlInput.value.trim();
  if (!inputVal) {
    errorMessage.textContent = 'Please enter a target website URL (e.g., example.com).';
    errorMessage.hidden = false;
    urlInput.focus();
    return;
  }

  // Prepend https:// if user omitted protocol
  if (!/^https?:\/\//i.test(inputVal)) {
    inputVal = `https://${inputVal}`;
  }

  let parsed;
  try {
    parsed = new URL(inputVal);
  } catch {
    errorMessage.textContent = 'Enter a valid public website URL, such as https://example.com.';
    errorMessage.hidden = false;
    urlInput.focus();
    return;
  }

  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
    errorMessage.textContent = 'Use a public http:// or https:// URL without a username or password.';
    errorMessage.hidden = false;
    urlInput.focus();
    return;
  }

  busy = true;
  submitButton.disabled = true;
  submitButton.querySelector('.button-text').textContent = 'Analyzing...';
  loading.hidden = false;
  results.hidden = true;

  // Progressive Step Simulator for UI feedback
  setScanStep(1, 'Resolving hostname and asserting public IP address...');
  const t1 = setTimeout(() => setScanStep(2, 'Initiating TLS handshake and verifying certificates...'), 500);
  const t2 = setTimeout(() => setScanStep(3, 'Parsing HTTP defensive response headers and cookies...'), 1200);
  const t3 = setTimeout(() => setScanStep(4, 'Cross-referencing Google Safe Browsing threat lists...'), 1800);

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: inputVal })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'The security check could not be completed.');

    renderReport(data);
  } catch (err) {
    errorMessage.textContent = err.message || 'A network error interrupted the check. Please try again.';
    errorMessage.hidden = false;
  } finally {
    clearTimeout(t1);
    clearTimeout(t2);
    clearTimeout(t3);
    busy = false;
    submitButton.disabled = false;
    submitButton.querySelector('.button-text').textContent = 'Analyze Posture';
    loading.hidden = true;
  }
});
