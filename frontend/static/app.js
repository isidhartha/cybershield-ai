const API = 'http://localhost:8000';
let scanReports = [];
let scanStats = { scans: 0, critical: 0, warnings: 0, clean: 0 };

// ---- NAVIGATION ----
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.cs-nav').forEach(b => b.classList.remove('active'));
  const view = document.getElementById('view-' + name);
  const btn = document.getElementById('nav-' + name);
  if (view) view.classList.add('active');
  if (btn) btn.classList.add('active');
  const titles = {
    dashboard: '// DASHBOARD', codescan: '// CODE SCAN', secrets: '// SECRETS SCAN',
    owasp: '// OWASP CHECK', aireview: '// AI REVIEW', reports: '// REPORTS', chat: '// AI CHAT'
  };
  document.getElementById('viewTitle').textContent = titles[name] || '// ' + name.toUpperCase();
}

// ---- HEALTH ----
async function checkHealth() {
  try {
    const r = await fetch(`${API}/health`);
    if (r.ok) {
      document.getElementById('connBadge').innerHTML = '<span style="color:#22c55e">● SECURE CONNECTION</span>';
      loadToolsStatus();
    } else throw new Error();
  } catch {
    document.getElementById('connBadge').innerHTML = '<span style="color:#ef4444">● API OFFLINE</span>';
  }
}

async function loadToolsStatus() {
  try {
    const r = await fetch(`${API}/api/v1/tools/status`);
    if (!r.ok) return;
    const data = await r.json();
    const tools = data.tools || data;
    const grid = document.getElementById('toolsGrid');
    grid.innerHTML = '';
    Object.entries(tools).forEach(([name, status]) => {
      const badge = document.createElement('div');
      const ok = status === true || status === 'available' || status === 'ok';
      badge.className = 'tool-badge';
      badge.innerHTML = `
        <span style="color:${ok ? '#22c55e' : '#ef4444'}">${ok ? '✓' : '✗'}</span>
        <span class="text-xs font-mono">${name}</span>
      `;
      grid.appendChild(badge);
    });
    document.getElementById('toolsStatus').textContent = Object.keys(tools).length + ' tools loaded';
  } catch {
    document.getElementById('toolsStatus').textContent = 'Tools unavailable';
  }
}

// ---- MATRIX BACKGROUND ----
function initMatrix() {
  const canvas = document.getElementById('matrixCanvas');
  const ctx = canvas.getContext('2d');
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  const cols = Math.floor(canvas.width / 20);
  const drops = Array(cols).fill(1);
  const chars = '01ABCDEF<>{}()[]/*';

  setInterval(() => {
    ctx.fillStyle = 'rgba(7,11,20,0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#ef4444';
    ctx.font = '12px JetBrains Mono';
    drops.forEach((y, i) => {
      const c = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(c, i * 20, y * 20);
      if (y * 20 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }, 60);
}

// ---- SCAN ----
async function runScan(type) {
  const codeMap = { code: 'scanCode', secrets: 'secretsCode', owasp: 'owaspCode', aireview: 'reviewCode' };
  const code = document.getElementById(codeMap[type])?.value?.trim();
  if (!code) return showToast('Please paste code first', 'error');

  const scanId = 'scan_' + Date.now();
  setProgress(0, 'Initializing scan…');
  scanStats.scans++;
  updateStats();

  // WebSocket progress
  const wsConn = startScanWS(scanId);

  const endpoints = {
    code: { url: '/api/v1/scan/code', body: { code, language: document.getElementById('scanLang')?.value || 'python' } },
    secrets: { url: '/api/v1/scan/secrets', body: { code } },
    owasp: { url: '/api/v1/scan/owasp', body: { code } },
    aireview: { url: '/api/v1/review/code', body: { code, language: document.getElementById('reviewLang')?.value || 'python' } }
  };

  const ep = endpoints[type];
  try {
    setProgress(20, 'Sending to scanner…');
    const r = await fetch(`${API}${ep.url}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...ep.body, scan_id: scanId })
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    setProgress(100, 'Scan complete');
    if (wsConn) wsConn.close();

    if (type === 'aireview') {
      renderAIReview(data);
    } else if (type === 'owasp') {
      renderOWASP(data);
    } else {
      const findings = data.findings || data.results || data.issues || [];
      renderFindings(findings, type === 'secrets' ? 'secretsResults' : 'scanResults');
      storeScanResult(scanId, type, findings);
      updateScanStats(findings);
    }
    showToast('Scan completed!', 'success');
  } catch (e) {
    setProgress(0, 'Scan failed');
    showToast(`Scan error: ${e.message}`, 'error');
    scanStats.scans = Math.max(0, scanStats.scans - 1);
    updateStats();
  }
}

function startScanWS(scanId) {
  try {
    const wsConn = new WebSocket(`ws://localhost:8000/ws/scan/${scanId}`);
    wsConn.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.progress !== undefined) setProgress(msg.progress, msg.message || '');
      } catch {}
    };
    return wsConn;
  } catch { return null; }
}

function setProgress(pct, msg) {
  const ring = document.getElementById('progressRing');
  const pctEl = document.getElementById('progressPct');
  const msgEl = document.getElementById('progressMsg');
  if (!ring) return;
  const circumference = 213.6;
  ring.style.strokeDashoffset = circumference * (1 - pct / 100);
  ring.style.stroke = pct === 100 ? '#22c55e' : pct > 0 ? '#3b82f6' : '#ef4444';
  if (pctEl) pctEl.textContent = pct + '%';
  if (msgEl) msgEl.textContent = msg;
}

function renderFindings(findings, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  if (!findings || findings.length === 0) {
    container.innerHTML = '<div class="cs-card rounded-xl p-4 text-green-400 font-mono text-sm">✓ No findings — code appears clean.</div>';
    scanStats.clean++;
    updateStats();
    return;
  }

  findings.slice(0, 30).forEach(f => {
    const sev = (f.severity || f.level || 'info').toLowerCase();
    const card = document.createElement('div');
    card.className = `finding-card finding-${sev}`;
    const sevClass = `sev-${sev}`;
    card.innerHTML = `
      <div class="flex items-start justify-between gap-3 mb-2">
        <span class="font-semibold text-sm" style="color:var(--cs-text)">${f.title || f.check || f.rule || 'Finding'}</span>
        <span class="sev-badge ${sevClass} flex-shrink-0">${sev}</span>
      </div>
      <div class="text-xs font-mono mb-2" style="color:#94a3b8;line-height:1.5">${f.description || f.message || f.details || ''}</div>
      ${f.line_number ? `<div class="text-xs font-mono" style="color:#64748b">Line ${f.line_number}</div>` : ''}
      ${f.secret_value ? `<div class="text-xs font-mono mt-1 px-2 py-1 rounded" style="background:rgba(239,68,68,0.1);color:#ef4444">${maskSecret(f.secret_value)}</div>` : ''}
      <button onclick="getFix(${JSON.stringify(f).replace(/"/g,'&quot;')})" class="mt-2 text-xs px-3 py-1 rounded border border-blue-500/30 text-blue-400 hover:bg-blue-500/10 transition">
        <i class="fas fa-wand-magic-sparkles mr-1"></i>Get AI Fix
      </button>
    `;
    container.appendChild(card);
  });
}

function maskSecret(val) {
  if (!val) return '';
  if (val.length <= 8) return '••••••••';
  return val.substring(0, 4) + '•'.repeat(Math.min(val.length - 8, 12)) + val.substring(val.length - 4);
}

function renderOWASP(data) {
  const container = document.getElementById('owaspResults');
  container.innerHTML = '';
  const checks = data.checks || data.results || mockOWASPChecks();
  checks.forEach(c => {
    const status = c.status || (c.passed ? 'pass' : 'fail');
    const item = document.createElement('div');
    item.className = `owasp-item owasp-${status}`;
    item.innerHTML = `
      <i class="fas fa-${status === 'pass' ? 'circle-check text-green-400' : status === 'warn' ? 'triangle-exclamation text-yellow-400' : 'circle-xmark text-red-400'}"></i>
      <div class="flex-1">
        <div class="text-sm font-semibold" style="color:var(--cs-text)">${c.name || c.category}</div>
        <div class="text-xs font-mono mt-0.5" style="color:#94a3b8">${c.description || c.message || ''}</div>
      </div>
      <span class="text-xs font-mono uppercase px-2 py-0.5 rounded" style="background:rgba(255,255,255,0.05);color:#64748b">${status}</span>
    `;
    container.appendChild(item);
  });
}

function mockOWASPChecks() {
  return [
    { name: 'A01 Broken Access Control', status: 'warn', description: 'Potential access control issues detected' },
    { name: 'A02 Cryptographic Failures', status: 'pass', description: 'No hardcoded secrets found' },
    { name: 'A03 Injection', status: 'fail', description: 'SQL injection vectors detected' },
    { name: 'A04 Insecure Design', status: 'warn', description: 'Review error handling patterns' },
    { name: 'A05 Security Misconfiguration', status: 'pass', description: 'No obvious misconfigurations' },
    { name: 'A06 Vulnerable Components', status: 'pass', description: 'Dependencies appear up to date' },
    { name: 'A07 Auth Failures', status: 'pass', description: 'Authentication logic looks correct' },
    { name: 'A08 Software Integrity Failures', status: 'pass', description: 'No integrity issues detected' },
    { name: 'A09 Security Logging Failures', status: 'warn', description: 'Logging could be improved' },
    { name: 'A10 SSRF', status: 'pass', description: 'No SSRF vulnerabilities found' },
  ];
}

function renderAIReview(data) {
  const result = document.getElementById('aiReviewResult');
  const text = document.getElementById('aiReviewText');
  result.classList.remove('hidden');
  const content = data.review || data.analysis || data.result || JSON.stringify(data, null, 2);
  text.innerHTML = content.replace(/\n/g, '<br/>');
}

function updateScanStats(findings) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => {
    const s = (f.severity || 'low').toLowerCase();
    if (sev[s] !== undefined) sev[s]++;
  });
  if (sev.critical > 0 || sev.high > 0) scanStats.critical += sev.critical + sev.high;
  else scanStats.warnings += sev.medium;
  updateStats();
}

function updateStats() {
  document.getElementById('stat-scans').textContent = scanStats.scans;
  document.getElementById('stat-critical').textContent = scanStats.critical;
  document.getElementById('stat-warnings').textContent = scanStats.warnings;
  document.getElementById('stat-clean').textContent = scanStats.clean;
}

function storeScanResult(id, type, findings) {
  scanReports.unshift({ id, type, findings: findings.length, timestamp: new Date() });
  renderRecentScans();
  renderReports();
}

function renderRecentScans() {
  const container = document.getElementById('recentScans');
  container.innerHTML = '';
  scanReports.slice(0, 5).forEach(s => {
    const item = document.createElement('div');
    item.className = 'flex items-center justify-between py-2 border-b border-cs-border text-xs font-mono';
    item.innerHTML = `
      <span style="color:#94a3b8">${s.id}</span>
      <span style="color:#64748b">${s.type}</span>
      <span style="color:${s.findings > 0 ? '#ef4444' : '#22c55e'}">${s.findings} findings</span>
    `;
    container.appendChild(item);
  });
}

function renderReports() {
  const container = document.getElementById('reportsList');
  if (scanReports.length === 0) {
    container.innerHTML = '<div class="text-xs text-slate-600 italic font-mono">No reports generated yet.</div>';
    return;
  }
  container.innerHTML = '';
  scanReports.forEach(s => {
    const card = document.createElement('div');
    card.className = 'cs-card rounded-xl p-4 flex items-center gap-4';
    card.innerHTML = `
      <div class="flex-1">
        <div class="text-xs font-mono text-red-400">${s.id}</div>
        <div class="text-xs text-slate-500 mt-1">${s.type.toUpperCase()} · ${s.findings} findings · ${s.timestamp.toLocaleString()}</div>
      </div>
      <div class="flex gap-2">
        <button onclick="downloadReport('${s.id}', 'html')" class="text-xs px-3 py-1.5 rounded border border-blue-500/30 text-blue-400 hover:bg-blue-500/10 transition">
          <i class="fas fa-download mr-1"></i>HTML
        </button>
        <button onclick="exportJSON('${s.id}')" class="text-xs px-3 py-1.5 rounded border border-green-500/30 text-green-400 hover:bg-green-500/10 transition">
          <i class="fas fa-download mr-1"></i>JSON
        </button>
      </div>
    `;
    container.appendChild(card);
  });
}

async function downloadReport(scanId, format) {
  try {
    const r = await fetch(`${API}/api/v1/report/${scanId}/${format}`);
    if (!r.ok) throw new Error('Report unavailable');
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `report_${scanId}.${format}`;
    a.click(); URL.revokeObjectURL(url);
  } catch (e) { showToast(`Download failed: ${e.message}`, 'error'); }
}

function exportJSON(scanId) {
  const report = scanReports.find(r => r.id === scanId);
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `${scanId}.json`;
  a.click(); URL.revokeObjectURL(url);
}

// ---- AI FIX ----
async function getFix(finding) {
  document.getElementById('remediationModal').classList.remove('hidden');
  document.getElementById('remediationContent').innerHTML = '<div class="animate-pulse text-slate-500">Loading AI fix suggestion…</div>';
  try {
    const r = await fetch(`${API}/api/v1/remediation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding })
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    document.getElementById('remediationContent').innerHTML =
      (data.suggestion || data.fix || data.remediation || JSON.stringify(data)).replace(/\n/g, '<br/>');
  } catch (e) {
    document.getElementById('remediationContent').textContent = `Error: ${e.message}`;
  }
}

function closeModal() {
  document.getElementById('remediationModal').classList.add('hidden');
}

// ---- CHAT ----
async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';

  const container = document.getElementById('chatMessages');
  const userEl = document.createElement('div');
  userEl.className = 'cs-chat-user text-right mb-2';
  userEl.innerHTML = `<span style="color:#64748b;font-size:0.7rem">You</span><div class="mt-1">${msg}</div>`;
  container.appendChild(userEl);
  container.scrollTop = container.scrollHeight;

  const aiEl = document.createElement('div');
  aiEl.className = 'cs-chat-ai mb-2';
  aiEl.innerHTML = '<i class="fas fa-shield-halved text-red-400 mr-2"></i><span class="animate-pulse">Thinking…</span>';
  container.appendChild(aiEl);
  container.scrollTop = container.scrollHeight;

  try {
    const r = await fetch(`${API}/api/v1/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg })
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    aiEl.innerHTML = `<i class="fas fa-shield-halved text-red-400 mr-2"></i>${data.response || data.message || JSON.stringify(data)}`;
  } catch (e) {
    aiEl.innerHTML = `<i class="fas fa-shield-halved text-red-400 mr-2"></i>Error: ${e.message}`;
  }
}

// ---- SIDEBAR ----
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('mobileOverlay').classList.toggle('hidden');
}

// ---- TOAST ----
function showToast(msg, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fas fa-${type === 'error' ? 'triangle-exclamation' : 'shield-check'} mr-2 text-${type === 'error' ? 'red' : 'green'}-400"></i>${msg}`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// ---- INIT ----
checkHealth();
initMatrix();
setInterval(checkHealth, 30000);
