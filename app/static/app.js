/**
 * SpamShield AI - Enterprise Threat Defense Engine Client Logic
 * Handles real-time inference, XAI rendering, URL forensics, batch processing, and telemetry.
 */

let selectedChannel = "auto";
let activeSnippetLang = "curl";
let batchDataCache = null;
let currentBatchFilter = "all";

// Attack and Legitimate Preset Scenarios
const PRESETS = {
  paypal: "URGENT: Your PayPal account has been temporarily restricted due to unauthorized login attempts. Verify your identity immediately at http://paypal-security-verification.xyz/login or your account will be permanently closed within 24 hours.",
  usps: "USPS: We attempted to deliver your parcel #US9821019, but house address was incomplete. Update address and pay redelivery fee ($0.45) here: http://usps-parcel-redelivery.top/track",
  crypto: "Earn $5,000 to $10,000 weekly working from home with automated Bitcoin AI trading robot! Guaranteed 500% ROI. No experience needed. Join Telegram: t.me/crypto_wealth_signals",
  lottery: "DEAR BENEFICIARY, I am Barrister Mohammed Bello, legal attorney to late oil magnate. He left an unclaimed inheritance of $14.5M USD. Contact me urgently with your bank details to claim 40% share.",
  work_email: "Hi team, please find attached the revised project roadmap for Q3. Let me know your thoughts before tomorrow's sprint review meeting at 2:00 PM.",
  doctor_sms: "Your appointment with Dr. Henderson is confirmed for Monday, Oct 12 at 2:30 PM. Please arrive 10 minutes early. Reply 1 to confirm, 2 to cancel."
};

const URL_PRESETS = {
  paypal_phish: "http://paypal-security-verification.xyz/login",
  chase_auth: "http://chase-bank-verify-auth.top/restore",
  ip_host: "http://192.168.1.1/apple-id-verify",
  github_safe: "https://github.com/torvalds/linux"
};

// ================= Tab Management =================
function switchTab(tabId) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));

  const target = document.getElementById(tabId);
  if (target) target.classList.add("active");

  const btnMap = {
    "tab-msg": "tabBtnMsg",
    "tab-url": "tabBtnUrl",
    "tab-batch": "tabBtnBatch",
    "tab-stats": "tabBtnStats",
    "tab-api": "tabBtnApi"
  };

  const btn = document.getElementById(btnMap[tabId]);
  if (btn) btn.classList.add("active");

  if (tabId === "tab-stats") {
    refreshTelemetry();
  } else if (tabId === "tab-api") {
    renderCodeSnippet();
  }
}

// ================= Channel Selection =================
function setChannel(channel, btn) {
  selectedChannel = channel;
  document.querySelectorAll("#channelSelector .channel-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
}

// ================= Preset Loading =================
function loadPreset(presetKey) {
  const text = PRESETS[presetKey] || "";
  const input = document.getElementById("messageInput");
  input.value = text;
  updateCharCount();

  // Highlight textarea briefly
  input.style.borderColor = "var(--accent-cyan)";
  setTimeout(() => { input.style.borderColor = ""; }, 400);

  // Auto trigger scan
  scanMessage();
}

function loadUrlPreset(presetKey) {
  const url = URL_PRESETS[presetKey] || "";
  const input = document.getElementById("urlInput");
  input.value = url;
  scanUrl();
}

function updateCharCount() {
  const text = document.getElementById("messageInput").value || "";
  const chars = text.length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  document.getElementById("charCount").innerText = `${chars} characters • ${words} words`;
}

function clearMessage() {
  document.getElementById("messageInput").value = "";
  updateCharCount();
  document.getElementById("resultsContent").style.display = "none";
  document.getElementById("resultsEmpty").style.display = "block";
  document.getElementById("scanLatency").style.display = "none";
}

// ================= Core Message Scan =================
async function scanMessage() {
  const text = document.getElementById("messageInput").value.trim();
  if (!text) {
    alert("Please enter or paste a message to scan.");
    return;
  }

  const btn = document.getElementById("btnScanMessage");
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="pulse-dot"></span> Analyzing Threat Vectors...`;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, channel: selectedChannel })
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    renderMessageResults(data);
    refreshTelemetry();
  } catch (err) {
    alert("Scan failed: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
}

function renderMessageResults(data) {
  document.getElementById("resultsEmpty").style.display = "none";
  const resultsContent = document.getElementById("resultsContent");
  resultsContent.style.display = "block";

  // Latency badge
  const latencyBadge = document.getElementById("scanLatency");
  latencyBadge.innerText = `${data.latency_ms || 3.2}ms`;
  latencyBadge.style.display = "inline-block";

  // Verdict Banner
  const banner = document.getElementById("verdictBanner");
  const icon = document.getElementById("verdictIcon");
  const title = document.getElementById("verdictTitle");
  const cat = document.getElementById("verdictCategory");
  const score = document.getElementById("verdictScore");

  banner.className = "verdict-banner";
  score.innerText = `${data.risk_score}%`;

  if (data.risk_level === "CRITICAL") {
    banner.classList.add("critical");
    icon.innerText = "🚨";
    title.innerText = "CRITICAL THREAT DETECTED";
    score.style.color = "var(--status-critical)";
  } else if (data.risk_level === "HIGH") {
    banner.classList.add("danger");
    icon.innerText = "⚠️";
    title.innerText = "HIGH-RISK SPAM / PHISHING";
    score.style.color = "var(--status-danger)";
  } else if (data.risk_level === "SUSPICIOUS") {
    banner.classList.add("suspicious");
    icon.innerText = "⚡";
    title.innerText = "SUSPICIOUS COMMUNICATION";
    score.style.color = "var(--status-warning)";
  } else {
    banner.classList.add("safe");
    icon.innerText = "🛡️";
    title.innerText = "VERIFIED LEGITIMATE (HAM)";
    score.style.color = "var(--status-safe)";
  }

  cat.innerText = data.category.replace(/_/g, " ");

  // Progress Bar
  const fill = document.getElementById("riskBarFill");
  fill.style.width = `${data.risk_score}%`;
  if (data.risk_score >= 70) {
    fill.style.background = "linear-gradient(90deg, #f59e0b, #ff2a5f)";
  } else if (data.risk_score >= 35) {
    fill.style.background = "linear-gradient(90deg, #10b981, #f59e0b)";
  } else {
    fill.style.background = "linear-gradient(90deg, #3b82f6, #10b981)";
  }

  document.getElementById("riskProbabilityText").innerText = `${data.spam_probability.toFixed(4)} (Score: ${data.risk_score}/100)`;

  // Breakdown metrics
  const bd = data.breakdown || {};
  document.getElementById("metricMlProb").innerText = `${Math.round((bd.ml_probability || 0) * 100)}%`;
  document.getElementById("metricHeuristic").innerText = `${Math.round((bd.heuristic_score || 0) * 100)}%`;
  document.getElementById("metricUrgency").innerText = `${Math.round((bd.urgency_score || 0) * 100)}%`;
  document.getElementById("metricLinks").innerText = `${Math.round((bd.link_score || 0) * 100)}%`;

  // Highlighted XAI Text
  const highlightBox = document.getElementById("highlightedContainer");
  highlightBox.innerHTML = data.highlighted_html || htmlEscape(data.text || "");

  // Red Flags List
  const flagsList = document.getElementById("redFlagsList");
  flagsList.innerHTML = "";
  const flags = data.red_flags || [];
  document.getElementById("flagsCount").innerText = flags.length;

  if (flags.length === 0) {
    flagsList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; padding: 6px;">No suspicious red-flag keywords, evasive characters, or malicious links identified.</div>`;
  } else {
    flags.forEach(flag => {
      const card = document.createElement("div");
      card.className = `flag-card ${flag.severity || 'HIGH'}`;
      card.innerHTML = `
        <span class="flag-badge ${flag.severity || 'HIGH'}">${flag.severity || 'FLAG'}</span>
        <div class="flag-detail">
          <div class="flag-phrase">${htmlEscape(flag.phrase)}</div>
          <div class="flag-reason">${htmlEscape(flag.reason || flag.category)}</div>
        </div>
      `;
      flagsList.appendChild(card);
    });
  }

  // Recommendations
  const recsList = document.getElementById("recommendationsList");
  recsList.innerHTML = "";
  (data.recommendations || []).forEach(rec => {
    const li = document.createElement("li");
    li.className = "rec-item";
    li.innerHTML = `<span>&bull;</span> <span>${htmlEscape(rec)}</span>`;
    recsList.appendChild(li);
  });
}

// ================= URL Scanner =================
async function scanUrl() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) {
    alert("Please enter a URL to inspect.");
    return;
  }

  const btn = document.getElementById("btnScanUrl");
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="pulse-dot"></span> Inspecting URL...`;

  try {
    const response = await fetch("/api/scan-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    renderUrlResults(data);
  } catch (err) {
    alert("URL scan failed: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
}

function renderUrlResults(data) {
  document.getElementById("urlResultsEmpty").style.display = "none";
  const content = document.getElementById("urlResultsContent");
  content.style.display = "block";

  const latencyBadge = document.getElementById("urlLatency");
  latencyBadge.innerText = `${data.latency_ms || 2.1}ms`;
  latencyBadge.style.display = "inline-block";

  const banner = document.getElementById("urlVerdictBanner");
  const icon = document.getElementById("urlVerdictIcon");
  const title = document.getElementById("urlVerdictTitle");
  const host = document.getElementById("urlHostDisplay");
  const score = document.getElementById("urlRiskScore");

  banner.className = "verdict-banner";
  score.innerText = `${data.risk_score}%`;
  host.innerText = data.hostname || data.url;

  if (data.is_suspicious) {
    banner.classList.add(data.risk_score >= 60 ? "critical" : "danger");
    icon.innerText = "🚨";
    title.innerText = "MALICIOUS / PHISHING LINK";
    score.style.color = "var(--status-critical)";
  } else {
    banner.classList.add("safe");
    icon.innerText = "🛡️";
    title.innerText = "LEGITIMATE / CLEAN URL";
    score.style.color = "var(--status-safe)";
  }

  // Populate checks table
  const tbody = document.getElementById("urlChecksBody");
  tbody.innerHTML = "";

  const checks = [
    { attr: "Target Hostname", val: data.hostname || "N/A", status: "info" },
    { attr: "Security Protocol", val: data.url.startsWith("https") ? "HTTPS (TLS Encrypted)" : "HTTP (Unencrypted)", status: data.url.startsWith("https") ? "safe" : "danger" },
    { attr: "Threat Risk Assessment", val: data.is_suspicious ? `High Risk (${data.risk_score}/100)` : `Safe (${data.risk_score}/100)`, status: data.is_suspicious ? "danger" : "safe" },
    { attr: "Detected Threat Flags", val: (data.flags && data.flags.length > 0) ? data.flags.join("<br>&bull; ") : "None. Clean domain structure.", status: (data.flags && data.flags.length > 0) ? "danger" : "safe" }
  ];

  checks.forEach(c => {
    const tr = document.createElement("tr");
    const colorStyle = c.status === "danger" ? "color: #f87171;" : c.status === "safe" ? "color: #34d399;" : "color: #94a3b8;";
    tr.innerHTML = `
      <td style="font-weight: 600; color: #e2e8f0;">${c.attr}</td>
      <td style="${colorStyle}">${c.val}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ================= Batch File Scanner =================
let selectedBatchFile = null;

function handleFileSelected(event) {
  const file = event.target.files[0];
  if (file) {
    selectedBatchFile = file;
    document.getElementById("dropFileName").innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    document.getElementById("btnStartBatch").disabled = false;
  }
}

// Drag & drop setup
const dropZone = document.getElementById("dropZone");
if (dropZone) {
  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("dragover"); });
  dropZone.addEventListener("dragleave", e => { e.preventDefault(); dropZone.classList.remove("dragover"); });
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      selectedBatchFile = e.dataTransfer.files[0];
      document.getElementById("dropFileName").innerText = `Selected: ${selectedBatchFile.name} (${(selectedBatchFile.size / 1024).toFixed(1)} KB)`;
      document.getElementById("btnStartBatch").disabled = false;
    }
  });
}

async function uploadAndProcessBatch() {
  if (!selectedBatchFile) return;

  const btn = document.getElementById("btnStartBatch");
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="pulse-dot"></span> Processing Batch with AI...`;

  const formData = new FormData();
  formData.append("file", selectedBatchFile);

  try {
    const response = await fetch("/api/scan-batch", {
      method: "POST",
      body: formData
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    batchDataCache = data;
    renderBatchResults(data);
    refreshTelemetry();
  } catch (err) {
    alert("Batch processing error: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
}

function renderBatchResults(data) {
  document.getElementById("batchResultsWrapper").style.display = "block";
  document.getElementById("batchTotal").innerText = data.total_records;
  document.getElementById("batchSpamCount").innerText = data.spam_detected;
  document.getElementById("batchHamCount").innerText = data.ham_verified;
  document.getElementById("batchSpamRate").innerText = `${data.spam_percentage}%`;

  filterBatchTable(currentBatchFilter);
}

function filterBatchTable(filter, btn) {
  currentBatchFilter = filter;
  if (btn) {
    document.querySelectorAll("#tab-batch .channel-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
  }

  if (!batchDataCache || !batchDataCache.records) return;

  const tbody = document.getElementById("batchTableBody");
  tbody.innerHTML = "";

  const filtered = batchDataCache.records.filter(r => {
    if (filter === "spam") return r.is_spam;
    if (filter === "ham") return !r.is_spam;
    return true;
  });

  filtered.forEach(rec => {
    const tr = document.createElement("tr");
    const badgeClass = rec.is_spam ? "flag-badge HIGH" : "flag-badge";
    const badgeText = rec.is_spam ? "SPAM" : "SAFE";
    const badgeColor = rec.is_spam ? "background: rgba(239,68,68,0.2); color:#fca5a5;" : "background: rgba(16,185,129,0.2); color:#6ee7b7;";

    tr.innerHTML = `
      <td style="color: var(--text-muted); font-family: var(--font-mono);">${rec.id}</td>
      <td title="${htmlEscape(rec.full_text)}">${htmlEscape(rec.text)}</td>
      <td><span style="font-size: 0.72rem; font-weight: 700; padding: 2px 6px; border-radius: 4px; ${badgeColor}">${badgeText}</span></td>
      <td style="font-family: var(--font-mono); font-weight: 700; ${rec.is_spam ? 'color:#f87171;' : 'color:#34d399;'}">${rec.risk_score}%</td>
      <td style="font-size: 0.75rem; color: var(--text-secondary);">${htmlEscape(rec.category.replace(/_/g, " "))}</td>
    `;
    tbody.appendChild(tr);
  });
}

function downloadSampleCsv() {
  const sampleData = `message
"URGENT: Your PayPal account has been locked. Verify immediately at http://paypal-verify.xyz/login"
"Hi Alex, please find attached the revised budget report for tomorrow's standup."
"USPS: Package #US982103 held due to unpaid $1.50 clearance fee: http://usps-redelivery.top"
"Your doctor appointment is confirmed for Thursday at 10:30 AM. Reply 1 to confirm."
"Earn $5,000 weekly with AI crypto robot! Guaranteed 500% profit. Telegram: t.me/crypto_wealth"
"Hey Sarah, are we still meeting for lunch at Marco's at 1 PM?"
"Netflix: Your subscription has expired. Update payment here: http://netflix-billing.click"
"Thanks for sending over the pull request. Merged to main."
"Final Notice: Wells Fargo online access suspended. Confirm your SSN: http://wellsfargo-auth.top"
"Your flight DL 1892 to Chicago is boarding at Gate B14."
`;

  const blob = new Blob([sampleData], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "sample_spam_ham_dataset.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function exportBatchCsv() {
  if (!batchDataCache || !batchDataCache.records) {
    alert("No batch results to export. Run a scan first.");
    return;
  }

  let csvContent = "ID,Classification,Risk_Score,Category,Message\n";
  const filtered = batchDataCache.records.filter(r => {
    if (currentBatchFilter === "spam") return r.is_spam;
    if (currentBatchFilter === "ham") return !r.is_spam;
    return true;
  });

  filtered.forEach(r => {
    const safeText = `"${r.full_text.replace(/"/g, '""')}"`;
    csvContent += `${r.id},${r.is_spam ? "SPAM" : "HAM"},${r.risk_score}%,${r.category},${safeText}\n`;
  });

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `spamshield_results_${currentBatchFilter}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ================= Threat Telemetry =================
async function refreshTelemetry() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("metricScans").innerText = `${data.total_scans.toLocaleString()}`;
    document.getElementById("metricBlocked").innerText = `${data.block_rate_percentage}%`;

    const container = document.getElementById("categoryBarsContainer");
    if (container) {
      container.innerHTML = "";
      const categories = data.threat_distribution || {};
      const maxVal = Math.max(...Object.values(categories), 1);

      Object.entries(categories).forEach(([catName, count]) => {
        const pct = Math.round((count / maxVal) * 100);
        const row = document.createElement("div");
        row.className = "category-bar-row";
        row.innerHTML = `
          <div class="category-bar-header">
            <span>${catName.replace(/_/g, " ")}</span>
            <span style="font-family: var(--font-mono); color: var(--accent-cyan);">${count} hits</span>
          </div>
          <div class="category-bar-track">
            <div class="category-bar-fill" style="width: ${pct}%;"></div>
          </div>
        `;
        container.appendChild(row);
      });
    }

    // Health probe uptime
    const healthRes = await fetch("/api/health");
    if (healthRes.ok) {
      const hData = await healthRes.json();
      const mins = Math.floor(hData.uptime_seconds / 60);
      const secs = hData.uptime_seconds % 60;
      document.getElementById("telemetryUptime").innerText = `${mins}m ${secs}s`;
    }
  } catch (err) {
    console.warn("Telemetry refresh failed", err);
  }
}

// ================= Developer API Playground =================
const CODE_SNIPPETS = {
  curl: `curl -X POST "http://localhost:8000/api/scan" \\
     -H "Content-Type: application/json" \\
     -d '{
       "text": "URGENT: Your PayPal account has been suspended! Verify here: http://paypal-fake.xyz/login",
       "channel": "email"
     }'`,

  python: `import requests

url = "http://localhost:8000/api/scan"
payload = {
    "text": "URGENT: Your PayPal account has been suspended! Verify here: http://paypal-fake.xyz/login",
    "channel": "email"
}

response = requests.post(url, json=payload)
data = response.json()

print(f"Is Spam: {data['is_spam']}")
print(f"Risk Score: {data['risk_score']}% ({data['risk_level']})")
print(f"Identified Red Flags: {len(data['red_flags'])}")`,

  javascript: `const response = await fetch("http://localhost:8000/api/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    text: "URGENT: Your PayPal account has been suspended! Verify here: http://paypal-fake.xyz/login",
    channel: "email"
  })
});

const result = await response.json();
console.log("Threat Index:", result.risk_score);
console.log("Category:", result.category);`,

  nodejs: `const axios = require('axios');

async function checkSpam() {
  const { data } = await axios.post('http://localhost:8000/api/scan', {
    text: 'URGENT: Your PayPal account has been suspended! Verify here: http://paypal-fake.xyz/login',
    channel: 'email'
  });

  console.log('Result:', data.is_spam ? 'SPAM DETECTED' : 'CLEAN');
  console.log('Risk:', data.risk_score + '%');
}

checkSpam();`
};

function switchCodeSnippet(lang, btn) {
  activeSnippetLang = lang;
  document.querySelectorAll(".code-tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  renderCodeSnippet();
}

function renderCodeSnippet() {
  const pre = document.getElementById("codeSnippetDisplay");
  if (pre) {
    pre.innerText = CODE_SNIPPETS[activeSnippetLang] || CODE_SNIPPETS.curl;
  }
}

function copyActiveCodeSnippet() {
  const snippet = CODE_SNIPPETS[activeSnippetLang] || "";
  navigator.clipboard.writeText(snippet).then(() => {
    const btn = document.querySelector(".btn-copy");
    if (btn) {
      const orig = btn.innerText;
      btn.innerText = "Copied!";
      setTimeout(() => { btn.innerText = orig; }, 1500);
    }
  });
}

async function testLiveApiCall() {
  const display = document.getElementById("apiResponseDisplay");
  const wrapper = document.getElementById("apiResponseWrapper");
  wrapper.style.display = "block";
  display.innerText = "Sending POST /api/scan request...";

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "URGENT: Your PayPal account has been suspended! Verify here: http://paypal-fake.xyz/login",
        channel: "email"
      })
    });

    const json = await res.json();
    display.innerText = JSON.stringify(json, null, 2);
  } catch (err) {
    display.innerText = "Error: " + err.message;
  }
}

// Helper: Escape HTML
function htmlEscape(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Initialization on DOM Load
document.addEventListener("DOMContentLoaded", () => {
  updateCharCount();
  renderCodeSnippet();
  refreshTelemetry();
  // Auto refresh stats every 30 seconds
  setInterval(refreshTelemetry, 30000);
});
