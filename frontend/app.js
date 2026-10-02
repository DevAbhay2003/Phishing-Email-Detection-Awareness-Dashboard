/**
 * SentinelPhish Frontend Application Controller
 * Cybersecurity Project: Phishing Email Detection & Awareness Dashboard
 */

// Global State
let samplePresets = [];
let chartClassificationInstance = null;
let chartRiskDistInstance = null;
let chartIndicatorsInstance = null;
let debounceTimer = null;

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  fetchSamplePresets();
  setupFormHandlers();
  setupFileUpload();
  loadDashboardData();
  loadHistoryLogs();
});

/* ==========================================================================
   1. Tab Navigation
   ========================================================================== */
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetSection = document.getElementById(targetId);
      if (targetSection) {
        targetSection.classList.add("active");
      }

      // Re-render or fetch data when switching to Dashboard or History
      if (targetId === "tab-dashboard") {
        loadDashboardData();
      } else if (targetId === "tab-history") {
        loadHistoryLogs();
      }
    });
  });
}

/* ==========================================================================
   2. Sample Demonstrations
   ========================================================================== */
async function fetchSamplePresets() {
  try {
    const res = await fetch("/api/samples");
    const data = await res.json();
    if (data.success && data.samples) {
      samplePresets = data.samples;
    }
  } catch (err) {
    console.warn("Could not preload sample presets:", err);
  }
}

function loadSamplePreset(index) {
  if (!samplePresets || index >= samplePresets.length) return;
  const sample = samplePresets[index];

  document.getElementById("senderInput").value = sample.sender || "";
  document.getElementById("subjectInput").value = sample.subject || "";
  document.getElementById("bodyInput").value = sample.body || "";
  document.getElementById("urlsInput").value = sample.urls || "";
  document.getElementById("attachmentInput").value = sample.attachment_name || "";
  document.getElementById("expectedOrgInput").value = "";
  document.getElementById("selectedFileName").textContent = "";

  // Switch to analyzer tab if not already on it
  const analyzerTabBtn = document.querySelector('[data-tab="tab-analyzer"]');
  if (analyzerTabBtn && !analyzerTabBtn.classList.contains("active")) {
    analyzerTabBtn.click();
  }

  // Smooth scroll
  document.getElementById("emailAnalyzeForm").scrollIntoView({ behavior: "smooth" });
}

/* ==========================================================================
   3. File Upload & Drag/Drop
   ========================================================================== */
function setupFileUpload() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileUploadInput");
  const fileNameLabel = document.getElementById("selectedFileName");

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--accent-blue)";
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.style.borderColor = "var(--border-color)";
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--border-color)";
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      handleFileSelected(fileInput.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });
}

function handleFileSelected(file) {
  const fileNameLabel = document.getElementById("selectedFileName");
  fileNameLabel.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
}

/* ==========================================================================
   4. Email Analysis Submission
   ========================================================================== */
function setupFormHandlers() {
  const form = document.getElementById("emailAnalyzeForm");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await performAnalysis();
  });
}

async function performAnalysis() {
  const btn = document.getElementById("btnSubmitAnalyze");
  const originalBtnHtml = btn.innerHTML;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> TRIAGING THREAT...`;
  btn.disabled = true;

  const fileInput = document.getElementById("fileUploadInput");
  const hasFile = fileInput.files && fileInput.files.length > 0;

  try {
    let response;

    if (hasFile) {
      // Multipart Form Data for .eml/.txt file upload
      const formData = new FormData();
      formData.append("file", fileInput.files[0]);
      formData.append("sender", document.getElementById("senderInput").value);
      formData.append("subject", document.getElementById("subjectInput").value);
      formData.append("body", document.getElementById("bodyInput").value);
      formData.append("urls", document.getElementById("urlsInput").value);
      formData.append("attachment_name", document.getElementById("attachmentInput").value);
      formData.append("expected_org", document.getElementById("expectedOrgInput").value);

      response = await fetch("/api/analyze", {
        method: "POST",
        body: formData
      });
    } else {
      // JSON Payload
      const payload = {
        sender: document.getElementById("senderInput").value,
        subject: document.getElementById("subjectInput").value,
        body: document.getElementById("bodyInput").value,
        urls: document.getElementById("urlsInput").value,
        attachment_name: document.getElementById("attachmentInput").value,
        expected_org: document.getElementById("expectedOrgInput").value
      };

      response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    }

    const data = await response.json();

    if (!response.ok || !data.success) {
      alert(`Triage Error: ${data.error || "Failed to analyze email"}`);
      return;
    }

    renderAnalysisResults(data);
  } catch (err) {
    console.error("Analysis request error:", err);
    alert("Connection error: Could not reach SentinelPhish backend service.");
  } finally {
    btn.innerHTML = originalBtnHtml;
    btn.disabled = false;
  }
}

function renderAnalysisResults(res) {
  document.getElementById("emptyStatePlaceholder").style.display = "none";
  const resultContainer = document.getElementById("analysisResultContent");
  resultContainer.style.display = "block";

  // 1. Score and Classification
  const scoreDisplay = document.getElementById("riskScoreDisplay");
  scoreDisplay.textContent = res.risk_score;
  scoreDisplay.style.color = res.color_code;

  const classTag = document.getElementById("classificationTag");
  classTag.textContent = res.classification;
  classTag.style.backgroundColor = `${res.color_code}22`;
  classTag.style.color = res.color_code;
  classTag.style.border = `1px solid ${res.color_code}`;

  document.getElementById("threatLevelDisplay").textContent = `Assessed Tier: ${res.threat_level}`;

  // 2. Hybrid Metrics Breakdown
  document.getElementById("ruleScoreVal").textContent = res.rule_score;
  const mlProb = res.ml_assessment && res.ml_assessment.percentage !== undefined
    ? `${res.ml_assessment.percentage}% (${res.ml_assessment.label})`
    : "N/A";
  document.getElementById("mlProbVal").textContent = mlProb;

  // 3. Explainable Indicators ("WHY?")
  const indicatorsList = document.getElementById("indicatorsList");
  indicatorsList.innerHTML = "";

  if (res.indicators && res.indicators.length > 0) {
    res.indicators.forEach(ind => {
      const item = document.createElement("div");
      item.className = `indicator-item ${ind.severity}`;
      item.innerHTML = `
        <span class="ind-points" style="color: ${res.color_code}">+${ind.points} pts</span>
        <div>
          <strong>${ind.type}:</strong> ${escapeHtml(ind.description)}
        </div>
      `;
      indicatorsList.appendChild(item);
    });
  } else {
    indicatorsList.innerHTML = `<div class="indicator-item LOW"><span>✓</span> Zero high-risk social engineering or malicious patterns detected.</div>`;
  }

  // 4. Sender Analysis Breakdown
  const senderList = document.getElementById("senderFindingsList");
  senderList.innerHTML = "";
  const sRes = res.sender_analysis || {};
  document.getElementById("senderScoreBadge").textContent = `${sRes.sender_risk_score || 0}/100`;

  if (sRes.findings && sRes.findings.length > 0) {
    sRes.findings.forEach(f => {
      const li = document.createElement("li");
      li.textContent = f;
      senderList.appendChild(li);
    });
  }

  // 5. Attachment Analysis Breakdown
  const attList = document.getElementById("attachmentFindingsList");
  attList.innerHTML = "";
  const aRes = res.attachment_analysis || {};
  document.getElementById("attachmentScoreBadge").textContent = `${aRes.attachment_risk_score || 0}/100`;

  if (aRes.findings && aRes.findings.length > 0) {
    aRes.findings.forEach(f => {
      const li = document.createElement("li");
      li.textContent = f;
      attList.appendChild(li);
    });
  }

  // 6. URL Static Analyses
  const urlContainer = document.getElementById("urlAnalysisList");
  urlContainer.innerHTML = "";
  const urls = res.url_analyses || [];

  if (urls.length === 0) {
    urlContainer.innerHTML = `<p style="font-size: 12px; color: var(--text-dim); margin-top: 4px;">No hyperlinks detected in the message.</p>`;
  } else {
    urls.forEach(u => {
      const urlCard = document.createElement("div");
      urlCard.className = "url-card";

      let badgeColor = "#10b981";
      if (u.url_risk_score >= 40) badgeColor = "#ef4444";
      else if (u.url_risk_score >= 20) badgeColor = "#f97316";

      const findingsHtml = u.findings.map(f => `<li>• ${escapeHtml(f)}</li>`).join("");

      urlCard.innerHTML = `
        <div class="url-header">
          <span class="url-string">${escapeHtml(u.url)}</span>
          <span class="url-risk-tag" style="background: ${badgeColor}22; color: ${badgeColor}; border: 1px solid ${badgeColor}">
            Score: ${u.url_risk_score}/100
          </span>
        </div>
        <ul style="list-style: none; font-size: 11px; color: var(--text-muted); margin-top: 6px;">
          ${findingsHtml}
        </ul>
      `;
      urlContainer.appendChild(urlCard);
    });
  }

  // 7. Defensive Recommendations
  const recList = document.getElementById("recommendationsList");
  recList.innerHTML = "";
  const recs = res.recommendations || [];
  recs.forEach(r => {
    const li = document.createElement("li");
    li.innerHTML = `<i class="fa-solid fa-shield-check"></i> <span>${escapeHtml(r)}</span>`;
    recList.appendChild(li);
  });

  // Smooth scroll down to view findings on mobile
  if (window.innerWidth < 1024) {
    resultContainer.scrollIntoView({ behavior: "smooth" });
  }
}

function resetAnalyzerForm() {
  document.getElementById("emailAnalyzeForm").reset();
  document.getElementById("selectedFileName").textContent = "";
  document.getElementById("emptyStatePlaceholder").style.display = "block";
  document.getElementById("analysisResultContent").style.display = "none";
}

/* ==========================================================================
   5. Security Analytics Dashboard (Chart.js)
   ========================================================================== */
async function loadDashboardData() {
  try {
    const [statsRes, indRes] = await Promise.all([
      fetch("/api/dashboard/stats"),
      fetch("/api/dashboard/indicators")
    ]);

    const stats = await statsRes.json();
    const indData = await indRes.json();

    if (stats.success) {
      document.getElementById("kpiTotal").textContent = stats.total_analyzed;
      document.getElementById("kpiHigh").textContent = stats.high_risk;
      document.getElementById("kpiSuspicious").textContent = stats.suspicious;
      document.getElementById("kpiModerate").textContent = stats.moderate_risk;
      document.getElementById("kpiLow").textContent = stats.low_risk;
      document.getElementById("kpiAvgScore").textContent = stats.average_risk_score;

      renderClassificationChart(stats.classification_breakdown);
      renderRiskDistChart(stats.risk_distribution);
    }

    if (indData.success && indData.top_indicators) {
      renderIndicatorsChart(indData.top_indicators);
    }
  } catch (err) {
    console.error("Dashboard data load error:", err);
  }
}

function renderClassificationChart(breakdown) {
  const ctx = document.getElementById("chartClassification").getContext("2d");
  const labels = Object.keys(breakdown);
  const data = Object.values(breakdown);

  if (chartClassificationInstance) {
    chartClassificationInstance.destroy();
  }

  chartClassificationInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: [
          "#ef4444", // High Risk (Red)
          "#f97316", // Suspicious (Orange)
          "#eab308", // Moderate (Yellow)
          "#10b981"  // Low (Green)
        ],
        borderColor: "#131d36",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#94a3b8", font: { size: 11 } }
        }
      }
    }
  });
}

function renderRiskDistChart(dist) {
  const ctx = document.getElementById("chartRiskDistribution").getContext("2d");
  const labels = Object.keys(dist);
  const data = Object.values(dist);

  if (chartRiskDistInstance) {
    chartRiskDistInstance.destroy();
  }

  chartRiskDistInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Emails in Range",
        data: data,
        backgroundColor: "#3b82f6",
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "rgba(255,255,255,0.05)" } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderIndicatorsChart(indicators) {
  const ctx = document.getElementById("chartIndicators").getContext("2d");
  const labels = indicators.map(i => i.indicator.replace("CONTENT_", "").replace("URL_", "").replace("_", " "));
  const data = indicators.map(i => i.count);

  if (chartIndicatorsInstance) {
    chartIndicatorsInstance.destroy();
  }

  chartIndicatorsInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Frequency Triggered",
        data: data,
        backgroundColor: "#06b6d4",
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#94a3b8", font: { size: 11 } }, grid: { color: "rgba(255,255,255,0.05)" } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

/* ==========================================================================
   6. Phishing Awareness Checklist
   ========================================================================== */
function updateChecklistScore() {
  const boxes = document.querySelectorAll(".checklist-box");
  const checked = Array.from(boxes).filter(b => b.checked).length;
  const resultDiv = document.getElementById("checklistResult");

  if (checked === 5) {
    resultDiv.style.background = "rgba(16, 185, 129, 0.15)";
    resultDiv.style.borderColor = "#10b981";
    resultDiv.style.color = "#86efac";
    resultDiv.innerHTML = `<strong>High Defensive Vigilance (5/5 checks passed):</strong> The email passes all primary safety hygiene checks. Exercise normal security awareness.`;
  } else if (checked >= 3) {
    resultDiv.style.background = "rgba(234, 179, 8, 0.15)";
    resultDiv.style.borderColor = "#eab308";
    resultDiv.style.color = "#fef08a";
    resultDiv.innerHTML = `<strong>Caution Required (${checked}/5 checks passed):</strong> Some security warning signs are present. Do not click links or open attachments before confirming out-of-band.`;
  } else {
    resultDiv.style.background = "rgba(239, 68, 68, 0.15)";
    resultDiv.style.borderColor = "#ef4444";
    resultDiv.style.color = "#fca5a5";
    resultDiv.innerHTML = `<strong>High Phishing Alert (${checked}/5 checks passed):</strong> Multiple red flags identified! Treat this communication as a likely social engineering threat.`;
  }
}

/* ==========================================================================
   7. Threat History Log & Telemetry Modal
   ========================================================================== */
function filterHistoryDebounced() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    loadHistoryLogs();
  }, 300);
}

async function loadHistoryLogs() {
  const search = document.getElementById("historySearchInput")?.value || "";
  const classification = document.getElementById("historyClassificationFilter")?.value || "";
  const sort = document.getElementById("historySortSelect")?.value || "newest";

  const url = `/api/analyses?search=${encodeURIComponent(search)}&classification=${encodeURIComponent(classification)}&sort=${sort}`;

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById("historyTableBody");
    tbody.innerHTML = "";

    if (!data.success || !data.analyses || data.analyses.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 24px; color: var(--text-dim);">No matching analysis audit records found.</td></tr>`;
      return;
    }

    data.analyses.forEach(item => {
      const tr = document.createElement("tr");

      let badgeColor = "#10b981";
      if (item.classification.includes("HIGH RISK")) badgeColor = "#ef4444";
      else if (item.classification === "SUSPICIOUS") badgeColor = "#f97316";
      else if (item.classification === "MODERATE RISK") badgeColor = "#eab308";

      const timeStr = item.created_at ? item.created_at.replace("T", " ").substring(0, 19) : "N/A";
      const domainStr = item.sender_domain || "Unknown Domain";
      const subjStr = item.subject || "No Subject";
      const attStr = item.attachment_name || "-";

      tr.innerHTML = `
        <td><code>#${item.analysis_id}</code></td>
        <td style="color: var(--text-muted); font-size: 11px;">${timeStr}</td>
        <td><code>${escapeHtml(domainStr)}</code></td>
        <td style="max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(subjStr)}">
          ${escapeHtml(subjStr)}
        </td>
        <td><strong style="color: ${badgeColor}; font-family: 'JetBrains Mono', monospace;">${item.risk_score}/100</strong></td>
        <td><span class="badge-tag" style="background: ${badgeColor}22; color: ${badgeColor}; border: 1px solid ${badgeColor}">${escapeHtml(item.classification)}</span></td>
        <td><code>${escapeHtml(attStr)}</code></td>
        <td>
          <button class="btn-sm" onclick="inspectAnalysis(${item.analysis_id})" title="Inspect Findings"><i class="fa-solid fa-eye"></i></button>
          <button class="btn-sm btn-danger" onclick="deleteAnalysisRecord(${item.analysis_id})" title="Delete Record"><i class="fa-solid fa-trash-can"></i></button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load history logs:", err);
  }
}

async function inspectAnalysis(id) {
  try {
    const res = await fetch(`/api/analyses/${id}`);
    const data = await res.json();
    if (!data.success || !data.analysis) {
      alert("Could not load telemetry details.");
      return;
    }

    const a = data.analysis;
    const modalBody = document.getElementById("modalBodyContent");

    const indHtml = a.indicators.length > 0
      ? a.indicators.map(i => `<li>• <strong>${escapeHtml(i.indicator_type)}</strong> (${i.severity}): ${escapeHtml(i.description)}</li>`).join("")
      : "<li>No specific indicators recorded.</li>";

    const urlHtml = a.url_analyses.length > 0
      ? a.url_analyses.map(u => `<li>• <code>${escapeHtml(u.url)}</code> (Score: ${u.risk_score})</li>`).join("")
      : "<li>No URLs associated.</li>";

    modalBody.innerHTML = `
      <div style="margin-bottom: 14px;">
        <h4 style="color: #fff; font-size: 15px; margin-bottom: 4px;">${escapeHtml(a.subject)}</h4>
        <p style="font-size: 11px; color: var(--text-dim);">Analysis ID: #${a.analysis_id} &bull; Recorded: ${a.created_at}</p>
      </div>

      <div style="display: flex; gap: 16px; margin-bottom: 16px;">
        <div><strong>Sender Domain:</strong> <code>${escapeHtml(a.sender_domain || "N/A")}</code></div>
        <div><strong>Risk Score:</strong> <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #38bdf8;">${a.risk_score}/100</span></div>
        <div><strong>Tier:</strong> <span class="badge-tag">${escapeHtml(a.classification)}</span></div>
      </div>

      <h5 style="color: var(--accent-cyan); margin: 12px 0 6px;">Triggered Evidentiary Indicators:</h5>
      <ul style="list-style: none; font-size: 12px; color: #cbd5e1; display: flex; flex-direction: column; gap: 4px;">
        ${indHtml}
      </ul>

      <h5 style="color: var(--accent-cyan); margin: 14px 0 6px;">Analyzed Hyperlinks:</h5>
      <ul style="list-style: none; font-size: 12px; color: #cbd5e1; display: flex; flex-direction: column; gap: 4px;">
        ${urlHtml}
      </ul>
    `;

    document.getElementById("detailModal").classList.add("active");
  } catch (err) {
    console.error("Inspect error:", err);
  }
}

async function deleteAnalysisRecord(id) {
  if (!confirm(`Delete audit log #${id}?`)) return;
  try {
    const res = await fetch(`/api/analyses/${id}`, { method: "DELETE" });
    const data = await res.json();
    if (data.success) {
      loadHistoryLogs();
      loadDashboardData();
    } else {
      alert(`Delete failed: ${data.error}`);
    }
  } catch (err) {
    console.error("Delete error:", err);
  }
}

function closeModal() {
  document.getElementById("detailModal").classList.remove("active");
}

// Close modal on click outside dialog
window.addEventListener("click", (e) => {
  const modal = document.getElementById("detailModal");
  if (e.target === modal) {
    closeModal();
  }
});

/* Helper: Escape HTML to prevent XSS in dynamic rendering */
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
