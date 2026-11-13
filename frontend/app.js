const API_BASE = window.location.origin;

// Benchmark Snippets
const BENCHMARKS = {
  sql_injection: `import os
import sqlite3

def fetch_user_record(cursor, user_id):
    # CRITICAL: SQL Injection vulnerability via raw string formatting
    query = f"SELECT * FROM users WHERE username = '{user_id}' AND is_active = 1"
    cursor.execute(query)

    # CRITICAL: Remote command execution vulnerability
    os.system("echo User queried: " + user_id)

    try:
        val = int(user_id)
    except:
        # MAJOR: Bare except suppresses system signals
        pass

    return cursor.fetchall()
`,
  aws_secret: `import pickle
import hashlib
from math import *

# CRITICAL: Exposed cloud credential key
AWS_ACCESS_KEY = "AKIA1111222233334444"
DB_PASSWD = "super_insecure_hardcoded_password"

# MAJOR: Mutable default argument
def process_incoming_job(raw_payload, user_id, cache_list=[]):
    # CRITICAL: Insecure deserialization can execute arbitrary code
    data = pickle.loads(raw_payload)

    # MAJOR: Insecure hash function deprecated for cryptography
    sig = hashlib.md5(user_id.encode()).hexdigest()

    cache_list.append(data)
    return {"status": "ok", "hash": sig}
`,
  clean_code: `def binary_search(elements: list[int], target: int) -> int:
    """Performs an efficient binary search over a sorted integer array.

    Args:
        elements: Monotonically increasing list of integers.
        target: Target value to locate.

    Returns:
        Index of the target if found, otherwise -1.
    """
    left = 0
    right = len(elements) - 1

    while left <= right:
        mid = (left + right) // 2
        if elements[mid] == target:
            return mid
        elif elements[mid] < target:
            left = mid + 1
        else:
            right = mid - 1

    return -1
`
};

// DOM Elements
const metricTotal = document.getElementById("metric-total");
const metricCritical = document.getElementById("metric-critical");
const metricAvg = document.getElementById("metric-avg");

const repoNameInput = document.getElementById("repo-name");
const fileNameInput = document.getElementById("file-name");
const sampleSelect = document.getElementById("sample-select");
const codeEditor = document.getElementById("code-editor");
const btnRunAnalysis = document.getElementById("btn-run-analysis");

const reportTimestamp = document.getElementById("report-timestamp");
const gradeBadge = document.getElementById("grade-badge");
const scoreNumber = document.getElementById("score-number");
const pillCrit = document.getElementById("pill-crit");
const pillMaj = document.getElementById("pill-maj");
const pillMin = document.getElementById("pill-min");
const pillInfo = document.getElementById("pill-info");
const issuesContainer = document.getElementById("issues-container");

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  loadAnalytics();

  // Load default benchmark
  sampleSelect.value = "sql_injection";
  codeEditor.value = BENCHMARKS.sql_injection;
});

function setupEventListeners() {
  sampleSelect.addEventListener("change", (e) => {
    const val = e.target.value;
    if (BENCHMARKS[val]) {
      codeEditor.value = BENCHMARKS[val];
      if (val === "sql_injection") {
        fileNameInput.value = "user_service.py";
      } else if (val === "aws_secret") {
        fileNameInput.value = "worker_pipeline.py";
      } else {
        fileNameInput.value = "search_algorithms.py";
      }
    }
  });

  btnRunAnalysis.addEventListener("click", handleRunAnalysis);
}

async function loadAnalytics() {
  try {
    const res = await fetch(`${API_BASE}/api/analytics/review-summary`);
    if (!res.ok) return;
    const data = await res.json();
    metricTotal.textContent = data.total_reviews;
    metricCritical.textContent = data.critical_vulnerabilities_found;
    metricAvg.textContent = `${data.avg_score} / 100`;
  } catch (err) {
    console.error("Analytics fetch error:", err);
  }
}

async function handleRunAnalysis() {
  const code = codeEditor.value.trim();
  if (!code) {
    alert("Please enter or paste Python code to analyze.");
    return;
  }

  btnRunAnalysis.disabled = true;
  btnRunAnalysis.textContent = "Analyzing AST & Vulnerabilities...";

  const payload = {
    filename: fileNameInput.value.trim() || "app.py",
    repo_name: repoNameInput.value.trim() || "core-backend",
    code: codeEditor.value
  };

  try {
    const res = await fetch(`${API_BASE}/api/reviews/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      alert(`Review failed: ${err.detail || "Validation Error"}`);
      return;
    }

    const report = await res.json();
    displayReviewReport(report);
    await loadAnalytics();
  } catch (err) {
    alert(`Error: ${err.message}`);
  } finally {
    btnRunAnalysis.disabled = false;
    btnRunAnalysis.textContent = "⚡ Run CodeReview AI";
  }
}

function displayReviewReport(report) {
  reportTimestamp.textContent = `Analyzed ${report.created_at}`;

  // Grade & Score
  gradeBadge.className = `grade-badge ${report.grade.replace("+", "\\+")}`;
  gradeBadge.textContent = report.grade;
  scoreNumber.textContent = report.score;

  // Severity Counts
  let crit = 0, maj = 0, min = 0, info = 0;
  for (const iss of report.issues) {
    if (iss.severity === "CRITICAL") crit++;
    else if (iss.severity === "MAJOR") maj++;
    else if (iss.severity === "MINOR") min++;
    else if (iss.severity === "INFO") info++;
  }

  pillCrit.textContent = `${crit} Critical`;
  pillMaj.textContent = `${maj} Major`;
  pillMin.textContent = `${min} Minor`;
  pillInfo.textContent = `${info} Info`;

  // Render Issues
  if (report.issues.length === 0) {
    issuesContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✅</div>
        <h3 style="color:var(--accent-emerald);">All Checks Passed (100/100)</h3>
        <p>Zero static analysis defects, security vulnerabilities, or anti-patterns detected in source AST.</p>
      </div>
    `;
    return;
  }

  issuesContainer.innerHTML = report.issues.map(iss => `
    <div class="issue-card ${iss.severity}">
      <div class="issue-header">
        <span class="issue-rule ${iss.severity}">[${escapeHtml(iss.rule_id)}] ${iss.severity} · ${escapeHtml(iss.category)}</span>
        <span class="issue-line-badge">Line ${iss.line_number}</span>
      </div>
      <div class="issue-title">${escapeHtml(iss.title)}</div>
      <div class="issue-desc">${escapeHtml(iss.description)}</div>
      ${iss.suggested_fix ? `
        <div class="fix-box">
          <div class="fix-label">Recommended Fix:</div>
          <div class="fix-code">${escapeHtml(iss.suggested_fix)}</div>
        </div>
      ` : ''}
    </div>
  `).join("");
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
