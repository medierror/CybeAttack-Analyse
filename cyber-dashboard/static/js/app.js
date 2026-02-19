/**
 * CyberShield Dashboard — Frontend Logic
 * Handles drag-and-drop upload, AJAX submission, chart rendering, and history.
 */

// ═══════════════════════════════════════════════════════════
//  DOM REFERENCES
// ═══════════════════════════════════════════════════════════

const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const fileName = document.getElementById('file-name');
const fileSize = document.getElementById('file-size');
const fileRemove = document.getElementById('file-remove');
const scanBtn = document.getElementById('scan-btn');
const progressBar = document.getElementById('progress-bar');
const progressText = document.getElementById('progress-text');
const resultsSection = document.getElementById('results-section');
const historyList = document.getElementById('history-list');

let selectedFile = null;
let attackChart = null;
let severityChart = null;

// ═══════════════════════════════════════════════════════════
//  FILE SELECTION (click + drag-and-drop)
// ═══════════════════════════════════════════════════════════

uploadZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) selectFile(e.target.files[0]);
});

// Drag events
['dragenter', 'dragover'].forEach(evt => {
    uploadZone.addEventListener(evt, (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
});

['dragleave', 'drop'].forEach(evt => {
    uploadZone.addEventListener(evt, (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
    });
});

uploadZone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files.length > 0) selectFile(e.dataTransfer.files[0]);
});

function selectFile(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['txt', 'log', 'csv'].includes(ext)) {
        alert('Unsupported file type. Please upload .txt, .log, or .csv files.');
        return;
    }
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    fileInfo.style.display = 'flex';
    scanBtn.disabled = false;
}

fileRemove.addEventListener('click', () => {
    selectedFile = null;
    fileInput.value = '';
    fileInfo.style.display = 'none';
    scanBtn.disabled = true;
});

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ═══════════════════════════════════════════════════════════
//  ASYNC FILE UPLOAD (Fetch API)
// ═══════════════════════════════════════════════════════════

scanBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    // Show progress, disable button
    scanBtn.disabled = true;
    progressBar.style.display = 'block';
    progressText.textContent = 'Uploading file...';
    resultsSection.style.display = 'none';

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        progressText.textContent = 'Analyzing log file for threats...';

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Upload failed');
        }

        progressText.textContent = 'Scan complete! Rendering results...';

        // Small delay for visual feedback
        await new Promise(resolve => setTimeout(resolve, 500));

        // Hide progress, show results
        progressBar.style.display = 'none';
        renderResults(data);

        // Reset file input
        selectedFile = null;
        fileInput.value = '';
        fileInfo.style.display = 'none';
        scanBtn.disabled = true;

        // Refresh history
        loadHistory();

    } catch (error) {
        progressBar.style.display = 'none';
        scanBtn.disabled = false;
        alert('Error: ' + error.message);
        console.error('Upload error:', error);
    }
});

// ═══════════════════════════════════════════════════════════
//  RENDER RESULTS
// ═══════════════════════════════════════════════════════════

function renderResults(data) {
    resultsSection.style.display = 'block';

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Update filename
    document.getElementById('results-filename').textContent = `— ${data.filename}`;

    // Update stat cards with animation
    animateCounter('stat-total-lines', data.total_lines);
    animateCounter('stat-attacks', data.total_attacks);
    animateCounter('stat-clean', data.clean_lines);

    // Threat level
    const level = getThreatLevel(data.total_attacks, data.total_lines);
    const levelEl = document.getElementById('stat-threat-level');
    levelEl.textContent = level.label;
    levelEl.style.color = level.color;

    // Charts
    renderAttackChart(data.attack_summary);
    renderSeverityChart(data.severity_summary);

    // Threat table
    renderThreatTable(data.threats);
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    const duration = 800;
    const start = performance.now();
    const startVal = 0;

    function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(startVal + (target - startVal) * eased).toLocaleString();
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

function getThreatLevel(attacks, total) {
    if (attacks === 0) return { label: 'Safe', color: '#10b981' };
    const ratio = attacks / total;
    if (ratio < 0.05) return { label: 'Low', color: '#3b82f6' };
    if (ratio < 0.15) return { label: 'Medium', color: '#f59e0b' };
    if (ratio < 0.35) return { label: 'High', color: '#ef4444' };
    return { label: 'Critical', color: '#ec4899' };
}

// ═══════════════════════════════════════════════════════════
//  CHART.JS RENDERING
// ═══════════════════════════════════════════════════════════

const chartColors = [
    '#00f0ff', '#7b61ff', '#ef4444', '#f59e0b',
    '#10b981', '#ec4899', '#3b82f6', '#8b5cf6',
];

function renderAttackChart(attackSummary) {
    const canvas = document.getElementById('chart-attack-types');
    const labels = Object.keys(attackSummary);
    const values = Object.values(attackSummary);

    // Destroy old chart
    if (attackChart) attackChart.destroy();

    if (labels.length === 0) {
        canvas.parentElement.innerHTML = `
            <div class="no-attacks">
                <div class="no-attacks__icon">✅</div>
                <div class="no-attacks__text">No attacks detected</div>
                <div class="no-attacks__sub">All log lines appear clean</div>
            </div>`;
        return;
    }

    attackChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: chartColors.slice(0, labels.length),
                borderWidth: 0,
                hoverOffset: 8,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca3af',
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 10,
                        font: { family: "'Inter', sans-serif", size: 12 },
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleColor: '#00f0ff',
                    bodyColor: '#e5e7eb',
                    borderColor: 'rgba(0, 240, 255, 0.2)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                    titleFont: { family: "'Inter', sans-serif", weight: 600 },
                    bodyFont: { family: "'Inter', sans-serif" },
                },
            },
        },
    });
}

function renderSeverityChart(severitySummary) {
    const canvas = document.getElementById('chart-severity');
    const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
    const severityColors = {
        'Critical': '#ef4444',
        'High': '#f59e0b',
        'Medium': '#3b82f6',
        'Low': '#10b981',
    };

    const labels = [];
    const values = [];
    const colors = [];

    for (const sev of severityOrder) {
        if (severitySummary[sev]) {
            labels.push(sev);
            values.push(severitySummary[sev]);
            colors.push(severityColors[sev]);
        }
    }

    // Destroy old chart
    if (severityChart) severityChart.destroy();

    if (labels.length === 0) {
        canvas.parentElement.innerHTML = `
            <div class="no-attacks">
                <div class="no-attacks__icon">🛡️</div>
                <div class="no-attacks__text">All clear</div>
                <div class="no-attacks__sub">No severity data to display</div>
            </div>`;
        return;
    }

    severityChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
                data: values,
                backgroundColor: colors.map(c => c + '33'),
                borderColor: colors,
                borderWidth: 2,
                borderRadius: 6,
                barPercentage: 0.6,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#9ca3af', font: { family: "'Inter', sans-serif" } },
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#e5e7eb', font: { family: "'Inter', sans-serif", weight: 600 } },
                },
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleColor: '#00f0ff',
                    bodyColor: '#e5e7eb',
                    borderColor: 'rgba(0, 240, 255, 0.2)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                },
            },
        },
    });
}

// ═══════════════════════════════════════════════════════════
//  THREAT TABLE
// ═══════════════════════════════════════════════════════════

function renderThreatTable(threats) {
    const tbody = document.getElementById('threat-tbody');
    const countEl = document.getElementById('threat-count');
    countEl.textContent = threats.length;

    if (threats.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:32px;color:#10b981;">
            ✅ No threats detected — file is clean!</td></tr>`;
        return;
    }

    tbody.innerHTML = threats.map((t, i) => `
        <tr>
            <td>${i + 1}</td>
            <td style="font-family:var(--font-mono);color:var(--accent-cyan);">${t.line_number}</td>
            <td><span class="attack-badge">${escapeHtml(t.attack_type)}</span></td>
            <td><span class="severity-badge severity-badge--${t.severity.toLowerCase()}">${t.severity}</span></td>
            <td style="font-family:var(--font-mono);font-size:0.78rem;">${escapeHtml(t.matched_pattern || '—')}</td>
            <td title="${escapeHtml(t.raw_line)}">${escapeHtml(truncate(t.raw_line, 80))}</td>
        </tr>
    `).join('');
}

// ═══════════════════════════════════════════════════════════
//  SCAN HISTORY
// ═══════════════════════════════════════════════════════════

async function loadHistory() {
    try {
        const res = await fetch('/api/history');
        const scans = await res.json();

        if (scans.length === 0) {
            historyList.innerHTML = '<p class="history-empty">No scans yet. Upload a log file to begin.</p>';
            return;
        }

        historyList.innerHTML = scans.map(s => `
            <div class="history-item" data-scan-id="${s.id}">
                <div class="history-item__name">${escapeHtml(s.filename)}</div>
                <div class="history-item__meta">
                    <span class="history-item__attacks ${s.total_attacks === 0 ? 'history-item__attacks--clean' : ''}">
                        ${s.total_attacks === 0 ? '✓ Clean' : `⚠ ${s.total_attacks} threats`}
                    </span>
                    <span>${formatDate(s.upload_time)}</span>
                </div>
            </div>
        `).join('');

        // Click handler for history items
        historyList.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', () => loadScan(item.dataset.scanId));
        });

    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

async function loadScan(scanId) {
    try {
        const res = await fetch(`/api/scan/${scanId}`);
        const data = await res.json();
        renderResults(data);
    } catch (err) {
        console.error('Failed to load scan:', err);
    }
}

// ═══════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '…' : str;
}

function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    loadHistory();
});
