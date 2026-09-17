/* API-SHIELD dashboard JS — polling, charts, report generation. */
(function () {
  "use strict";

  async function jfetch(url, options) {
    const resp = await fetch(url, options);
    let data = null;
    try { data = await resp.json(); } catch (e) { data = null; }
    if (!resp.ok) throw new Error((data && data.error && data.error.message) || ("HTTP " + resp.status));
    return data;
  }

  async function generateReport(format) {
    const btn = event && event.target;
    if (btn) btn.disabled = true;
    try {
      const r = await jfetch("/api/report/" + SCAN_ID, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: format }),
      });
      const dl = document.getElementById("dl-link");
      dl.href = "/api/report/" + SCAN_ID + "/download?format=" + format;
      dl.textContent = "Download " + format.toUpperCase() + " report";
      dl.className = "";
      const ta = document.createElement("a");
      ta.href = dl.href;
      ta.download = "";
      document.body.appendChild(ta);
      ta.click();
      ta.remove();
    } catch (err) {
      alert("Report generation failed: " + err.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function statCounts() {
    const map = {};
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].forEach(function (s) {
      const el = document.getElementById("c-" + s);
      if (el) map[s] = parseInt(el.textContent, 10) || 0;
    });
    return map;
  }

  function setStats(counts) {
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].forEach(function (s) {
      const el = document.getElementById("c-" + s);
      if (el && counts) el.textContent = counts[s] || 0;
    });
  }

  function drawCharts(chartsData) {
    if (typeof Chart === "undefined") return;
    const sev = document.getElementById("chart-severity");
    const owa = document.getElementById("chart-owasp");
    const scr = document.getElementById("chart-score");
    const ep = document.getElementById("chart-endpoints");
    if (!sev || !owa || !scr || !ep) return;

    const counts = chartsData.counts || statCounts();
    const owasp = chartsData.owasp || {};

    renderChart(sev, "doughnut", "Vulnerability Severity", counts, ["#ff5f5f", "#d64545", "#f0b429", "#2e86de", "#5c7a99"]);
    renderChart(owa, "bar", "OWASP Categories", owasp, ["#7cc4ff"]);
    renderChart(scr, "bar", "Security Score (0-100)", { "Score 0-100": chartsData.score }, ["#7cc4ff"]);
    renderChart(ep, "doughnut", "Endpoints", { Scanned: chartsData.endpoints_count || 0, "Not Scanned": 1 }, ["#2fb344", "#1f3a5c"]);
  }

  function renderChart(canvas, type, label, data, colors) {
    if (canvas._chart) canvas._chart.destroy();
    canvas._chart = new Chart(canvas, {
      type: type,
      data: {
        labels: Object.keys(data).length ? Object.keys(data) : ["No data"],
        datasets: [{ label: label, data: Object.keys(data).length ? Object.values(data) : [0], backgroundColor: colors }],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#c8d7e6", font: { size: 10 } } } },
        scales: type === "bar" ? { y: { beginAtZero: true, ticks: { color: "#9fb3c8" } }, x: { ticks: { color: "#9fb3c8", maxRotation: 45 } } } : {},
      },
    });
  }

  async function pollScan() {
    if (!window.SCAN_ID || SCAN_STATUS !== "running") return;
    try {
      const data = await jfetch("/api/scans/" + SCAN_ID);
      const scan = data.scan || {};
      const bar = document.getElementById("progress-bar");
      const msg = document.getElementById("progress-msg");
      if (bar) {
        const p = Math.round((scan.progress || 0) * 100);
        bar.style.width = p + "%";
      }
      if (msg) msg.textContent = scan.status === "completed" ? "Scan complete." : "Scanning…";
      if (scan.status === "completed" || scan.status === "failed") {
        setStats(scan.counts || {});
        drawCharts({ counts: scan.counts || {}, owasp: {}, score: scan.score || 0, endpoints_count: scan.endpoints_count || 0 });
        setTimeout(function () { window.location.reload(); }, 1200);
        return;
      }
    } catch (e) { /* transient polling error */ }
    setTimeout(pollScan, 2500);
  }

  async function loadLiveStats() {
    try {
      const data = await jfetch("/api/score/" + SCAN_ID);
      setStats(data.counts || {});
      drawCharts({
        counts: data.counts || {},
        owasp: data.owasp || {},
        score: data.score || 0,
        endpoints_count: data.endpoints_count || 0,
      });
    } catch (e) { /* no-op on page initial load for running scans */ }
  }

  function loadStaticOverview() {
    if (window.SCAN_ID && SCAN_STATUS === "completed") loadLiveStats();
  }

  document.addEventListener("DOMContentLoaded", function () {
    window.generateReport = generateReport;
    loadStaticOverview();
    pollScan();
  });
})();