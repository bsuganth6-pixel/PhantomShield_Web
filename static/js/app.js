// PhantomShield AI — Shared frontend utilities

const PS = {
  // ── Escape user content before injecting into innerHTML ──
  esc(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  },

  // ── Severity → badge class ──
  sevClass(sev) {
    const s = (sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "badge-high";
    if (s === "medium") return "badge-medium";
    if (s === "low") return "badge-low";
    return "badge-neutral";
  },

  badge(sev) {
    return `<span class="badge ${this.sevClass(sev)}">${this.esc(sev || "INFO")}</span>`;
  },

  // ── Color for a 0-100 risk score ──
  scoreColor(score) {
    if (score >= 70) return "#FF3B5C";
    if (score >= 40) return "#FFD23F";
    if (score >= 15) return "#00F5FF";
    return "#00FF88";
  },

  // ── Render an SVG circular gauge for a 0-100 score ──
  gauge(score, label = "RISK") {
    const r = 45, c = 2 * Math.PI * r;
    const offset = c - (score / 100) * c;
    const color = this.scoreColor(score);
    return `
      <div class="gauge">
        <svg width="110" height="110" viewBox="0 0 110 110">
          <circle class="gauge-bg" cx="55" cy="55" r="${r}"></circle>
          <circle class="gauge-fill" cx="55" cy="55" r="${r}"
            stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${offset}"></circle>
        </svg>
        <div class="gauge-label">
          <span class="gauge-num" style="color:${color}">${score}</span>
          <span class="gauge-max">${label}</span>
        </div>
      </div>`;
  },

  // ── Render an indicator/finding card ──
  indicator(item) {
    const sev = (item.severity || "info").toLowerCase();
    const icon = sev === "high" || sev === "critical" ? "triangle-exclamation"
               : sev === "medium" ? "circle-exclamation" : "circle-info";
    return `
      <div class="indicator sev-${sev}">
        <div class="indicator-icon"><i class="fa-solid fa-${icon}"></i></div>
        <div class="indicator-body">
          <strong>${this.esc(item.type)} ${this.badge(item.severity)}</strong>
          <span>${this.esc(item.detail)}</span>
        </div>
      </div>`;
  },

  // ── POST JSON helper ──
  async postJSON(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    return resp.json();
  },

  async postForm(url, formData) {
    const resp = await fetch(url, { method: "POST", body: formData });
    return resp.json();
  },

  setLoading(loaderEl, btnEl, isLoading) {
    if (loaderEl) loaderEl.classList.toggle("active", isLoading);
    if (btnEl) btnEl.disabled = isLoading;
  },
};

// ── Check configured API keys on load, update sidebar pill ──
(async function checkStatus() {
  const pill = document.getElementById("api-status-text");
  const dot = document.querySelector("#api-status-pill .dot");
  if (!pill) return;
  try {
    const data = await (await fetch("/api/status")).json();
    const liveCount = Object.values(data).filter(Boolean).length;
    pill.textContent = liveCount > 0
      ? `${liveCount} live API${liveCount > 1 ? "s" : ""} connected`
      : "Offline mode (heuristics only)";
    if (dot) dot.style.background = liveCount > 0 ? "#00FF88" : "#FFD23F";
  } catch (e) {
    pill.textContent = "Backend unreachable";
    if (dot) dot.style.background = "#FF3B5C";
  }
})();
