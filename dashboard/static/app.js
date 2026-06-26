const state = {
  config: null,
  form: { app: {}, attack: {} },
  currentRun: null,
  history: [],
  eventSource: null,
  artifactCache: new Map(),
  sidebarCollapsed: false,
  activeHistoryRun: null,
  autoOpenResults: false,
  lastHistoryLoadAt: 0,
  dismissedReportOverlayRunId: null,
};

const shellEl = document.querySelector(".shell");
const views = document.querySelectorAll(".view");
const navLinks = document.querySelectorAll(".nav-link");
const configGroupsEl = document.querySelector("#config-groups");
const tomlPreviewEl = document.querySelector("#toml-preview");
const configNotesEl = document.querySelector("#config-notes");
const statusSummaryEl = document.querySelector("#status-summary");
const historyListEl = document.querySelector("#history-list");
const roundNowEl = document.querySelector("#round-now");
const roundTotalEl = document.querySelector("#round-total");
const runStateEl = document.querySelector("#run-state");
const roundProgressEl = document.querySelector("#round-progress");
const serverAccuracyChartEl = document.querySelector("#server-accuracy-chart");
const serverLossChartEl = document.querySelector("#server-loss-chart");
const serverAsrChartEl = document.querySelector("#server-asr-chart");
const trainChartEl = document.querySelector("#train-chart");
const attackFeedEl = document.querySelector("#attack-feed");
const defenseFeedEl = document.querySelector("#defense-feed");
const logConsoleEl = document.querySelector("#log-console");
const resultSummaryEl = document.querySelector("#result-summary");
const artifactGroupsEl = document.querySelector("#artifact-groups");
const sidebarToggleEl = document.querySelector("#sidebar-toggle");
const llmSummaryPreviewEl = document.querySelector("#llm-summary-preview");
const attackSummaryPreviewEl = document.querySelector("#attack-summary-preview");
const openLlmReportEl = document.querySelector("#open-llm-report");
const openAttackReportEl = document.querySelector("#open-attack-report");
const modalOverlayEl = document.querySelector("#modal-overlay");
const modalTitleEl = document.querySelector("#modal-title");
const modalBodyEl = document.querySelector("#modal-body");
const modalCloseEl = document.querySelector("#modal-close");
const reportOverlayEl = document.querySelector("#report-overlay");
const reportOverlayCloseEl = document.querySelector("#report-overlay-close");

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed: ${response.status}`);
  }
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? response.json() : response.text();
}

function serializeValue(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  return JSON.stringify(value ?? "");
}

function titleCase(value) {
  return String(value ?? "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b([a-z])/g, (match) => match.toUpperCase());
}

function clientLabelForId(id, clientNumberMap = {}) {
  const normalized = String(id || "").replace(/\*$/, "").trim();
  const clientNumber = clientNumberMap?.[normalized];
  if (!clientNumber) return null;
  return `Client ${clientNumber}`;
}

function datasetLabel(value) {
  const option = state.config?.groups
    ?.flatMap((group) => group.fields || [])
    ?.find((field) => field.scope === "app" && field.key === "dataset")
    ?.options?.find((optionValue) => (
      typeof optionValue === "string" ? optionValue === value : optionValue.value === value
    ));
  if (!option) return titleCase(value);
  return typeof option === "string" ? titleCase(option) : option.label;
}

function compactPath(path) {
  if (!path) return "Pending";
  const normalized = String(path).replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  if (!parts.length) return normalized;
  if (parts.length === 1) return parts[0];
  return `${parts[Math.max(0, parts.length - 2)]}/${parts[parts.length - 1]}`;
}

function formatRunName(run) {
  const strategy = titleCase(run?.strategy || run?.meta?.strategy || "");
  const dataset = datasetLabel(run?.dataset || run?.meta?.dataset || "");
  const timestamp = run?.timestamp || run?.meta?.timestamp || "";
  if (strategy || dataset || timestamp) {
    return [strategy, dataset, timestamp].filter(Boolean).join(" · ");
  }
  return titleCase(run?.name || run?.path || "Run");
}

function renderTomlPreview() {
  if (!state.config) return;
  const app = { ...state.config.defaults.app, ...state.form.app };
  const attack = { ...state.config.defaults.attack, ...state.form.attack };
  const lines = ["[tool.flwr.app.config]"];
  Object.keys(app).sort().forEach((key) => lines.push(`${key} = ${serializeValue(app[key])}`));
  lines.push("", "[tool.flwr.attack]");
  Object.keys(attack).sort().forEach((key) => lines.push(`${key} = ${serializeValue(attack[key])}`));
  tomlPreviewEl.textContent = lines.join("\n");
}

function getValue(scope, key) {
  return state.form[scope][key];
}

function setValue(scope, key, value) {
  state.form[scope][key] = value;
  renderTomlPreview();
}

function buildField(field) {
  const template = document.querySelector("#field-template");
  const node = template.content.firstElementChild.cloneNode(true);
  node.querySelector(".field-label").textContent = field.label || titleCase(field.key);
  const host = node.querySelector(".field-control");
  const value = getValue(field.scope, field.key);

  if (field.type === "boolean") {
    const wrapper = document.createElement("div");
    wrapper.className = "checkbox-row";
    const control = document.createElement("input");
    control.type = "checkbox";
    control.checked = Boolean(value);
    const text = document.createElement("span");
    text.textContent = control.checked ? "Enabled" : "Disabled";
    control.addEventListener("change", () => {
      setValue(field.scope, field.key, control.checked);
      text.textContent = control.checked ? "Enabled" : "Disabled";
    });
    wrapper.append(control, text);
    host.appendChild(wrapper);
    return node;
  }

  const control = document.createElement(field.type === "select" ? "select" : "input");
  if (field.type === "select") {
    field.options.forEach((option) => {
      const opt = document.createElement("option");
      if (typeof option === "string") {
        opt.value = option;
        opt.textContent = option;
      } else {
        opt.value = option.value;
        opt.textContent = option.label;
      }
      if (String(value) === opt.value) opt.selected = true;
      control.appendChild(opt);
    });
    control.addEventListener("change", () => setValue(field.scope, field.key, control.value));
  } else {
    control.type = field.type === "number" ? "number" : "text";
    if (field.step !== undefined) control.step = field.step;
    if (field.min !== undefined) control.min = field.min;
    if (field.max !== undefined) control.max = field.max;
    if (field.placeholder) control.placeholder = field.placeholder;
    control.value = value ?? "";
    control.addEventListener("change", () => {
      setValue(field.scope, field.key, field.type === "number" && control.value !== "" ? Number(control.value) : control.value);
    });
  }

  host.appendChild(control);
  if (field.help) {
    const help = document.createElement("small");
    help.className = "field-help";
    help.textContent = field.help;
    host.appendChild(help);
  }
  return node;
}

function renderConfig() {
  configGroupsEl.innerHTML = "";
  state.config.groups.forEach((group) => {
    const card = document.createElement("section");
    card.className = "card";
    card.innerHTML = `<div class="card-header"><div><p class="eyebrow">Config Group</p><h3>${group.title}</h3></div></div>`;
    const grid = document.createElement("div");
    grid.className = "field-grid";
    group.fields.forEach((field) => grid.appendChild(buildField(field)));
    card.appendChild(grid);
    configGroupsEl.appendChild(card);
  });
  configNotesEl.innerHTML = "";
  state.config.notes.forEach((note) => {
    const item = document.createElement("li");
    item.textContent = note;
    configNotesEl.appendChild(item);
  });
  renderTomlPreview();
}

function resetForm() {
  state.form = clone(state.config.defaults);
  renderConfig();
  renderStatus();
}

function applyPreset(name) {
  resetForm();
  if (name === "baseline") {
    state.form.attack.enabled = false;
    state.form.app.strategy = "fedavg";
    state.form.app.partitioner = "iid";
    state.form.app["dirichlet-alpha"] = state.config.defaults.app["dirichlet-alpha"];
  }
  if (name === "stress") {
    state.form.attack.enabled = true;
    state.form.attack.preset = "all";
    state.form.attack.mode = "adaptive";
    state.form.attack.selection_mode = "churn";
    state.form.attack.malicious_fraction = 0.35;
    state.form.attack.churn_fraction = 0.5;
  }
  if (name === "stealth") {
    state.form.attack.enabled = true;
    state.form.attack.mode = "weighted_random";
    state.form.attack.intensity_ramp_mode = "linear";
    state.form.attack.intensity_ramp_multiplier_start = 0.5;
    state.form.attack.intensity_ramp_multiplier_end = 1.6;
    state.form.attack.layering_mode = "sample_k";
    state.form.attack.layered_k = 2;
  }
  if (name === "backdoor") {
    state.form.attack.enabled = true;
    state.form.attack.preset = "backdoor_only";
    state.form.attack.mode = "phase";
    state.form.attack.layering_mode = "fixed";
    state.form.attack.layered_attacks = "backdoor";
    state.form.attack.layer_intensity_backdoor = 1.0;
  }
  renderTomlPreview();
}

function renderStatus() {
  const run = state.currentRun;
  statusSummaryEl.innerHTML = [
    ["State", titleCase(run?.status || "idle")],
    ["Dataset", datasetLabel(run?.effectiveConfig?.app?.dataset || state.form.app.dataset)],
    ["Strategy", titleCase(run?.effectiveConfig?.app?.strategy || state.form.app.strategy)],
    ["Run Folder", compactPath(run?.runDir || "pending")],
  ].map(([label, value]) => `<div class="status-pill"><small>${label}</small><strong>${escapeHtml(value)}</strong></div>`).join("");
  const total = run?.totalRounds || 0;
  const round = run?.round || 0;
  roundNowEl.textContent = String(round);
  roundTotalEl.textContent = String(total);
  runStateEl.textContent = titleCase(run?.status || "idle");
  roundProgressEl.style.width = total > 0 ? `${(round / total) * 100}%` : "0%";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatInline(text) {
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
}

function summarizeMarkdown(markdown) {
  if (!markdown) return "No report available yet.";
  return markdown
    .replace(/^#+\s+/gm, "")
    .replace(/[`*_>|-]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 260) + (markdown.length > 260 ? "..." : "");
}

function formatAttackSummary(text, clientNumberMap = {}) {
  if (!text || !clientNumberMap || !Object.keys(clientNumberMap).length) {
    return text;
  }

  const labelFor = (id) => {
    const label = clientLabelForId(id, clientNumberMap);
    return label || String(id);
  };

  let output = text.replace(/(\b\d+\b)\s*\(id:(\d+)\*?\)/g, (_match, clientNumber, id) => {
    const mapped = clientNumberMap[id];
    return mapped ? `Client ${mapped}` : `Client ${clientNumber}`;
  });

  output = output.replace(/\s*\(ids:\s*([0-9;\s]+)\)/g, "");
  output = output.replace(/id:(\d+)\*?/g, (_match, id) => labelFor(id));
  output = output.replace(/ever_malicious_client_ids:\s*`?([0-9;\s]+)`?/g, (_match, ids) => {
    const labels = ids
      .split(";")
      .map((value) => value.trim())
      .filter(Boolean)
      .map((value) => labelFor(value))
      .join("; ");
    return `ever_malicious_clients: ${labels}`;
  });
  output = output.replace(/top_norm_clients\s*$/gm, "top_norm_clients");
  output = output.replace(/\b(\d{12,})(\*?)/g, (_match, id, suffix) => {
    const label = clientLabelForId(id, clientNumberMap);
    return label ? `${label}${suffix}` : `${id}${suffix}`;
  });
  output = output.replace(/(^|[|:]\s*)(\d+(?:;\d+)+)(?=(?:\s*\||\s*$))/gm, (_match, prefix, ids) => {
    const labels = ids
      .split(";")
      .map((value) => value.trim())
      .filter(Boolean)
      .map((value) => labelFor(value))
      .join("; ");
    return `${prefix}${labels}`;
  });

  output = output.replace(
    /## Client Numbering[\s\S]*?(?=\n## |\nNotes:|$)/,
    "## Client Numbering\n- This dashboard normalizes Flower node IDs into readable labels such as `Client 1` through `Client 100` for this run.\n\n",
  );
  return output;
}

function renderChart(target, seriesMap, options = {}) {
  const entries = Object.entries(seriesMap || {}).filter(([, points]) => Array.isArray(points) && points.length);
  if (!entries.length) {
    target.innerHTML = `<div class="empty">No points yet.</div>`;
    return;
  }
  const palette = ["#0f766e", "#ef8b17", "#b42318", "#3b82f6"];
  const allPoints = entries.flatMap(([, points]) => points);
  const maxRound = Math.max(...allPoints.map((point) => point.round || 0), 1);
  const values = allPoints.map((point) => point.value || 0);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const left = 68;
  const right = 30;
  const top = 18;
  const bottom = 260;
  const width = 760 - left - right;
  const height = bottom - top;

  const isPercent = Boolean(options.percent);
  const formatValue = (value) => {
    if (isPercent) return `${(value * 100).toFixed(0)}%`;
    const abs = Math.abs(value);
    if (abs >= 1000) return value.toFixed(0);
    if (abs >= 100) return value.toFixed(1);
    if (abs >= 10) return value.toFixed(2);
    return value.toFixed(3).replace(/\.?0+$/, "");
  };

  const yTicks = Array.from({ length: 5 }, (_, index) => {
    const t = index / 4;
    const value = max - t * span;
    const y = top + t * height;
    return { value, y };
  });

  const xTickValues = Array.from(new Set([
    1,
    Math.max(1, Math.round(maxRound / 4)),
    Math.max(1, Math.round(maxRound / 2)),
    Math.max(1, Math.round((3 * maxRound) / 4)),
    maxRound,
  ])).sort((a, b) => a - b);

  const xTicks = xTickValues.map((roundValue) => ({
    value: roundValue,
    x: left + (roundValue / maxRound) * width,
  }));

  const gridLines = yTicks.map((tick) => `
    <line x1="${left}" y1="${tick.y}" x2="${left + width}" y2="${tick.y}" class="chart-grid" />
    <text x="${left - 10}" y="${tick.y + 4}" class="chart-axis-label chart-axis-y">${formatValue(tick.value)}</text>
  `).join("");

  const xLabels = xTicks.map((tick) => `
    <line x1="${tick.x}" y1="${bottom}" x2="${tick.x}" y2="${bottom + 5}" class="chart-axis" />
    <text x="${tick.x}" y="${bottom + 20}" text-anchor="middle" class="chart-axis-label">R${tick.value}</text>
  `).join("");

  const polylines = entries.map(([name, points], index) => {
    const pointsAttr = points.map((point) => {
      const x = left + (point.round / maxRound) * width;
      const y = bottom - ((point.value - min) / span) * height;
      return `${x},${y}`;
    }).join(" ");
    const lastPoint = points[points.length - 1];
    const lastX = left + ((lastPoint.round || 0) / maxRound) * width;
    const lastY = bottom - (((lastPoint.value || 0) - min) / span) * height;
    return `
      <polyline fill="none" stroke="${palette[index % palette.length]}" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" points="${pointsAttr}" />
      <circle cx="${lastX}" cy="${lastY}" r="3.5" fill="${palette[index % palette.length]}" />
    `;
  }).join("");
  const legend = entries.map(([name], index) => `<span><span class="legend-dot" style="background:${palette[index % palette.length]}"></span>${name}</span>`).join("");
  target.innerHTML = `
    <div class="chart-shell">
      <svg viewBox="0 0 760 320" preserveAspectRatio="xMidYMid meet">
        ${gridLines}
        <line x1="${left}" y1="${bottom}" x2="${left + width}" y2="${bottom}" class="chart-axis" />
        <line x1="${left}" y1="${top}" x2="${left}" y2="${bottom}" class="chart-axis" />
        ${xLabels}
        ${polylines}
        <text x="${left + width / 2}" y="308" text-anchor="middle" class="chart-axis-title">Round</text>
      </svg>
      <div class="chart-legend">${legend}</div>
    </div>
  `;
}

function renderFeeds() {
  const attackRows = state.currentRun?.recentAttackEvents || [];
  const defenseRows = state.currentRun?.recentDefenseEvents || [];
  attackFeedEl.innerHTML = attackRows.length ? attackRows.slice(-12).reverse().map((row) => `
    <div class="feed-item">
      <strong>Round ${row.round}: ${row.attack_name}</strong>
      <small>Intensity ${row.intensity || "n/a"} | malicious ${row.num_malicious || 0}/${row.num_selected_clients || 0}</small>
    </div>`).join("") : `<div class="empty">No logged attack events yet.</div>`;
  defenseFeedEl.innerHTML = defenseRows.length ? defenseRows.slice(-12).reverse().map((row) => `
    <div class="feed-item">
      <strong>Round ${row.round}: ${row.defense_strategy || "defense"}</strong>
      <small>Selected ${row.num_selected_by_defense || 0} | malicious fraction ${row.malicious_selected_fraction || 0}</small>
    </div>`).join("") : `<div class="empty">No defense-selection rows yet.</div>`;
}

function renderLogs() {
  logConsoleEl.textContent = (state.currentRun?.logs || []).join("\n");
  logConsoleEl.scrollTop = logConsoleEl.scrollHeight;
}

function renderReportOverlay() {
  const shouldShow = Boolean(
    state.currentRun
    && state.currentRun.llmStatus === "running"
    && state.dismissedReportOverlayRunId !== state.currentRun.id,
  );
  reportOverlayEl.classList.toggle("hidden", !shouldShow);
  reportOverlayEl.setAttribute("aria-hidden", shouldShow ? "false" : "true");
}

function renderCurrentRun() {
  renderStatus();
  const metrics = state.currentRun?.metrics || {};
  renderChart(serverAccuracyChartEl, { accuracy: metrics.evaluate_server?.accuracy }, { percent: true });
  renderChart(serverLossChartEl, { loss: metrics.evaluate_server?.loss });
  renderChart(serverAsrChartEl, { backdoor_asr: metrics.evaluate_server?.backdoor_asr }, { percent: true });
  renderChart(trainChartEl, {
    train_loss: metrics.train_client?.train_loss,
    poisoned_examples: metrics.train_client?.poisoned_examples,
  });
  renderFeeds();
  renderLogs();
  renderReportOverlay();
}

function markdownToHtml(markdown) {
  if (!markdown) return "No markdown available.";
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let index = 0;

  const isTableSeparator = (line) => /^\s*\|?[\s:-]+(?:\|[\s:-]+)+\|?\s*$/.test(line);
  const isTableRow = (line) => /^\s*\|.+\|\s*$/.test(line);

  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trim();

    if (!trimmed) {
      index += 1;
      continue;
    }

    if (trimmed.startsWith("```")) {
      const codeLines = [];
      index += 1;
      while (index < lines.length && !lines[index].trim().startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      index += 1;
      blocks.push(`<pre>${escapeHtml(codeLines.join("\n"))}</pre>`);
      continue;
    }

    if (/^---+$/.test(trimmed)) {
      blocks.push("<hr />");
      index += 1;
      continue;
    }

    if (trimmed.startsWith("# ")) {
      blocks.push(`<h1>${formatInline(trimmed.slice(2))}</h1>`);
      index += 1;
      continue;
    }

    if (trimmed.startsWith("## ")) {
      blocks.push(`<h2>${formatInline(trimmed.slice(3))}</h2>`);
      index += 1;
      continue;
    }

    if (trimmed.startsWith("### ")) {
      blocks.push(`<h3>${formatInline(trimmed.slice(4))}</h3>`);
      index += 1;
      continue;
    }

    if (isTableRow(line) && index + 1 < lines.length && isTableSeparator(lines[index + 1])) {
      const header = line.split("|").slice(1, -1).map((cell) => cell.trim());
      const bodyRows = [];
      index += 2;
      while (index < lines.length && isTableRow(lines[index])) {
        bodyRows.push(lines[index].split("|").slice(1, -1).map((cell) => cell.trim()));
        index += 1;
      }
      blocks.push(`
        <div class="markdown-table-wrap">
          <table class="markdown-table">
            <thead><tr>${header.map((cell) => `<th>${formatInline(cell)}</th>`).join("")}</tr></thead>
            <tbody>
              ${bodyRows.map((row) => `<tr>${row.map((cell) => `<td>${formatInline(cell)}</td>`).join("")}</tr>`).join("")}
            </tbody>
          </table>
        </div>
      `);
      continue;
    }

    if (trimmed.startsWith("- ")) {
      const items = [];
      while (index < lines.length && lines[index].trim().startsWith("- ")) {
        items.push(`<li>${formatInline(lines[index].trim().slice(2))}</li>`);
        index += 1;
      }
      blocks.push(`<ul>${items.join("")}</ul>`);
      continue;
    }

    const paragraphLines = [trimmed];
    index += 1;
    while (
      index < lines.length
      && lines[index].trim()
      && !lines[index].trim().startsWith("#")
      && !lines[index].trim().startsWith("- ")
      && !lines[index].trim().startsWith("```")
      && !/^---+$/.test(lines[index].trim())
      && !(isTableRow(lines[index]) && index + 1 < lines.length && isTableSeparator(lines[index + 1]))
    ) {
      paragraphLines.push(lines[index].trim());
      index += 1;
    }
    blocks.push(`<p>${formatInline(paragraphLines.join(" "))}</p>`);
  }

  return blocks.join("");
}

function renderSummary(summary) {
  resultSummaryEl.innerHTML = [
    ["Dataset", datasetLabel(summary.dataset)],
    ["Strategy", titleCase(summary.strategy)],
    ["Rounds", summary.roundCount],
    ["Last Accuracy", summary.lastAccuracy ?? "n/a"],
    ["Attack Events", summary.loggedAttackEvents ?? 0],
    ["Run Folder", compactPath(summary.path)],
  ].map(([label, value]) => `<div class="summary-item"><span class="metric-label">${label}</span><strong>${escapeHtml(value ?? "n/a")}</strong></div>`).join("");
}

function groupArtifacts(artifacts) {
  const groups = {
    "Key Summaries": [],
    "Plots": [],
    "Metrics & CSVs": [],
    "Logs & Raw Files": [],
  };
  artifacts.forEach((file) => {
    const path = file.path.toLowerCase();
    if (path.includes("attack_summary") || path.includes("llm_") || path.endsWith("meta.json")) {
      groups["Key Summaries"].push(file);
    } else if (file.kind === "image" || path.includes("/plots/") || path.includes("/graphs/")) {
      groups["Plots"].push(file);
    } else if (path.endsWith(".csv") || path.endsWith(".json") || path.endsWith(".jsonl")) {
      groups["Metrics & CSVs"].push(file);
    } else {
      groups["Logs & Raw Files"].push(file);
    }
  });
  return groups;
}

function renderArtifacts(runPath, artifacts) {
  if (!artifacts.length) {
    artifactGroupsEl.innerHTML = `<div class="empty">No artifacts found.</div>`;
    return;
  }
  const groups = groupArtifacts(artifacts);
  artifactGroupsEl.innerHTML = Object.entries(groups)
    .filter(([, files]) => files.length)
    .map(([title, files]) => `
      <section class="artifact-group">
        <h4>${title}</h4>
        <div class="artifact-items">
          ${files.map((file) => `
            <div class="artifact-item" data-run="${runPath}" data-file="${file.path}" data-kind="${file.kind}">
              <strong>${file.path}</strong>
              <small>${file.kind} · ${Math.max(1, Math.round(file.size / 1024))} KB</small>
            </div>
          `).join("")}
        </div>
      </section>
    `).join("");
  artifactGroupsEl.querySelectorAll(".artifact-item").forEach((item) => {
    item.addEventListener("click", () => previewArtifact(item.dataset.run, item.dataset.file, item.dataset.kind));
  });
}

function openModal(title, contentHtml, options = {}) {
  modalTitleEl.textContent = title;
  modalBodyEl.innerHTML = contentHtml;
  modalOverlayEl.querySelector(".modal-card")?.classList.toggle("report-modal", Boolean(options.reportLayout));
  modalOverlayEl.classList.remove("hidden");
  modalOverlayEl.setAttribute("aria-hidden", "false");
}

function closeModal() {
  modalOverlayEl.classList.add("hidden");
  modalOverlayEl.setAttribute("aria-hidden", "true");
  modalBodyEl.innerHTML = "";
  modalOverlayEl.querySelector(".modal-card")?.classList.remove("report-modal");
}

async function previewArtifact(runPath, filePath, kind) {
  if (kind === "image") {
    openModal(
      filePath,
      `<img src="/api/history/file?path=${encodeURIComponent(runPath)}&file=${encodeURIComponent(filePath)}" alt="${escapeHtml(filePath)}" />`,
    );
    return;
  }
  const cacheKey = `${runPath}:${filePath}`;
  let content = state.artifactCache.get(cacheKey);
  if (!content) {
    const response = await fetch(`/api/history/file?path=${encodeURIComponent(runPath)}&file=${encodeURIComponent(filePath)}`);
    content = await response.text();
    state.artifactCache.set(cacheKey, content);
  }
  const identifiedContent = filePath.includes("attack_summary")
    ? formatAttackSummary(content, state.activeHistoryRun?.clientNumberMap)
    : content;
  openModal(
    filePath,
    kind === "markdown"
      ? `<div class="markdown-panel">${markdownToHtml(identifiedContent)}</div>`
      : `<pre>${escapeHtml(identifiedContent)}</pre>`,
    { reportLayout: kind === "markdown" },
  );
}

async function loadHistoryRun(path) {
  const payload = await api(`/api/history/run?path=${encodeURIComponent(path)}`);
  state.activeHistoryRun = payload;
  renderSummary(payload.summary);
  llmSummaryPreviewEl.textContent = summarizeMarkdown(payload.llmSummary);
  attackSummaryPreviewEl.textContent = summarizeMarkdown(
    formatAttackSummary(payload.attackSummary, payload.clientNumberMap),
  );
  renderArtifacts(path, payload.artifacts || []);
}

async function loadHistory() {
  const payload = await api("/api/history");
  state.history = payload.runs || [];
  historyListEl.innerHTML = state.history.length ? state.history.map((run) => `
    <div class="history-item" data-path="${run.path}">
      <strong>${escapeHtml(formatRunName(run))}</strong>
      <small>${escapeHtml(compactPath(run.path))}</small>
      <small>${escapeHtml(`${datasetLabel(run.dataset || "dataset")} · ${titleCase(run.strategy || "strategy")}`)}</small>
    </div>`).join("") : `<div class="empty">No runs found yet.</div>`;
  historyListEl.querySelectorAll(".history-item").forEach((item) => {
    item.addEventListener("click", async () => {
      await loadHistoryRun(item.dataset.path);
      switchView("results-view");
    });
  });
}

function switchView(targetId) {
  navLinks.forEach((link) => link.classList.toggle("active", link.dataset.target === targetId));
  views.forEach((view) => view.classList.toggle("active", view.id === targetId));
  if (targetId !== "results-view" && state.currentRun?.status !== "running") {
    state.autoOpenResults = false;
  }
}

function setSidebarCollapsed(collapsed) {
  state.sidebarCollapsed = collapsed;
  shellEl.classList.toggle("sidebar-collapsed", collapsed);
  sidebarToggleEl.textContent = collapsed ? "→" : "←";
  sidebarToggleEl.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
  window.localStorage.setItem("dynamic-fl-sidebar-collapsed", collapsed ? "1" : "0");
}

async function refreshRun(runId, { allowAutoSwitch = true } = {}) {
  const previousStatus = state.currentRun?.status;
  state.currentRun = await api(`/api/runs/${runId}`);
  renderCurrentRun();
  const runSettled = state.currentRun.status !== "running";
  const reportSettled = state.currentRun.llmStatus !== "running";
  if (runSettled && state.currentRun.runDir) {
    await loadHistoryRun(state.currentRun.runDir);
    if (allowAutoSwitch && state.autoOpenResults && reportSettled) {
      reportOverlayEl.classList.add("hidden");
      reportOverlayEl.setAttribute("aria-hidden", "true");
      switchView("results-view");
      state.autoOpenResults = false;
    }
  }
}

function connectRunStream(runId) {
  if (state.eventSource) state.eventSource.close();
  state.eventSource = new EventSource(`/api/runs/${runId}/events`);
  ["log", "round", "attack", "defense", "llm"].forEach((name) => {
    state.eventSource.addEventListener(name, () => refreshRun(runId));
  });
  state.eventSource.addEventListener("done", async () => {
    await refreshRun(runId, { allowAutoSwitch: true });
    await maybeLoadHistory({ force: true });
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
  });
  state.eventSource.addEventListener("error", () => {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
  });
}

async function launchRun() {
  try {
    state.currentRun = await api("/api/runs", {
      method: "POST",
      body: JSON.stringify({ app: state.form.app, attack: state.form.attack }),
    });
    state.autoOpenResults = true;
    state.dismissedReportOverlayRunId = null;
    connectRunStream(state.currentRun.id);
    renderCurrentRun();
    switchView("monitor-view");
  } catch (error) {
    alert(error.message);
  }
}

async function maybeLoadHistory({ force = false } = {}) {
  const now = Date.now();
  if (!force && now - state.lastHistoryLoadAt < 30000) {
    return;
  }
  await loadHistory();
  state.lastHistoryLoadAt = now;
}

async function initializeDashboard() {
  setSidebarCollapsed(window.localStorage.getItem("dynamic-fl-sidebar-collapsed") === "1");
  state.config = await api("/api/config");
  resetForm();
  await maybeLoadHistory({ force: true });

  setInterval(async () => {
    try {
      if (state.currentRun?.status === "running") {
        await refreshRun(state.currentRun.id);
        return;
      }
      await maybeLoadHistory();
    } catch (error) {
      console.error("Dashboard refresh failed:", error);
    }
  }, 5000);
}

navLinks.forEach((button) => button.addEventListener("click", () => switchView(button.dataset.target)));
sidebarToggleEl.addEventListener("click", () => setSidebarCollapsed(!state.sidebarCollapsed));
openLlmReportEl.addEventListener("click", () => {
  const content = state.activeHistoryRun?.llmSummary;
  openModal(
    "LLM Analysis",
    content ? `<div class="markdown-panel">${markdownToHtml(content)}</div>` : `<div class="empty">No LLM summary available for this run yet.</div>`,
    { reportLayout: true },
  );
});
openAttackReportEl.addEventListener("click", () => {
  const content = formatAttackSummary(
    state.activeHistoryRun?.attackSummary,
    state.activeHistoryRun?.clientNumberMap,
  );
  openModal(
    "Attack Summary",
    content ? `<div class="markdown-panel">${markdownToHtml(content)}</div>` : `<div class="empty">No attack summary available for this run yet.</div>`,
    { reportLayout: true },
  );
});
modalCloseEl.addEventListener("click", closeModal);
reportOverlayCloseEl.addEventListener("click", () => {
  state.dismissedReportOverlayRunId = state.currentRun?.id || null;
  renderReportOverlay();
});
modalOverlayEl.addEventListener("click", (event) => {
  if (event.target === modalOverlayEl) {
    closeModal();
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !modalOverlayEl.classList.contains("hidden")) {
    closeModal();
  }
});

document.querySelector("#reload-config").addEventListener("click", async () => {
  try {
    state.config = await api("/api/config");
    resetForm();
    await maybeLoadHistory({ force: true });
  } catch (error) {
    alert(error.message);
  }
});

document.querySelector("#reset-form").addEventListener("click", () => {
  if (!state.config) return;
  resetForm();
});

document.querySelector("#launch-run").addEventListener("click", () => launchRun());
document.querySelectorAll(".preset").forEach((button) => button.addEventListener("click", () => {
  if (!state.config) return;
  applyPreset(button.dataset.preset);
}));

initializeDashboard().catch((error) => {
  console.error("Dashboard failed to initialize:", error);
  alert(`Dashboard failed to initialize: ${error.message}`);
});
