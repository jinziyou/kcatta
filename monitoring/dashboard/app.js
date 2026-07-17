"use strict";

const params = new URLSearchParams(window.location.search);
const prometheusBase = (
  params.get("prometheus") || `${window.location.protocol}//${window.location.hostname}:10065`
).replace(/\/$/, "");
const refreshMilliseconds = 15_000;
const chartHours = 6;

const palette = {
  cyan: "#49d6d0",
  blue: "#6ba4ff",
  amber: "#ffbd66",
  red: "#ff6e7d",
};

document.getElementById("prometheus-alerts").href = `${prometheusBase}/alerts`;

async function prometheusRequest(path, query) {
  const url = new URL(`/api/v1/${path}`, prometheusBase);
  for (const [key, value] of Object.entries(query)) {
    url.searchParams.set(key, String(value));
  }
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Prometheus ${response.status}: ${response.statusText}`);
  }
  const payload = await response.json();
  if (payload.status !== "success") {
    throw new Error(payload.error || "Prometheus query failed");
  }
  return payload.data.result;
}

async function instantQuery(expression) {
  return prometheusRequest("query", { query: expression });
}

async function rangeQuery(expression) {
  const end = Math.floor(Date.now() / 1000);
  return prometheusRequest("query_range", {
    query: expression,
    start: end - chartHours * 3600,
    end,
    step: 60,
  });
}

function scalar(result, fallback = null) {
  if (!result.length || !result[0].value) {
    return fallback;
  }
  const value = Number(result[0].value[1]);
  return Number.isFinite(value) ? value : fallback;
}

function setMetric(id, value, tone = "") {
  const element = document.getElementById(id);
  element.textContent = value;
  element.className = `metric${tone ? ` ${tone}` : ""}`;
}

function ratioTone(value, { lowIsBad = false } = {}) {
  if (value === null) return "";
  if (lowIsBad) {
    if (value < 0.5) return "bad";
    if (value < 0.8) return "warn";
    return "good";
  }
  if (value >= 0.9) return "bad";
  if (value >= 0.75) return "warn";
  return "good";
}

function formatPercent(value) {
  return value === null ? "—" : `${(value * 100).toFixed(1)}%`;
}

function formatInteger(value) {
  return value === null ? "—" : Math.round(value).toLocaleString("zh-CN");
}

function formatBytes(value) {
  if (value === null) return "—";
  const units = ["B", "KiB", "MiB", "GiB"];
  let index = 0;
  let scaled = value;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  return `${scaled.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function createSvgElement(name, attributes = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) {
    element.setAttribute(key, String(value));
  }
  return element;
}

function normalizedSeries(result, definitions) {
  return definitions.map((definition, index) => {
    const source = result[index];
    return {
      ...definition,
      points: (source?.values || [])
        .map(([time, value]) => [Number(time), Number(value)])
        .filter(([, value]) => Number.isFinite(value)),
    };
  });
}

function drawChart(containerId, series) {
  const container = document.getElementById(containerId);
  container.replaceChildren();
  const populated = series.filter((item) => item.points.length > 0);
  if (!populated.length) {
    const empty = document.createElement("p");
    empty.className = "chart-empty";
    empty.textContent = "尚无缓存事件样本；打开报告详情后会开始形成趋势。";
    container.append(empty);
    return;
  }

  const width = Math.max(container.clientWidth, 360);
  const height = 218;
  const margin = { top: 10, right: 12, bottom: 24, left: 45 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const timestamps = populated.flatMap((item) => item.points.map(([time]) => time));
  const values = populated.flatMap((item) => item.points.map(([, value]) => value));
  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  const timeSpan = Math.max(maxTime - minTime, 1);
  const maxValue = Math.max(...values, 0);
  const yMax = maxValue > 0 ? maxValue * 1.08 : 1;
  const x = (time) => margin.left + ((time - minTime) / timeSpan) * plotWidth;
  const y = (value) => margin.top + plotHeight - (value / yMax) * plotHeight;
  const svg = createSvgElement("svg", {
    viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: "none",
    "aria-hidden": "true",
  });

  for (let index = 0; index <= 4; index += 1) {
    const lineY = margin.top + (plotHeight * index) / 4;
    svg.append(
      createSvgElement("line", {
        x1: margin.left,
        y1: lineY,
        x2: width - margin.right,
        y2: lineY,
        class: "chart-grid-line",
      }),
    );
    const label = createSvgElement("text", {
      x: margin.left - 8,
      y: lineY + 3,
      "text-anchor": "end",
      class: "chart-label",
    });
    label.textContent = (yMax * (1 - index / 4)).toPrecision(2);
    svg.append(label);
  }

  for (let index = 0; index <= 3; index += 1) {
    const timestamp = minTime + (timeSpan * index) / 3;
    const label = createSvgElement("text", {
      x: x(timestamp),
      y: height - 5,
      "text-anchor": index === 0 ? "start" : index === 3 ? "end" : "middle",
      class: "chart-label",
    });
    label.textContent = new Date(timestamp * 1000).toLocaleTimeString("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
    });
    svg.append(label);
  }

  for (const item of populated) {
    const path = item.points
      .map(([time, value], index) => `${index === 0 ? "M" : "L"}${x(time).toFixed(1)},${y(value).toFixed(1)}`)
      .join(" ");
    svg.append(
      createSvgElement("path", {
        d: path,
        stroke: item.color,
        class: "chart-path",
      }),
    );
  }
  container.append(svg);

  const legend = document.createElement("div");
  legend.className = "legend";
  for (const item of series) {
    const entry = document.createElement("span");
    entry.className = "legend-item";
    entry.style.setProperty("--legend-color", item.color);
    entry.textContent = item.label;
    legend.append(entry);
  }
  container.append(legend);
}

async function refreshSummary() {
  const expressions = [
    'up{job="analyzer"}',
    "kcatta:report_projection_cache_hit_ratio:rate15m",
    "kcatta:report_projection_cache_entries_utilization:ratio",
    "kcatta:report_projection_cache_bytes_utilization:ratio",
    "kcatta_report_projection_cache_entries",
    "kcatta_report_projection_cache_max_entries",
    "kcatta_report_projection_cache_bytes",
    "kcatta_report_projection_cache_max_bytes",
    'sum(ALERTS{alertstate="firing",alertname=~"Kcatta.*"})',
  ];
  const results = await Promise.all(expressions.map((expression) => instantQuery(expression)));
  const [up, hitRatio, entryRatio, byteRatio, entries, maxEntries, bytes, maxBytes, alerts] =
    results.map((result) => scalar(result));

  setMetric("analyzer-up", up === 1 ? "UP" : "DOWN", up === 1 ? "good" : "bad");
  document.getElementById("analyzer-up-detail").textContent =
    up === 1 ? "Prometheus 正常抓取" : "未收到 Analyzer 指标";
  setMetric("hit-ratio", formatPercent(hitRatio), ratioTone(hitRatio, { lowIsBad: true }));
  setMetric("entry-ratio", formatPercent(entryRatio), ratioTone(entryRatio));
  setMetric("byte-ratio", formatPercent(byteRatio), ratioTone(byteRatio));
  setMetric("firing-count", formatInteger(alerts ?? 0), alerts && alerts > 0 ? "bad" : "good");
  document.getElementById("entry-detail").textContent = `${formatInteger(entries)} / ${formatInteger(maxEntries)}`;
  document.getElementById("byte-detail").textContent = `${formatBytes(bytes)} / ${formatBytes(maxBytes)}`;
}

async function refreshCharts() {
  const [hits, misses, invalidations, evictions, skipped] = await Promise.all([
    rangeQuery("rate(kcatta_report_projection_cache_hits_total[5m])"),
    rangeQuery("rate(kcatta_report_projection_cache_misses_total[5m])"),
    rangeQuery("rate(kcatta_report_projection_cache_invalidations_total[5m])"),
    rangeQuery("rate(kcatta_report_projection_cache_evictions_total[5m])"),
    rangeQuery("rate(kcatta_report_projection_cache_skipped_total[5m])"),
  ]);
  drawChart(
    "lookup-chart",
    normalizedSeries([hits[0], misses[0]], [
      { label: "命中 / 秒", color: palette.cyan },
      { label: "未命中 / 秒", color: palette.blue },
    ]),
  );
  drawChart(
    "pressure-chart",
    normalizedSeries([invalidations[0], evictions[0], skipped[0]], [
      { label: "精确失效 / 秒", color: palette.amber },
      { label: "LRU 淘汰 / 秒", color: palette.red },
      { label: "超限跳过 / 秒", color: palette.blue },
    ]),
  );
}

async function refreshAlerts() {
  const alerts = await instantQuery(
    'ALERTS{alertstate=~"pending|firing",alertname=~"Kcatta.*"}',
  );
  const container = document.getElementById("alerts");
  container.replaceChildren();
  if (!alerts.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "当前没有 pending 或 firing 的 Kcatta 告警。";
    container.append(empty);
    return;
  }
  alerts
    .sort((left, right) => String(left.metric.alertname).localeCompare(String(right.metric.alertname)))
    .forEach((alert) => {
      const row = document.createElement("div");
      row.className = "alert-row";

      const state = document.createElement("span");
      state.className = `alert-state ${alert.metric.alertstate || "pending"}`;
      state.textContent = alert.metric.alertstate || "pending";

      const name = document.createElement("span");
      name.className = "alert-name";
      name.textContent = alert.metric.alertname || "Unknown alert";

      const meta = document.createElement("span");
      meta.className = "alert-meta";
      meta.textContent = [alert.metric.severity, alert.metric.component]
        .filter(Boolean)
        .join(" · ");

      row.append(state, name, meta);
      container.append(row);
    });
}

let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  const connection = document.getElementById("connection");
  try {
    await Promise.all([refreshSummary(), refreshCharts(), refreshAlerts()]);
    connection.className = "status ok";
    connection.textContent = "Prometheus 已连接";
    document.getElementById("last-updated").textContent = `更新于 ${new Date().toLocaleTimeString("zh-CN")}`;
  } catch (error) {
    connection.className = "status error";
    connection.textContent = "Prometheus 不可用";
    console.error(error);
  } finally {
    refreshing = false;
  }
}

window.addEventListener("resize", () => {
  window.clearTimeout(window.__kcattaResizeTimer);
  window.__kcattaResizeTimer = window.setTimeout(refreshCharts, 180);
});

refresh();
window.setInterval(refresh, refreshMilliseconds);
