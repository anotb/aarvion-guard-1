// Aarvion local console — vanilla JS, no framework, no external calls.
// Talks to the guard's local API. Every request carries the bearer token
// captured from ?t=<token> on load (the `aarvion-guard dashboard` command
// opens the browser at /?t=<token>).

"use strict";

// ---- auth token (captured once, kept module-private) -----------------------
const TOKEN = new URLSearchParams(location.search).get("t") || "";

// Strip the token from the visible URL so it isn't left in the address bar /
// history after load. It stays in the TOKEN module variable.
if (TOKEN && window.history && history.replaceState) {
  const clean = location.pathname + location.hash;
  history.replaceState(null, "", clean);
}

// ---- tiny helpers ----------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const el = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers, {
    Authorization: "Bearer " + TOKEN,
  });
  if (opts.body != null && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { message: text }; }
  }
  if (!res.ok) {
    const msg =
      (data && (data.error || data.message)) ||
      `${res.status} ${res.statusText}`;
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// Relative-time formatter, e.g. "12s", "4m", "2h", "3d".
function relTime(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const diff = Math.max(0, Date.now() - t);
  const s = Math.floor(diff / 1000);
  if (s < 5) return "just now";
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  if (h < 24) return h + "h";
  const d = Math.floor(h / 24);
  return d + "d";
}

function absTime(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  return new Date(t).toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

// ---- token gate ------------------------------------------------------------
if (!TOKEN) {
  const notice = el("tokenNotice");
  notice.hidden = false;
  notice.classList.remove("notice-hidden");
}

// ===========================================================================
// 1) STATUS + SYNC PILL
// ===========================================================================

// Maps a backend sync status to { cls, text } for the pill.
const SYNC_MAP = {
  in_sync:     { cls: "pill-synced",  text: "In sync" },
  synced:      { cls: "pill-synced",  text: "In sync" },
  local_ahead: { cls: "pill-local",   text: "Local ahead" },
  cloud_ahead: { cls: "pill-cloud",   text: "Cloud ahead" },
  unknown:     { cls: "pill-unknown", text: "Unknown" },
};

function renderSync(status) {
  const pill = el("syncPill");
  const key = String(status || "unknown").toLowerCase();
  const m = SYNC_MAP[key] || SYNC_MAP.unknown;
  pill.className = "pill " + m.cls;
  $(".pill-text", pill).textContent = m.text;
}

function setSyncBusy(busy) {
  el("syncPill").classList.toggle("is-busy", busy);
}

async function loadStatus() {
  try {
    const s = await api("/api/status");
    if (s.entity_id) el("entityId").textContent = s.entity_id;
    if (s.tenant) el("tenant").textContent = s.tenant;
    // Accept a few shapes: {sync}, {sync_status}, {sync:{status}}
    const sync =
      (s.sync && s.sync.status) || s.sync_status || s.sync || "unknown";
    renderSync(sync);
  } catch (err) {
    if (err.status === 401) {
      el("entityId").textContent = "unauthorized";
    }
    renderSync("unknown");
  }
}

el("syncNow").addEventListener("click", async () => {
  const btn = el("syncNow");
  btn.disabled = true;
  setSyncBusy(true);
  try {
    const r = await api("/api/sync", { method: "POST" });
    const sync =
      (r && ((r.sync && r.sync.status) || r.sync_status || r.status || r.sync)) ||
      "unknown";
    renderSync(sync);
  } catch {
    renderSync("unknown");
  } finally {
    setSyncBusy(false);
    btn.disabled = false;
  }
});

// ===========================================================================
// 2) LIVE DECISIONS FEED
// ===========================================================================

const FRESH_MS = 6000; // rows newer than this get the accent rail tick
let feedStarted = false;

function verdictClass(decision) {
  switch (String(decision || "").toLowerCase()) {
    case "allow": return "chip-allow";
    case "deny":  return "chip-deny";
    case "ask":   return "chip-ask";
    default:      return "chip-other";
  }
}

function rowStateClass(decision, iso) {
  const d = String(decision || "").toLowerCase();
  if (d === "deny") return "is-deny";
  if (d === "ask") return "is-ask";
  const t = Date.parse(iso);
  if (!Number.isNaN(t) && Date.now() - t < FRESH_MS) return "is-fresh";
  return "";
}

// The feed rows come from decision Records. Pull the caller from whichever
// governance field is populated, else fall back to surface origin.
function callerOf(r) {
  return (
    r.caller_principal_id ||
    r.caller ||
    r.caller_source ||
    r.replica_id ||
    "—"
  );
}

function renderFeed(records) {
  const body = el("feedBody");
  const loading = el("feedLoading");
  const empty = el("feedEmpty");
  const error = el("feedError");

  loading.hidden = true;
  error.hidden = true;

  if (!Array.isArray(records) || records.length === 0) {
    body.replaceChildren();
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const frag = document.createDocumentFragment();
  for (const r of records) {
    const tr = document.createElement("tr");
    const state = rowStateClass(r.decision, r.timestamp);
    if (state) tr.className = state;

    // time
    const tdTime = document.createElement("td");
    tdTime.className = "cell-time";
    tdTime.textContent = relTime(r.timestamp);
    const small = document.createElement("small");
    small.textContent = absTime(r.timestamp);
    tdTime.appendChild(small);
    tr.appendChild(tdTime);

    // surface
    const tdSurface = document.createElement("td");
    tdSurface.className = "cell-surface";
    tdSurface.textContent = r.surface || r.direction || "—";
    tr.appendChild(tdSurface);

    // decision chip
    const tdDec = document.createElement("td");
    tdDec.className = "cell-decision";
    const chip = document.createElement("span");
    chip.className = "chip " + verdictClass(r.decision);
    chip.textContent = String(r.decision || "—").toLowerCase();
    tdDec.appendChild(chip);
    tr.appendChild(tdDec);

    // reason
    const tdReason = document.createElement("td");
    tdReason.className = "cell-reason";
    if (r.reason) {
      tdReason.textContent = r.reason;
    } else {
      tdReason.textContent = "—";
      tdReason.classList.add("is-empty");
    }
    tr.appendChild(tdReason);

    // caller
    const tdCaller = document.createElement("td");
    tdCaller.className = "cell-caller";
    const caller = callerOf(r);
    tdCaller.textContent = caller;
    tdCaller.title = caller;
    tr.appendChild(tdCaller);

    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
}

async function loadFeed() {
  const error = el("feedError");
  try {
    const data = await api("/api/feed?limit=100");
    // Accept {decisions:[...]}, {feed:[...]}, or a bare array.
    const records = Array.isArray(data)
      ? data
      : (data && (data.decisions || data.feed || data.records)) || [];
    renderFeed(records);
    el("liveDot").classList.remove("is-idle");
  } catch (err) {
    el("feedLoading").hidden = true;
    el("liveDot").classList.add("is-idle");
    // Keep any already-rendered rows; just surface the error below.
    error.hidden = false;
    error.textContent =
      err.status === 401
        ? "Not authorized. Reopen the console from `aarvion-guard dashboard`."
        : "Could not load decisions: " + err.message;
  }
}

function startFeed() {
  if (feedStarted) return;
  feedStarted = true;
  loadFeed();
  setInterval(loadFeed, 4000);
}

// ===========================================================================
// 3) LOCAL OVERLAY EDITOR
// ===========================================================================

const ruleTpl = el("ruleTpl");
let ruleSeq = 0; // client-side id source for new rules

// list<->comma helpers
function toList(str) {
  return String(str || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
function fromList(arr) {
  return Array.isArray(arr) ? arr.join(", ") : "";
}

function makeRuleCard(rule) {
  const node = ruleTpl.content.firstElementChild.cloneNode(true);

  // stash the stable id (server id for existing rules; a fresh one otherwise)
  node.dataset.id = rule.id || "local-" + Date.now() + "-" + ruleSeq++;

  const setVal = (field, value) => {
    const inp = node.querySelector(`[data-field="${field}"]`);
    if (inp) inp.value = value == null ? "" : value;
  };
  setVal("description", rule.description);
  setVal("reason", rule.reason);

  const match = rule.match || {};
  setVal("tools", fromList(match.tools));
  setVal("command_contains", fromList(match.command_contains));
  setVal("host_suffixes", fromList(match.host_suffixes));
  setVal("methods", fromList(match.methods));

  const verdictSel = node.querySelector('[data-field="verdict"]');
  verdictSel.value = rule.verdict === "ask" ? "ask" : "deny";

  const enabled = rule.enabled !== false; // default on
  setEnabled(node, enabled);
  applyVerdictStyle(node, verdictSel.value);

  // wiring
  verdictSel.addEventListener("change", () =>
    applyVerdictStyle(node, verdictSel.value)
  );

  const toggle = node.querySelector('[data-field="enabled"]');
  toggle.addEventListener("click", () => {
    const now = toggle.getAttribute("aria-checked") === "true";
    setEnabled(node, !now);
  });

  node.querySelector('[data-action="delete"]').addEventListener("click", () => {
    node.remove();
    refreshOverlayEmpty();
  });

  return node;
}

function setEnabled(node, on) {
  const toggle = node.querySelector('[data-field="enabled"]');
  toggle.setAttribute("aria-checked", on ? "true" : "false");
  toggle.querySelector(".toggle-text").textContent = on ? "on" : "off";
  node.classList.toggle("is-off", !on);
}

function applyVerdictStyle(node, verdict) {
  node.classList.remove("v-deny", "v-ask");
  node.classList.add(verdict === "ask" ? "v-ask" : "v-deny");
  const bar = node.querySelector('[data-role="bar"]');
  if (bar) bar.className = "rule-bar";
}

// Read the current editor state back into rule objects.
function collectRules() {
  const cards = el("ruleList").querySelectorAll(".rule");
  const rules = [];
  for (const node of cards) {
    const get = (f) => {
      const inp = node.querySelector(`[data-field="${f}"]`);
      return inp ? inp.value : "";
    };
    const toggle = node.querySelector('[data-field="enabled"]');
    rules.push({
      id: node.dataset.id,
      description: get("description").trim(),
      match: {
        tools: toList(get("tools")),
        command_contains: toList(get("command_contains")),
        host_suffixes: toList(get("host_suffixes")),
        methods: toList(get("methods")),
      },
      verdict: get("verdict") === "ask" ? "ask" : "deny",
      reason: get("reason").trim(),
      enabled: toggle.getAttribute("aria-checked") === "true",
    });
  }
  return rules;
}

function refreshOverlayEmpty() {
  const hasRules = el("ruleList").querySelector(".rule");
  el("overlayEmpty").hidden = !!hasRules;
}

function clearRuleErrors() {
  el("overlayError").hidden = true;
  el("overlaySaved").hidden = true;
  for (const e of el("ruleList").querySelectorAll('[data-role="err"]')) {
    e.hidden = true;
    e.textContent = "";
  }
}

function renderOverlay(rules) {
  const list = el("ruleList");
  list.replaceChildren();
  for (const r of rules || []) list.appendChild(makeRuleCard(r));
  refreshOverlayEmpty();
}

async function loadOverlay() {
  const loading = el("overlayLoading");
  const error = el("overlayError");
  try {
    const data = await api("/api/overlay");
    const rules = Array.isArray(data) ? data : (data && data.rules) || [];
    loading.hidden = true;
    renderOverlay(rules);
  } catch (err) {
    loading.hidden = true;
    error.hidden = false;
    error.textContent =
      err.status === 401
        ? "Not authorized. Reopen the console from `aarvion-guard dashboard`."
        : "Could not load overlay: " + err.message;
  }
}

el("addRule").addEventListener("click", () => {
  const node = makeRuleCard({ verdict: "deny", enabled: true, match: {} });
  el("ruleList").appendChild(node);
  refreshOverlayEmpty();
  const first = node.querySelector('[data-field="description"]');
  if (first) first.focus();
});

el("saveOverlay").addEventListener("click", async () => {
  clearRuleErrors();
  const btn = el("saveOverlay");
  const rules = collectRules();
  btn.disabled = true;
  btn.textContent = "Saving…";
  try {
    await api("/api/overlay", {
      method: "PUT",
      body: JSON.stringify({ rules }),
    });
    el("overlaySaved").hidden = false;
    // Reload to pick up server-normalised ids/ordering.
    await loadOverlay();
    setTimeout(() => (el("overlaySaved").hidden = true), 3000);
  } catch (err) {
    showOverlayError(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Save overlay";
  }
});

// Surface server validation errors — inline on the offending rule when the
// error names a rule id, otherwise in the panel-level banner.
function showOverlayError(err) {
  const banner = el("overlayError");
  const data = err.data || {};

  // Shape A: {errors:[{id, message}]} or {errors:[{rule_id, error}]}
  const perRule = data.errors || data.rule_errors || data.details;
  let placedInline = false;

  if (Array.isArray(perRule)) {
    for (const e of perRule) {
      const id = e.id || e.rule_id || e.ruleId;
      const msg = e.message || e.error || e.msg || String(e);
      const node = id
        ? el("ruleList").querySelector(`.rule[data-id="${cssEscape(id)}"]`)
        : null;
      if (node) {
        const box = node.querySelector('[data-role="err"]');
        box.textContent = msg;
        box.hidden = false;
        placedInline = true;
      }
    }
  }

  if (!placedInline) {
    banner.hidden = false;
    banner.textContent = "Overlay rejected: " + err.message;
  } else {
    banner.hidden = false;
    banner.textContent = "Overlay rejected — see the flagged rule(s) above.";
  }
}

// Minimal CSS.escape fallback for attribute selectors.
function cssEscape(v) {
  if (window.CSS && CSS.escape) return CSS.escape(v);
  return String(v).replace(/["\\\]]/g, "\\$&");
}

// ===========================================================================
// boot
// ===========================================================================
loadStatus();
setInterval(loadStatus, 15000); // keep the pill fresh
startFeed();
loadOverlay();
