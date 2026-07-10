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
// 4) TAB NAVIGATION
// ===========================================================================

// Lazy loaders run once when a view is first shown; pollers keep running.
const viewLoaded = { decisions: true, packs: false, learning: false, approvals: false };

function showView(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    const on = tab.dataset.view === name;
    tab.classList.toggle("is-active", on);
    tab.setAttribute("aria-selected", on ? "true" : "false");
  }
  for (const view of document.querySelectorAll(".view")) {
    const on = view.id === "view-" + name;
    view.classList.toggle("is-active", on);
    view.hidden = !on;
  }
  if (!viewLoaded[name]) {
    viewLoaded[name] = true;
    if (name === "packs") loadPacks();
    if (name === "learning") loadLearn();
  }
}

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => showView(tab.dataset.view));
}

// ===========================================================================
// 5) PACKS BOARD
// ===========================================================================

const packTpl = el("packTpl");
const MODES = ["off", "observe", "ask", "enforce"];

function packModeClass(mode) {
  return "m-" + (MODES.includes(mode) ? mode : "observe");
}

function makePackCard(pack) {
  const node = packTpl.content.firstElementChild.cloneNode(true);
  node.dataset.id = pack.id;

  node.querySelector('[data-field="title"]').textContent = pack.title || pack.id;
  node.querySelector('[data-field="id"]').textContent = pack.id;

  const sel = node.querySelector('[data-field="mode"]');
  sel.value = MODES.includes(pack.mode) ? pack.mode : "observe";
  applyPackMode(node, sel.value);
  sel.addEventListener("change", () => applyPackMode(node, sel.value));

  // stash params so a round-trip Save preserves allowlists/quiet-hours untouched.
  node._params = pack.params || null;

  renderAgentChips(node, pack.per_agent || {});
  return node;
}

function applyPackMode(node, mode) {
  node.classList.remove("m-off", "m-observe", "m-ask", "m-enforce");
  node.classList.add(packModeClass(mode));
}

function renderAgentChips(node, perAgent) {
  const wrap = node.querySelector('[data-role="agents"]');
  const chips = node.querySelector('[data-role="chips"]');
  chips.replaceChildren();
  const names = Object.keys(perAgent).sort();
  if (names.length === 0) {
    wrap.hidden = true;
    node._perAgent = {};
    return;
  }
  wrap.hidden = false;
  node._perAgent = Object.assign({}, perAgent);
  for (const name of names) {
    const chip = document.createElement("span");
    chip.className = "chip-agent " + packModeClass(perAgent[name]);
    const who = document.createElement("span");
    who.textContent = name;
    const m = document.createElement("span");
    m.className = "chip-agent-mode";
    m.textContent = perAgent[name];
    chip.append(who, m);
    chips.appendChild(chip);
  }
}

function renderPacks(packs) {
  const list = el("packList");
  list.replaceChildren();
  for (const p of packs || []) list.appendChild(makePackCard(p));
}

async function loadPacks() {
  const loading = el("packsLoading");
  const error = el("packsError");
  try {
    const data = await api("/api/packs");
    const packs = (data && data.packs) || [];
    loading.hidden = true;
    renderPacks(packs);
  } catch (err) {
    loading.hidden = true;
    error.hidden = false;
    error.textContent = authOr(err, "Could not load packs: " + err.message);
  }
}

function collectPacks() {
  const cards = el("packList").querySelectorAll(".pack");
  const packs = [];
  for (const node of cards) {
    const p = {
      id: node.dataset.id,
      title: node.querySelector('[data-field="title"]').textContent,
      mode: node.querySelector('[data-field="mode"]').value,
    };
    if (node._params) p.params = node._params;
    if (node._perAgent && Object.keys(node._perAgent).length) p.per_agent = node._perAgent;
    packs.push(p);
  }
  return packs;
}

el("savePacks").addEventListener("click", async () => {
  const btn = el("savePacks");
  el("packsError").hidden = true;
  el("packsSaved").hidden = true;
  btn.disabled = true;
  btn.textContent = "Saving…";
  try {
    await api("/api/packs", {
      method: "PUT",
      body: JSON.stringify({ packs: collectPacks() }),
    });
    el("packsSaved").hidden = false;
    await loadPacks();
    setTimeout(() => (el("packsSaved").hidden = true), 3000);
  } catch (err) {
    const e = el("packsError");
    e.hidden = false;
    e.textContent = authOr(err, "Packs rejected: " + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Save packs";
  }
});

// ===========================================================================
// 6) LEARNING PANEL
// ===========================================================================

function renderProfile(profile) {
  const body = el("learnBody");
  const empty = el("learnEmpty");
  body.replaceChildren();
  const entries = (profile && profile.entries) || [];
  if (entries.length === 0) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  const frag = document.createDocumentFragment();
  for (const e of entries) {
    const tr = document.createElement("tr");
    const cells = [
      [e.principal || "—", "cell-caller"],
      [e.surface || "—", "cell-surface"],
      [e.verb || "—", "cell-surface"],
      [String(e.count || 0), "cell-num"],
      [String(e.would_block || 0), "cell-num cell-block" + (e.would_block ? " is-hot" : "")],
      [relTime(e.last_seen), "cell-time"],
    ];
    for (const [text, cls] of cells) {
      const td = document.createElement("td");
      td.className = cls;
      td.textContent = text;
      tr.appendChild(td);
    }
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
}

function renderProposal(proposal) {
  const box = el("proposeBox");
  const list = el("proposeList");
  list.replaceChildren();
  const packs = (proposal && proposal.packs) || [];
  const active = packs.filter((p) => p.mode && p.mode !== "off");
  if (active.length === 0) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  for (const p of active) {
    const chip = document.createElement("span");
    chip.className = "propose-chip " + packModeClass(p.mode);
    const id = document.createElement("span");
    id.textContent = p.id;
    const mode = document.createElement("span");
    mode.className = "pc-mode";
    mode.textContent = p.mode;
    chip.append(id, mode);
    const agents = p.per_agent ? Object.keys(p.per_agent) : [];
    if (agents.length) {
      const a = document.createElement("span");
      a.className = "pc-agent";
      a.textContent = agents.join(", ");
      chip.appendChild(a);
    }
    list.appendChild(chip);
  }
}

async function loadLearn() {
  const loading = el("learnLoading");
  const error = el("learnError");
  try {
    const data = await api("/api/learn");
    loading.hidden = true;
    renderProfile(data && data.profile);
    renderProposal(data && data.proposal);
  } catch (err) {
    loading.hidden = true;
    error.hidden = false;
    error.textContent = authOr(err, "Could not load behaviour: " + err.message);
  }
}

el("protectNow").addEventListener("click", async () => {
  const btn = el("protectNow");
  el("learnError").hidden = true;
  el("learnSaved").hidden = true;
  btn.disabled = true;
  btn.textContent = "Promoting…";
  try {
    await api("/api/learn/promote", { method: "POST" });
    el("learnSaved").hidden = false;
    // Reflect the promotion on the packs board next time it's opened.
    viewLoaded.packs = false;
    setTimeout(() => (el("learnSaved").hidden = true), 3000);
  } catch (err) {
    const e = el("learnError");
    e.hidden = false;
    e.textContent = authOr(err, "Could not promote: " + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Protect me now";
  }
});

// ===========================================================================
// 7) APPROVALS INBOX
// ===========================================================================

const approvalTpl = el("approvalTpl");

function makeApprovalCard(p) {
  const node = approvalTpl.content.firstElementChild.cloneNode(true);
  node.dataset.id = p.decision_id;
  node.querySelector('[data-field="principal"]').textContent = p.principal || "agent";
  node.querySelector('[data-field="surface"]').textContent = p.surface || "?";
  node.querySelector('[data-field="verb"]').textContent = p.verb || "?";
  node.querySelector('[data-field="reason"]').textContent = p.reason || "awaiting your decision";

  for (const btn of node.querySelectorAll("[data-action]")) {
    btn.addEventListener("click", () => resolveApproval(node, btn.dataset.action));
  }
  return node;
}

async function resolveApproval(node, verdict) {
  const id = node.dataset.id;
  node.classList.add("is-resolving");
  try {
    await api("/api/approvals/" + encodeURIComponent(id), {
      method: "POST",
      body: JSON.stringify({ verdict }),
    });
    node.remove();
    refreshApprovalsEmpty();
    loadApprovals(); // resync count/badge
  } catch (err) {
    node.classList.remove("is-resolving");
    const e = el("approvalsError");
    e.hidden = false;
    e.textContent = authOr(err, "Could not resolve: " + err.message);
  }
}

function refreshApprovalsEmpty() {
  const has = el("approvalList").querySelector(".approval");
  el("approvalsEmpty").hidden = !!has;
}

function setApprovalsBadge(n) {
  const badge = el("approvalsBadge");
  badge.textContent = String(n);
  badge.hidden = n === 0;
}

function renderApprovals(pending) {
  const list = el("approvalList");
  list.replaceChildren();
  for (const p of pending || []) list.appendChild(makeApprovalCard(p));
  refreshApprovalsEmpty();
  setApprovalsBadge((pending || []).length);
}

async function loadApprovals() {
  try {
    const data = await api("/api/approvals");
    const pending = (data && data.pending) || [];
    el("approvalsError").hidden = true;
    // Don't clobber a card the user is mid-resolving; only re-render when the
    // set of ids actually changed.
    if (approvalsChanged(pending)) renderApprovals(pending);
    el("apprLive").classList.remove("is-idle");
  } catch (err) {
    el("apprLive").classList.add("is-idle");
    if (err.status === 401) {
      const e = el("approvalsError");
      e.hidden = false;
      e.textContent = "Not authorized. Reopen from `aarvion-guard dashboard`.";
    }
  }
}

let lastApprovalIds = "";
function approvalsChanged(pending) {
  const ids = (pending || []).map((p) => p.decision_id).sort().join(",");
  if (ids === lastApprovalIds) return false;
  lastApprovalIds = ids;
  return true;
}

// authOr: unify the 401 message across panels.
function authOr(err, fallback) {
  return err.status === 401
    ? "Not authorized. Reopen the console from `aarvion-guard dashboard`."
    : fallback;
}

// ===========================================================================
// boot
// ===========================================================================
loadStatus();
setInterval(loadStatus, 15000); // keep the pill fresh
startFeed();
loadOverlay();
// Approvals poll runs regardless of the active tab so the badge stays live.
loadApprovals();
setInterval(loadApprovals, 3000);
