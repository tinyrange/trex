// Virtual Lab Editor — vanilla client for the /api lab contract.
"use strict";

(() => {
const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(n.dataset, v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return n;
};
const appendAll = (parent, ...kids) => parent.append(...kids.flat().filter((k) => k != null && k !== false));
const clone = (v) => (v == null ? v : JSON.parse(JSON.stringify(v)));
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const NODE_W = 232, NODE_H = 94;
const DRAFT_KEY = "tinyrangex.lab.draft";

// ---------------------------------------------------------------- API
async function api(method, path, body) {
  const opts = { method, headers: {}, cache: "no-store" };
  if (method !== "GET") opts.headers["X-TinyRangeX"] = "lab";
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = (await res.text().catch(() => "")).trim();
    throw new Error(text || `${method} ${path}: ${res.status} ${res.statusText}`);
  }
  const ct = res.headers.get("Content-Type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

// ---------------------------------------------------------------- state
const S = {
  catalog: { recipes: [], templates: [] },
  recipes: new Map(),
  draft: emptyDefinition(),
  saved: null,          // last definition the server reported as saved
  applied: null,        // definition currently applied, if any
  view: null,           // last GET /api/lab response
  sel: { nodes: new Set(), link: -1 },
  tool: "select",
  cam: { x: 0, y: 0, k: 1 },
  undo: [], redo: [],
  connecting: null,     // {node, port}
  polling: false,
};

function emptyDefinition() { return { version: 1, name: "Untitled lab", nodes: [], links: [] }; }

function normalizeDefinition(d) {
  const def = d && typeof d === "object" ? clone(d) : {};
  const normalized = {
    version: 1,
    name: typeof def.name === "string" && def.name ? def.name : "Untitled lab",
    nodes: Array.isArray(def.nodes) ? def.nodes.filter((n) => n && n.id).map((n) => {
      const server = S.catalog.recipes.find((r) => r.legacyController && r.legacyController === n.recipe)?.id;
      const config = n.config && typeof n.config === "object" ? n.config : {};
      if (n.recipe === "web-server") delete config.memoryMiB;
      return {
        id: String(n.id), name: String(n.name ?? n.id), recipe: server || String(n.recipe ?? ""),
        x: Number.isFinite(+n.x) ? +n.x : 0, y: Number.isFinite(+n.y) ? +n.y : 0,
        config: normalizeNodeConfig(server ? { ...config, role: "domain-controller" } : config),
        media: n.media && typeof n.media === "object" ? n.media : {},
      };
    }) : [],
    links: Array.isArray(def.links) ? def.links.filter((l) => l && l.a && l.b).map((l) => ({
      a: { node: String(l.a.node), port: String(l.a.port) },
      b: { node: String(l.b.node), port: String(l.b.port) },
    })) : [],
  };
  const switches = new Map(normalized.nodes.filter((n) => n.recipe === "switch").map((n) => [n.id, new Set()]));
  const ends = normalized.links.flatMap((l) => [l.a, l.b]);
  for (const end of ends) if (end.port !== "lan") switches.get(end.node)?.add(end.port);
  for (const end of ends) {
    const used = switches.get(end.node);
    if (!used || end.port !== "lan") continue;
    for (let number = 1; number < 64; number++) {
      const port = `port${number}`;
      if (used.has(port)) continue;
      end.port = port;
      used.add(port);
      break;
    }
  }
  return normalized;
}
function softwareSelection(value) {
  if (typeof value === "string") return value ? [value] : [];
  return Array.isArray(value) ? [...new Set(value)].sort() : [];
}
function normalizeNodeConfig(config) {
  if (Object.hasOwn(config, "software")) {
    const selected = softwareSelection(config.software);
    if (selected.length) config.software = selected; else delete config.software;
  }
  return config;
}
function orderedRecord(record) {
  return Object.fromEntries(Object.entries(record || {}).sort(([a], [b]) => a.localeCompare(b)));
}
const defKey = (d) => JSON.stringify(normalizeDefinition(d), (key, value) =>
  key === "config" || key === "media" ? orderedRecord(value) : value);
const isDirty = () => !S.saved || defKey(S.draft) !== defKey(S.saved);
const nodeById = (id, def = S.draft) => def.nodes.find((n) => n.id === id);
const recipeOf = (node) => S.recipes.get(node.recipe);

function mutate(fn, { history = true } = {}) {
  if (history) {
    S.undo.push(JSON.stringify(S.draft));
    if (S.undo.length > 150) S.undo.shift();
    S.redo.length = 0;
  }
  fn(S.draft);
  draftChanged();
}
function draftChanged() {
  try { localStorage.setItem(DRAFT_KEY, JSON.stringify(S.draft)); } catch (_) {}
  renderAll();
  refreshInspectors();
}
function undo() {
  if (!S.undo.length) return;
  S.redo.push(JSON.stringify(S.draft));
  S.draft = JSON.parse(S.undo.pop());
  pruneSelection(); draftChanged();
}
function redo() {
  if (!S.redo.length) return;
  S.undo.push(JSON.stringify(S.draft));
  S.draft = JSON.parse(S.redo.pop());
  pruneSelection(); draftChanged();
}
function replaceDraft(def, { history = true } = {}) {
  mutate((d) => { const n = normalizeDefinition(def); d.version = 1; d.name = n.name; d.nodes = n.nodes; d.links = n.links; }, { history });
  pruneSelection();
}
function pruneSelection() {
  for (const id of [...S.sel.nodes]) if (!nodeById(id)) S.sel.nodes.delete(id);
  if (S.sel.link >= S.draft.links.length) S.sel.link = -1;
}

// ---------------------------------------------------------------- icons
const ICONS = {
  windows: '<svg viewBox="0 0 24 24"><path d="M3 5.5l7.5-1v7H3zM12 4.3L21 3v8.5h-9zM3 12.5h7.5v7L3 18.5zM12 12.5h9V21l-9-1.3z"/></svg>',
  linux: '<svg viewBox="0 0 24 24"><path d="M8 8a4 4 0 1 1 8 0c0 2 1 3 2 5l1 2a4 4 0 0 1-2 5H7a4 4 0 0 1-2-5l1-2c1-2 2-3 2-5Z"/><path d="m10 9 2 1 2-1m-5 3c-1 1-2 3-2 5m8-5c1 1 2 3 2 5m-8 3-2 1H4m11-1 2 1h3"/><path d="M10 7h.1m3.8 0h.1"/></svg>',
  dos: '<svg viewBox="0 0 24 24"><path d="M4 7l5 5-5 5M12 18h8"/></svg>',
  bsd: '<svg viewBox="0 0 24 24"><ellipse cx="12" cy="12" rx="9" ry="5.5"/><path d="M8 12h8"/></svg>',
  mac: '<svg viewBox="0 0 24 24"><path d="M12 7c-1-1-2.5-1.5-4-1-2.5.8-3.5 4-2.5 7.5S8.5 20 10 20c1 0 1.300-.5 2-.5s1 .5 2 .5c1.500 0 3.500-3 4.500-6.500.5-1.800-.5-3-1.500-3.500C15.500 5.500 13.500 6 12 7z"/><path d="M12 7c0-2 1-3.500 3-4"/></svg>',
  ibm: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9h10M7 12h10M7 15h6"/></svg>',
  switch: '<svg viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="10" rx="2"/><circle cx="8" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="16" cy="12" r="1.3"/></svg>',
  router: '<svg viewBox="0 0 24 24"><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="18" r="2.2"/><circle cx="12" cy="6" r="2.2"/><path d="M11 8l-4 8M13 8l4 8M8 18h8"/></svg>',
  network: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" stroke-dasharray="3 3"/></svg>',
  nat: '<svg viewBox="0 0 24 24"><path d="M7 18a5 5 0 010-10 6 6 0 0111.5 1.5A4.3 4.3 0 0118 18z"/></svg>',
  internet: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.500 3 14.500 0 18M12 3c-3 3.500-3 14.500 0 18"/></svg>',
  server: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/></svg>',
  file: '<svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>',
  log: '<svg viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 11h7M9 14h7M9 17h5"/></svg>',
  web: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M6.5 6.5h.01M9 6.5h.01"/></svg>',
  monitor: '<svg viewBox="0 0 24 24"><path d="M3 12h4l3-7 4 14 3-7h4"/></svg>',
  lab: '<svg viewBox="0 0 24 24"><path d="M9 3h6M10 3v6l-5 9a2 2 0 001.700 3h10.600a2 2 0 001.700-3l-5-9V3"/></svg>',
  box: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="7" height="7" rx="1.500"/><rect x="13" y="4" width="7" height="7" rx="1.500"/><rect x="4" y="13" width="7" height="7" rx="1.500"/><rect x="13" y="13" width="7" height="7" rx="1.500"/></svg>',
  gear: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.200 4.200l2.100 2.100M17.700 17.700l2.100 2.100M2 12h3M19 12h3M4.200 19.800l2.100-2.100M17.700 6.300l2.100-2.100"/></svg>',
  term: '<svg viewBox="0 0 24 24"><path d="M4 7l5 5-5 5M12 18h8"/></svg>',
  screen: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
  play: '<svg viewBox="0 0 24 24"><path d="M7 4l13 8-13 8z"/></svg>',
  chev: '<svg class="chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>',
  back: '<svg viewBox="0 0 24 24"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>',
  forward: '<svg viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  reload: '<svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 10-2.300 5.700M20 4v7h-7"/></svg>',
  fullscreen: '<svg viewBox="0 0 24 24"><path d="M4 9V4h5M15 4h5v5M20 15v5h-5M9 20H4v-5"/></svg>',
  exitFullscreen: '<svg viewBox="0 0 24 24"><path d="M9 4v5H4M20 9h-5V4M15 20v-5h5M4 15h5v5"/></svg>',
};
const ICON_RULES = [
  [/switch|hub|bridge/, "switch"], [/router|gateway(?!.*nat)/, "router"], [/nat/, "nat"],
  [/internet|wan/, "internet"], [/isolated|network|lan|segment/, "network"],
  [/win(dows)?|nt\d|xp|vista/, "windows"], [/dos|legacy|cp\/?m/, "dos"],
  [/mac|apple|darwin/, "mac"], [/bsd|unix|irix|solaris|aix|hp-?ux/, "bsd"],
  [/linux|debian|ubuntu|fedora|alpine|arch|centos|redhat|suse/, "linux"],
  [/ibm|as\/?400|mainframe|z\/?os|390|power/, "ibm"],
  [/file|share|nfs|smb/, "file"], [/dns|dhcp|server|domain|controller/, "server"],
  [/web|http/, "web"], [/monitor|capture/, "monitor"],
];
function iconFor(r) {
  if (!r) return ICONS.box;
  const text = `${r.id} ${r.title} ${r.family}`.toLowerCase();
  for (const [re, key] of ICON_RULES) if (re.test(text)) return ICONS[key];
  return ICONS.box;
}

// ---------------------------------------------------------------- toasts / status / modal
function toast(msg, kind = "") {
  const t = el("div", { class: `toast ${kind}`, text: msg });
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "err" ? 8000 : 3500);
}
function setStatus(msg) { $("#status").textContent = msg || ""; }

function modal({ title, body, buttons = [] }) {
  return new Promise((resolve) => {
    const back = $("#modal-back"), box = $("#modal");
    box.replaceChildren(el("h2", { text: title }), el("div", { class: "m-body" }, body),
      el("div", { class: "m-foot" }, buttons.map((b) => el("button", {
        class: `btn ${b.primary ? "primary" : ""} ${b.danger ? "danger" : ""}`, text: b.label,
        onclick: () => close(b.value),
      }))));
    back.hidden = false;
    const onKey = (e) => { if (e.key === "Escape") close(undefined); };
    function close(v) { back.hidden = true; box.replaceChildren(); document.removeEventListener("keydown", onKey, true); resolve(v); }
    back.onclick = (e) => { if (e.target === back) close(undefined); };
    document.addEventListener("keydown", onKey, true);
    box._close = close;
  });
}
function closeModal(v) { const box = $("#modal"); if (box._close) box._close(v); }

// ---------------------------------------------------------------- palette
const paletteGroup = (recipe) => recipe.group || recipe.family || "Other";
const releaseYear = (recipe) => (Number.isInteger(recipe?.releaseYear) && recipe.releaseYear > 0 ? recipe.releaseYear : null);
// Order dated recipes oldest first within the slots they already occupy, so
// undated entries and equal years keep their catalog placement.
function sortByReleaseYear(items) {
  const slots = [];
  items.forEach((r, i) => { if (releaseYear(r) !== null) slots.push(i); });
  const dated = slots.map((i) => items[i]).sort((a, b) => releaseYear(a) - releaseYear(b));
  const out = items.slice();
  slots.forEach((i, k) => { out[i] = dated[k]; });
  return out;
}
function renderPalette() {
  const q = $("#palette-search").value.trim().toLowerCase();
  const fams = new Map();
  for (const r of S.catalog.recipes) {
    const f = paletteGroup(r);
    const hay = `${r.title} ${r.id} ${r.family} ${f} ${releaseYear(r) ?? ""} ${r.description || ""}`.toLowerCase();
    if (q && !q.split(/\s+/).every((w) => hay.includes(w))) continue;
    if (!fams.has(f)) fams.set(f, []);
    fams.get(f).push(r);
  }
  const root = $("#palette");
  root.replaceChildren();
  if (!fams.size) { root.append(el("div", { class: "empty-note", text: S.catalog.recipes.length ? "No nodes match." : "Catalog is empty." })); return; }
  const collapsed = loadCollapsed();
  for (const [fam, items] of fams) {
    const sec = el("div", { class: `fam ${collapsed.has(fam) && !q ? "collapsed" : ""}` });
    const head = el("button", { class: "fam-head", "aria-expanded": String(!sec.classList.contains("collapsed")), onclick: () => {
      const closed = sec.classList.toggle("collapsed");
      head.setAttribute("aria-expanded", String(!closed));
      if (!q) {
        if (closed) collapsed.add(fam); else collapsed.delete(fam);
        saveCollapsed(collapsed);
      }
    } }, el("span", { text: fam }), el("span", { html: ICONS.chev }));
    const list = el("div", { class: "fam-items" });
    for (const r of sortByReleaseYear(items)) {
      const year = releaseYear(r);
      const blocked = r.blocked ? (typeof r.blocked === "string" ? r.blocked : "Unavailable") : "";
      const item = el("div", {
        class: "pal-item", draggable: blocked ? null : "true",
        title: blocked ? `Blocked: ${blocked}` : (r.description || r.title),
        style: blocked ? "opacity:.45;cursor:not-allowed" : null,
        ondragstart: (e) => { e.dataTransfer.setData("application/x-lab-recipe", r.id); e.dataTransfer.effectAllowed = "copy"; },
        ondblclick: () => { if (!blocked) addNodeAtCenter(r.id); },
      }, el("span", { class: "ico", html: iconFor(r) }), el("span", { class: "lbl", text: r.title }),
         year !== null ? el("span", { class: "sub", title: `Released ${year}`, text: String(year) }) : null,
         blocked ? el("span", { class: "sub", text: "blocked" }) : null);
      list.append(item);
    }
    sec.append(head, list);
    root.append(sec);
  }
}
function loadCollapsed() {
  try {
    const saved = JSON.parse(localStorage.getItem("tinyrangex.lab.collapsedGroups"));
    if (Array.isArray(saved)) return new Set(saved);
  } catch (_) {}
  return new Set(S.catalog.recipes.map(paletteGroup).filter((group) => group !== "Networking" && group !== "Windows 1.x–3.x"));
}
function saveCollapsed(s) { try { localStorage.setItem("tinyrangex.lab.collapsedGroups", JSON.stringify([...s])); } catch (_) {} }

function renderTemplates() {
  const root = $("#templates");
  root.replaceChildren();
  if (!S.catalog.templates.length) { root.append(el("div", { class: "empty-note", text: "No templates available." })); return; }
  for (const t of S.catalog.templates) {
    const n = (t.definition?.nodes || []).length;
    root.append(el("button", { class: "tpl-item", onclick: () => useTemplate(t) },
      el("div", { class: "t", text: t.title }),
      el("div", { class: "d", text: `${t.description || ""}${t.description ? " · " : ""}${n} node${n === 1 ? "" : "s"}` })));
  }
}

async function useTemplate(t) {
  let mode = "replace";
  if (S.draft.nodes.length) {
    mode = await modal({
      title: `Use template “${t.title}”`,
      body: el("div", { text: "The canvas already has nodes. Replace the draft with this template, or add the template's nodes beside the existing ones?" }),
      buttons: [{ label: "Cancel", value: undefined }, { label: "Add to canvas", value: "merge" }, { label: "Replace draft", value: "replace", primary: true }],
    });
    if (!mode) return;
  }
  const tdef = normalizeDefinition(t.definition);
  if (mode === "replace") {
    replaceDraft(tdef);
    S.sel.nodes.clear();
    fitView();
  } else {
    const bb = bbox(S.draft.nodes), tb = bbox(tdef.nodes);
    const dx = bb ? bb.x2 + 120 - (tb ? tb.x1 : 0) : 0, dy = bb && tb ? bb.y1 - tb.y1 : 0;
    const remap = new Map();
    mutate((d) => {
      for (const n of tdef.nodes) {
        const id = uniqueId(n.id, d, remap);
        remap.set(n.id, id);
        d.nodes.push({ ...n, id, x: n.x + dx, y: n.y + dy });
      }
      for (const l of tdef.links) d.links.push({ a: { node: remap.get(l.a.node), port: l.a.port }, b: { node: remap.get(l.b.node), port: l.b.port } });
      for (const n of d.nodes) if (remap.has(n.id) && typeof n.config?.domain === "string" && remap.has(n.config.domain)) n.config.domain = remap.get(n.config.domain);
    });
    S.sel.nodes = new Set(remap.values());
    renderAll();
  }
  toast(`Template “${t.title}” loaded into the draft.`);
}

// ---------------------------------------------------------------- node creation
function slug(s) { return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "node"; }
function uniqueId(base, def = S.draft, extra = new Map()) {
  const b = slug(base);
  const taken = new Set([...def.nodes.map((n) => n.id), ...extra.values()]);
  if (!taken.has(b)) return b;
  for (let i = 2; ; i++) if (!taken.has(`${b}-${i}`)) return `${b}-${i}`;
}
function uniqueName(base) {
  const taken = new Set(S.draft.nodes.map((n) => n.name));
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) if (!taken.has(`${base} ${i}`)) return `${base} ${i}`;
}
function addNode(recipeId, x, y, config = {}) {
  const r = S.recipes.get(recipeId);
  if (!r) return;
  if (r.blocked) { toast(`${r.title} is blocked: ${typeof r.blocked === "string" ? r.blocked : "unavailable"}`, "err"); return; }
  const id = uniqueId(r.id);
  const node = { id, name: uniqueName(r.title), recipe: r.id, x: Math.round(x - NODE_W / 2), y: Math.round(y - NODE_H / 2), config: {}, media: {} };
  for (const f of r.fields || []) if (f.default !== undefined && f.key !== "software") node.config[f.key] = clone(f.default);
  Object.assign(node.config, config);
  mutate((d) => d.nodes.push(node));
  S.sel.nodes = new Set([id]); S.sel.link = -1;
  renderAll();
  return node;
}
function addNodeAtCenter(recipeId, config) {
  const rect = $("#stage").getBoundingClientRect();
  const p = toWorld(rect.left + rect.width / 2, rect.top + rect.height / 2);
  const jitter = (S.draft.nodes.length % 5) * 24;
  return addNode(recipeId, p.x + jitter, p.y + jitter, config);
}

function removeSelection() {
  if (S.sel.link >= 0) {
    const i = S.sel.link;
    mutate((d) => d.links.splice(i, 1));
    S.sel.link = -1; renderAll(); return;
  }
  if (!S.sel.nodes.size) return;
  const ids = new Set(S.sel.nodes);
  mutate((d) => {
    d.nodes = d.nodes.filter((n) => !ids.has(n.id));
    d.links = d.links.filter((l) => !ids.has(l.a.node) && !ids.has(l.b.node));
    for (const n of d.nodes) if (typeof n.config?.domain === "string" && ids.has(n.config.domain)) delete n.config.domain;
  });
  for (const id of ids) WM.close(`inspect:${id}`);
  S.sel.nodes.clear(); renderAll();
}

// ---------------------------------------------------------------- canvas geometry
const stage = $("#stage"), world = $("#world");
function applyCam() {
  world.style.transform = `translate(${S.cam.x}px, ${S.cam.y}px) scale(${S.cam.k})`;
  stage.style.backgroundPosition = `${S.cam.x}px ${S.cam.y}px`;
  stage.style.backgroundSize = `${24 * S.cam.k}px ${24 * S.cam.k}px`;
  $("#zoom-val").textContent = `${Math.round(S.cam.k * 100)}%`;
}
function toWorld(cx, cy) {
  const r = stage.getBoundingClientRect();
  return { x: (cx - r.left - S.cam.x) / S.cam.k, y: (cy - r.top - S.cam.y) / S.cam.k };
}
function zoomAt(k, cx, cy) {
  const r = stage.getBoundingClientRect();
  const nk = clamp(k, 0.2, 3);
  const px = cx - r.left, py = cy - r.top;
  S.cam.x = px - ((px - S.cam.x) / S.cam.k) * nk;
  S.cam.y = py - ((py - S.cam.y) / S.cam.k) * nk;
  S.cam.k = nk; applyCam();
}
function bbox(nodes) {
  if (!nodes.length) return null;
  let x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
  for (const n of nodes) { x1 = Math.min(x1, n.x); y1 = Math.min(y1, n.y); x2 = Math.max(x2, n.x + nodeWidth(n)); y2 = Math.max(y2, n.y + NODE_H); }
  return { x1, y1, x2, y2 };
}
function fitView() {
  const r = stage.getBoundingClientRect();
  const bb = bbox(S.draft.nodes);
  if (!bb) { S.cam = { x: r.width / 2, y: r.height / 2, k: 1 }; applyCam(); return; }
  const pad = 80;
  const k = clamp(Math.min((r.width - pad * 2) / (bb.x2 - bb.x1), (r.height - pad * 2) / (bb.y2 - bb.y1)), 0.3, 1.25);
  S.cam = { k, x: r.width / 2 - ((bb.x1 + bb.x2) / 2) * k, y: r.height / 2 - ((bb.y1 + bb.y2) / 2) * k };
  applyCam();
}

function visiblePorts(node) {
  const ports = recipeOf(node)?.ports || [];
  if (node.recipe !== "switch") return ports;
  const used = new Set();
  for (const link of S.draft.links) {
    if (link.a.node === node.id) used.add(link.a.port);
    if (link.b.node === node.id) used.add(link.b.port);
  }
  const next = ports.find((p) => !used.has(p.id));
  return ports.filter((p) => p === next || used.has(p.id));
}
function nodeWidth(node) {
  return Math.max(NODE_W, 62 * (visiblePorts(node).length + 1));
}
function portLayout(node) {
  const ports = visiblePorts(node);
  if (node.recipe !== "switch") return ports.map((p) => ({ ...p, dx: NODE_W / 2, dy: 0, side: -1 }));
  const width = Math.max(NODE_W, 62 * (ports.length + 1));
  return ports.map((p, i) => ({ ...p, dx: width * (i + 1) / (ports.length + 1), dy: NODE_H, side: 1 }));
}
function portPos(nodeId, portId) {
  const n = nodeById(nodeId);
  if (!n) return null;
  const p = portLayout(n).find((q) => q.id === portId);
  if (!p) return { x: n.x + nodeWidth(n) / 2, y: n.y + NODE_H, side: 1, missing: true };
  return { x: n.x + p.dx, y: n.y + p.dy, side: p.side };
}
function edgePath(a, b) {
  const d = Math.max(40, Math.abs(b.y - a.y) / 2);
  return `M${a.x},${a.y} C${a.x},${a.y + a.side * d} ${b.x},${b.y + (b.side ?? -1) * d} ${b.x},${b.y}`;
}
function linkFor(nodeId, portId) {
  return S.draft.links.findIndex((l) => (l.a.node === nodeId && l.a.port === portId) || (l.b.node === nodeId && l.b.port === portId));
}

// ---------------------------------------------------------------- drift (draft vs applied)
function nodeSig(n) {
  const recipe = recipeOf(n);
  const media = recipe ? recipe.media.filter((slot) => mediaVisible(slot, recipe, n.config)).map((slot) => mediaReference(slot, n.media)) : orderedRecord(n.media);
  return JSON.stringify([n.recipe, orderedRecord(n.config), media]);
}
function linkSig(l) { const a = `${l.a.node}/${l.a.port}`, b = `${l.b.node}/${l.b.port}`; return a < b ? `${a}|${b}` : `${b}|${a}`; }
function computeDrift() {
  const ap = S.applied ? normalizeDefinition(S.applied) : null;
  const res = { nodes: new Map(), removed: [], links: 0, any: false };
  if (!ap) return res;
  const am = new Map(ap.nodes.map((n) => [n.id, n]));
  for (const n of S.draft.nodes) {
    const a = am.get(n.id);
    if (!a) res.nodes.set(n.id, "new");
    else if (nodeSig(a) !== nodeSig(n) || a.name !== n.name) res.nodes.set(n.id, "changed");
  }
  const dm = new Set(S.draft.nodes.map((n) => n.id));
  res.removed = ap.nodes.filter((n) => !dm.has(n.id));
  const al = new Set(ap.links.map(linkSig)), dl = new Set(S.draft.links.map(linkSig));
  for (const s of al) if (!dl.has(s)) res.links++;
  for (const s of dl) if (!al.has(s)) res.links++;
  res.any = res.nodes.size > 0 || res.removed.length > 0 || res.links > 0;
  return res;
}

// ---------------------------------------------------------------- render
function renderAll() {
  renderNodes(); renderEdges(); renderChrome(); refreshLogs();
}
function renderNodes() {
  const drift = computeDrift();
  const layer = $("#nodes");
  layer.replaceChildren();
  for (const n of S.draft.nodes) {
    const r = recipeOf(n);
    const rt = S.view?.nodes?.[n.id];
    const phase = rt?.phase || "stopped";
    const phaseLabel = {
      stopped: "Stopped", preparing: "Preparing", starting: "Starting", booting: "Booting",
      provisioning: "Provisioning", running: "Running", stopping: "Stopping", failed: "Failed",
    }[phase] || phase;
    const d = drift.nodes.get(n.id);
    const memory = n.config.memoryMiB ?? r?.fields.find((f) => f.key === "memoryMiB")?.default;
    const system = r?.title !== n.name ? r?.title : "";
    const subtitle = [
      rt?.address, system,
      !rt?.address && memory ? `${memory} MiB RAM` : "",
      r && !r.ports.length ? "No Ethernet" : "",
    ].filter(Boolean).join(" · ");
    const missing = missingMedia(n);
    const box = el("div", {
      class: `node ${S.sel.nodes.has(n.id) ? "selected" : ""} ${d ? `draft-${d}` : ""}`,
      style: `left:${n.x}px;top:${n.y}px;width:${nodeWidth(n)}px;height:${NODE_H}px`,
      dataset: { id: n.id },
      title: [n.name, subtitle, phaseLabel, d === "new" ? "Ready to start" : d === "changed" ? "Draft changes" : "", rt?.message,
        missing.length ? `Missing media: ${missing.map((m) => m.label || m.key).join(", ")}` : ""].filter(Boolean).join("\n"),
    },
      el("div", { class: "n-head" },
        el("div", { class: "n-ico", html: iconFor(r) }),
        el("div", { class: "n-txt" }, el("div", { class: "n-name", text: n.name }),
          subtitle ? el("div", { class: "n-sub", text: subtitle }) : null)));
    const acts = el("div", { class: "n-acts" });
    if (phase === "failed") {
      acts.append(el("button", { text: "Inspect failure", onclick: (e) => {
        e.stopPropagation();
        openInspector(n.id, "Runtime");
      } }));
    }
    for (const s of rt?.surfaces || []) {
      const label = `Open ${surfaceLabel(s).toLowerCase()} · ${s.name || s.id}`;
      acts.append(el("button", {
        title: label, "aria-label": label,
        onclick: (e) => { e.stopPropagation(); openSurface(n.id, s); },
      }, el("span", { class: "n-action-icon", html: surfaceIcon(s) }),
      isWeb(s) ? "Browser" : isTerminal(s) ? "Serial" : "Display"));
    }
    acts.append(el("button", { text: "Edit", title: "Edit node", "aria-label": "Edit node",
      onclick: (e) => { e.stopPropagation(); openInspector(n.id); },
    }));
    const state = el("span", { class: `n-status ${phase}` }, el("span", { class: "n-state" }), phaseLabel);
    box.append(el("div", { class: "n-foot" }, state, acts));
    for (const p of portLayout(n)) {
      const used = linkFor(n.id, p.id) >= 0;
      const armed = S.connecting && S.connecting.node === n.id && S.connecting.port === p.id;
      const compatible = !armed && canConnect(S.connecting, { node: n.id, port: p.id });
      box.append(el("div", {
        class: `port ${used ? "used" : ""} ${armed ? "armed" : ""} ${compatible ? "compatible" : ""}`,
        style: `left:${p.dx}px;top:${p.dy}px`, dataset: { node: n.id, port: p.id },
        title: `${p.label || p.id} (${p.kind})${used ? " · Connected" : " · Available"}`,
      }));
      box.append(el("div", { class: `port-label ${p.side < 0 ? "above" : "below"}`, style: `left:${p.dx}px;top:${p.dy}px`, text: p.label || p.id }));
    }
    layer.append(box);
  }
  $("#blank-hint").hidden = S.draft.nodes.length > 0;
}
function portSpec(ref) {
  const n = ref && nodeById(ref.node);
  return n && portLayout(n).find((p) => p.id === ref.port);
}
function canConnect(src, target) {
  if (!src || !target || src.node === target.node) return false;
  const a = portSpec(src), b = portSpec(target);
  const fromSwitch = nodeById(src.node)?.recipe === "switch", toSwitch = nodeById(target.node)?.recipe === "switch";
  if (!a || !b || a.kind !== b.kind || fromSwitch === toSwitch) return false;
  return linkFor(src.node, src.port) < 0 && linkFor(target.node, target.port) < 0;
}
function renderEdges() {
  const g = $("#edge-layer");
  g.replaceChildren();
  const ns = "http://www.w3.org/2000/svg";
  const ap = S.applied ? new Set(normalizeDefinition(S.applied).links.map(linkSig)) : null;
  S.draft.links.forEach((l, i) => {
    const a = portPos(l.a.node, l.a.port), b = portPos(l.b.node, l.b.port);
    if (!a || !b) return;
    const d = edgePath(a, b);
    const grp = document.createElementNS(ns, "g");
    grp.setAttribute("class", `edge-g ${S.sel.link === i ? "selected" : ""} ${ap && !ap.has(linkSig(l)) ? "pending" : ""}`);
    const hit = document.createElementNS(ns, "path");
    hit.setAttribute("class", "edge-hit"); hit.setAttribute("d", d); hit.dataset.link = i;
    const path = document.createElementNS(ns, "path");
    path.setAttribute("class", "edge"); path.setAttribute("d", d);
    const title = document.createElementNS(ns, "title");
    const label = (end) => `${nodeById(end.node)?.name || end.node} · ${portSpec(end)?.label || end.port}`;
    title.textContent = `${label(l.a)} ↔ ${label(l.b)}`;
    grp.append(title, hit, path);
    g.append(grp);
  });
}
function renderChrome() {
  const dirty = isDirty();
  $("#dirty-dot").hidden = !dirty;
  $("#save-btn").hidden = !dirty;
  $("#saved-pill").hidden = dirty;
  const name = $("#lab-name");
  if (document.activeElement !== name) name.value = S.draft.name;
  document.title = `${S.draft.name} — Virtual Lab Editor`;
  $("#undo-btn").disabled = !S.undo.length;
  $("#redo-btn").disabled = !S.redo.length;

  const st = S.view?.state || "idle";
  const pill = $("#run-pill");
  const label = { idle: "Stopped", applying: "Applying…", running: "Running", stopping: "Stopping…", failed: "Failed" }[st] || st;
  pill.textContent = label;
  pill.className = `pill ${st === "running" ? "running" : st === "failed" ? "error" : st === "applying" || st === "stopping" ? "busy" : ""}`;
  pill.title = S.view?.error || "";
  const failedNode = S.draft.nodes.find((node) => S.view?.nodes?.[node.id]?.phase === "failed");
  const failureButton = $("#failure-btn");
  failureButton.hidden = !failedNode;
  failureButton.onclick = failedNode ? () => openInspector(failedNode.id, "Runtime") : null;
  const drift = computeDrift();
  const driftPill = $("#drift-pill");
  const hasApplied = !!S.applied;
  driftPill.hidden = !(hasApplied && drift.any);
  if (drift.any) {
    const parts = [];
    const nn = [...drift.nodes.values()];
    if (nn.filter((v) => v === "new").length) parts.push(`${nn.filter((v) => v === "new").length} new`);
    if (nn.filter((v) => v === "changed").length) parts.push(`${nn.filter((v) => v === "changed").length} changed`);
    if (drift.removed.length) parts.push(`${drift.removed.length} removed`);
    if (drift.links) parts.push(`${drift.links} link change${drift.links === 1 ? "" : "s"}`);
    driftPill.textContent = `Draft differs · ${parts.join(", ")}`;
    driftPill.title = drift.removed.length ? `Running but removed from draft: ${drift.removed.map((n) => n.name).join(", ")}` : "Click to review the plan";
  }
  const busy = st === "applying" || st === "stopping";
  const applyBtn = $("#apply-btn");
  applyBtn.querySelector("span").textContent = hasApplied && st !== "idle" ? (drift.any ? "Apply Changes" : "Re-plan") : "Run Lab";
  applyBtn.disabled = busy;
  $("#stop-btn").hidden = !(st === "running" || st === "applying" || st === "failed");
  $("#stop-btn").disabled = st === "stopping";
  const ops = S.view?.operation || [];
  if (busy && ops.length) setStatus(ops.map((o) => `${o.node}: ${o.action}${o.detail ? ` (${o.detail})` : ""}`).join(" · "));
  else if (failedNode) setStatus(`${failedNode.name} failed`);
  else if (S.view?.error) setStatus(`Error: ${S.view.error}`);
  else setStatus(`${S.draft.nodes.length} node${S.draft.nodes.length === 1 ? "" : "s"}, ${S.draft.links.length} link${S.draft.links.length === 1 ? "" : "s"}`);
}

// ---------------------------------------------------------------- canvas interaction
const ghost = $("#ghost-edge");
let drag = null;   // {kind:'nodes'|'pan'|'connect', ...}
let spaceDown = false;
let lastNodeDown = null; // {id, t, x, y}: pointerdown re-renders nodes, so native dblclick targets are unreliable.
const DBL_MS = 450, DBL_PX = 6;

function setTool(t) {
  S.tool = t;
  document.querySelectorAll(".tool[data-tool]").forEach((b) => b.classList.toggle("active", b.dataset.tool === t));
  stage.classList.toggle("tool-pan", t === "pan");
  stage.classList.toggle("tool-connect", t === "connect");
  if (t !== "connect") cancelConnect();
}
function cancelConnect() {
  if (!S.connecting) return;
  S.connecting = null; ghost.setAttribute("d", ""); stage.classList.remove("connecting"); renderNodes();
}
function tryConnect(target) {
  const src = S.connecting;
  cancelConnect();
  if (!src || !target) return;
  if (src.node === target.node) { toast("A node cannot be connected to itself.", "err"); return; }
  if (!canConnect(src, target)) { toast("Connect an unused guest Ethernet port to an isolated switch.", "err"); return; }
  mutate((d) => d.links.push({ a: { ...src }, b: { ...target } }));
  S.sel.link = S.draft.links.length - 1; S.sel.nodes.clear(); renderAll();
}

stage.addEventListener("pointerdown", (e) => {
  if (e.target.closest(".win") || e.button === 2) return;
  stage.focus({ preventScroll: true });
  const portEl = e.target.closest(".port");
  const nodeEl = e.target.closest(".node");
  const edgeEl = e.target.closest(".edge-hit");
  if (e.target.closest(".n-acts")) return;

  if (e.button === 1 || spaceDown || S.tool === "pan" || (!portEl && !nodeEl && !edgeEl)) {
    if (!portEl && !nodeEl && !edgeEl && S.tool !== "pan" && !spaceDown && e.button === 0) {
      S.sel.nodes.clear(); S.sel.link = -1; cancelConnect(); renderAll();
    }
    drag = { kind: "pan", sx: e.clientX, sy: e.clientY, cx: S.cam.x, cy: S.cam.y };
    stage.classList.add("panning");
    stage.setPointerCapture(e.pointerId);
    return;
  }
  if (portEl) {
    e.preventDefault();
    const ref = { node: portEl.dataset.node, port: portEl.dataset.port };
    if (S.connecting) { tryConnect(ref); return; }
    const existing = linkFor(ref.node, ref.port);
    if (existing >= 0) { S.sel.link = existing; S.sel.nodes.clear(); renderAll(); return; }
    S.connecting = ref; stage.classList.add("connecting");
    drag = { kind: "connect", sx: e.clientX, sy: e.clientY, moved: false };
    stage.setPointerCapture(e.pointerId);
    renderNodes();
    return;
  }
  if (edgeEl) {
    S.sel.link = +edgeEl.dataset.link; S.sel.nodes.clear(); renderAll(); return;
  }
  if (nodeEl) {
    const id = nodeEl.dataset.id;
    if (S.tool === "connect" || S.connecting) {
      const n = nodeById(id);
      const free = portLayout(n).find((p) => S.connecting
        ? canConnect(S.connecting, { node: id, port: p.id }) : linkFor(id, p.id) < 0);
      if (!free) { toast("All ports on this node are connected.", "err"); return; }
      if (S.connecting) tryConnect({ node: id, port: free.id });
      else { S.connecting = { node: id, port: free.id }; stage.classList.add("connecting"); renderNodes(); }
      return;
    }
    const modified = e.shiftKey || e.ctrlKey || e.metaKey;
    const now = performance.now(), prev = lastNodeDown;
    const dbl = !modified && e.button === 0 && !!prev && prev.id === id && now - prev.t < DBL_MS && Math.hypot(e.clientX - prev.x, e.clientY - prev.y) < DBL_PX;
    lastNodeDown = dbl || modified || e.button !== 0 ? null : { id, t: now, x: e.clientX, y: e.clientY };
    if (modified) {
      if (S.sel.nodes.has(id)) S.sel.nodes.delete(id); else S.sel.nodes.add(id);
    } else if (!S.sel.nodes.has(id)) S.sel.nodes = new Set([id]);
    S.sel.link = -1;
    const start = toWorld(e.clientX, e.clientY);
    drag = { kind: "nodes", id, dbl, start, orig: new Map([...S.sel.nodes].map((nid) => { const n = nodeById(nid); return [nid, { x: n.x, y: n.y }]; })), snapshot: JSON.stringify(S.draft), moved: false };
    stage.setPointerCapture(e.pointerId);
    renderAll();
  }
});
stage.addEventListener("pointermove", (e) => {
  if (S.connecting) {
    const a = portPos(S.connecting.node, S.connecting.port);
    const p = toWorld(e.clientX, e.clientY);
    if (a) ghost.setAttribute("d", edgePath(a, { x: p.x, y: p.y, side: p.y < a.y ? 1 : -1 }));
  }
  if (!drag) return;
  if (drag.kind === "pan") {
    S.cam.x = drag.cx + e.clientX - drag.sx; S.cam.y = drag.cy + e.clientY - drag.sy; applyCam();
  } else if (drag.kind === "connect") {
    if (Math.hypot(e.clientX - drag.sx, e.clientY - drag.sy) > 4) drag.moved = true;
  } else if (drag.kind === "nodes") {
    const p = toWorld(e.clientX, e.clientY);
    const dx = Math.round(p.x - drag.start.x), dy = Math.round(p.y - drag.start.y);
    if (!drag.moved && Math.hypot(dx, dy) < 3) return;
    drag.moved = true;
    for (const [id, o] of drag.orig) {
      const n = nodeById(id);
      if (!n) continue;
      n.x = o.x + dx; n.y = o.y + dy;
      const div = $(`.node[data-id="${CSS.escape(id)}"]`);
      if (div) { div.style.left = `${n.x}px`; div.style.top = `${n.y}px`; }
    }
    renderEdges();
  }
});
function endDrag(e) {
  if (!drag) return;
  const d = drag; drag = null;
  stage.classList.remove("panning");
  if (d.kind === "nodes" && d.moved) {
    S.undo.push(d.snapshot); S.redo.length = 0;
    draftChanged();
  } else if (d.kind === "nodes" && d.dbl && e.type === "pointerup") {
    openInspector(d.id);
  } else if (d.kind === "connect" && d.moved) {
    const target = document.elementFromPoint(e.clientX, e.clientY)?.closest(".port");
    if (target) tryConnect({ node: target.dataset.node, port: target.dataset.port });
    else {
      const nodeEl = document.elementFromPoint(e.clientX, e.clientY)?.closest(".node");
      const n = nodeEl && nodeById(nodeEl.dataset.id);
      const free = n && n.id !== S.connecting?.node && portLayout(n).find((p) => canConnect(S.connecting, { node: n.id, port: p.id }));
      if (free) tryConnect({ node: n.id, port: free.id }); else cancelConnect();
    }
  }
}
stage.addEventListener("pointerup", endDrag);
stage.addEventListener("pointercancel", endDrag);
stage.addEventListener("dblclick", (e) => {
  // Fallback for synthetic or retained-target double-clicks; openInspector focuses an already open panel.
  const nodeEl = e.target.closest(".node");
  if (nodeEl && nodeEl.isConnected && !e.target.closest(".win, .n-acts, .port")) openInspector(nodeEl.dataset.id);
});
stage.addEventListener("contextmenu", (e) => {
  if (e.target.closest(".win")) return;
  const nodeEl = e.target.closest(".node");
  if (!nodeEl) { closeNodeMenu(); return; }
  e.preventDefault();
  openNodeMenu(nodeEl.dataset.id, e.clientX, e.clientY);
});
stage.addEventListener("wheel", (e) => {
  if (e.target.closest(".win")) return;
  e.preventDefault();
  // Pinch (ctrlKey), line-mode wheels, and coarse pixel wheels zoom; fine trackpad scrolling pans.
  const wheelLike = e.deltaMode !== 0 || (e.deltaX === 0 && Math.abs(e.deltaY) >= 50);
  if (e.ctrlKey || (wheelLike && !e.shiftKey)) {
    zoomAt(S.cam.k * Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0015)), e.clientX, e.clientY);
  } else {
    S.cam.x -= e.deltaX; S.cam.y -= e.deltaY; applyCam();
  }
}, { passive: false });
stage.addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("application/x-lab-recipe")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } });
stage.addEventListener("drop", (e) => {
  const id = e.dataTransfer.getData("application/x-lab-recipe");
  if (!id) return;
  e.preventDefault();
  const p = toWorld(e.clientX, e.clientY);
  addNode(id, p.x, p.y);
});

// ---------------------------------------------------------------- node context menu
const nodeMenu = $("#node-menu");
let nodeMenuReturn = null;
function duplicateNode(id) {
  const src = nodeById(id);
  if (!src) return;
  const r = recipeOf(src);
  if (r?.blocked) { toast(`${r.title} is blocked: ${typeof r.blocked === "string" ? r.blocked : "unavailable"}`, "err"); return; }
  const node = { ...clone(src), id: uniqueId(src.recipe), name: uniqueName(src.name), x: src.x + 32, y: src.y + 32 };
  mutate((d) => d.nodes.push(node));
  S.sel.nodes = new Set([node.id]); S.sel.link = -1;
  renderAll();
  toast(`Duplicated ${src.name} (links are not copied).`);
}
function startConnectFrom(id) {
  const n = nodeById(id);
  const free = n && portLayout(n).find((p) => linkFor(id, p.id) < 0);
  if (!free) { toast("All ports on this node are connected.", "err"); return; }
  S.connecting = { node: id, port: free.id }; stage.classList.add("connecting");
  renderNodes();
  setStatus(`Connecting ${n.name} · ${free.label || free.id}: click a compatible port or node, Esc to cancel.`);
}
function removeNodeById(id) {
  const n = nodeById(id);
  if (!n) return;
  S.sel.nodes = new Set([id]); S.sel.link = -1;
  removeSelection();
  toast(`Removed ${n.name}. Undo with Ctrl+Z.`);
}
function nodeMenuItems(id) {
  const n = nodeById(id);
  const r = recipeOf(n);
  const rt = S.view?.nodes?.[id];
  const items = [{ label: "Properties", key: "Enter", run: () => openInspector(id) }];
  if (rt?.phase === "failed") items.push({ label: "Inspect failure", danger: true, run: () => openInspector(id, "Runtime") });
  const surfaces = rt?.surfaces || [];
  if (surfaces.length) {
    items.push("-");
    for (const s of surfaces) items.push({ label: `Open ${surfaceLabel(s).toLowerCase()}${s.name ? ` · ${s.name}` : ""}`, icon: surfaceIcon(s), run: () => openSurface(id, s) });
  }
  if (rt) items.push({ label: "View logs", icon: ICONS.log, run: () => openLogs(id) });
  items.push("-");
  if (r?.fields?.some((f) => f.key === "software")) items.push({ label: "Add software…", run: () => openLibrary(id) });
  if (portLayout(n).some((p) => linkFor(id, p.id) < 0)) items.push({ label: "Connect…", run: () => startConnectFrom(id) });
  items.push({ label: "Duplicate", run: () => duplicateNode(id) });
  items.push("-", { label: "Remove node", key: "Del", danger: true, run: () => removeNodeById(id) });
  return items.filter((it, i, a) => it !== "-" || (i > 0 && a[i - 1] !== "-" && i < a.length - 1));
}
function openNodeMenu(id, cx, cy) {
  const n = nodeById(id);
  if (!n) return;
  menu.hidden = true;
  cancelConnect();
  if (!S.sel.nodes.has(id) || S.sel.nodes.size !== 1 || S.sel.link >= 0) { S.sel.nodes = new Set([id]); S.sel.link = -1; renderAll(); }
  nodeMenuReturn = document.activeElement;
  nodeMenu.dataset.node = id;
  nodeMenu.setAttribute("aria-label", `${n.name} actions`);
  nodeMenu.replaceChildren(el("div", { class: "ctx-title", text: n.name }), ...nodeMenuItems(id).map((it) => it === "-"
    ? el("hr", { role: "separator" })
    : el("button", { role: "menuitem", tabindex: "-1", class: it.danger ? "danger" : "", onclick: () => { closeNodeMenu(false); it.run(); } },
      el("span", { class: "ctx-ico", html: it.icon || "" }), el("span", { class: "ctx-label", text: it.label }),
      it.key ? el("kbd", { text: it.key }) : null)));
  nodeMenu.hidden = false;
  nodeMenu.style.left = "0px"; nodeMenu.style.top = "0px";
  const m = 8, w = nodeMenu.offsetWidth, h = nodeMenu.offsetHeight;
  const vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
  const x = cx + w + m > vw ? Math.max(m, cx - w) : cx;
  const y = cy + h + m > vh ? Math.max(m, Math.min(cy - h, vh - h - m)) : cy;
  nodeMenu.style.left = `${x}px`; nodeMenu.style.top = `${y}px`;
  nodeMenu.querySelector("[role=menuitem]")?.focus({ preventScroll: true });
}
function openNodeMenuForSelection() {
  if (S.sel.nodes.size !== 1) return false;
  const id = [...S.sel.nodes][0];
  const box = $(`.node[data-id="${CSS.escape(id)}"]`)?.getBoundingClientRect();
  if (!box) return false;
  openNodeMenu(id, box.left + Math.min(24, box.width / 2), box.bottom - 8);
  return true;
}
function closeNodeMenu(restoreFocus = true) {
  if (nodeMenu.hidden) return;
  nodeMenu.hidden = true;
  nodeMenu.replaceChildren();
  delete nodeMenu.dataset.node;
  const back = nodeMenuReturn; nodeMenuReturn = null;
  if (restoreFocus) (back?.isConnected ? back : stage).focus?.({ preventScroll: true });
}
document.addEventListener("keydown", (e) => {
  if (nodeMenu.hidden) return;
  const items = [...nodeMenu.querySelectorAll("[role=menuitem]")];
  const i = items.indexOf(document.activeElement);
  const go = (j) => { e.preventDefault(); e.stopPropagation(); items[(j + items.length) % items.length]?.focus(); };
  if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeNodeMenu(); }
  else if (e.key === "ArrowDown") go(i + 1);
  else if (e.key === "ArrowUp") go(i < 0 ? -1 : i - 1);
  else if (e.key === "Home") go(0);
  else if (e.key === "End") go(-1);
  else if (e.key === "Tab") go(i + (e.shiftKey ? -1 : 1));
  else if (e.key === "Enter" || e.key === " ") { if (i < 0) go(0); else e.stopPropagation(); }
  else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
    e.preventDefault(); e.stopPropagation();
    const k = e.key.toLowerCase();
    const hit = items.find((b, j) => j > i && b.textContent.trim().toLowerCase().startsWith(k)) || items.find((b) => b.textContent.trim().toLowerCase().startsWith(k));
    hit?.focus();
  } else e.stopPropagation();
}, true);
document.addEventListener("pointerdown", (e) => { if (!nodeMenu.hidden && !nodeMenu.contains(e.target)) closeNodeMenu(false); }, true);
document.addEventListener("contextmenu", (e) => { if (!nodeMenu.hidden && !nodeMenu.contains(e.target) && !e.target.closest?.(".node")) closeNodeMenu(false); }, true);
nodeMenu.addEventListener("contextmenu", (e) => e.preventDefault());
stage.addEventListener("wheel", () => closeNodeMenu(false), { passive: true });
window.addEventListener("resize", () => closeNodeMenu(false));
window.addEventListener("blur", () => closeNodeMenu(false));

function typingTarget(t) { return t && (t.closest("input, textarea, select, [contenteditable], .term, .display") != null); }
document.addEventListener("keydown", (e) => {
  if (!$("#library-back").hidden) { if (e.key === "Escape") closeLibrary(); return; }
  if (!$("#modal-back").hidden) return;
  if (typingTarget(e.target)) return;
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); save(); return; }
  if (mod && e.key.toLowerCase() === "z") { e.preventDefault(); e.shiftKey ? redo() : undo(); return; }
  if (mod && e.key.toLowerCase() === "y") { e.preventDefault(); redo(); return; }
  if (mod && e.key.toLowerCase() === "a") { e.preventDefault(); S.sel.nodes = new Set(S.draft.nodes.map((n) => n.id)); renderAll(); return; }
  if (mod) return;
  if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) { if (openNodeMenuForSelection()) e.preventDefault(); return; }
  if (e.key === "Delete" || e.key === "Backspace") { e.preventDefault(); removeSelection(); return; }
  if (e.key === "Escape") { cancelConnect(); S.sel.nodes.clear(); S.sel.link = -1; renderAll(); return; }
  if (e.key === " " && !spaceDown) { spaceDown = true; stage.classList.add("tool-pan"); e.preventDefault(); return; }
  const k = e.key.toLowerCase();
  if (k === "v") setTool("select");
  else if (k === "h") setTool("pan");
  else if (k === "c") setTool("connect");
  else if (k === "f") fitView();
  else if (k === "l") { e.preventDefault(); openLibrary(); }
  else if (k === "enter" && S.sel.nodes.size === 1) openInspector([...S.sel.nodes][0]);
});
document.addEventListener("keyup", (e) => {
  if (e.key === " ") { spaceDown = false; stage.classList.toggle("tool-pan", S.tool === "pan"); }
});

// ---------------------------------------------------------------- window manager
const WM = {
  wins: new Map(), z: 10,
  open(id, { title, icon, width = 460, height = 380, x, y, build, onClose }) {
    if (this.wins.has(id)) { const w = this.wins.get(id); this.focus(w); w.el.classList.remove("minimised"); return w; }
    const node = $("#tpl-window").content.firstElementChild.cloneNode(true);
    const host = $("#windows"), r = host.getBoundingClientRect();
    const n = this.wins.size;
    const px = x ?? clamp(r.width - width - 24 - n * 28, 16, Math.max(16, r.width - width - 16));
    const py = y ?? clamp(24 + n * 28, 16, Math.max(16, r.height - 160));
    Object.assign(node.style, { left: `${px}px`, top: `${py}px`, width: `${width}px`, height: `${height}px` });
    node.querySelector(".win-icon").innerHTML = icon || ICONS.gear;
    node.querySelector(".win-title").textContent = title;
    const w = { id, el: node, body: node.querySelector(".win-body"), onClose, setTitle: (t) => { node.querySelector(".win-title").textContent = t; } };
    node.querySelector(".win-close").onclick = () => this.close(id);
    node.querySelector(".win-min").onclick = () => node.classList.toggle("minimised");
    node.querySelector(".win-max").onclick = () => {
      if (w.restore) { Object.assign(node.style, w.restore); w.restore = null; }
      else {
        w.restore = { left: node.style.left, top: node.style.top, width: node.style.width, height: node.style.height };
        const hr = host.getBoundingClientRect();
        Object.assign(node.style, { left: "8px", top: "8px", width: `${hr.width - 16}px`, height: `${hr.height - 16}px` });
      }
      node.classList.remove("minimised");
    };
    node.addEventListener("pointerdown", () => this.focus(w), true);
    dragHandle(node.querySelector(".win-head"), node, "move");
    dragHandle(node.querySelector(".win-resize"), node, "resize");
    host.append(node);
    this.wins.set(id, w);
    this.focus(w);
    build?.(w);
    return w;
  },
  focus(w) {
    for (const o of this.wins.values()) o.el.classList.toggle("focused", o === w);
    w.el.style.zIndex = ++this.z;
  },
  close(id) {
    const w = this.wins.get(id);
    if (!w) return;
    this.wins.delete(id);
    try { w.onClose?.(); } catch (_) {}
    w.el.remove();
  },
};
// Explicit "Full screen" for a surface window. Uses the native Fullscreen API on the window element and,
// where the API is unavailable or the request is refused (for example inside a frame without
// allowfullscreen), fills the browser viewport instead, leaving that mode with Escape. While active the
// window carries .is-fullscreen, which hides window-manager chrome and anything marked .fs-hide; the
// surface supplies its own minimal controls. Window maximise is separate and keeps its own geometry.
function surfaceFullscreen(w, { onChange } = {}) {
  let pseudo = false, busy = false;
  const native = () => !!document.fullscreenElement && document.fullscreenElement === w.el;
  const active = () => native() || pseudo;
  let last = false;
  const sync = () => {
    const on = active();
    w.el.classList.toggle("is-fullscreen", on);
    w.el.classList.toggle("pseudo-fullscreen", pseudo);
    if (on !== last) { last = on; onChange?.(on); }
  };
  const onKey = (e) => {
    if (!pseudo || e.key !== "Escape") return;
    e.preventDefault(); e.stopPropagation();
    leavePseudo();
  };
  const enterPseudo = () => { pseudo = true; document.addEventListener("keydown", onKey, true); sync(); };
  const leavePseudo = () => { pseudo = false; document.removeEventListener("keydown", onKey, true); sync(); };
  const enter = async () => {
    if (busy || active()) return;
    WM.focus(w);
    w.el.classList.remove("minimised");
    if (!document.fullscreenEnabled || typeof w.el.requestFullscreen !== "function") { enterPseudo(); return; }
    busy = true;
    try { await w.el.requestFullscreen({ navigationUI: "hide" }); }
    catch (_) { if (!native() && w.el.isConnected) enterPseudo(); }
    finally { busy = false; sync(); }
  };
  const exit = async () => {
    if (busy) return;
    if (pseudo) { leavePseudo(); return; }
    if (!native()) return;
    busy = true;
    try { await document.exitFullscreen(); }
    catch (err) { toast(`Couldn't leave full screen: ${err.message}`, "err"); }
    finally { busy = false; sync(); }
  };
  document.addEventListener("fullscreenchange", sync);
  return {
    enter, exit, active,
    toggle: () => (active() ? exit() : enter()),
    dispose() {
      document.removeEventListener("fullscreenchange", sync);
      document.removeEventListener("keydown", onKey, true);
      if (native()) document.exitFullscreen().catch(() => {});
    },
  };
}
function dragHandle(handle, win, mode) {
  handle.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || e.target.closest("button")) return;
    e.preventDefault();
    const host = $("#windows").getBoundingClientRect();
    const r = win.getBoundingClientRect();
    const sx = e.clientX, sy = e.clientY;
    handle.setPointerCapture(e.pointerId);
    const move = (ev) => {
      if (mode === "move") {
        win.style.left = `${clamp(r.left - host.left + ev.clientX - sx, -r.width + 80, host.width - 80)}px`;
        win.style.top = `${clamp(r.top - host.top + ev.clientY - sy, 0, host.height - 40)}px`;
      } else {
        win.style.width = `${Math.max(280, r.width + ev.clientX - sx)}px`;
        win.style.height = `${Math.max(120, r.height + ev.clientY - sy)}px`;
      }
    };
    const up = () => { handle.removeEventListener("pointermove", move); handle.removeEventListener("pointerup", up); };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
  });
}

// ---------------------------------------------------------------- inspector
const inspectors = new Map(); // nodeId -> {win, staged, tab, render}

function openInspector(nodeId, tab) {
  const node = nodeById(nodeId);
  if (!node) return;
  const wid = `inspect:${nodeId}`;
  const existing = inspectors.get(nodeId);
  if (existing) {
    WM.open(wid, {});
    if (tab) { existing.tab = tab; existing.render(); }
    return;
  }
  const st = { staged: stageFrom(node), tab: tab || "General" };
  WM.open(wid, {
    title: `Node Properties — ${node.name}`, icon: ICONS.gear, width: 480, height: 470,
    build: (w) => { st.win = w; st.render = () => renderInspector(nodeId, st); st.render(); },
    onClose: () => {
      inspectors.delete(nodeId);
      for (const search of Object.values(st.packageSearch || {})) { clearTimeout(search.timer); search.ctrl?.abort(); search.seq++; }
    },
  });
  inspectors.set(nodeId, st);
}
function inspectorSig(node) {
  return JSON.stringify([node, S.view?.nodes?.[node.id] || null, computeDrift().nodes.get(node.id) || "", !!S.applied,
    S.draft.nodes.map((n) => [n.id, n.name, n.recipe])]);
}
function stageFrom(node) { return { name: node.name, config: clone(node.config || {}), media: clone(node.media || {}) }; }
function refreshInspectors() {
  for (const [id, st] of inspectors) {
    const node = nodeById(id);
    if (!node) { WM.close(`inspect:${id}`); continue; }
    // Staged edits survive; re-render only when inputs to this panel changed so open controls are not disturbed.
    const sig = inspectorSig(node);
    if (sig !== st.sig) st.render();
  }
}
function fieldGroups(r) {
  const groups = ["General"];
  for (const f of r?.fields || []) { const g = f.group || "General"; if (!groups.includes(g)) groups.push(g); }
  if (r?.media?.length) groups.push("Media");
  groups.push("Runtime");
  return groups;
}
function domainControllers(node) {
  const server = recipeOf(node)?.domainController;
  return S.draft.nodes.filter((n) => n.id !== node.id && n.recipe === server && n.config.role === "domain-controller");
}
function mediaVisible(m, r, cfg) {
  if (!m.when) return true;
  const f = (r?.fields || []).find((x) => x.key === m.when);
  const v = cfg[m.when] !== undefined ? cfg[m.when] : f?.default;
  if (m.when === "software") return softwareSelection(v).includes(m.equals);
  return v === m.equals || String(v) === String(m.equals);
}
function mediaReference(slot, media) { return media?.[slot.key] || slot.default || ""; }
function missingMedia(node) {
  const r = recipeOf(node);
  return (r?.media || []).filter((m) => mediaVisible(m, r, node.config || {}) && !mediaReference(m, node.media));
}
function effective(f, cfg) { return cfg[f.key] !== undefined ? cfg[f.key] : f.default; }

function renderInspector(nodeId, st) {
  const node = nodeById(nodeId);
  if (!node) return;
  const r = recipeOf(node);
  const w = st.win;
  st.sig = inspectorSig(node);
  w.setTitle(`Node Properties — ${node.name}`);
  const groups = fieldGroups(r);
  if (!groups.includes(st.tab)) st.tab = "General";
  const active = document.activeElement;
  const focusKey = active && w.body.contains(active) ? active.dataset.key : null;
  const scroll = w.body.querySelector(".form")?.scrollTop;

  const tabs = el("div", { class: "win-tabs" }, groups.map((g) => el("button", {
    class: `win-tab ${g === st.tab ? "active" : ""}`, text: g, onclick: () => { st.tab = g; renderInspector(nodeId, st); },
  })));
  const form = el("div", { class: "form" });
  const orig = { name: node.name, config: node.config || {}, media: node.media || {} };

  if (st.tab === "General") {
    form.append(el("label", { class: "k", text: "Name" }),
      inputEl("text", st.staged.name, (v) => { st.staged.name = v; markChanged(); }, "name", st.staged.name !== orig.name));
    form.append(el("label", { class: "k", text: "Recipe" }), el("div", { class: "kv", text: r ? `${r.title} (${r.id})` : `${node.recipe} — not in catalog` }));
    if (releaseYear(r) !== null) form.append(el("label", { class: "k", text: "Released" }), el("div", { class: "kv", text: String(releaseYear(r)) }));
    form.append(el("label", { class: "k", text: "Node ID" }), el("div", { class: "kv", text: node.id }));
    if (r?.description) form.append(el("div", { class: "full kv", style: "font-family:var(--sans)", text: r.description }));
  }
  if (r && st.tab !== "Media" && st.tab !== "Runtime") {
    for (const f of r.fields || []) {
      if ((f.group || "General") !== st.tab) continue;
      if (node.recipe === "router" && f.key.startsWith("dhcp") && f.key !== "dhcp" && st.staged.config.dhcp === false) continue;
      const cur = effective(f, st.staged.config);
      const changed = JSON.stringify(cur) !== JSON.stringify(effective(f, orig.config));
      const set = (v) => {
        if (v === undefined || v === "" && f.kind !== "string") delete st.staged.config[f.key];
        else st.staged.config[f.key] = v;
        markChanged();
      };
      const wide = f.kind === "alpine-packages" || f.kind === "multiline";
      const label = el("label", { class: `k ${wide ? "full" : ""}`, title: f.help || "" }, f.label || f.key, " ", impactBadge(f.impact));
      let ctl;
      if (f.kind === "alpine-packages") {
        ctl = alpinePackagesControl(nodeId, st, f, cur, set, changed);
      } else if (f.key === "domain" && f.kind === "string") {
        const opts = [{ value: "", label: "(none)" }, ...domainControllers(node).map((n) => ({ value: n.id, label: `${n.name} (${n.id})` }))];
        if (cur && !opts.some((o) => o.value === cur)) opts.push({ value: cur, label: `${cur} (missing node)` });
        ctl = selectEl(opts, cur ?? "", (v) => set(v === "" ? undefined : v), f.key, changed);
      } else if (f.kind === "boolean") {
        const inp = el("input", { type: "checkbox", "data-key": f.key });
        inp.checked = !!cur;
        inp.onchange = () => {
          set(inp.checked);
          if (node.recipe === "router" && f.key === "dhcp") renderInspector(nodeId, st);
        };
        ctl = el("label", { class: `toggle ${changed ? "changed" : ""}` }, inp, el("span"));
      } else if (f.kind === "packages") {
        ctl = el("div", { class: "package-options" }, f.options.map((option) => {
          const checked = softwareSelection(cur).includes(option.value);
          const checkbox = el("input", { type: "checkbox", "data-key": option.value });
          checkbox.checked = checked;
          checkbox.onchange = () => {
            const selected = new Set(softwareSelection(st.staged.config.software));
            if (checkbox.checked) selected.add(option.value); else selected.delete(option.value);
            set(selected.size ? [...selected].sort() : undefined);
            renderInspector(nodeId, st);
          };
          return el("label", {}, checkbox, option.label);
        }), el("button", { class: "btn small", text: "Browse software…", onclick: () => openLibrary(nodeId) }));
      } else if (f.kind === "select") {
        const opts = (f.options || []).map((o) => (typeof o === "object" ? o : { value: o, label: String(o) }));
        ctl = selectEl(opts, cur, (v) => set(v), f.key, changed);
      } else if (f.kind === "number") {
        ctl = inputEl("number", cur ?? "", (v) => set(v === "" ? undefined : Number(v)), f.key, changed);
        if (f.min !== undefined) ctl.min = f.min;
        if (f.max !== undefined) ctl.max = f.max;
      } else if (f.kind === "multiline") {
        ctl = multilineEl(`inspector-${nodeId}-${f.key}`, typeof cur === "string" ? cur : cur == null ? "" : JSON.stringify(cur, null, 2), (v) => set(v === "" ? undefined : v), f, changed);
        label.htmlFor = ctl.id;
      } else {
        ctl = inputEl("text", cur ?? "", (v) => set(v), f.key, changed);
      }
      form.append(label, ctl);
      if (f.help) {
        const hint = el("div", { class: `hint ${wide ? "full" : ""}`, id: `inspector-${nodeId}-${f.key}-help`, text: f.help });
        if (f.kind === "multiline") ctl.setAttribute("aria-describedby", hint.id);
        form.append(hint);
      }
    }
  }
  if (st.tab === "Media") {
    form.classList.add("media-form");
    const shown = (r?.media || []).filter((m) => mediaVisible(m, r, st.staged.config));
    if (!shown.length) form.append(el("div", { class: "full kv", text: "No media slots apply to the current configuration." }));
    for (const m of shown) {
      const override = st.staged.media[m.key];
      const ref = String(mediaReference(m, st.staged.media));
      const changed = override !== orig.media[m.key];
      form.append(el("div", { class: `media-row ${changed ? "changed" : ""}` },
        el("div", { class: "media-caption" }, el("b", { title: m.hint || "", text: m.key === "system" ? "Installation media" : (m.label || m.key) }),
          !override && m.default ? el("span", { class: "media-default", text: "Library default" }) : null),
        el("div", { class: "media-value" },
          el("span", { class: "media-filename", title: ref, text: ref ? ref.split("/").at(-1) : "Choose a file" }),
          el("button", { class: "btn small", text: ref ? "Change…" : "Browse…", onclick: async () => {
            const picked = await pickMedia(node.recipe, m, ref);
            if (picked !== undefined) { st.staged.media[m.key] = picked; renderInspector(nodeId, st); }
          } }),
          override ? el("button", { class: "btn small", text: m.default ? "Reset" : "Clear", title: m.default ? "Use library default" : "Clear media selection", onclick: () => { delete st.staged.media[m.key]; renderInspector(nodeId, st); } }) : null)));
    }
  }
  if (st.tab === "Runtime") {
    const rt = S.view?.nodes?.[node.id];
    const drift = computeDrift().nodes.get(node.id);
    form.append(el("label", { class: "k", text: "Phase" }), el("div", { class: "kv", text: rt?.phase || "not running" }));
    if (rt?.message) form.append(el("label", { class: "k", text: "Message" }), el("div", { class: "kv", text: rt.message }));
    if (rt?.phase === "running" && S.draft.links.some((link) => link.a.node === nodeId || link.b.node === nodeId)) {
      form.append(el("label", { class: "k", text: "IPv4 address" }), el("div", { class: "kv", text: rt.address ? `${rt.address} · ${rt.addressObserved ? "observed" : "configured"}` : "None reported" }));
    }
    form.append(el("label", { class: "k", text: "Draft vs running" }), el("div", { class: "kv", text: !S.applied ? "nothing applied" : drift === "new" ? "not in running lab" : drift === "changed" ? "draft differs from running" : "matches running lab" }));
    if (r?.hint) form.append(el("label", { class: "k", text: "Hint" }), el("div", { class: "kv", style: "font-family:var(--sans)", text: r.hint }));
    const missing = missingMedia(node);
    if (missing.length) form.append(el("label", { class: "k", text: "Missing media" }), el("div", { class: "kv", style: "color:var(--err)", text: missing.map((m) => m.label || m.key).join(", ") }));
    const surfaces = rt?.surfaces || [];
    form.append(el("label", { class: "k", text: "Surfaces" }), surfaces.length
      ? el("div", { style: "display:flex;gap:6px;flex-wrap:wrap" }, surfaces.map((s) => el("button", { class: "btn small", title: `Open ${surfaceLabel(s).toLowerCase()} · ${s.name || s.id}`, onclick: () => openSurface(node.id, s) }, el("span", { html: surfaceIcon(s) }), s.name || s.id)))
      : el("div", { class: "kv", text: rt?.phase === "running" ? "none advertised" : "available while the node is running" }));
    if (rt?.log?.length) {
      const details = rt.log.join("\n");
      const box = el("details", { class: "full diagnostics", open: rt.phase === "failed" },
        el("summary", { text: "Startup details" }), el("pre", { text: details }),
        navigator.clipboard ? el("button", { class: "btn small", text: "Copy details", onclick: async () => {
          try { await navigator.clipboard.writeText(details); toast("Copied startup details."); }
          catch (err) { toast(err.message, "err"); }
        } }) : null);
      form.append(box);
    }
    const logCount = rt?.log?.length || 0;
    form.append(el("label", { class: "k", text: "Logs" }), el("div", { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap" },
      el("button", { class: "btn small", title: `Open the runtime log panel filtered to ${node.name}`, onclick: () => openLogs(node.id) }, el("span", { html: ICONS.log }), "View logs"),
      el("span", { class: "kv", text: logCount ? `${logCount} entr${logCount === 1 ? "y" : "ies"}` : rt ? "no entries yet" : "not running" })));
  }

  const dirty = JSON.stringify(st.staged) !== JSON.stringify(stageFrom(node));
  const foot = el("div", { class: "win-foot" },
    el("span", { class: "note", text: dirty ? "Unapplied edits in this panel." : "Edits update the draft; Run Lab applies it." }),
    el("button", { class: "btn small danger", text: "Remove node", onclick: () => { S.sel.nodes = new Set([node.id]); S.sel.link = -1; removeSelection(); } }),
    el("button", { class: "btn small", text: "Discard", disabled: !dirty, onclick: () => { st.staged = stageFrom(node); renderInspector(nodeId, st); } }),
    el("button", { class: "btn small primary", text: "Apply", disabled: !dirty, onclick: () => commitInspector(nodeId, st) }));

  w.body.replaceChildren(el("div", { style: "display:flex;flex-direction:column;height:100%" }, tabs, el("div", { style: "flex:1;overflow:auto" }, form), foot));
  if (scroll) form.parentElement.scrollTop = scroll;
  if (focusKey) { const f = w.body.querySelector(`[data-key="${CSS.escape(focusKey)}"]`); if (f) { f.focus(); if (f.setSelectionRange && (f.type === "text" || f.type === "search" || f.type === "textarea")) { const n = f.value.length; f.setSelectionRange(n, n); } } }

  function markChanged() {
    const now = JSON.stringify(st.staged) !== JSON.stringify(stageFrom(node));
    foot.querySelector(".note").textContent = now ? "Unapplied edits in this panel." : "Edits update the draft; Run Lab applies it.";
    foot.querySelectorAll(".btn")[1].disabled = !now;
    foot.querySelectorAll(".btn")[2].disabled = !now;
  }
}
function commitInspector(nodeId, st) {
  const name = st.staged.name.trim() || nodeId;
  mutate((d) => {
    const n = nodeById(nodeId, d);
    if (!n) return;
    n.name = name; n.config = clone(st.staged.config); n.media = clone(st.staged.media);
  });
  st.staged = stageFrom(nodeById(nodeId));
  renderInspector(nodeId, st);
}
function impactBadge(impact) {
  if (!impact) return null;
  const cls = impact === "live" ? "live" : impact === "restart" ? "restart" : "rebuild";
  return el("span", { class: `badge ${cls}`, title: `Changing this needs: ${impact}`, text: impact });
}
// Alpine package picker: stages a sorted array of package IDs; no value means the base package set.
// Search state lives on the inspector so results survive re-renders; only the latest query may land.
function alpinePackagesControl(nodeId, st, f, cur, set, changed) {
  st.packageSearch ??= {};
  const p = st.packageSearch[f.key] ??= { q: "", searched: "", status: "idle", results: [], error: "", seq: 0, timer: 0, ctrl: null, known: new Map() };
  const selected = Array.isArray(cur) ? [...new Set(cur.map(String))].sort() : [];
  const update = (ids) => {
    set(ids.length ? [...new Set(ids)].sort() : undefined);
    renderInspector(nodeId, st);
    const box = st.win.body;
    if (!box.contains(document.activeElement)) box.querySelector(`[data-key="${CSS.escape(`${f.key}:search`)}"]`)?.focus();
  };
  const add = (id) => update([...selected, id]);
  const remove = (id) => update(selected.filter((x) => x !== id));

  const search = () => {
    clearTimeout(p.timer); p.ctrl?.abort(); p.ctrl = null;
    const q = p.q.trim();
    const seq = ++p.seq;
    if (!q) { Object.assign(p, { status: "idle", searched: "", results: [], error: "" }); p.draw(); return; }
    p.status = "pending"; p.error = ""; p.draw();
    const ctrl = new AbortController();
    p.ctrl = ctrl;
    fetch(`/api/alpine/packages?${new URLSearchParams({ q })}`, { cache: "no-store", signal: ctrl.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error((await res.text().catch(() => "")).trim() || `Package search failed: ${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((body) => {
        if (seq !== p.seq) return;
        const results = (Array.isArray(body?.packages) ? body.packages : []).filter((x) => x && x.id != null)
          .map((x) => ({ id: String(x.id), name: String(x.name ?? x.id), version: x.version ? String(x.version) : "", description: x.description ? String(x.description) : "", repository: x.repository ? String(x.repository) : "" }));
        for (const r of results) p.known.set(r.id, r);
        Object.assign(p, { status: "done", searched: q, results, ctrl: null });
        p.draw();
      })
      .catch((err) => {
        if (seq !== p.seq || err.name === "AbortError") return;
        Object.assign(p, { status: "error", searched: q, error: err.message || String(err), ctrl: null });
        p.draw();
      });
  };

  const input = el("input", { type: "search", "data-key": `${f.key}:search`, placeholder: "Search Alpine packages…", spellcheck: "false", autocomplete: "off", "aria-label": `Search ${f.label || f.key}` });
  input.value = p.q;
  input.addEventListener("input", () => {
    p.q = input.value;
    clearTimeout(p.timer);
    p.timer = setTimeout(search, 250);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); search(); }
    else if (e.key === "Escape" && input.value) { e.preventDefault(); e.stopPropagation(); input.value = p.q = ""; search(); }
  });

  const results = el("div", { class: "pkg-results", role: "list", "aria-label": "Package search results" });
  const state = el("div", { class: "pkg-state", role: "status", "aria-live": "polite" });
  function draw() {
    const pending = p.status === "pending";
    results.classList.toggle("stale", pending);
    results.setAttribute("aria-busy", pending ? "true" : "false");
    state.className = `pkg-state ${p.status === "error" ? "err" : ""}`;
    if (p.status === "idle") state.replaceChildren("Search the Alpine repositories by package name or description.");
    else if (pending) state.replaceChildren(`Searching for “${p.q.trim()}”…`);
    else if (p.status === "error") state.replaceChildren(el("span", { text: p.error }), " ", el("button", { class: "btn small", text: "Retry", onclick: search }));
    else if (!p.results.length) state.replaceChildren(`No packages match “${p.searched}”.`);
    else state.replaceChildren(`${p.results.length} package${p.results.length === 1 ? "" : "s"} for “${p.searched}”`);
    const shown = p.status === "idle" ? [] : p.status === "error" ? [] : p.results;
    results.replaceChildren(...shown.slice(0, 200).map((r) => {
      const on = selected.includes(r.id);
      return el("div", { class: `pkg-row ${on ? "on" : ""}`, role: "listitem" },
        el("div", { class: "pkg-main" },
          el("div", { class: "pkg-name" }, el("b", { text: r.name }), r.version ? el("span", { class: "pkg-meta", text: r.version }) : null,
            r.repository ? el("span", { class: "pkg-meta", text: r.repository }) : null),
          r.description ? el("div", { class: "pkg-desc", text: r.description }) : null),
        el("button", { class: `btn small ${on ? "" : "primary"}`, "data-key": `${f.key}:pick:${r.id}`, "aria-pressed": on ? "true" : "false",
          "aria-label": `${on ? "Remove" : "Add"} ${r.name}`, text: on ? "Remove" : "Add", onclick: () => (on ? remove(r.id) : add(r.id)) }));
    }), p.results.length > 200 && shown.length ? el("div", { class: "pkg-state", text: `Showing the first 200 — refine the search to narrow ${p.results.length} matches.` }) : null);
  }

  const chips = selected.length
    ? el("div", { class: "pkg-chips", role: "list", "aria-label": "Selected packages" }, selected.map((id) => {
      const info = p.known.get(id);
      return el("span", { class: "pkg-chip", role: "listitem", title: info ? [info.version, info.description].filter(Boolean).join(" — ") : id },
        el("span", { text: id }),
        el("button", { class: "pkg-x", "data-key": `${f.key}:rm:${id}`, title: `Remove ${id}`, "aria-label": `Remove ${id}`, text: "✕", onclick: () => remove(id) }));
    }))
    : el("div", { class: "pkg-none", text: "No extra packages — the node uses the base package set." });
  const head = el("div", { class: "pkg-head" },
    el("span", { class: "pkg-count", text: selected.length ? `${selected.length} selected` : "Base packages only" }),
    selected.length ? el("button", { class: "btn small", text: "Clear all", title: "Remove every selected package", "data-key": `${f.key}:clear`, onclick: () => update([]) }) : null);
  const box = el("div", { class: `pkg-picker full ${changed ? "changed" : ""}` }, head, chips, input, state, results);
  p.draw = draw; // in-flight searches always update the newest render
  draw();
  return box;
}
function inputEl(type, value, onInput, key, changed) {
  const i = el("input", { type, "data-key": key, class: changed ? "changed" : null });
  i.value = value ?? "";
  i.addEventListener("input", () => { onInput(i.value); i.classList.add("changed"); });
  return i;
}
// Staged multi-line text (e.g. inline JSON). f.max is a UTF-8 byte limit, matching the backend.
function multilineEl(id, value, onInput, f, changed) {
  const t = el("textarea", { id, class: `multiline ${changed ? "changed" : ""}`, "data-key": f.key, spellcheck: "false", autocapitalize: "off", autocomplete: "off", wrap: "off", rows: "10" });
  t.value = value ?? "";
  const check = () => {
    const bytes = new TextEncoder().encode(t.value).length;
    const over = f.max !== undefined && bytes > f.max;
    t.setCustomValidity(over ? `${bytes} bytes; limit is ${f.max}` : "");
    t.setAttribute("aria-invalid", over ? "true" : "false");
    t.title = over ? t.validationMessage : "";
  };
  if (f.max !== undefined) t.maxLength = f.max;
  check();
  t.addEventListener("input", () => { check(); onInput(t.value); t.classList.add("changed"); });
  return t;
}
function selectEl(opts, value, onChange, key, changed) {
  const s = el("select", { "data-key": key, class: changed ? "changed" : null });
  let found = false;
  opts.forEach((o, idx) => {
    const op = el("option", { value: String(idx), text: o.label ?? String(o.value) });
    if (JSON.stringify(o.value) === JSON.stringify(value)) { op.selected = true; found = true; }
    s.append(op);
  });
  if (!found && value !== undefined && value !== "") {
    s.prepend(el("option", { value: "-1", text: `${value} (current)`, selected: true }));
  } else if (!found) {
    s.prepend(el("option", { value: "-1", text: "(default)", selected: true }));
  }
  s.addEventListener("change", () => { const i = +s.value; onChange(i < 0 ? value : opts[i].value); s.classList.add("changed"); });
  return s;
}

// ---------------------------------------------------------------- media picker
async function pickMedia(recipe, slot, current) {
  let resp = null, chosen;
  const body = el("div");
  const load = async (d) => {
    body.replaceChildren(el("div", { class: "empty-note", text: "Loading…" }));
    const q = new URLSearchParams({ recipe, slot: slot.key });
    if (d) q.set("dir", d);
    try { resp = await api("GET", `/api/media?${q}`); }
    catch (err) {
      body.replaceChildren(el("div", { class: "toast err", text: err.message }),
        d ? el("button", { class: "btn small", text: "Browse all libraries", onclick: () => load(null) }) : el("button", { class: "btn small", text: "Retry", onclick: () => load(null) }));
      return;
    }
    draw();
  };
  const draw = () => {
    const list = el("div", { class: "choice-list" });
    if (resp.up) list.append(el("button", { class: "choice", onclick: () => load(resp.up) }, el("span", { html: ICONS.file }), el("div", { class: "c-main", text: ".. (up)" })));
    for (const it of resp.items || []) {
      const isDir = it.kind === "folder";
      list.append(el("button", {
        class: `choice ${resp.selected && resp.selected === it.ref ? "active" : ""}`,
        title: it.ref,
        onclick: () => { if (isDir) load(it.ref); else if (slot.kind !== "folder") { chosen = it.ref; closeModal("pick"); } },
        style: !isDir && slot.kind === "folder" ? "opacity:.5;cursor:default" : null,
      }, el("span", { html: isDir ? ICONS.file : ICONS.box }), el("div", { class: "c-main" }, el("div", { text: it.name }), el("div", { class: "c-sub", text: isDir ? "folder" : "file" }))));
    }
    if (!(resp.items || []).length) list.append(el("div", { class: "empty-note", text: "This folder is empty." }));
    body.replaceChildren(el("div", { class: "kv", style: "margin-bottom:10px;word-break:break-all", text: resp.path || "Media roots" }), list);
    if (slot.kind === "folder") {
      body.append(el("div", { style: "margin-top:12px;display:flex;justify-content:flex-end" },
        el("button", { class: "btn primary small", disabled: !resp.selected, title: resp.selected ? "" : "Open a folder to bind it",
          text: "Use this folder", onclick: () => { chosen = resp.selected; closeModal("pick"); } })));
    }
  };
  const p = modal({ title: `Select ${slot.label || slot.key}${slot.hint ? ` — ${slot.hint}` : ""}`, body, buttons: [{ label: "Cancel", value: undefined }] });
  const parent = current.slice(0, Math.max(0, current.lastIndexOf("/")));
  load(slot.kind === "folder" ? current : parent);
  const res = await p;
  return res === "pick" ? chosen : undefined;
}

// ---------------------------------------------------------------- surfaces
function isWeb(s) { return s.kind === "web"; }
function isTerminal(s) { return !isWeb(s) && /term|serial|console|text|tty/i.test(s.kind || ""); }
function surfaceLabel(s) { return isWeb(s) ? "Browser" : isTerminal(s) ? "Terminal" : "Display"; }
function surfaceIcon(s) { return isWeb(s) ? ICONS.web : isTerminal(s) ? ICONS.term : ICONS.screen; }
function surfacePath(nodeId, s) { return `/api/nodes/${encodeURIComponent(nodeId)}/surfaces/${encodeURIComponent(s.id)}`; }
function surfaceAvailable(nodeId, sid) { return !!(S.view?.nodes?.[nodeId]?.surfaces || []).some((s) => s.id === sid); }

function openSurface(nodeId, s) {
  const node = nodeById(nodeId);
  const name = node?.name || nodeId;
  if (isWeb(s)) openBrowser(nodeId, s, name);
  else if (isTerminal(s)) openTerminal(nodeId, s, name);
  else openDisplay(nodeId, s, name);
}

// Guest-local location: "/path?query#hash" relative to the upstream root that a browse session maps.
// Returns the normalized form, or null for anything that is not a plain rooted path.
function browseLocalPath(path) {
  if (typeof path !== "string" || path.length > 8192 || !path.startsWith("/") || path.startsWith("//") || /[\\\u0000-\u001f\u007f]/.test(path)) return null;
  let u;
  try { u = new URL(path, "http://guest.invalid/"); } catch { return null; }
  if (u.origin !== "http://guest.invalid") return null;
  return u.pathname + u.search + u.hash;
}
// Editor-relative frame URL for a guest-local path, or null when it would leave the session's base.
function browseFrameURL(base, path) {
  const p = browseLocalPath(path);
  if (p === null) return null;
  let root, u;
  try { root = new URL(base, location.href); u = new URL(root.pathname + p.slice(1), location.origin); } catch { return null; }
  if (u.origin !== location.origin || !u.pathname.startsWith(root.pathname)) return null;
  return u.pathname + u.search + u.hash;
}
// Human-visible address for a guest-local path under the session's upstream address.
function browseDisplay(root, path) { return root.origin + root.pathname + path.slice(1); }
// Map typed text to a guest-local path. Only addresses on the session's upstream origin (and under its
// path) are accepted; a leading "/", "?" or "#" is taken relative to the upstream root.
function browseAddressToLocal(root, text) {
  text = text.trim();
  if (!text) return null;
  const parse = (t, b) => { try { return new URL(t, b); } catch { return null; } };
  const inScope = (u) => u && u.origin === root.origin && !u.username && !u.password && u.pathname.startsWith(root.pathname);
  let u;
  if (/^[a-z][a-z0-9+.-]*:/i.test(text) && !/^[^/:]+:\d+(?:[/?#]|$)/.test(text)) u = parse(text);
  else if (/^[/?#]/.test(text)) u = text.startsWith("//") ? parse(`${root.protocol}${text}`) : parse(text, root);
  else {
    u = parse(`${root.protocol}//${text}`);
    if (!inScope(u)) u = parse(text, root);
  }
  if (!inScope(u)) return null;
  return browseLocalPath("/" + (u.pathname + u.search + u.hash).slice(root.pathname.length));
}
// Per-window history of guest-local paths.
function browseHistory(limit = 200) {
  return {
    entries: [], index: -1,
    get current() { return this.entries[this.index] ?? null; },
    get canBack() { return this.index > 0; },
    get canForward() { return this.index < this.entries.length - 1; },
    push(p) {
      if (p === this.current) return;
      this.entries.splice(this.index + 1, Infinity, p);
      if (this.entries.length > limit) this.entries.splice(0, this.entries.length - limit);
      this.index = this.entries.length - 1;
    },
    replace(p) { if (this.index < 0) this.push(p); else this.entries[this.index] = p; },
    // Apply a toolbar navigation once its target document reports (or is assumed to be) at path p.
    commit(op, p) {
      if (op.kind === "go" && op.index >= 0 && op.index < this.entries.length) { this.index = op.index; this.entries[op.index] = p; }
      else if (op.kind === "reload") this.replace(p);
      else this.push(p);
    },
  };
}

// Guest web surface in a sandboxed frame. The frame gets an opaque origin (no allow-same-origin),
// so it cannot reach the editor's cookies, storage or API; it also may not navigate the top page or
// open popups. All frame URLs stay under the browse session's private base; the toolbar shows the
// upstream address instead. Injected guest script reports its location by postMessage, and this
// window keeps its own history so toolbar navigations never add entries to the editor's history
// (every toolbar navigation uses a fresh frame).
function openBrowser(nodeId, s, name) {
  const wid = `surface:${nodeId}:${s.id}`;
  const bounds = $("#windows").getBoundingClientRect();
  const width = Math.min(1100, bounds.width - 32);
  const height = Math.min(780, bounds.height - 32);
  const browsePrefix = `${surfacePath(nodeId, s)}/browse/`;
  WM.open(wid, {
    title: `${name} · ${s.name || s.id}`, icon: ICONS.web, width, height,
    x: (bounds.width - width) / 2, y: (bounds.height - height) / 2,
    build: (w) => {
      const view = el("div", { class: "browser-view" });
      const msg = el("div", { class: "browser-msg", role: "status", text: "Loading…" });
      const status = el("span", { class: "note", text: "Loading…" });
      const hist = browseHistory();
      let frame = null, alive = true, watch = 0;
      // session: { base, root } once fetched; private to this window and dropped when the surface stops.
      let session = null, sessionSeq = 0, sessionBusy = false, retryAt = 0;
      // pending: toolbar navigation awaiting its document; candidate: guest-announced link target that
      // may not be able to report itself (non-HTML); fallback: last commit made without a report.
      let pending = null, candidate = null, fallback = null, settle = 0;

      const setState = (text, overlay) => {
        status.textContent = text;
        msg.textContent = text;
        msg.hidden = !overlay;
        view.setAttribute("aria-busy", overlay && text.startsWith("Loading") ? "true" : "false");
      };
      const navBtn = (label, icon, onclick) => el("button", { type: "button", class: "icon-btn small", title: label, "aria-label": label, html: icon, onclick });
      const back = navBtn("Back", ICONS.back, () => go(-1));
      const fwd = navBtn("Forward", ICONS.forward, () => go(1));
      const reload = navBtn("Reload", ICONS.reload, () => reloadPage());
      const addr = el("input", {
        class: "browser-address", type: "text", spellcheck: "false", autocomplete: "off", autocapitalize: "off",
        "aria-label": "Address", placeholder: "Connecting…", enterkeyhint: "go",
        onfocus: () => addr.select(),
        oninput: () => addr.removeAttribute("aria-invalid"),
        onblur: () => syncBar(),
        onkeydown: (e) => { if (e.key === "Escape") { e.preventDefault(); addr.removeAttribute("aria-invalid"); addr.blur(); syncBar(); } },
      });
      const addrForm = el("form", { class: "browser-address-form", onsubmit: (e) => {
        e.preventDefault();
        if (!session) return;
        const p = browseAddressToLocal(session.root, addr.value);
        if (p === null) {
          addr.setAttribute("aria-invalid", "true");
          toast(`Only addresses under ${browseDisplay(session.root, "/")} can be opened in this window.`, "err");
          return;
        }
        addr.removeAttribute("aria-invalid");
        addr.blur();
        navigate({ kind: "push", path: p });
      } }, addr);
      const full = navBtn("Full screen", ICONS.fullscreen, () => fs.toggle());
      // Full screen keeps only the navigation bar so the address, history and exit stay reachable.
      const fs = surfaceFullscreen(w, { onChange: (on) => {
        const label = on ? "Exit full screen (Esc)" : "Full screen";
        full.title = label; full.setAttribute("aria-label", label); full.innerHTML = on ? ICONS.exitFullscreen : ICONS.fullscreen;
        full.setAttribute("aria-pressed", String(on));
      } });
      full.setAttribute("aria-pressed", "false");
      const nav = el("div", { class: "browser-nav", role: "group", "aria-label": "Browser navigation" }, back, fwd, reload, addrForm, full);

      const syncBar = () => {
        back.disabled = !hist.canBack;
        fwd.disabled = !hist.canForward;
        if (document.activeElement === addr) return;
        const p = pending?.path ?? hist.current;
        addr.value = session && p ? browseDisplay(session.root, p) : "";
        addr.title = addr.value;
      };
      const unload = () => { clearTimeout(settle); frame?.remove(); frame = null; pending = null; candidate = null; fallback = null; };
      const dropSession = () => { sessionSeq++; sessionBusy = false; session = null; };

      const fetchSession = async () => {
        const seq = ++sessionSeq;
        sessionBusy = true;
        try {
          const r = await api("GET", `${surfacePath(nodeId, s)}/browse-session`);
          if (seq !== sessionSeq || !alive) return false;
          const base = typeof r?.base === "string" ? new URL(r.base, location.href) : null;
          const root = typeof r?.address === "string" ? new URL(r.address) : null;
          if (!base || base.origin !== location.origin || !base.pathname.startsWith(browsePrefix) || !base.pathname.endsWith("/") || base.search || base.hash) throw new Error("the lab returned an invalid browse base");
          if (!root || !/^https?:$/.test(root.protocol) || root.username || root.password) throw new Error("the lab returned an invalid upstream address");
          if (!root.pathname.endsWith("/")) root.pathname += "/";
          root.search = ""; root.hash = "";
          session = { base: base.pathname, root };
          return true;
        } catch (err) {
          if (seq !== sessionSeq || !alive) return false;
          retryAt = Date.now() + 3000;
          setState(`Couldn't open the web surface: ${err.message}`, true);
          return false;
        } finally {
          if (seq === sessionSeq) sessionBusy = false;
        }
      };

      // Load a guest-local path in a fresh frame and record how history should change once it lands.
      const navigate = async (op) => {
        if (!alive) return;
        if (!surfaceAvailable(nodeId, s.id)) { unload(); dropSession(); setState("Waiting for the guest web surface…", true); syncBar(); return; }
        if (!session) {
          unload();
          setState("Loading…", true);
          if (!(await fetchSession()) || !alive) return;
        }
        const url = browseFrameURL(session.base, op.path);
        if (url === null) { toast("That address is outside this web surface.", "err"); return; }
        unload();
        pending = op;
        const f = frame = el("iframe", {
          class: "browser-frame", title: `${name} — ${s.name || s.id}`,
          sandbox: "allow-scripts allow-forms", referrerpolicy: "no-referrer", allow: "",
        });
        f.addEventListener("load", () => onLoad(f));
        f.src = url;
        view.prepend(f);
        setState("Loading…", true);
        syncBar();
      };
      const go = (delta) => {
        const i = hist.index + delta;
        if (i < 0 || i >= hist.entries.length) return;
        navigate({ kind: "go", index: i, path: hist.entries[i] });
      };
      // Reload refetches the session too, so a guest restarted between polls recovers.
      const reloadPage = () => {
        dropSession();
        navigate(hist.current ? { kind: "reload", path: hist.current } : { kind: "push", path: "/" });
      };

      // Documents that can't report their location (images, text, downloads shown inline) settle on the
      // path we asked for, or on the link target the guest announced just before leaving.
      const onLoad = (f) => {
        if (!alive || f !== frame) return;
        setState(`Connected · ${s.name || s.id}`, false);
        clearTimeout(settle);
        const p = pending, c = candidate && Date.now() - candidate.at < 30000 ? candidate : null;
        candidate = null;
        if (!p && !c) return;
        settle = setTimeout(() => {
          if (!alive || f !== frame) return;
          if (p && pending === p) { pending = null; hist.commit(p, p.path); fallback = { path: p.path, at: Date.now() }; }
          else if (!p && c) { hist.push(c.path); fallback = { path: c.path, at: Date.now() }; }
          syncBar();
        }, 150);
      };
      const onMessage = (e) => {
        if (!frame || e.source !== frame.contentWindow || e.origin !== "null" || !session) return;
        const d = e.data;
        if (!d || typeof d !== "object" || typeof d.type !== "string") return;
        const p = browseLocalPath(d.path);
        if (p === null || browseFrameURL(session.base, p) === null) return;
        if (d.type === "lab-web-navigation") {
          if (!pending) candidate = { path: p, at: Date.now() };
          return;
        }
        if (d.type !== "lab-web-location") return;
        candidate = null;
        if (pending) { const op = pending; pending = null; hist.commit(op, p); }
        else if (fallback && Date.now() - fallback.at < 2000) hist.replace(p); // late report from the same document
        else hist.push(p);
        fallback = null;
        syncBar();
      };

      // Follow the lab: drop the frame and private session when the surface goes away, and reopen the
      // current entry with a fresh session once it returns.
      const check = () => {
        if (!alive) return;
        const up = surfaceAvailable(nodeId, s.id);
        if (!up && (frame || session || sessionBusy)) {
          unload(); dropSession(); syncBar();
          setState("Surface stopped — waiting for the node to run again…", true);
        } else if (up && !frame && !sessionBusy && Date.now() >= retryAt) {
          navigate(hist.current ? { kind: "reload", path: hist.current } : { kind: "push", path: "/" });
        }
        watch = setTimeout(check, 1000);
      };

      view.append(msg);
      w.body.classList.add("browser-body");
      w.body.append(nav, view, el("div", { class: "browser-status fs-hide" }, status));
      window.addEventListener("message", onMessage);
      // Clicks inside the frame never reach the editor; raise the window when the frame takes focus.
      const raise = () => setTimeout(() => { if (alive && frame && document.activeElement === frame) WM.focus(w); }, 0);
      window.addEventListener("blur", raise);
      w.onClose = () => {
        alive = false; clearTimeout(watch); unload(); dropSession(); fs.dispose();
        window.removeEventListener("blur", raise); window.removeEventListener("message", onMessage);
      };
      syncBar();
      navigate({ kind: "push", path: "/" });
      watch = setTimeout(check, 1000);
    },
  });
}

const KEYMAP = (() => {
  const m = {
    Enter: "ret", Escape: "esc", Backspace: "backspace", Tab: "tab", Space: "spc", Minus: "minus", Equal: "equal",
    BracketLeft: "bracket_left", BracketRight: "bracket_right", Backslash: "backslash", Semicolon: "semicolon",
    Quote: "apostrophe", Backquote: "grave_accent", Comma: "comma", Period: "dot", Slash: "slash", CapsLock: "caps_lock",
    ShiftLeft: "shift", ShiftRight: "shift_r", ControlLeft: "ctrl", ControlRight: "ctrl_r", AltLeft: "alt", AltRight: "alt_r",
    MetaLeft: "meta_l", MetaRight: "meta_r", ContextMenu: "menu", Insert: "insert", Delete: "delete", Home: "home", End: "end",
    PageUp: "pgup", PageDown: "pgdn", ArrowUp: "up", ArrowDown: "down", ArrowLeft: "left", ArrowRight: "right",
    NumLock: "num_lock", NumpadDecimal: "kp_decimal", NumpadAdd: "kp_add", NumpadSubtract: "kp_subtract",
    NumpadMultiply: "kp_multiply", NumpadDivide: "kp_divide", NumpadEnter: "kp_enter", PrintScreen: "print",
    ScrollLock: "scroll_lock", Pause: "pause", IntlBackslash: "less",
  };
  for (let c = 65; c <= 90; c++) m[`Key${String.fromCharCode(c)}`] = String.fromCharCode(c + 32);
  for (let i = 0; i <= 9; i++) { m[`Digit${i}`] = String(i); m[`Numpad${i}`] = `kp_${i}`; }
  for (let i = 1; i <= 12; i++) m[`F${i}`] = `f${i}`;
  return m;
})();

function openDisplay(nodeId, s, name) {
  const wid = `surface:${nodeId}:${s.id}`;
  const bounds = $("#windows").getBoundingClientRect();
  const width = Math.min(1240, bounds.width - 32);
  const height = Math.min(870, bounds.height - 32);
  WM.open(wid, {
    title: name, icon: ICONS.screen, width, height,
    x: (bounds.width - width) / 2, y: (bounds.height - height) / 2,
    build: (w) => {
      const base = surfacePath(nodeId, s);
      const img = el("img", { alt: "", draggable: "false" });
      const msg = el("div", { class: "disp-msg", text: "Connecting to display…" });
      const disp = el("div", { class: "display", tabindex: "0" }, img, msg);
      const pointerInfo = el("span", { class: "pointer-hint kv", text: "" });
      const pressed = new Set();
      let absolute = false, alive = true, lastURL = null, timer = 0, socket = null, heldButtons = false;
      const send = (event) => {
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(event));
      };
      const releaseAll = () => {
        flush();
        for (const key of pressed) send({ kind: "key", key, down: false });
        if (heldButtons) send({ kind: "pointer", x: 0, y: 0, absolute: false, buttons: [] });
        pressed.clear();
        heldButtons = false;
      };
      const bar = el("div", { class: "win-foot display-tools fs-hide", style: "padding:8px 12px;border-top:1px solid var(--border)" },
        pointerInfo,
        el("button", { class: "btn small", text: "Full screen", title: "Show the display full screen", onclick: () => fs.enter() }),
        el("button", { class: "btn small", text: "Ctrl+Alt+Del", onclick: () => send({ kind: "keys", keys: ["ctrl", "alt", "delete"] }) }),
        el("button", { class: "btn small", text: "Release keys", title: "Release all held keys and buttons", onclick: () => { releaseAll(); toast("Released keys and buttons."); } }),
        el("button", { class: "btn small", text: "Type text…", onclick: async () => {
          const ta = el("textarea", { style: "width:100%;height:120px;background:var(--panel-2);border:1px solid var(--border-strong);border-radius:7px;padding:8px;font-family:var(--mono)" });
          setTimeout(() => ta.focus(), 0);
          const ok = await modal({ title: `Type into ${name}`, body: ta, buttons: [{ label: "Cancel" }, { label: "Send", value: true, primary: true }] });
          if (ok && ta.value) send({ kind: "text", text: ta.value });
        } }),
        el("a", { class: "btn small", href: `${base}/frame?save`, download: `${nodeId}-${s.id}.png`, text: "Screenshot", style: "text-decoration:none" }));
      // Full screen shows only the guest display plus a small control strip that slides away while the
      // pointer is elsewhere; it returns when the pointer nears the top edge, on touch, or on focus.
      const fsExit = el("button", { type: "button", class: "btn small", text: "Exit full screen", title: "Exit full screen (Esc)", onclick: () => fs.exit() });
      const fsBar = el("div", { class: "fs-bar", role: "toolbar", "aria-label": "Full screen controls" },
        el("span", { class: "fs-title", text: name }),
        el("button", { type: "button", class: "btn small", text: "Ctrl+Alt+Del", onclick: () => { send({ kind: "keys", keys: ["ctrl", "alt", "delete"] }); disp.focus(); } }),
        fsExit);
      let fsIdle = 0;
      const revealBar = (ms = 2500) => {
        fsBar.classList.remove("idle");
        clearTimeout(fsIdle);
        fsIdle = setTimeout(() => { if (!fsBar.matches(":hover, :focus-within")) fsBar.classList.add("idle"); else revealBar(ms); }, ms);
      };
      const fs = surfaceFullscreen(w, { onChange: (on) => {
        clearTimeout(fsIdle);
        if (on) revealBar(3500);
        // Leaving full screen also releases the pointer; keep keyboard input on the display either way.
        setTimeout(() => { if (alive) disp.focus(); }, 0);
      } });
      w.el.addEventListener("pointermove", (e) => { if (fs.active() && e.clientY < 56) revealBar(); });
      w.el.addEventListener("pointerdown", (e) => { if (fs.active() && e.pointerType === "touch") revealBar(); });
      w.body.style.display = "flex"; w.body.style.flexDirection = "column"; w.body.style.overflow = "hidden";
      disp.style.flex = "1";
      w.el.append(fsBar);
      const hint = S.view?.nodes?.[nodeId]?.message || recipeOf(nodeById(nodeId) || {})?.hint;
      appendAll(w.body, hint && hint !== "Machine started" ? el("div", { class: "kv fs-hide", style: "padding:6px 12px;border-bottom:1px solid var(--border);font-family:var(--sans)", text: hint }) : null, disp, bar);

      const fitFrame = () => {
        if (!img.naturalWidth || !img.naturalHeight) return;
        const scale = Math.min(disp.clientWidth / img.naturalWidth, disp.clientHeight / img.naturalHeight);
        img.style.width = `${Math.round(img.naturalWidth * scale)}px`;
        img.style.height = `${Math.round(img.naturalHeight * scale)}px`;
      };
      const resize = new ResizeObserver(fitFrame);
      resize.observe(disp);
      const updatePointerHint = () => {
        pointerInfo.textContent = absolute ? "" : document.pointerLockElement === img ? "Esc releases pointer" : "Click to capture pointer";
      };
      const lockChange = () => {
        updatePointerHint();
        if (document.pointerLockElement !== img && !absolute) releaseAll();
      };
      let latest = null, decoding = false;
      const showFrame = () => {
        if (!alive || !latest || decoding) return;
        decoding = true;
        const packet = latest;
        latest = null;
        const next = URL.createObjectURL(new Blob([packet.subarray(1)], { type: "image/png" }));
        img.onload = img.onerror = () => {
          decoding = false;
          if (lastURL) URL.revokeObjectURL(lastURL);
          if (!alive) { URL.revokeObjectURL(next); return; }
          lastURL = next;
          fitFrame();
          msg.hidden = true;
          showFrame();
        };
        img.src = next;
      };
      const connect = () => {
        if (!alive) return;
        if (!surfaceAvailable(nodeId, s.id)) {
          msg.textContent = "Waiting for guest display…";
          msg.hidden = false;
          timer = setTimeout(connect, 1000);
          return;
        }
        const url = new URL(`${base}/display`, location.href);
        url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const connection = new WebSocket(url);
        socket = connection;
        connection.binaryType = "arraybuffer";
        connection.onmessage = (event) => {
          if (!alive || !(event.data instanceof ArrayBuffer)) return;
          const packet = new Uint8Array(event.data);
          const mode = packet[0] === 1;
          if (mode !== absolute) {
            releaseAll();
            absolute = mode;
            if (absolute && document.pointerLockElement === img) document.exitPointerLock();
          }
          updatePointerHint();
          latest = packet;
          showFrame();
        };
        connection.onclose = () => {
          pressed.clear(); heldButtons = false;
          if (!alive) return;
          if (document.pointerLockElement === img) document.exitPointerLock();
          msg.textContent = "Reconnecting to display…";
          msg.hidden = false;
          timer = setTimeout(connect, 750);
        };
      };

      // keyboard
      disp.addEventListener("keydown", (e) => {
        const k = KEYMAP[e.code];
        if (!k) return;
        e.preventDefault(); e.stopPropagation();
        if (e.repeat && pressed.has(k)) { send({ kind: "key", key: k, down: true }); return; }
        pressed.add(k); send({ kind: "key", key: k, down: true });
      });
      disp.addEventListener("keyup", (e) => {
        const k = KEYMAP[e.code];
        if (!k) return;
        e.preventDefault(); e.stopPropagation();
        pressed.delete(k); send({ kind: "key", key: k, down: false });
      });
      disp.addEventListener("blur", releaseAll);

      // pointer
      const buttonsOf = (b) => [b & 1 && "left", b & 2 && "right", b & 4 && "middle"].filter(Boolean);
      let pending = null, animation = 0;
      const flush = () => {
        cancelAnimationFrame(animation);
        animation = 0;
        if (pending) send(pending);
        pending = null;
      };
      const absPos = (e) => {
        const r = img.getBoundingClientRect();
        if (!r.width || !r.height) return null;
        return { x: Math.round(clamp((e.clientX - r.left) / r.width, 0, 1) * 32767), y: Math.round(clamp((e.clientY - r.top) / r.height, 0, 1) * 32767) };
      };
      const onPointer = (e, wheel = 0) => {
        if (!absolute && document.pointerLockElement !== img) return;
        const moving = e.type === "mousemove";
        const point = absolute ? absPos(e) : { x: moving ? e.movementX || 0 : 0, y: moving ? e.movementY || 0 : 0 };
        if (!point) return;
        const buttons = buttonsOf(e.buttons);
        const event = { kind: "pointer", ...point, absolute, buttons, wheel };
        if (moving) {
          if (pending && !absolute) { event.x += pending.x; event.y += pending.y; }
          pending = event;
          if (!animation) animation = requestAnimationFrame(flush);
        } else {
          // Send transitions in order even when motion arrived in the same frame.
          flush();
          send(event);
        }
        heldButtons = buttons.length > 0;
      };
      img.addEventListener("mousemove", (e) => onPointer(e));
      img.addEventListener("mousedown", (e) => {
        disp.focus();
        if (!absolute && document.pointerLockElement !== img) { img.requestPointerLock?.(); e.preventDefault(); return; }
        e.preventDefault(); onPointer(e);
      });
      img.addEventListener("mouseup", (e) => { e.preventDefault(); onPointer(e); });
      const outsideUp = (e) => { if (heldButtons && e.target !== img) onPointer(e); };
      window.addEventListener("mouseup", outsideUp);
      img.addEventListener("contextmenu", (e) => e.preventDefault());
      img.addEventListener("wheel", (e) => { e.preventDefault(); onPointer(e, e.deltaY < 0 ? 1 : -1); }, { passive: false });
      document.addEventListener("pointerlockchange", lockChange);

      w.onClose = () => {
        alive = false; clearTimeout(timer); clearTimeout(fsIdle);
        fs.dispose();
        releaseAll();
        socket?.close();
        resize.disconnect();
        if (document.pointerLockElement === img) document.exitPointerLock();
        document.removeEventListener("pointerlockchange", lockChange);
        window.removeEventListener("mouseup", outsideUp);
        if (lastURL) URL.revokeObjectURL(lastURL);
      };
      connect();
      setTimeout(() => disp.focus(), 0);
    },
  });
}

function openTerminal(nodeId, s, name) {
  const wid = `surface:${nodeId}:${s.id}`;
  const bounds = $("#windows").getBoundingClientRect();
  const width = Math.min(900, bounds.width - 32);
  const height = Math.min(580, bounds.height - 32);
  WM.open(wid, {
    title: `${name} · Serial console`, icon: ICONS.term, width, height,
    x: (bounds.width - width) / 2, y: (bounds.height - height) / 2,
    build: (w) => {
      const out = el("div", { class: "term" });
      const status = el("span", { class: "note", text: "Connecting…" });
      const terminal = new Terminal({ cols: 96, rows: 28, scrollback: 1024, fontSize: 13,
        fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", cursorBlink: true,
        theme: { background: "#0b0b10", foreground: "#e3e3ea", cursor: "#e3e3ea" } });
      let alive = true, socket, retry;
      const encoder = new TextEncoder();
      const send = (text) => {
        if (socket?.readyState !== WebSocket.OPEN) return;
        const bytes = encoder.encode(text);
        for (let i = 0; i < bytes.length; i += 4096) socket.send(bytes.subarray(i, i + 4096));
      };
      const toolbar = el("div", { class: "win-foot display-tools serial-tools" }, status,
        el("button", { class: "btn small", text: "Ctrl+C", onclick: () => { send("\x03"); terminal.focus(); } }),
        el("button", { class: "btn small", text: "Paste…", onclick: async () => {
          const input = el("textarea", { class: "terminal-paste", "aria-label": "Text to send" });
          setTimeout(() => input.focus(), 0);
          const ok = await modal({ title: `Send text to ${name}`, body: input, buttons: [{ label: "Cancel" }, { label: "Send", value: true, primary: true }] });
          if (ok && input.value) terminal.paste(input.value);
          terminal.focus();
        } }));
      w.body.classList.add("terminal-body");
      w.body.append(out, toolbar);
      terminal.open(out);
      terminal.onData(send);
      const connect = () => {
        if (!alive) return;
        if (!surfaceAvailable(nodeId, s.id)) {
          status.textContent = "Waiting for guest console…";
          retry = setTimeout(connect, 1000);
          return;
        }
        const url = new URL(`${surfacePath(nodeId, s)}/serial`, location.href);
        url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const connection = new WebSocket(url);
        socket = connection;
        connection.binaryType = "arraybuffer";
        connection.onopen = () => { terminal.reset(); status.textContent = "Connected"; };
        connection.onmessage = (event) => { if (alive) terminal.write(new Uint8Array(event.data)); };
        connection.onclose = () => {
          if (!alive) return;
          status.textContent = "Reconnecting…";
          retry = setTimeout(connect, 750);
        };
      };
      connect();
      terminal.focus();
      w.onClose = () => { alive = false; clearTimeout(retry); socket?.close(); terminal.dispose(); };
    },
  });
}

// ---------------------------------------------------------------- runtime logs
// The lab view carries an ordered, bounded log per node but no timestamps that
// order entries across nodes, so the panel groups entries by node.
const LOGS = { filter: "", win: null, sig: "", pending: false, follow: true };
const LOGS_WID = "logs";

function logNodeName(id) {
  return nodeById(id)?.name || (S.applied?.nodes || []).find((n) => n.id === id)?.name || id;
}
function logNodeIds() {
  const ids = [];
  const add = (id) => { if (id && !ids.includes(id)) ids.push(id); };
  for (const n of S.draft.nodes) add(n.id);
  for (const n of S.applied?.nodes || []) add(n.id);
  for (const id of Object.keys(S.view?.nodes || {})) add(id);
  return ids;
}
function logGroups(filter) {
  const nodes = S.view?.nodes || {};
  return logNodeIds().filter((id) => !filter || id === filter).map((id) => {
    const rt = nodes[id];
    const inDraft = !!nodeById(id);
    return { id, name: logNodeName(id), phase: rt?.phase || "", entries: rt?.log || [], inDraft, running: !!rt };
  });
}
function logLabNotes(filter) {
  const notes = [];
  if (S.view?.error) notes.push(`error — ${S.view.error}`);
  for (const o of S.view?.operation || []) {
    if (filter && o.node !== filter) continue;
    notes.push(`${o.node ? `${logNodeName(o.node)}: ` : ""}${o.action}${o.detail ? ` (${o.detail})` : ""}`);
  }
  return notes;
}
function logPlainText(filter) {
  const out = [];
  const notes = logLabNotes(filter);
  if (notes.length) out.push(`== Lab (${S.view?.state || "idle"}) ==`, ...notes, "");
  for (const g of logGroups(filter)) {
    if (!g.entries.length && filter !== g.id) continue;
    out.push(`== ${g.name}${g.name !== g.id ? ` (${g.id})` : ""}${g.phase ? ` · ${g.phase}` : ""} ==`);
    out.push(...(g.entries.length ? g.entries : ["(no entries)"]), "");
  }
  return out.join("\n").trim();
}
function logsSig() {
  return JSON.stringify([LOGS.filter, S.view?.state, S.view?.error, S.view?.operation, logGroups("").map((g) => [g.id, g.name, g.phase, g.entries, g.inDraft])]);
}
function phaseClass(p) { return /^(failed|error)$/.test(p) ? "err" : p === "running" ? "ok" : p ? "busy" : ""; }

function openLogs(nodeId = "") {
  LOGS.filter = nodeId || "";
  const existing = WM.wins.get(LOGS_WID);
  if (existing) { WM.open(LOGS_WID, {}); LOGS.sig = ""; renderLogs({ jump: true }); return; }
  const bounds = $("#windows").getBoundingClientRect();
  const width = Math.min(640, bounds.width - 32);
  const height = Math.min(520, bounds.height - 32);
  WM.open(LOGS_WID, {
    title: "Runtime logs", icon: ICONS.log, width, height,
    x: Math.max(16, (bounds.width - width) / 2), y: Math.max(16, (bounds.height - height) / 3),
    build: (w) => {
      LOGS.win = w;
      LOGS.sig = "";
      LOGS.follow = true;
      w.body.classList.add("logs-body");
      renderLogs({ jump: true });
    },
    onClose: () => { LOGS.win = null; LOGS.pending = false; },
  });
}
function logsSelectionActive() {
  const sel = document.getSelection();
  if (!sel || sel.isCollapsed || !sel.rangeCount || !LOGS.win) return false;
  return LOGS.win.body.querySelector(".logs-list")?.contains(sel.getRangeAt(0).commonAncestorContainer) || false;
}
function refreshLogs() {
  renderLogsBadge();
  if (!LOGS.win) return;
  if (logsSig() === LOGS.sig) return;
  // Do not replace text the user is selecting; apply the update once the selection clears.
  if (logsSelectionActive()) { LOGS.pending = true; setLogsNote(); return; }
  renderLogs();
}
document.addEventListener("selectionchange", () => {
  if (LOGS.pending && !logsSelectionActive()) { LOGS.pending = false; renderLogs(); }
});
function renderLogsBadge() {
  const badge = $("#logs-count");
  const failed = logGroups("").filter((g) => phaseClass(g.phase) === "err").length;
  const problems = failed + (S.view?.error ? 1 : 0);
  badge.hidden = !problems;
  badge.textContent = problems ? String(problems) : "";
  const parts = [failed ? `${failed} node${failed === 1 ? "" : "s"} failed` : "", S.view?.error ? "lab error" : ""].filter(Boolean);
  $("#logs-btn").title = parts.length ? `Runtime logs — ${parts.join(", ")}` : "Runtime logs — startup diagnostics reported by each node";
  $("#logs-btn").setAttribute("aria-label", parts.length ? `Logs, ${parts.join(", ")}` : "Logs");
}
function setLogsNote() {
  const note = LOGS.win?.body.querySelector(".logs-foot .note");
  if (!note) return;
  const groups = logGroups(LOGS.filter);
  const n = groups.reduce((t, g) => t + g.entries.length, 0);
  const shown = groups.filter((g) => g.entries.length).length;
  note.textContent = LOGS.pending ? "Updates paused while text is selected."
    : `${n} entr${n === 1 ? "y" : "ies"}${LOGS.filter ? "" : ` from ${shown} node${shown === 1 ? "" : "s"}`} · each node keeps its most recent entries`;
}
function renderLogs({ jump = false } = {}) {
  const w = LOGS.win;
  if (!w) return;
  LOGS.sig = logsSig();
  LOGS.pending = false;
  const prevList = w.body.querySelector(".logs-list");
  const prevScroll = prevList ? prevList.scrollTop : 0;
  const atBottom = prevList ? prevList.scrollHeight - prevList.scrollTop - prevList.clientHeight < 8 : true;
  const active = document.activeElement;
  const focusKey = active && w.body.contains(active) ? active.dataset.key : null;

  if (LOGS.filter && !logNodeIds().includes(LOGS.filter)) LOGS.filter = "";
  w.setTitle(LOGS.filter ? `Runtime logs — ${logNodeName(LOGS.filter)}` : "Runtime logs");
  const ids = logNodeIds();
  const nodes = S.view?.nodes || {};
  const select = el("select", { class: "field logs-filter", "aria-label": "Show logs from", "data-key": "filter",
    onchange: (e) => { LOGS.filter = e.target.value; renderLogs({ jump: true }); } },
    el("option", { value: "", text: "All nodes" }),
    ids.map((id) => {
      const count = nodes[id]?.log?.length || 0;
      return el("option", { value: id, selected: id === LOGS.filter, text: `${logNodeName(id)}${count ? ` (${count})` : ""}${nodeById(id) ? "" : " — not in draft"}` });
    }));
  const follow = el("label", { class: "logs-follow" },
    el("input", { type: "checkbox", checked: LOGS.follow, "data-key": "follow", onchange: (e) => { LOGS.follow = e.target.checked; if (LOGS.follow) { const l = w.body.querySelector(".logs-list"); l.scrollTop = l.scrollHeight; } } }),
    "Follow new entries");
  const copy = el("button", { class: "btn small", text: "Copy", "data-key": "copy", title: "Copy the shown entries as plain text", onclick: () => copyLogs() });
  const head = el("div", { class: "logs-head" }, el("label", { class: "logs-label", text: "Source" }), select, follow, copy);

  const list = el("div", { class: "logs-list", tabindex: "0", role: "region", "aria-label": LOGS.filter ? `Log entries from ${logNodeName(LOGS.filter)}` : "Log entries grouped by node" });
  const notes = logLabNotes(LOGS.filter);
  if (notes.length) {
    list.append(el("section", { class: `log-group lab ${S.view?.error ? "err" : ""}`, "aria-label": "Lab operation" },
      el("h3", { class: "log-src" }, el("span", { class: "log-name", text: "Lab" }), el("span", { class: `pill ${S.view?.error ? "error" : "busy"}`, text: S.view?.state || "idle" })),
      el("pre", { class: "log-lines", text: notes.join("\n") })));
  }
  const groups = logGroups(LOGS.filter);
  const withEntries = groups.filter((g) => g.entries.length);
  for (const g of LOGS.filter ? groups : withEntries) {
    const cls = phaseClass(g.phase);
    list.append(el("section", { class: `log-group ${cls}`, "aria-label": `${g.name} log` },
      el("h3", { class: "log-src" },
        el("span", { class: "log-name", text: g.name }),
        g.name !== g.id ? el("span", { class: "log-id", text: g.id }) : null,
        el("span", { class: `pill ${cls === "err" ? "error" : cls === "ok" ? "running" : cls}`, text: g.phase || "not running" }),
        !g.inDraft ? el("span", { class: "badge", text: "not in draft" }) : null,
        el("span", { class: "log-acts" },
          !LOGS.filter && ids.length > 1 ? el("button", { class: "btn small", text: "Only this node", onclick: () => { LOGS.filter = g.id; renderLogs({ jump: true }); } }) : null,
          g.inDraft ? el("button", { class: "btn small", text: "Inspect", title: `Open ${g.name} runtime properties`, onclick: () => openInspector(g.id, "Runtime") }) : null)),
      g.entries.length
        ? el("pre", { class: "log-lines", text: g.entries.join("\n") })
        : el("div", { class: "log-empty", text: g.running ? "No entries reported yet." : "Not running — entries appear after Run Lab starts this node." })));
  }
  if (!list.childElementCount || (!LOGS.filter && !withEntries.length && !notes.length)) {
    const st = S.view?.state || "idle";
    list.replaceChildren(el("div", { class: "lib-state logs-empty" },
      el("div", { class: "big", text: st === "idle" ? "No runtime logs yet" : "Waiting for diagnostics" }),
      el("div", { class: "small", text: !S.draft.nodes.length && !ids.length
        ? "Add nodes to the canvas, then Run Lab. Each node reports its startup phases and failures here."
        : st === "idle" ? "Run Lab to start the nodes. Each node reports its startup phases and failures here, grouped by node."
        : "Nodes have not reported any entries yet. This panel updates live." }),
      st === "idle" && S.draft.nodes.length ? el("button", { class: "btn small primary", text: "Run Lab", onclick: planAndApply }) : null));
  }
  const foot = el("div", { class: "win-foot logs-foot" }, el("span", { class: "note", role: "status" }));
  w.body.replaceChildren(head, list, foot);
  setLogsNote();
  // A single node reads newest-last; the grouped view opens at the top so every source is visible in order.
  if (jump) list.scrollTop = LOGS.filter ? list.scrollHeight : 0;
  else if (LOGS.follow && atBottom && prevList) list.scrollTop = list.scrollHeight;
  else list.scrollTop = prevScroll;
  if (focusKey) w.body.querySelector(`[data-key="${CSS.escape(focusKey)}"]`)?.focus();
}
async function copyLogs() {
  const text = logPlainText(LOGS.filter);
  if (!text) { toast("Nothing to copy yet."); return; }
  try {
    if (!navigator.clipboard) throw new Error("Clipboard unavailable; select the text in the panel instead.");
    await navigator.clipboard.writeText(text);
    toast(LOGS.filter ? `Copied ${logNodeName(LOGS.filter)} log.` : "Copied runtime logs.");
  } catch (err) { toast(err.message, "err"); }
}

// ---------------------------------------------------------------- plan / apply / stop / save
async function planAndApply() {
  const def = normalizeDefinition(S.draft);
  let plan;
  try { plan = await api("POST", "/api/plan", def); }
  catch (err) { toast(`Plan failed: ${err.message}`, "err"); return; }
  const changes = plan.changes || [], issues = plan.issues || [];
  WM.close("plan");
  WM.open("plan", {
    title: "Apply plan", icon: ICONS.play, width: 520, height: Math.min(560, 200 + (changes.length + issues.length) * 42),
    x: Math.max(16, ($("#windows").getBoundingClientRect().width - 520) / 2), y: 40,
    build: (w) => {
      const nameOf = (id) => nodeById(id)?.name || nodeById(id, normalizeDefinition(S.applied || {}))?.name || id || "lab";
      const byNode = new Map();
      for (const issue of issues) {
        if (!byNode.has(issue.node)) byNode.set(issue.node, []);
        byNode.get(issue.node).push(issue);
      }
      const issueList = el("div", { class: "plan-list" }, [...byNode].map(([id, entries]) => {
        const node = nodeById(id);
        const mediaIssue = node && entries.some((issue) => recipeOf(node)?.media.some((slot) => slot.key === issue.field));
        return el("div", { class: "plan-row plan-issue" },
          el("div", { class: "plan-issue-head" }, el("b", { text: id ? nameOf(id) : "Lab" }),
            node ? el("button", { class: "btn small", text: mediaIssue ? "Choose media" : "Edit node", onclick: () => {
              WM.close("plan"); openInspector(id, mediaIssue ? "Media" : undefined);
            } }) : null),
          el("ul", {}, entries.map((issue) => el("li", { text: issue.message }))));
      }));
      const order = { rebuild: 0, restart: 1, start: 2, stop: 3, live: 4, layout: 5 };
      const sorted = [...changes].sort((a, b) => (order[a.action] ?? 9) - (order[b.action] ?? 9));
      const changeList = el("div", { class: "plan-list" }, sorted.map((c) => el("div", { class: "plan-row" },
        el("span", { class: `badge ${c.action === "live" || c.action === "layout" ? "live" : c.action === "restart" || c.action === "start" || c.action === "stop" ? "restart" : "rebuild"}`, text: c.action }),
        el("div", { class: "what" }, el("b", { text: nameOf(c.node) }), c.detail ? el("div", { class: "kv", text: c.detail }) : null))));
      const counts = {};
      for (const c of changes) counts[c.action] = (counts[c.action] || 0) + 1;
      const summary = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(", ");
      const blocking = issues.length > 0;
      w.body.style.display = "flex"; w.body.style.flexDirection = "column";
      appendAll(w.body,
        issues.length ? el("div", { class: "plan-empty", style: "color:var(--err);padding-bottom:0", text: `${issues.length} issue${issues.length === 1 ? "" : "s"} must be resolved before applying.` }) : null,
        issues.length ? issueList : null,
        changes.length ? el("div", { class: "plan-empty", style: "padding-bottom:0", text: `Changes: ${summary}` }) : el("div", { class: "plan-empty", text: "The running lab already matches this draft." }),
        changes.length ? changeList : null,
        el("div", { style: "flex:1" }),
        el("div", { class: "win-foot" },
          el("span", { class: "note", text: isDirty() ? "Draft is unsaved; applying does not save it." : "" }),
          el("button", { class: "btn small", text: "Close", onclick: () => WM.close("plan") }),
          el("button", { class: "btn small primary", text: "Apply", disabled: blocking || !changes.length, onclick: async (e) => {
            e.target.disabled = true;
            try { const v = await api("POST", "/api/apply", def); ingestView(v); toast("Apply started.", "ok"); WM.close("plan"); }
            catch (err) { toast(`Apply failed: ${err.message}`, "err"); e.target.disabled = false; }
          } })));
    },
  });
}
async function stopLab() {
  const ok = await modal({ title: "Stop lab", body: el("div", { text: "Stop all running machines in this lab? Unsaved guest state will be lost." }),
    buttons: [{ label: "Cancel" }, { label: "Stop", value: true, primary: true }] });
  if (!ok) return;
  try { ingestView(await api("POST", "/api/stop", {})); toast("Stopping lab."); }
  catch (err) { toast(`Stop failed: ${err.message}`, "err"); }
}
async function save() {
  try {
    const v = await api("PUT", "/api/lab", normalizeDefinition(S.draft));
    S.saved = normalizeDefinition(v?.definition ?? S.draft);
    ingestView(v, { adopt: false });
    toast("Lab saved.", "ok");
  } catch (err) { toast(`Save failed: ${err.message}`, "err"); }
  renderChrome();
}
function exportDefinition() {
  const def = normalizeDefinition(S.draft);
  for (const n of def.nodes) n.media = {};
  const blob = new Blob([JSON.stringify(def, null, 2) + "\n"], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `${slug(def.name)}.lab.json` });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  toast("Exported without media bindings.");
}
async function importDefinition(file) {
  let parsed;
  try { parsed = JSON.parse(await file.text()); }
  catch (err) { toast(`Import failed: ${err.message}`, "err"); return; }
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.nodes)) { toast("Import failed: not a lab definition.", "err"); return; }
  const def = normalizeDefinition(parsed);
  const unknown = [...new Set(def.nodes.filter((n) => !S.recipes.has(n.recipe)).map((n) => n.recipe))];
  replaceDraft(def);
  S.sel.nodes.clear(); fitView();
  toast(`Imported “${def.name}” as draft.${unknown.length ? ` Unknown recipes: ${unknown.join(", ")}` : ""}`, unknown.length ? "err" : "ok");
}

// ---------------------------------------------------------------- polling
let lastViewKey = "";
function ingestView(v, { adopt = true } = {}) {
  if (!v || typeof v !== "object") return;
  const viewKey = JSON.stringify(v);
  const same = viewKey === lastViewKey;
  lastViewKey = viewKey;
  if (same && adopt) return;
  const prevSaved = S.saved ? defKey(S.saved) : null;
  const wasDirty = S.saved ? isDirty() : true;
  S.view = v;
  S.applied = v.applied ?? null;
  if (v.definition) {
    const next = normalizeDefinition(v.definition);
    const changed = prevSaved !== JSON.stringify(next);
    S.saved = next;
    // Adopt server definition only when the user has no unsaved draft.
    if (adopt && changed && !wasDirty && prevSaved !== null) { S.draft = clone(next); pruneSelection(); }
  }
  renderAll();
  refreshInspectors();
}
async function poll() {
  if (S.polling) return;
  S.polling = true;
  try {
    const v = await api("GET", "/api/lab");
    ingestView(v);
    $("#conn").className = "conn ok"; $("#conn-text").textContent = "Connected";
  } catch (err) {
    $("#conn").className = "conn bad"; $("#conn-text").textContent = "Disconnected";
    $("#conn").title = err.message;
  } finally {
    S.polling = false;
    const st = S.view?.state;
    setTimeout(poll, st === "applying" || st === "stopping" ? 700 : document.hidden ? 4000 : 1500);
  }
}

// ---------------------------------------------------------------- chrome wiring
document.querySelectorAll(".tool[data-tool]").forEach((b) => b.addEventListener("click", () => setTool(b.dataset.tool)));
$("#fit-btn").onclick = fitView;
$("#zoom-in").onclick = () => { const r = stage.getBoundingClientRect(); zoomAt(S.cam.k * 1.2, r.left + r.width / 2, r.top + r.height / 2); };
$("#zoom-out").onclick = () => { const r = stage.getBoundingClientRect(); zoomAt(S.cam.k / 1.2, r.left + r.width / 2, r.top + r.height / 2); };
$("#zoom-val").onclick = () => { const r = stage.getBoundingClientRect(); zoomAt(1, r.left + r.width / 2, r.top + r.height / 2); };
$("#undo-btn").onclick = undo;
$("#redo-btn").onclick = redo;
$("#save-btn").onclick = save;
$("#apply-btn").onclick = planAndApply;
$("#stop-btn").onclick = stopLab;
$("#drift-pill").onclick = planAndApply;
$("#palette-search").addEventListener("input", renderPalette);
$("#palette-search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { const first = $("#palette .pal-item[draggable]"); first?.dispatchEvent(new MouseEvent("dblclick")); }
  if (e.key === "Escape") { e.target.value = ""; renderPalette(); }
});
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab[data-pane]").forEach((o) => {
    o.classList.toggle("active", o === t);
    o.setAttribute("aria-selected", o === t);
  });
  $("#pane-nodes").hidden = t.dataset.pane !== "nodes";
  $("#pane-templates").hidden = t.dataset.pane !== "templates";
}));
const labName = $("#lab-name");
labName.addEventListener("change", () => {
  const v = labName.value.trim() || "Untitled lab";
  if (v !== S.draft.name) mutate((d) => { d.name = v; });
});
labName.addEventListener("keydown", (e) => { if (e.key === "Enter") labName.blur(); if (e.key === "Escape") { labName.value = S.draft.name; labName.blur(); } });

const menu = $("#main-menu");
$("#menu-btn").onclick = (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; };
document.addEventListener("click", (e) => { if (!e.target.closest(".menu-wrap")) menu.hidden = true; });
menu.addEventListener("click", async (e) => {
  const act = e.target.dataset.act;
  if (!act) return;
  menu.hidden = true;
  if (act === "new") {
    if (S.draft.nodes.length && !(await modal({ title: "New blank lab", body: el("div", { text: "Clear the canvas? The saved lab is unchanged until you save." }), buttons: [{ label: "Cancel" }, { label: "Clear canvas", value: true, primary: true }] }))) return;
    replaceDraft(emptyDefinition()); S.sel.nodes.clear(); fitView();
  } else if (act === "reload") {
    if (S.saved) { replaceDraft(S.saved); fitView(); toast("Draft reset to saved lab."); }
  } else if (act === "import") $("#import-file").click();
  else if (act === "export") exportDefinition();
  else if (act === "revert") {
    if (!S.applied) { toast("Nothing is applied yet.", "err"); return; }
    replaceDraft(S.applied); toast("Draft reset to the running lab.");
  }
});
$("#import-file").addEventListener("change", (e) => { const f = e.target.files[0]; e.target.value = ""; if (f) importDefinition(f); });
window.addEventListener("resize", () => applyCam());
window.addEventListener("beforeunload", (e) => { if (isDirty()) { e.preventDefault(); e.returnValue = ""; } });

// ---------------------------------------------------------------- software library
const LIB = { items: null, error: null, loading: null, filter: "lab", opener: null, node: null, choice: null };
const libBack = $("#library-back"), libBox = $("#library"), libQ = $("#lib-q"), libList = $("#lib-results");
const SW_ICON = '<svg viewBox="0 0 24 24"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/></svg>';
const natural = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });

function normalizeSoftware(resp) {
  const list = Array.isArray(resp?.software) ? resp.software : [];
  return list.filter((s) => s && (s.title || s.id)).map((s) => {
    const title = String(s.title || s.id);
    const byOS = new Map();
    for (const t of Array.isArray(s.targets) ? s.targets : []) {
      const os = String(t?.os ?? "").trim();
      if (!os) continue;
      const lab = t.availability === "lab" && Boolean(t.recipe && t.package);
      const via = typeof t.via === "string" ? t.via.trim() : "";
      const prev = byOS.get(os.toLowerCase());
      if (!prev || (lab && !prev.lab)) byOS.set(os.toLowerCase(), { os, lab, via, recipe: t.recipe, package: t.package, hay: `${os} ${via}`.toLowerCase() });
    }
    const targets = [...byOS.values()].sort((a, b) => natural(a.os, b.os));
    return { id: String(s.id ?? title), title, targets };
  }).sort((a, b) => natural(a.title, b.title));
}
function loadSoftware() {
  if (LIB.items || LIB.loading) return LIB.loading;
  LIB.error = null;
  LIB.loading = api("GET", "/api/software")
    .then((r) => { LIB.items = normalizeSoftware(r); })
    .catch((err) => { LIB.error = err; })
    .finally(() => { LIB.loading = null; if (!libBack.hidden) renderLibrary(); });
  return LIB.loading;
}

// Every query word must appear in the title or in one of the shown systems.
// Words not found in the title select which systems are highlighted.
function matchSoftware(item, words, filter) {
  const node = LIB.node && nodeById(LIB.node);
  const targets = filter === "lab" ? item.targets.filter((t) => t.lab && (!node || node.recipe === t.recipe)) : item.targets;
  if (filter === "lab" && !targets.length) return null;
  if (!words.length) return { item, targets, rank: 0, hits: new Set() };
  const title = item.title.toLowerCase();
  const rest = words.filter((w) => !title.includes(w));
  if (rest.some((w) => !targets.some((t) => t.hay.includes(w)))) return null;
  const phrase = words.join(" ");
  const rank = title.startsWith(phrase) ? 0 : title.includes(phrase) ? 1 : !rest.length ? 2 : 3;
  const hits = new Set(rest.length ? targets.filter((t) => rest.every((w) => t.hay.includes(w))) : []);
  // Words split across several systems ("windows 95 98"): highlight any system that contains one.
  if (rest.length && !hits.size) for (const t of targets) if (rest.some((w) => t.hay.includes(w))) hits.add(t);
  return { item, targets, rank, hits };
}
function highlight(text, words) {
  if (!words.length) return [text];
  const lower = text.toLowerCase(), marks = new Array(text.length).fill(false);
  for (const w of words) for (let i = lower.indexOf(w); i >= 0; i = lower.indexOf(w, i + 1)) marks.fill(true, i, i + w.length);
  const out = [];
  for (let i = 0; i < text.length;) {
    let j = i; while (j < text.length && marks[j] === marks[i]) j++;
    out.push(marks[i] ? el("mark", { text: text.slice(i, j) }) : text.slice(i, j));
    i = j;
  }
  return out;
}
function libState(kind, big, small, button) {
  libList.setAttribute("role", "group");
  return el("div", { class: `lib-state ${kind}`, role: "status" }, el("div", { class: "big", text: big }), small ? el("div", { class: "small", text: small }) : null, button);
}
function renderLibrary() {
  const count = $("#lib-count");
  if (LIB.choice) { renderSoftwareDestination(); return; }
  if (!LIB.items) {
    if (LIB.error) {
      count.textContent = "";
      libList.replaceChildren(libState("err", "Couldn't load the software library", LIB.error.message,
        el("button", { class: "btn small", text: "Try again", onclick: () => { loadSoftware(); renderLibrary(); libQ.focus(); } })));
    } else {
      count.textContent = "Loading…";
      libList.replaceChildren(...Array.from({ length: 5 }, () => el("div", { class: "lib-skel", "aria-hidden": "true" }, el("i"), el("i"), el("i"))));
      libList.setAttribute("aria-busy", "true");
    }
    return;
  }
  libList.removeAttribute("aria-busy");
  const words = libQ.value.toLowerCase().split(/\s+/).filter(Boolean);
  const results = LIB.items.map((it) => matchSoftware(it, words, LIB.filter)).filter(Boolean)
    .sort((a, b) => a.rank - b.rank || natural(a.item.title, b.item.title));
  const total = LIB.items.length;
  count.textContent = results.length ? `${results.length} ${results.length === 1 ? "application" : "applications"}` : "";
  if (!total) { libList.replaceChildren(libState("", "No software is listed yet", "Titles appear here once the repository has software recipes.")); return; }
  if (!results.length) {
    const hidden = LIB.filter === "lab" ? LIB.items.filter((it) => matchSoftware(it, words, "all")).length : 0;
    const q = libQ.value.trim();
    libList.replaceChildren(libState("", q ? `No matches for “${q}”` : "No applications available for this guest",
      hidden ? "The compatibility list includes more titles." : q ? "Try part of a title or operating system." : null,
      el("div", { style: "display:flex;gap:8px" },
        hidden ? el("button", { class: "btn small", text: "View compatibility", onclick: () => setLibFilter("all", true) }) : null,
        q ? el("button", { class: "btn small", text: "Clear search", onclick: () => { libQ.value = ""; renderLibrary(); libQ.focus(); } }) : null)));
    return;
  }
  libList.setAttribute("role", "list");
  libList.replaceChildren(...results.map(({ item, targets, hits }) => {
    const lab = targets.filter((t) => t.lab), smoke = targets.filter((t) => !t.lab);
    const chip = (t) => el("span", {
      class: `tgt ${t.lab ? "lab" : "smoke"}`,
    }, el("span", { html: iconFor({ id: t.os, title: t.os, family: "" }) }), el("span", {}, hits.has(t) ? highlight(t.os, words) : t.os),
      t.via ? el("span", { class: "tgt-via" }, "via ", hits.has(t) ? highlight(t.via, words) : t.via) : null);
    const name = (t) => (t.via ? `${t.os} via ${t.via}` : t.os);
    const label = [item.title, ...targets.map(name)].join(". ");
    return el("div", { class: "sw", role: "listitem", tabindex: "-1", "aria-label": label, dataset: { id: item.id } },
      el("span", { class: "sw-ico", html: SW_ICON }),
      el("div", { class: "sw-title" }, el("span", { class: "t" }, highlight(item.title, words)),
        lab.length ? el("button", { class: "btn small sw-add", text: "Add to guest…", onclick: () => {
          LIB.choice = { title: item.title, targets: lab };
          renderLibrary();
          $("#lib-destination")?.focus();
        } }) : null),
      el("div", { class: "sw-targets" },
        targets.length ? null : el("span", { class: "sw-none", text: "No supported systems listed." }),
        lab.length ? el("span", { class: "tgt-group" }, lab.map(chip)) : null,
        smoke.length ? el("span", { class: "tgt-group" }, el("span", { class: "tgt-label", text: "Tested separately" }), smoke.map(chip)) : null));
  }));
}
function renderSoftwareDestination() {
  const { title, targets } = LIB.choice;
  $("#lib-count").textContent = "";
  libList.setAttribute("role", "group");
  const choices = [];
  for (const target of targets) {
    const recipe = S.recipes.get(target.recipe);
    if (!recipe || recipe.blocked) continue;
    for (const node of S.draft.nodes.filter((n) => n.recipe === recipe.id)) {
      const installed = softwareSelection(node.config.software).includes(target.package);
      choices.push({ target, node, label: `${node.name}${installed ? " · Already selected" : ""}`, installed });
    }
    choices.push({ target, label: `New ${recipe.title} guest` });
  }
  const preferred = choices.findIndex((c) => !c.installed && c.node && (c.node.id === LIB.node || S.sel.nodes.has(c.node.id)));
  const fallback = choices.findIndex((c) => !c.installed);
  const select = el("select", { id: "lib-destination", class: "f-input" }, choices.map((choice, i) =>
    el("option", { value: i, text: choice.label, disabled: choice.installed })));
  if (fallback >= 0) select.value = String(preferred >= 0 ? preferred : fallback);
  const add = el("button", { class: "btn small primary", disabled: fallback < 0 });
  const info = el("div", { class: "hint" });
  const update = () => {
    const choice = choices[select.value];
    add.textContent = choice?.node ? "Add to guest" : "Create guest";
    const parts = [];
    if (choice?.target.via) parts.push(`Included with ${choice.target.via}.`);
    if (choice?.node && S.view?.nodes?.[choice.node.id]?.phase === "running") parts.push("Apply Changes will rebuild this guest and replace its temporary disk.");
    info.textContent = parts.join(" ");
  };
  add.onclick = () => {
    const choice = choices[select.value];
    if (!choice || choice.installed) return;
    const id = choice.target.package;
    let node = choice.node && nodeById(choice.node.id);
    if (choice.node && !node) { renderSoftwareDestination(); return; }
    if (node) {
      const packages = softwareSelection([...softwareSelection(node.config.software), id]);
      const inspector = inspectors.get(node.id);
      if (inspector) inspector.staged.config.software = softwareSelection([...softwareSelection(inspector.staged.config.software), id]);
      mutate(() => { node.config.software = packages; });
    } else {
      node = addNodeAtCenter(choice.target.recipe, { software: [id] });
    }
    if (!node) return;
    closeLibrary();
    S.sel.nodes = new Set([node.id]);
    S.sel.link = -1;
    renderAll();
    if (missingMedia(node).length) openInspector(node.id, "Media");
    toast(`${title} added to ${node.name}. Apply the lab to install it.`, "ok");
  };
  select.onchange = update;
  update();
  libList.replaceChildren(el("div", { class: "lib-destination" },
    el("button", { class: "btn small", text: "Back to applications", onclick: () => { LIB.choice = null; renderLibrary(); libQ.focus(); } }),
    el("h3", { text: title }),
    choices.length ? el("label", { for: "lib-destination", text: "Guest" }) : null,
    choices.length ? select : el("p", { text: "No compatible guests are available on this lab host." }),
    info, choices.length ? add : null));
}
function setLibFilter(f, focus) {
  LIB.filter = f;
  LIB.choice = null;
  libBox.querySelectorAll(".seg-btn").forEach((b) => { const on = b.dataset.filter === f; b.classList.toggle("active", on); b.setAttribute("aria-checked", String(on)); b.tabIndex = on ? 0 : -1; });
  renderLibrary();
  if (focus) libQ.focus();
}
function openLibrary(node = null) {
  if (!libBack.hidden) { libQ.focus(); libQ.select(); return; }
  if (!$("#modal-back").hidden) return;
  menu.hidden = true;
  LIB.opener = document.activeElement;
  LIB.node = node;
  LIB.choice = null;
  $("#lib-sub").textContent = node ? `Choose an application for ${nodeById(node)?.name}.` : "Choose an application for a guest in this lab.";
  libBack.hidden = false;
  $("#library-btn").setAttribute("aria-expanded", "true");
  if (!LIB.items) loadSoftware();
  setLibFilter("lab", false);
  libQ.focus(); libQ.select();
}
function closeLibrary() {
  if (libBack.hidden) return;
  libBack.hidden = true;
  LIB.node = null;
  LIB.choice = null;
  $("#library-btn").setAttribute("aria-expanded", "false");
  const back = LIB.opener && LIB.opener.isConnected ? LIB.opener : $("#library-btn");
  LIB.opener = null;
  back.focus?.();
}
$("#library-btn").onclick = () => openLibrary();
$("#logs-btn").onclick = () => openLogs();
$("#lib-close").onclick = closeLibrary;
libBack.addEventListener("pointerdown", (e) => { if (e.target === libBack) closeLibrary(); });
libQ.addEventListener("input", () => { LIB.choice = null; renderLibrary(); libList.scrollTop = 0; });
libBox.querySelectorAll(".seg-btn").forEach((b) => b.addEventListener("click", () => setLibFilter(b.dataset.filter)));
libBox.addEventListener("keydown", (e) => {
  const rows = [...libList.querySelectorAll(".sw")];
  const at = rows.indexOf(document.activeElement);
  const go = (i) => { const r = rows[clamp(i, 0, rows.length - 1)]; if (r) { r.focus(); r.scrollIntoView({ block: "nearest" }); } };
  if (e.key === "Escape") {
    e.preventDefault(); e.stopPropagation();
    if (e.target === libQ && libQ.value) { libQ.value = ""; renderLibrary(); } else closeLibrary();
    return;
  }
  if (e.key === "Tab") {
    const focusables = [...libBox.querySelectorAll("button:not([disabled]), input, select")].filter((n) => n.offsetParent !== null && n.tabIndex >= 0);
    if (!focusables.length) return;
    const first = focusables[0], last = focusables[focusables.length - 1];
    if (at >= 0) { e.preventDefault(); (e.shiftKey ? libQ : first).focus(); return; }
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    return;
  }
  if (e.target.classList?.contains("seg-btn") && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
    e.preventDefault(); setLibFilter(LIB.filter === "all" ? "lab" : "all");
    libBox.querySelector(".seg-btn.active").focus();
    return;
  }
  if (e.target === libQ) {
    if ((e.key === "ArrowDown" || e.key === "Enter") && rows.length) { e.preventDefault(); go(0); }
    return;
  }
  if (at < 0) return;
  if (e.key === "ArrowDown") { e.preventDefault(); go(at + 1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); at === 0 ? libQ.focus() : go(at - 1); }
  else if (e.key === "Home") { e.preventDefault(); go(0); }
  else if (e.key === "End") { e.preventDefault(); go(rows.length - 1); }
  else if (e.key === "PageDown") { e.preventDefault(); go(at + 8); }
  else if (e.key === "PageUp") { e.preventDefault(); go(at - 8); }
  else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) libQ.focus(); // keep typing into search
  else if (e.key === "Backspace") { libQ.focus(); }
});

// ---------------------------------------------------------------- boot
async function boot() {
  applyCam();
  fitView();
  try {
    const cat = await api("GET", "/api/catalog");
    S.catalog = { recipes: cat.recipes || [], templates: cat.templates || [] };
    S.recipes = new Map(S.catalog.recipes.map((r) => [r.id, r]));
  } catch (err) {
    $("#palette").replaceChildren(el("div", { class: "empty-note", text: `Catalog unavailable: ${err.message}` }));
    toast(`Catalog unavailable: ${err.message}`, "err");
  }
  renderPalette(); renderTemplates();
  try {
    const v = await api("GET", "/api/lab");
    S.saved = normalizeDefinition(v.definition || emptyDefinition());
    S.draft = clone(S.saved);
    let stored = null;
    try { stored = JSON.parse(localStorage.getItem(DRAFT_KEY) || "null"); } catch (_) {}
    if (stored && defKey(stored) !== defKey(S.saved)) {
      S.draft = normalizeDefinition(stored);
      toast("Restored your unsaved draft. Use ⋯ → Reset draft to saved lab to discard it.");
    }
    ingestView(v, { adopt: false });
    $("#conn").className = "conn ok"; $("#conn-text").textContent = "Connected";
  } catch (err) {
    $("#conn").className = "conn bad"; $("#conn-text").textContent = "Disconnected";
    toast(`Lab state unavailable: ${err.message}`, "err");
    renderAll();
  }
  fitView();
  setTimeout(poll, 1500);
}
boot();
})();
