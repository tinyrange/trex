"use strict";
// Browser side of the web3270 protocol: renders 3270 screens and line-mode
// console transcripts in one or two panes, and sends input. The server's
// device models are the only console state.
(() => {
  const token = location.hash.slice(1);
  const $ = (id) => document.getElementById(id);
  const tabsEl = $("tabs"), keysEl = $("keys"), pfEl = $("pf"), panesEl = $("panes");
  const kbd = $("kbd"), machineEl = $("machine"), toastEl = $("toast"), splitBtn = $("split");
  const settingsDlg = $("settings"), form = settingsDlg.querySelector("form");
  let terminals = [], panes = [], active = null;
  const histories = new Map(); // line-console input history by console

  // --- settings ----------------------------------------------------------
  const defaults = { font: "auto", colors: "color", cursor: "block", enter: "enter", sound: true };
  const settings = (() => {
    try { return { ...defaults, ...JSON.parse(localStorage.getItem("web3270.settings") || "{}") }; }
    catch { return { ...defaults }; }
  })();
  function saveSettings() {
    try { localStorage.setItem("web3270.settings", JSON.stringify(settings)); } catch { /* private mode */ }
  }
  function applySettings() {
    document.body.classList.toggle("green", settings.colors === "green");
    document.body.classList.toggle("amber", settings.colors === "amber");
    document.body.classList.toggle("cursor-underline", settings.cursor === "underline");
    for (const p of panes) p.fit();
  }

  let toastTimer = 0;
  function toast(text, ms = 3500) {
    toastEl.textContent = text;
    toastEl.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toastEl.hidden = true; }, ms);
  }

  let audio = null;
  function beep() {
    try {
      audio = audio || new AudioContext();
      const o = audio.createOscillator(), g = audio.createGain();
      o.frequency.value = 880;
      g.gain.value = 0.06;
      o.connect(g).connect(audio.destination);
      o.start();
      o.stop(audio.currentTime + 0.12);
    } catch { /* no audio */ }
  }

  // Strip terminal control sequences from VT220 output.
  const clean = (s) => s.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[@-_]|[\x00-\x08\x0b-\x1f\x7f]/g, "");

  // --- a pane shows one console --------------------------------------------
  class Pane {
    constructor() {
      this.el = $("paneTemplate").content.firstElementChild.cloneNode(true);
      const q = (s) => this.el.querySelector(s);
      this.screenEl = q(".screen"); this.selEl = q(".selection"); this.lineEl = q(".line");
      this.linesEl = q(".lines"); this.lineInput = q(".lineInput"); this.banner = q(".banner");
      this.bannerText = q(".bannerText");
      this.readerEl = q(".readerView"); this.deck = q(".deck"); this.queuedEl = q(".queued");
      this.formEl = q(".lineForm");
      q(".submitDeck").addEventListener("click", () => {
        const text = this.deck.value.replace(/\s+$/, "");
        if (!text) { this.queuedEl.textContent = "The deck is empty."; return; }
        const long = text.split("\n").filter((l) => l.length > 80).length;
        this.send({ type: "deck", text });
        this.queuedEl.textContent = long ? `Submitted (${long} cards were longer than 80 columns and are cut).` : "Submitted.";
      });
      q(".download").addEventListener("click", async () => {
        try {
          const r = await fetch(`api/output?terminal=${encodeURIComponent(this.term.name)}`, { headers: { Authorization: "Bearer " + token } });
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          const a = document.createElement("a");
          a.href = URL.createObjectURL(await r.blob());
          a.download = `${this.term.name}.txt`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 10000);
        } catch (err) { this.flashMsg("X " + err.message); }
      });
      this.oia = { conn: q(".conn"), lock: q(".lock"), ins: q(".ins"), msg: q(".msg"), dev: q(".dev"), pos: q(".pos") };
      this.ws = null; this.term = null; this.screen = null; this.retry = 0; this.retryTimer = 0;
      this.lineCount = 0; this.historyAt = 0; this.selection = null; this.alarms = null; this.msgTimer = 0;
      this.el.addEventListener("mousedown", () => activate(this));
      q(".reconnect").addEventListener("click", () => this.connect());
      this.lineInput.addEventListener("focus", () => activate(this));
      q(".lineForm").addEventListener("submit", (e) => { e.preventDefault(); this.submitLine(); });
      this.lineInput.addEventListener("keydown", (e) => this.lineKey(e));
      this.linesEl.addEventListener("click", () => { if (this.term.kind === "line" && !String(getSelection()).length) this.lineInput.focus(); });
      this.screenEl.addEventListener("mousedown", (e) => this.mouseDown(e));
      panesEl.appendChild(this.el);
    }
    get display() { return this.term && this.term.kind === "3270"; }

    show(name) {
      this.term = terminals.find((t) => t.name === name) || terminals[0];
      this.screen = null; this.alarms = null; this.lineCount = 0; this.clearSelection();
      this.screenEl.replaceChildren(); this.linesEl.replaceChildren();
      const kind = this.term.kind;
      this.screenEl.hidden = kind !== "3270";
      this.lineEl.hidden = kind !== "line" && kind !== "printer";
      this.formEl.hidden = kind === "printer";
      this.readerEl.hidden = kind !== "reader";
      for (const [k, v] of Object.entries(this.oia)) if (k !== "conn") v.textContent = "";
      this.historyAt = this.history().length;
      this.retry = 0;
      this.connect();
      if (this === active) refreshChrome();
    }
    history() {
      if (!histories.has(this.term.name)) histories.set(this.term.name, []);
      return histories.get(this.term.name);
    }

    connect() {
      clearTimeout(this.retryTimer);
      if (this.ws) { this.ws.onclose = null; this.ws.close(); }
      const term = this.term;
      // Relative to the page, so the consoles can be served under a prefix.
      const u = new URL("ws", location.href);
      u.protocol = location.protocol === "https:" ? "wss:" : "ws:";
      u.hash = "";
      u.search = `?token=${encodeURIComponent(token)}&terminal=${encodeURIComponent(term.name)}`;
      const ws = new WebSocket(u);
      this.ws = ws;
      this.oia.conn.textContent = "4  ...";
      ws.onopen = () => {
        this.retry = 0;
        this.banner.hidden = true;
        this.oia.conn.textContent = "4A";
        if (this === active) focusInput();
      };
      ws.onmessage = (e) => {
        if (term !== this.term) return;
        const m = JSON.parse(e.data);
        if (m.type === "screen") this.render(m);
        else if (m.type === "lines") this.renderLines(m);
        else if (m.type === "inhibit") this.flashMsg("X " + m.reason);
        else if (m.type === "reader") {
          this.oia.dev.textContent = m.name;
          this.oia.lock.textContent = m.queued ? `${m.queued} cards in the hopper` : "hopper empty";
        }
        if (m.status) setMachineStatus(m.status);
      };
      ws.onclose = () => {
        if (term !== this.term || this.closed) return;
        this.retry = Math.min(this.retry + 1, 6);
        let wait = Math.round(250 * (1 << this.retry) / 1000);
        this.oia.conn.textContent = "4  disconnected";
        this.banner.hidden = false;
        const tick = () => {
          this.bannerText.textContent = wait > 0 ? `Disconnected. Reconnecting in ${wait}s.` : "Reconnecting…";
          if (wait-- <= 0) { this.connect(); return; }
          this.retryTimer = setTimeout(tick, 1000);
        };
        tick();
      };
    }
    close() {
      this.closed = true;
      clearTimeout(this.retryTimer);
      if (this.ws) { this.ws.onclose = null; this.ws.close(); }
      this.el.remove();
    }
    send(m) {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(m));
      else this.flashMsg("X not connected");
    }
    key(k) { this.clearSelection(); this.send({ type: "key", key: k }); }
    flashMsg(text) {
      this.oia.msg.textContent = text;
      clearTimeout(this.msgTimer);
      this.msgTimer = setTimeout(() => { this.oia.msg.textContent = ""; }, 2500);
    }

    // 3270 display.
    render(s) {
      const resized = !this.screen || this.screen.rows !== s.rows || this.screen.cols !== s.cols;
      this.screen = s;
      if (resized) this.clearSelection();
      const style = (i) => s.attr[i] + s.color[i] + s.hilite[i];
      const frag = document.createDocumentFragment();
      for (let r = 0; r < s.rows; r++) {
        const row = document.createElement("span");
        row.className = "row";
        let start = r * s.cols;
        const end = start + s.cols;
        while (start < end) {
          const st = style(start);
          let stop = start + 1;
          if (start !== s.cursor) while (stop < end && stop !== s.cursor && style(stop) === st) stop++;
          const span = document.createElement("span");
          let cls = st[0];
          if (st[1] !== "0") cls += " c" + st[1];
          if (st[2] !== "0") cls += " h" + st[2];
          if (start === s.cursor) cls += " cur";
          span.className = cls;
          span.textContent = s.text.slice(start, stop);
          row.appendChild(span);
          start = stop;
        }
        frag.appendChild(row);
      }
      this.screenEl.replaceChildren(frag);
      this.screenEl.classList.toggle("ins", s.insert);
      this.oia.lock.textContent = s.locked ? "X SYSTEM" : "";
      this.oia.ins.textContent = s.insert ? "^ INSERT" : "";
      this.oia.dev.textContent = `${s.name}  model ${s.model}`;
      const r = Math.floor(s.cursor / s.cols) + 1, c = (s.cursor % s.cols) + 1;
      this.oia.pos.textContent = String(r).padStart(3, "0") + "/" + String(c).padStart(3, "0");
      if (this.alarms !== null && s.alarms > this.alarms) this.alarm();
      this.alarms = s.alarms;
      if (resized) this.fit();
      if (this === active) syncModel();
    }
    alarm() {
      if (settings.sound) beep();
      else {
        this.el.classList.remove("flash");
        void this.el.offsetWidth;
        this.el.classList.add("flash");
      }
    }
    fit() {
      if (!this.term) return;
      if (!this.display) {
        this.lineEl.style.fontSize = settings.font === "auto" ? "" : settings.font + "px";
        return;
      }
      if (!this.screen) return;
      let size = +settings.font;
      if (settings.font === "auto") {
        const vp = this.el.querySelector(".viewport");
        const w = vp.clientWidth - 8, h = vp.clientHeight - 8;
        size = Math.max(6, Math.floor(Math.min(w / (this.screen.cols * 0.61), h / (this.screen.rows * 1.25))));
      }
      this.screenEl.style.fontSize = size + "px";
      this.el.querySelector(".oia").style.fontSize = Math.min(size, 16) + "px";
      this.placeSelection();
    }
    cellAt(x, y) {
      const rect = this.screenEl.getBoundingClientRect();
      const s = this.screen;
      const col = Math.max(0, Math.min(s.cols - 1, Math.floor((x - rect.left) / (rect.width / s.cols))));
      const row = Math.max(0, Math.min(s.rows - 1, Math.floor((y - rect.top) / (rect.height / s.rows))));
      return { row, col };
    }
    mouseDown(e) {
      if (e.button !== 0 || !this.screen) return;
      e.preventDefault();
      activate(this);
      focusInput();
      const start = this.cellAt(e.clientX, e.clientY);
      let moved = false;
      const move = (ev) => {
        const at = this.cellAt(ev.clientX, ev.clientY);
        if (!moved && at.row === start.row && at.col === start.col) return;
        moved = true;
        this.selection = { r0: Math.min(start.row, at.row), r1: Math.max(start.row, at.row),
          c0: Math.min(start.col, at.col), c1: Math.max(start.col, at.col) };
        this.placeSelection();
      };
      const up = () => {
        removeEventListener("mousemove", move);
        removeEventListener("mouseup", up);
        if (!moved) {
          this.clearSelection();
          this.send({ type: "cursor", row: start.row, col: start.col });
        }
      };
      addEventListener("mousemove", move);
      addEventListener("mouseup", up);
    }
    placeSelection() {
      const sel = this.selection;
      if (!sel || !this.screen) { this.selEl.hidden = true; return; }
      const vp = this.el.querySelector(".viewport").getBoundingClientRect();
      const rect = this.screenEl.getBoundingClientRect();
      const cw = rect.width / this.screen.cols, rh = rect.height / this.screen.rows;
      Object.assign(this.selEl.style, {
        left: rect.left - vp.left + sel.c0 * cw + "px", top: rect.top - vp.top + sel.r0 * rh + "px",
        width: (sel.c1 - sel.c0 + 1) * cw + "px", height: (sel.r1 - sel.r0 + 1) * rh + "px",
      });
      this.selEl.hidden = false;
    }
    clearSelection() { this.selection = null; this.selEl.hidden = true; }
    selectionText() {
      const s = this.screen, sel = this.selection, out = [];
      for (let r = sel.r0; r <= sel.r1; r++) out.push(s.text.slice(r * s.cols + sel.c0, r * s.cols + sel.c1 + 1).trimEnd());
      return out.join("\n");
    }

    // Line-mode console.
    renderLines(m) {
      const el = this.linesEl;
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
      el.querySelector(".partial")?.remove();
      if (this.lineCount !== 0 && m.first > this.lineCount) {
        const gap = document.createElement("div");
        gap.textContent = `… ${m.first - this.lineCount} lines not shown …`;
        el.appendChild(gap);
      }
      const frag = document.createDocumentFragment();
      for (const line of m.lines) {
        const div = document.createElement("div");
        div.textContent = clean(line) || "​";
        frag.appendChild(div);
      }
      el.appendChild(frag);
      this.lineCount = m.first + m.lines.length;
      while (el.childElementCount > 5000) el.firstElementChild.remove();
      const empty = el.querySelector(".empty");
      if (this.lineCount === 0 && !m.partial) {
        if (!empty) {
          const div = document.createElement("div");
          div.className = "empty";
          div.textContent = "No console output yet.";
          el.appendChild(div);
        }
      } else empty?.remove();
      if (m.partial) {
        const div = document.createElement("div");
        div.className = "partial";
        div.textContent = clean(m.partial);
        el.appendChild(div);
      }
      this.oia.lock.textContent = m.waiting && this.term.name !== "SYSTEM" ? "READ PENDING" : "";
      this.oia.dev.textContent = m.name;
      if (atBottom) el.scrollTop = el.scrollHeight;
    }
    submitLine() {
      const text = this.lineInput.value;
      this.send({ type: "line", text });
      const h = this.history();
      if (text && h[h.length - 1] !== text) h.push(text);
      if (h.length > 200) h.shift();
      this.historyAt = h.length;
      this.lineInput.value = "";
      this.linesEl.scrollTop = this.linesEl.scrollHeight;
    }
    lineKey(e) {
      if ((e.key === "Enter" || e.key === "NumpadEnter") && !e.isComposing) {
        // Explicitly: not every keyboard produces the keypress that
        // implicit form submission waits for.
        e.preventDefault();
        this.submitLine();
        return;
      }
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
      e.preventDefault();
      const h = this.history();
      this.historyAt = Math.max(0, Math.min(h.length, this.historyAt + (e.key === "ArrowUp" ? -1 : 1)));
      this.lineInput.value = h[this.historyAt] || "";
    }
  }

  // --- panes, tabs and header ---------------------------------------------
  function activate(p) {
    if (active === p) return;
    active = p;
    for (const x of panes) {
      x.el.classList.toggle("active", x === p);
      x.el.classList.toggle("focused", x === p && document.activeElement === kbd);
    }
    refreshChrome();
  }
  function refreshChrome() {
    if (!active || !active.term) return;
    for (const b of tabsEl.children) {
      const on = b.dataset.name === active.term.name;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", String(on));
    }
    keysEl.hidden = !active.display;
    if (!active.display) { pfEl.hidden = true; $("pfToggle").setAttribute("aria-expanded", "false"); }
    const params = new URLSearchParams();
    params.set("terminal", panes[0].term.name);
    if (panes[1]) params.set("split", panes[1].term.name);
    history.replaceState(null, "", `?${params}${location.hash}`);
    syncModel();
  }
  function focusInput() {
    if (!active) return;
    if (active.display) kbd.focus({ preventScroll: true });
    else if (active.term.kind === "line") active.lineInput.focus();
    else if (active.term.kind === "reader") active.deck.focus();
    else active.linesEl.focus();
  }
  function setMachineStatus(status) {
    machineEl.textContent = status === "running" ? "Machine running" : "Machine " + status;
    machineEl.classList.toggle("bad", status !== "running");
  }
  function setSplit(name) {
    if (name && panes.length === 1) {
      const p = new Pane();
      panes.push(p);
      panesEl.classList.add("split");
      p.show(name);
      activate(p);
    } else if (!name && panes.length === 2) {
      const gone = panes.pop();
      gone.close();
      panesEl.classList.remove("split");
      activate(panes[0]);
    }
    splitBtn.setAttribute("aria-pressed", String(panes.length === 2));
    for (const p of panes) p.fit();
    refreshChrome();
  }
  splitBtn.addEventListener("click", () => {
    if (panes.length === 2) { setSplit(null); return; }
    const shown = panes[0].term.name;
    const other = terminals.find((t) => t.name !== shown && t.kind === "3270") || terminals.find((t) => t.name !== shown);
    if (other) setSplit(other.name);
    else toast("There is only one console.");
  });

  // --- keyboard -------------------------------------------------------------
  const special = {
    Tab: "TAB", Home: "HOME", End: "ERASEEOF", Insert: "INSERT", Delete: "DELETE",
    Backspace: "BACKSPACE", Escape: "RESET", Pause: "CLEAR", ArrowLeft: "LEFT", ArrowRight: "RIGHT",
    ArrowUp: "UP", ArrowDown: "DOWN",
  };
  function onKey(e) {
    const p = active;
    if (!p || !p.display || e.isComposing || e.keyCode === 229) return;
    const altGraph = e.getModifierState && e.getModifierState("AltGraph");
    const enter = e.key === "Enter" || e.code === "NumpadEnter";
    if (enter) {
      e.preventDefault();
      const ctrl = e.ctrlKey || e.metaKey;
      const sendsEnter = settings.enter === "enter" ? !ctrl : ctrl;
      p.key(sendsEnter ? "ENTER" : "NEWLINE");
      return;
    }
    if (e.code === "ControlRight" && settings.enter === "newline") { e.preventDefault(); p.key("ENTER"); return; }
    if ((e.ctrlKey || e.metaKey) && !altGraph) return; // browser shortcuts such as copy
    let k = null;
    const f = /^F(\d+)$/.exec(e.key);
    if (f && +f[1] >= 1 && +f[1] <= 12) k = "PF" + (+f[1] + (e.shiftKey ? 12 : 0));
    else if (e.altKey && !altGraph && /^Digit[123]$/.test(e.code)) k = "PA" + e.code.slice(5);
    else if (e.key === "Tab" && e.shiftKey) k = "BACKTAB";
    else if (special[e.key]) k = special[e.key];
    if (k) { e.preventDefault(); p.key(k); return; }
    if (e.target === kbd) return; // text arrives as an input event
    if ([...e.key].length === 1 && (!e.altKey || altGraph)) {
      e.preventDefault();
      p.send({ type: "text", text: e.key });
      focusInput();
    }
  }
  kbd.addEventListener("keydown", onKey);
  panesEl.addEventListener("keydown", (e) => { if (e.target.classList.contains("screen")) onKey(e); });
  kbd.addEventListener("input", (e) => {
    if (e.isComposing || !active || !active.display) { if (!e.isComposing) kbd.value = ""; return; }
    if (e.inputType === "deleteContentBackward") active.key("BACKSPACE");
    else if (e.inputType === "insertLineBreak") active.key("ENTER");
    else if (kbd.value) { active.clearSelection(); active.send({ type: "text", text: kbd.value.replace(/[\r\n]/g, "") }); }
    kbd.value = "";
  });
  kbd.addEventListener("compositionend", (e) => {
    if (e.data && active && active.display) active.send({ type: "text", text: e.data });
    kbd.value = "";
  });
  kbd.addEventListener("focus", () => active && active.el.classList.add("focused"));
  kbd.addEventListener("blur", () => { for (const p of panes) p.el.classList.remove("focused"); });
  kbd.addEventListener("paste", (e) => {
    if (!active || !active.display) return;
    e.preventDefault();
    const lines = e.clipboardData.getData("text").replace(/\r/g, "").split("\n");
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
    lines.forEach((line, i) => {
      if (i > 0) active.key("NEWLINE");
      if (line) active.send({ type: "text", text: line });
    });
  });
  // Copy a rectangle selected on a 3270 screen.
  document.addEventListener("copy", (e) => {
    if (!active || !active.display || !active.selection) return;
    e.clipboardData.setData("text/plain", active.selectionText());
    e.preventDefault();
    toast("Copied the selected rectangle.", 1500);
  });

  // --- toolbar, settings, save ---------------------------------------------
  for (const b of keysEl.querySelectorAll("button[data-key]")) {
    b.addEventListener("click", () => { active && active.key(b.dataset.key); focusInput(); });
  }
  for (let i = 1; i <= 24; i++) {
    const b = document.createElement("button");
    b.textContent = "PF" + i;
    b.addEventListener("click", () => { active && active.key("PF" + i); focusInput(); });
    pfEl.appendChild(b);
  }
  const toggle = $("pfToggle");
  toggle.addEventListener("click", () => {
    pfEl.hidden = !pfEl.hidden;
    toggle.setAttribute("aria-expanded", String(!pfEl.hidden));
    for (const p of panes) p.fit();
  });
  addEventListener("resize", () => { for (const p of panes) p.fit(); });

  function syncModel() {
    const set = $("modelSet");
    set.hidden = !active || !active.display;
    if (active && active.screen) form.model.value = String(active.screen.model);
  }
  $("settingsButton").addEventListener("click", () => {
    form.font.value = settings.font; form.colors.value = settings.colors; form.cursor.value = settings.cursor;
    form.enter.value = settings.enter; form.sound.checked = settings.sound;
    syncModel();
    settingsDlg.showModal();
  });
  form.addEventListener("change", (e) => {
    if (e.target.name === "model") {
      if (active && active.display) active.send({ type: "model", model: +form.model.value });
      return;
    }
    settings.font = form.font.value; settings.colors = form.colors.value; settings.cursor = form.cursor.value;
    settings.enter = form.enter.value; settings.sound = form.sound.checked;
    saveSettings();
    applySettings();
  });
  settingsDlg.addEventListener("close", focusInput);

  const saveBtn = $("save");
  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    toast("Saving the machine state…", 60000);
    try {
      const r = await fetch("api/checkpoint", { method: "POST", headers: { Authorization: "Bearer " + token } });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      toast(`Saved ${d.saved} in ${d.seconds.toFixed(1)} s.`);
    } catch (err) {
      toast("Saving failed: " + err.message, 6000);
    } finally {
      saveBtn.disabled = false;
      focusInput();
    }
  });

  // --- file transfer (IND$FILE) ---------------------------------------------
  const transferDlg = $("transfer"), tform = $("transferForm"), tstatus = $("transferStatus");
  let polling = 0;
  function transferStatus(text, cls = "") { tstatus.textContent = text; tstatus.className = "status " + cls; }
  function syncTransferForm() {
    const put = tform.direction.value === "put";
    for (const el of tform.querySelectorAll(".uploadOnly")) el.hidden = !put;
    tform.file.required = put;
  }
  tform.addEventListener("change", syncTransferForm);
  $("transferButton").addEventListener("click", () => {
    if (!active || !active.display) return;
    syncTransferForm();
    if (!polling) transferStatus("");
    transferDlg.showModal();
  });
  $("transferClose").addEventListener("click", () => transferDlg.close());
  transferDlg.addEventListener("close", focusInput);
  const api = (path) => `${path}${path.includes("?") ? "&" : "?"}terminal=${encodeURIComponent(active.term.name)}`;
  tform.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (polling) return;
    const p = new URLSearchParams({ direction: tform.direction.value, dataset: tform.dataset.value.trim(),
      mode: tform.mode.value, options: tform.options.value.trim(),
      submit: tform.direction.value === "put" && tform.submit.checked ? "1" : "" });
    const body = tform.direction.value === "put" ? tform.file.files[0] : undefined;
    $("transferStart").disabled = true;
    try {
      const r = await fetch(api(`api/transfer?${p}`), { method: "POST", headers: { Authorization: "Bearer " + token }, body });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      transferStatus(`Started: ${d.command}`);
      poll(active.term.name, tform.direction.value, p.get("dataset"));
    } catch (err) {
      transferStatus(err.message, "bad");
      $("transferStart").disabled = false;
    }
  });
  function poll(name, direction, dataset) {
    const q = `?terminal=${encodeURIComponent(name)}`;
    polling = setInterval(async () => {
      try {
        const s = await (await fetch(`api/transfer${q}`, { headers: { Authorization: "Bearer " + token } })).json();
        if (s.done && s.submit && !s.submitted && !s.failed) {
          transferStatus(`${s.message}\nSubmitting the job…`);
          return;
        }
        if (!s.done) {
          transferStatus(direction === "put" ? `Uploading… ${s.records} records sent` : `Downloading… ${s.bytes} bytes received`);
          return;
        }
        clearInterval(polling);
        polling = 0;
        $("transferStart").disabled = false;
        if (s.failed) { transferStatus(s.message || "The transfer failed.", "bad"); return; }
        if (direction === "get") {
          const r = await fetch(`api/transfer/data${q}`, { headers: { Authorization: "Bearer " + token } });
          const blob = await r.blob();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = dataset.replace(/'/g, "").replace(/[()]/g, ".").replace(/\.$/, "") || "download";
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 10000);
          transferStatus(`${s.message}\nDownloaded ${blob.size} bytes as ${a.download}.`, "good");
        } else if (s.submit) {
          const ok = s.submitted === "typed";
          transferStatus(`${s.message}\n${ok ? "SUBMIT " + dataset + " was typed: watch the terminal for the job number." : s.submitted}`, ok ? "good" : "bad");
        } else transferStatus(s.message, "good");
      } catch (err) {
        clearInterval(polling);
        polling = 0;
        $("transferStart").disabled = false;
        transferStatus(err.message, "bad");
      }
    }, 500);
  }

  // --- snapshots ------------------------------------------------------------
  const snapDlg = $("snapshots"), snapForm = $("snapshotForm"), snapList = $("snapshotList"), snapStatus = $("snapshotStatus");
  const auth = { Authorization: "Bearer " + token };
  function snapMessage(text, cls = "") { snapStatus.textContent = text; snapStatus.className = "status " + cls; }
  async function snapCall(action, name) {
    const r = await fetch(`api/snapshots/${action}?name=${encodeURIComponent(name)}`, { method: "POST", headers: auth });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }
  async function loadSnapshots() {
    try {
      const d = await (await fetch("api/snapshots", { headers: auth })).json();
      snapList.replaceChildren();
      if (!d.snapshots || !d.snapshots.length) {
        const li = document.createElement("li");
        li.className = "empty";
        li.textContent = d.error || "No snapshots yet.";
        snapList.appendChild(li);
        return;
      }
      for (const sn of d.snapshots) {
        const li = document.createElement("li");
        const name = document.createElement("span");
        name.className = "snapName";
        name.textContent = sn.name;
        const meta = document.createElement("span");
        meta.className = "snapMeta";
        meta.textContent = `${new Date(sn.saved).toLocaleString()} · ${Math.round(sn.bytes / 1048576)} MB`;
        const restore = document.createElement("button");
        restore.type = "button";
        restore.textContent = "Restore";
        restore.addEventListener("click", async () => {
          if (!confirm(`Replace the running machine with snapshot "${sn.name}"?`)) return;
          snapMessage(`Restoring ${sn.name}…`);
          try { const r = await snapCall("restore", sn.name); snapMessage(`Restored ${sn.name} in ${r.seconds.toFixed(1)} s.`, "good"); }
          catch (err) { snapMessage(err.message, "bad"); }
        });
        const del = document.createElement("button");
        del.type = "button";
        del.textContent = "Delete";
        del.addEventListener("click", async () => {
          if (!confirm(`Delete snapshot "${sn.name}"?`)) return;
          try { await snapCall("delete", sn.name); snapMessage(`Deleted ${sn.name}.`); loadSnapshots(); }
          catch (err) { snapMessage(err.message, "bad"); }
        });
        li.append(name, meta, restore, del);
        snapList.appendChild(li);
      }
    } catch (err) { snapMessage(err.message, "bad"); }
  }
  $("snapshotsButton").addEventListener("click", () => { snapMessage(""); loadSnapshots(); snapDlg.showModal(); });
  $("snapshotsClose").addEventListener("click", () => snapDlg.close());
  snapDlg.addEventListener("close", focusInput);
  snapForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = snapForm.snapName.value.trim();
    if (!name) { snapMessage("Give the snapshot a name.", "bad"); return; }
    snapMessage(`Saving ${name}…`);
    try {
      const r = await snapCall("save", name);
      snapMessage(`Saved ${name} in ${r.seconds.toFixed(1)} s.`, "good");
      snapForm.snapName.value = "";
      loadSnapshots();
    } catch (err) { snapMessage(err.message, "bad"); }
  });

  // --- start ------------------------------------------------------------------
  applySettings();
  fetch("api/terminals", { headers: { Authorization: "Bearer " + token } })
    .then((r) => { if (!r.ok) throw new Error(r.status === 403 ? "invalid session token" : "HTTP " + r.status); return r.json(); })
    .then((d) => {
      terminals = d.terminals;
      saveBtn.hidden = !d.canSave;
      $("snapshotsButton").hidden = !d.snapshots;
      setMachineStatus(d.status);
      for (const t of terminals) {
        const b = document.createElement("button");
        b.textContent = t.name;
        b.title = { "3270": "3270 display", line: "line-mode console", printer: "printer or punch output", reader: "card reader" }[t.kind] || t.kind;
        b.dataset.name = t.name;
        b.addEventListener("click", () => { if (active) { active.show(t.name); refreshChrome(); } });
        tabsEl.appendChild(b);
      }
      const params = new URLSearchParams(location.search);
      const first = new Pane();
      panes.push(first);
      activate(first);
      first.show(params.get("terminal") || terminals[0].name);
      const split = params.get("split");
      if (split && terminals.some((t) => t.name === split)) setSplit(split);
    })
    .catch((err) => { machineEl.textContent = "Cannot open the console list: " + err.message; machineEl.classList.add("bad"); });
})();
