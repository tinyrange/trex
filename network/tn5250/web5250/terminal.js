"use strict";
// A 5250 display station in the browser. The server publishes screens
// (GET /api/screen, long-poll) and receives operator actions (POST
// /api/input): field contents typed on a given screen, the cursor and an
// AID key. Typing edits the grid locally, as a real terminal buffers input
// until an AID key is pressed.
(() => {
  const token = location.hash.slice(1);
  const auth = { Authorization: "Bearer " + token };
  const ROWS = 24, COLS = 80, CELLS = ROWS * COLS;
  const el = (id) => document.getElementById(id);
  const screenEl = el("screen");

  let screen = null;        // last published screen
  let version = 0;
  let fieldAt = new Int16Array(CELLS).fill(-1); // cell -> field array index
  let buffers = [];         // per field: array of characters being edited
  let dirty = new Set();    // field indexes the operator changed
  let cursor = 0;           // cell index
  let insert = false;
  let sentRecords = -1;     // records value of the screen the last input was for
  let spans = [];

  // Grid of spans, built once.
  for (let r = 0; r < ROWS; r++) {
    const row = document.createElement("div");
    row.className = "r";
    for (let c = 0; c < COLS; c++) {
      const s = document.createElement("span");
      s.dataset.cell = String(r * COLS + c);
      row.appendChild(s);
      spans.push(s);
    }
    screenEl.appendChild(row);
  }

  const pf = (id, first) => {
    const row = el(id);
    for (let i = first; i < first + 12; i++) {
      const b = document.createElement("button");
      b.dataset.key = "PF" + i;
      b.textContent = "F" + i;
      row.appendChild(b);
    }
  };
  pf("pf1", 1);
  pf("pf2", 13);

  const fieldStart = (f) => (f.row - 1) * COLS + (f.col - 1);

  function showNotes(text) {
    const notes = el("notes");
    if (!text) { notes.hidden = true; return; }
    if (notes.dataset.text === text) return;
    notes.dataset.text = text;
    notes.textContent = text;
    notes.hidden = false;
  }

  const layout = (s) => s.fields.map((f) => [f.index, f.row, f.col, f.length].join(",")).join(";");

  function load(s) {
    showNotes(s.notes);
    const changed = !screen || s.records !== screen.records;
    // A host update that keeps the same input fields (a status line, a
    // refreshed sign-on) leaves the operator's typing and cursor alone, as
    // a display station does; a new set of fields starts afresh.
    const keep = changed && screen && dirty.size > 0 && layout(s) === layout(screen);
    const previous = buffers;
    screen = s;
    if (changed) {
      fieldAt.fill(-1);
      buffers = [];
      s.fields.forEach((f, i) => {
        const start = fieldStart(f);
        for (let k = 0; k < f.length && start + k < CELLS; k++) fieldAt[start + k] = i;
        const text = f.hidden ? "" : f.text;
        buffers.push(keep && dirty.has(i) ? previous[i] : Array.from({ length: f.length }, (_, k) => text[k] || " "));
      });
      if (!keep) {
        dirty = new Set();
        cursor = (s.row - 1) * COLS + (s.col - 1);
      }
    }
    draw();
  }

  function cellClass(a) {
    const group = (a >> 3) & 3;
    let cls = "c" + group + ((a & 2) ? "h" : "");
    if ((a & 7) !== 7) {
      if (a & 1) cls += " rv";
      if (a & 4) cls += " u";
    }
    return cls;
  }

  function draw() {
    if (!screen) return;
    const attrs = screen.attrs;
    for (let i = 0; i < CELLS; i++) {
      const a = parseInt(attrs.substr(2 * i, 2), 16);
      const fi = fieldAt[i];
      let ch = screen.rows[(i / COLS) | 0][i % COLS] || " ";
      if (fi >= 0) {
        const f = screen.fields[fi];
        ch = f.hidden ? " " : buffers[fi][i - fieldStart(f)];
      }
      const s = spans[i];
      const cls = cellClass(a) + (i === cursor ? " cur" : "");
      if (s.className !== cls) s.className = cls;
      if (s.textContent !== ch) s.textContent = ch;
    }
    const locked = screen.inhibited || sentRecords === screen.records;
    el("lock").textContent = locked ? "X SYSTEM" : "";
    el("mode").textContent = insert ? "INSERT" : "";
    el("position").textContent = String(((cursor / COLS) | 0) + 1).padStart(2, "0") + "/" + String((cursor % COLS) + 1).padStart(2, "0");
    el("state").textContent = screen.status || "Ready";
  }

  const locked = () => !screen || screen.inhibited || sentRecords === screen.records;

  function inputFields() {
    return screen ? screen.fields.map((f, i) => [i, f]).filter(([, f]) => !f.bypass) : [];
  }

  function moveTo(cell) {
    cursor = ((cell % CELLS) + CELLS) % CELLS;
    draw();
  }

  function nextField(back) {
    const list = inputFields();
    if (!list.length) return;
    const starts = list.map(([, f]) => fieldStart(f));
    const cur = fieldAt[cursor];
    let pick;
    if (back) {
      const before = starts.filter((s) => s < cursor && !(cur >= 0 && s === fieldStart(screen.fields[cur])));
      pick = before.length ? before[before.length - 1] : starts[starts.length - 1];
    } else {
      const after = starts.filter((s) => s > cursor);
      pick = after.length ? after[0] : starts[0];
    }
    moveTo(pick);
  }

  function editable() {
    const fi = fieldAt[cursor];
    return fi >= 0 && !screen.fields[fi].bypass ? fi : -1;
  }

  function type(ch) {
    if (locked()) return;
    const fi = editable();
    if (fi < 0) return;
    const f = screen.fields[fi];
    const buf = buffers[fi];
    const pos = cursor - fieldStart(f);
    if (f.monocase) ch = ch.toUpperCase(); // as the display station translates
    if (insert) {
      if (buf[buf.length - 1] !== " ") return; // no room: keyboard error
      buf.splice(pos, 0, ch);
      buf.pop();
    } else {
      buf[pos] = ch;
    }
    dirty.add(fi);
    if (pos + 1 < f.length) moveTo(cursor + 1);
    else nextField(false);
  }

  function erase(back) {
    if (locked()) return;
    if (back) {
      // Within an editable field only; at a field's first position nothing happens.
      if (cursor === 0 || fieldAt[cursor - 1] < 0 || fieldAt[cursor - 1] !== fieldAt[cursor] && fieldAt[cursor] >= 0) return;
      moveTo(cursor - 1);
    }
    const fi = editable();
    if (fi < 0) return;
    const buf = buffers[fi];
    const pos = cursor - fieldStart(screen.fields[fi]);
    buf.splice(pos, 1);
    buf.push(" ");
    dirty.add(fi);
    draw();
  }

  function eraseToEnd() {
    const fi = editable();
    if (fi < 0 || locked()) return;
    const buf = buffers[fi];
    for (let k = cursor - fieldStart(screen.fields[fi]); k < buf.length; k++) buf[k] = " ";
    dirty.add(fi);
    draw();
  }

  async function send(key) {
    if (!screen) return;
    if (locked() && key !== "SYSREQ" && key !== "ATTN") return;
    const fields = {};
    for (const fi of dirty) fields[screen.fields[fi].index] = buffers[fi].join("").replace(/\s+$/, "");
    const body = { records: screen.records, fields, row: ((cursor / COLS) | 0) + 1, col: (cursor % COLS) + 1, key };
    if (key !== "SYSREQ" && key !== "ATTN") sentRecords = screen.records;
    draw();
    try {
      const r = await fetch("/api/input", { method: "POST", headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error(r.status + " " + (await r.text()));
    } catch (e) {
      sentRecords = -1;
      el("state").textContent = "Send failed: " + e.message;
    }
  }

  screenEl.addEventListener("keydown", (e) => {
    const k = e.key;
    let handled = true;
    if (/^F([1-9]|1[0-2])$/.test(k)) send("PF" + (Number(k.slice(1)) + (e.shiftKey ? 12 : 0)));
    else if (k === "Enter") send("ENTER");
    else if (k === "PageUp") send("ROLLDOWN");
    else if (k === "PageDown") send("ROLLUP");
    else if (k === "Escape") send("ATTN");
    else if (k === "Tab") nextField(e.shiftKey);
    else if (k === "ArrowLeft") moveTo(cursor - 1);
    else if (k === "ArrowRight") moveTo(cursor + 1);
    else if (k === "ArrowUp") moveTo(cursor - COLS);
    else if (k === "ArrowDown") moveTo(cursor + COLS);
    else if (k === "Home") { const list = inputFields(); if (list.length) moveTo(fieldStart(list[0][1])); }
    else if (k === "End" && e.ctrlKey) eraseToEnd();
    else if (k === "Backspace") erase(true);
    else if (k === "Delete") erase(false);
    else if (k === "Insert") { insert = !insert; draw(); }
    else if (k === "Control" && e.location === 2) reset(); // right Ctrl, as on PC5250
    else if (k.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) type(k);
    else handled = false;
    if (handled) e.preventDefault();
  });

  screenEl.addEventListener("paste", (e) => {
    const text = (e.clipboardData && e.clipboardData.getData("text")) || "";
    for (const ch of text.replace(/[\r\n]+/g, " ")) type(ch);
    e.preventDefault();
  });

  screenEl.addEventListener("mousedown", (e) => {
    const cell = e.target && e.target.dataset && e.target.dataset.cell;
    if (cell !== undefined) moveTo(Number(cell));
    screenEl.focus();
    e.preventDefault();
  });

  // Reset unlocks the keyboard locally, for example when the host never
  // answers an input.
  function reset() {
    sentRecords = -1;
    insert = false;
    draw();
  }

  document.getElementById("keys").addEventListener("click", (e) => {
    const key = e.target && e.target.dataset && e.target.dataset.key;
    if (key === "RESET") reset();
    else if (key) send(key);
    screenEl.focus();
  });

  async function poll() {
    for (;;) {
      try {
        const r = await fetch("/api/screen?after=" + version, { headers: auth });
        if (r.status === 403) { el("state").textContent = "Session token rejected; reopen the printed URL."; return; }
        if (r.status === 200) {
          const s = await r.json();
          version = s.version;
          if (sentRecords !== -1 && s.records !== sentRecords) sentRecords = -1;
          load(s);
        }
      } catch (e) {
        el("state").textContent = "Disconnected; retrying…";
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
  }

  screenEl.focus();
  poll();
})();
