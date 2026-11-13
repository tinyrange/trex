"use strict";
// Launcher page: lists systems, starts and stops them, and links to their
// consoles. Polls the system list once a second.
(() => {
  const token = location.hash.slice(1);
  const list = document.getElementById("systems");
  const cards = new Map();
  const headers = { Authorization: "Bearer " + token };

  function card(name) {
    if (cards.has(name)) return cards.get(name);
    const el = document.getElementById("card").content.firstElementChild.cloneNode(true);
    const q = (s) => el.querySelector(s);
    const c = { el, q, busy: false };
    q(".start").addEventListener("click", () => {
      const from = q(".from").value;
      act(name, from ? `start?snapshot=${encodeURIComponent(from)}` : "start", c);
    });
    q(".stop").addEventListener("click", () => act(name, "stop", c));
    q(".saveStop").addEventListener("click", () => act(name, "stop?save=1", c));
    list.appendChild(el);
    cards.set(name, c);
    return c;
  }

  async function act(name, action, c) {
    c.busy = true;
    for (const b of c.el.querySelectorAll("button")) b.disabled = true;
    try {
      const r = await fetch(`api/systems/${encodeURIComponent(name)}/${action}`, { method: "POST", headers });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        c.q(".error").textContent = d.error || `HTTP ${r.status}`;
      }
    } catch (err) {
      c.q(".error").textContent = err.message;
    } finally {
      c.busy = false;
      refresh();
    }
  }

  function render(s) {
    const c = card(s.name), q = c.q;
    q(".title").textContent = s.title || s.name;
    q(".desc").textContent = s.description || "";
    const state = q(".state");
    state.textContent = s.state;
    state.className = "state " + s.state;
    q(".tnRow").hidden = !s.tn3270;
    q(".tn").textContent = s.tn3270 || "";
    q(".sinceRow").hidden = !s.since;
    q(".since").textContent = s.since ? new Date(s.since).toLocaleString() : "";
    q(".saveRow").hidden = !s.saves;
    q(".saved").textContent = s.hasState ? "yes: Start resumes it" : "none yet";
    if (!c.busy) q(".error").textContent = s.error || "";
    const running = s.state === "running", idle = s.state === "stopped" || s.state === "failed";
    q(".start").hidden = !idle;
    q(".start").textContent = s.hasState ? "Resume" : "Start";
    const from = q(".from");
    const names = s.snapshots || [];
    from.hidden = !idle || names.length === 0;
    const want = ["", ...names].join("\n");
    if (from.dataset.names !== want) {
      const keep = from.value;
      from.replaceChildren();
      const first = document.createElement("option");
      first.value = "";
      first.textContent = s.hasState ? "from where it stopped" : "fresh";
      from.appendChild(first);
      for (const n of names) {
        const o = document.createElement("option");
        o.value = n;
        o.textContent = "from snapshot: " + n;
        from.appendChild(o);
      }
      from.dataset.names = want;
      if (names.includes(keep)) from.value = keep;
    }
    q(".stop").hidden = idle;
    q(".saveStop").hidden = !running || !s.saves;
    const open = q(".open");
    open.hidden = !running;
    open.href = `s/${encodeURIComponent(s.name)}/#${token}`;
    if (!c.busy) for (const b of c.el.querySelectorAll("button")) b.disabled = s.state === "stopping";
    const log = q(".log");
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 20;
    log.textContent = (s.log || []).join("\n");
    if (atBottom) log.scrollTop = log.scrollHeight;
    if (s.state === "starting") q(".logBox").open = true;
  }

  async function refresh() {
    try {
      const r = await fetch("api/systems", { headers });
      if (!r.ok) throw new Error(r.status === 403 ? "invalid session token" : `HTTP ${r.status}`);
      const d = await r.json();
      for (const s of d.systems) render(s);
      document.getElementById("note").textContent = "Start a system, then open its consoles here or connect a tn3270 client.";
    } catch (err) {
      document.getElementById("note").textContent = "Cannot reach the launcher: " + err.message;
    }
  }
  refresh();
  setInterval(refresh, 1000);
})();
