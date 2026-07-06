"use strict";

// ---- state + helpers ----
let token = localStorage.getItem("kh_token") || "";
let version = "";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function setToken(t) {
  token = t || "";
  if (token) localStorage.setItem("kh_token", token);
  else localStorage.removeItem("kh_token");
}

// api issues a /v1/* request and returns {status, json, text}.
async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["X-Vault-Token"] = token;
  const opts = { method, headers };
  if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
  const res = await fetch("/v1/" + path.replace(/^\/+/, ""), opts);
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { /* non-JSON */ }
  return { status: res.status, json, text };
}

function errText(r) {
  if (r.json && r.json.errors && r.json.errors.length) return r.json.errors.join("; ");
  return r.text || ("HTTP " + r.status);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function parseKV(parts) {
  const data = {};
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i < 0) throw new Error("invalid key=value: " + p);
    data[p.slice(0, i)] = p.slice(i + 1);
  }
  return data;
}

// ---- boot / seal status ----
async function loadSealStatus() {
  const r = await api("GET", "sys/seal-status");
  const s = r.json || {};
  version = s.version || "";
  $("#login-version").textContent = version ? "version " + version : "";
  return s;
}

async function boot() {
  const s = await loadSealStatus();
  if (s.sealed) {
    showUnseal(s);
    showLogin();
    return;
  }
  if (token) {
    const r = await api("GET", "auth/token/lookup-self");
    if (r.status === 200) { showApp(); return; }
    setToken("");
  }
  showLogin();
}

function showUnseal(s) {
  $("#seal-banner").classList.remove("hidden");
  $("#seal-banner").textContent = "This server is sealed.";
  const box = $("#unseal-box");
  box.classList.remove("hidden");
  $("#unseal-progress").textContent =
    s.n ? `Unseal progress: ${s.progress || 0}/${s.t}` : "";
}

// ---- login screen ----
function showLogin() {
  $("#login").classList.remove("hidden");
  $("#app").classList.add("hidden");
}

function loginError(msg) {
  const e = $("#login-error");
  if (!msg) { e.classList.add("hidden"); return; }
  e.classList.remove("hidden");
  e.textContent = msg;
}

function wireLogin() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const m = tab.dataset.method;
      $$("#login-form .fields").forEach((f) =>
        f.classList.toggle("hidden", f.dataset.method !== m));
      $("#login-form").dataset.method = m;
    });
  });
  $("#login-form").dataset.method = "token";

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    loginError("");
    const f = ev.target;
    const method = f.dataset.method || "token";
    try {
      if (method === "token") {
        setToken(f.token.value.trim());
        const r = await api("GET", "auth/token/lookup-self");
        if (r.status !== 200) throw new Error("invalid token");
      } else if (method === "userpass") {
        const p = f.up_path.value.trim() || "userpass";
        const r = await api("POST", `auth/${p}/login/${encodeURIComponent(f.username.value.trim())}`,
          { password: f.password.value });
        if (!r.json || !r.json.auth) throw new Error(errText(r));
        setToken(r.json.auth.client_token);
      } else if (method === "approle") {
        const p = f.ar_path.value.trim() || "approle";
        const r = await api("POST", `auth/${p}/login`,
          { role_id: f.role_id.value.trim(), secret_id: f.secret_id.value.trim() });
        if (!r.json || !r.json.auth) throw new Error(errText(r));
        setToken(r.json.auth.client_token);
      }
      showApp();
    } catch (e) {
      setToken("");
      loginError(e.message);
    }
  });

  $("#unseal-btn").addEventListener("click", async () => {
    const key = $("#unseal-key").value.trim();
    if (!key) return;
    const r = await api("PUT", "sys/unseal", { key });
    if (r.json && r.json.sealed === false) { location.reload(); return; }
    if (r.json && r.json.sealed) {
      $("#unseal-progress").textContent = `Unseal progress: ${r.json.progress}/${r.json.t}`;
      $("#unseal-key").value = "";
    } else {
      $("#unseal-progress").textContent = errText(r);
    }
  });
}

// ---- app shell ----
async function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  const s = await loadSealStatus();
  const pill = $("#seal-pill");
  pill.textContent = s.sealed ? "sealed" : "unsealed";
  pill.className = "pill " + (s.sealed ? "sealed" : "unsealed");
  renderView("secrets");
}

function wireApp() {
  $$(".nav").forEach((n) =>
    n.addEventListener("click", () => {
      $$(".nav").forEach((x) => x.classList.remove("active"));
      n.classList.add("active");
      renderView(n.dataset.view);
    }));
  $("#logout-btn").addEventListener("click", () => { setToken(""); location.reload(); });
}

function renderView(view) {
  const main = $("#main");
  main.innerHTML = "";
  ({
    secrets: viewSecrets,
    policies: viewPolicies,
    tokens: viewTokens,
    leases: viewLeases,
    audit: viewAudit,
    console: viewConsole,
    about: viewAbout,
  }[view] || viewSecrets)(main);
}

function card(title, innerHTML) {
  const d = document.createElement("div");
  d.className = "card";
  d.innerHTML = (title ? `<h3>${esc(title)}</h3>` : "") + innerHTML;
  return d;
}

// ---- Secrets ----
async function viewSecrets(main) {
  const mounts = card("Secrets engines", `
    <div id="mounts"></div>
    <div class="row" style="margin-top:12px">
      <input id="m-path" placeholder="path (e.g. secret)" style="max-width:180px">
      <select id="m-type"><option value="kv">kv</option><option value="transit">transit</option><option value="totp">totp</option></select>
      <select id="m-ver"><option value="">v1</option><option value="2">v2</option></select>
      <button id="m-enable" class="small">Enable</button>
    </div>`);
  const io = card("Read / write a secret", `
    <label>Path</label><input id="s-path" placeholder="secret/hello">
    <div class="row" style="margin:10px 0">
      <button id="s-read" class="small">Read</button>
      <button id="s-write" class="small ghost">Write</button>
    </div>
    <div id="s-pairs" class="kv-pairs"></div>
    <button id="s-addpair" class="small ghost" style="margin-top:6px">+ field</button>
    <pre id="s-out" class="hidden"></pre>`);
  main.append(mounts, io);

  async function refreshMounts() {
    const r = await api("GET", "sys/mounts");
    const data = (r.json && r.json.data) || {};
    const rows = Object.keys(data).sort().map((p) =>
      `<tr><td>${esc(p)}</td><td>${esc(data[p].type)}</td><td>${esc((data[p].options && data[p].options.version) || "")}</td></tr>`).join("");
    $("#mounts").innerHTML = `<table><thead><tr><th>Path</th><th>Type</th><th>Version</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  refreshMounts();

  $("#m-enable").addEventListener("click", async () => {
    const path = $("#m-path").value.trim();
    if (!path) return;
    const body = { type: $("#m-type").value };
    if ($("#m-ver").value) body.options = { version: $("#m-ver").value };
    const r = await api("POST", "sys/mounts/" + path, body);
    if (r.status >= 400) alert(errText(r)); else refreshMounts();
  });

  function addPair(k = "", v = "") {
    const row = document.createElement("div");
    row.className = "kv-pair";
    row.innerHTML = `<input placeholder="key" value="${esc(k)}"><input placeholder="value" value="${esc(v)}"><button class="small ghost">–</button>`;
    row.querySelector("button").addEventListener("click", () => row.remove());
    $("#s-pairs").append(row);
  }
  addPair();
  $("#s-addpair").addEventListener("click", () => addPair());

  $("#s-read").addEventListener("click", async () => {
    const r = await api("GET", $("#s-path").value.trim());
    showOut(r);
  });
  $("#s-write").addEventListener("click", async () => {
    const data = {};
    $$("#s-pairs .kv-pair").forEach((row) => {
      const [k, v] = $$("input", row);
      if (k.value.trim()) data[k.value.trim()] = v.value;
    });
    const r = await api("PUT", $("#s-path").value.trim(), data);
    showOut(r);
  });
  function showOut(r) {
    const out = $("#s-out");
    out.classList.remove("hidden");
    out.textContent = r.text ? JSON.stringify(r.json, null, 2) : "HTTP " + r.status + " (no content)";
  }
}

// ---- Policies ----
async function viewPolicies(main) {
  const c = card("Policies (ACL)", `
    <div class="row">
      <select id="p-list" style="max-width:220px"></select>
      <button id="p-load" class="small">Load</button>
      <input id="p-name" placeholder="new policy name" style="max-width:200px">
    </div>
    <textarea id="p-body" rows="12" style="margin-top:12px;font-family:var(--mono)" placeholder='path "secret/*" { capabilities = ["read"] }'></textarea>
    <div class="row" style="margin-top:10px"><button id="p-save" class="small">Save</button><span id="p-msg" class="ok"></span></div>`);
  main.append(c);

  async function refresh() {
    const r = await api("LIST", "sys/policies/acl");
    const keys = (r.json && r.json.data && r.json.data.keys) || [];
    $("#p-list").innerHTML = keys.map((k) => `<option>${esc(k)}</option>`).join("");
  }
  refresh();
  $("#p-load").addEventListener("click", async () => {
    const name = $("#p-list").value;
    if (!name) return;
    $("#p-name").value = name;
    const r = await api("GET", "sys/policies/acl/" + name);
    $("#p-body").value = (r.json && r.json.data && r.json.data.policy) || "";
  });
  $("#p-save").addEventListener("click", async () => {
    const name = $("#p-name").value.trim();
    if (!name) { alert("policy name required"); return; }
    const r = await api("PUT", "sys/policies/acl/" + name, { policy: $("#p-body").value });
    if (r.status >= 400) { alert(errText(r)); return; }
    $("#p-msg").textContent = "saved";
    setTimeout(() => ($("#p-msg").textContent = ""), 1500);
    refresh();
  });
}

// ---- Tokens ----
async function viewTokens(main) {
  const c = card("Create a token", `
    <label>Policies (comma-separated)</label>
    <input id="t-pol" placeholder="default">
    <label style="margin-top:8px">TTL</label>
    <input id="t-ttl" placeholder="768h">
    <div class="row" style="margin-top:10px"><button id="t-create" class="small">Create</button></div>
    <pre id="t-out" class="hidden"></pre>`);
  const self = card("Your token", `<pre id="t-self">loading…</pre>`);
  main.append(c, self);
  const r = await api("GET", "auth/token/lookup-self");
  $("#t-self").textContent = JSON.stringify(r.json && r.json.data, null, 2);
  $("#t-create").addEventListener("click", async () => {
    const body = {};
    const pol = $("#t-pol").value.trim();
    if (pol) body.policies = pol.split(",").map((s) => s.trim());
    if ($("#t-ttl").value.trim()) body.ttl = $("#t-ttl").value.trim();
    const resp = await api("POST", "auth/token/create", body);
    const out = $("#t-out"); out.classList.remove("hidden");
    out.textContent = JSON.stringify(resp.json, null, 2);
  });
}

// ---- Leases ----
async function viewLeases(main) {
  const c = card("Token leases", `<div id="l-list">loading…</div>`);
  main.append(c);
  const r = await api("LIST", "sys/leases/lookup/auth/token/create/");
  const keys = (r.json && r.json.data && r.json.data.keys) || [];
  if (!keys.length) { $("#l-list").innerHTML = '<p class="muted">No active token leases.</p>'; return; }
  $("#l-list").innerHTML = "<table><thead><tr><th>Lease ID</th><th></th></tr></thead><tbody>" +
    keys.map((k) => {
      const id = "auth/token/create/" + k;
      return `<tr><td>${esc(id)}</td><td><button class="small ghost" data-id="${esc(id)}">Revoke</button></td></tr>`;
    }).join("") + "</tbody></table>";
  $$("#l-list button").forEach((b) => b.addEventListener("click", async () => {
    await api("POST", "sys/leases/revoke", { lease_id: b.dataset.id });
    viewLeases(main);
  }));
}

// ---- Audit ----
async function viewAudit(main) {
  const c = card("Audit devices", `<div id="a-list">loading…</div>`);
  main.append(c);
  const r = await api("GET", "sys/audit");
  const data = (r.json && r.json.data) || {};
  const keys = Object.keys(data);
  if (!keys.length) { $("#a-list").innerHTML = '<p class="muted">No audit devices enabled.</p>'; return; }
  $("#a-list").innerHTML = "<table><thead><tr><th>Path</th><th>Type</th><th>Options</th></tr></thead><tbody>" +
    keys.map((k) => `<tr><td>${esc(k)}</td><td>${esc(data[k].type)}</td><td><code>${esc(JSON.stringify(data[k].options || {}))}</code></td></tr>`).join("") +
    "</tbody></table>";
}

// ---- Console (REPL) ----
function viewConsole(main) {
  const c = document.createElement("div");
  c.className = "card console";
  c.innerHTML = `
    <h3>Interactive console</h3>
    <p class="muted">Commands: <code>read</code>, <code>write</code>, <code>list</code>, <code>delete</code>, <code>kv get|put</code>. e.g. <code>write secret/x a=b</code></p>
    <div id="console-out"></div>
    <div class="console-input"><span class="prompt">&gt;</span><input id="console-in" placeholder="write secret/x a=b" autocomplete="off"></div>`;
  main.append(c);
  const out = $("#console-out", c);
  const input = $("#console-in", c);
  input.focus();

  function print(html, cls) {
    const d = document.createElement("div");
    d.className = "console-line" + (cls ? " " + cls : "");
    d.innerHTML = html;
    out.append(d);
    out.scrollTop = out.scrollHeight;
  }

  input.addEventListener("keydown", async (ev) => {
    if (ev.key !== "Enter") return;
    const line = input.value.trim();
    if (!line) return;
    input.value = "";
    print("&gt; " + esc(line), "console-cmd");
    try {
      const r = await runCommand(line);
      print("<pre>" + esc(r.text ? JSON.stringify(r.json, null, 2) : "HTTP " + r.status + " (no content)") + "</pre>");
    } catch (e) {
      print('<span style="color:var(--danger)">' + esc(e.message) + "</span>");
    }
  });
}

// runCommand maps a keephippo/vault-style command to a /v1/* call.
async function runCommand(line) {
  const parts = line.split(/\s+/);
  let cmd = parts.shift();
  if (cmd === "kv") {
    const sub = parts.shift();
    if (sub === "get") cmd = "read";
    else if (sub === "put") cmd = "write";
    else throw new Error("kv: use 'kv get' or 'kv put'");
  }
  const path = parts.shift();
  if (!path && cmd !== "help") throw new Error("a path is required");
  switch (cmd) {
    case "read": return api("GET", path);
    case "list": return api("LIST", path);
    case "delete": return api("DELETE", path);
    case "write": return api("PUT", path, parseKV(parts));
    default: throw new Error("unknown command: " + cmd);
  }
}

// ---- About ----
function viewAbout(main) {
  const c = document.createElement("div");
  c.className = "card about";
  c.innerHTML = `
    <img src="/ui/icons/256x256.png" alt="keephippo" width="120" height="120">
    <div>
      <h2>keephippo</h2>
      <p class="muted">A from-scratch, Vault-compatible secrets manager.</p>
      <p>Version: <strong id="about-version">${esc(version || "…")}</strong></p>
      <p class="muted">The web console is just another client of the <code>/v1/*</code> API.</p>
    </div>`;
  main.append(c);
  if (!version) loadSealStatus().then(() => { const el = $("#about-version"); if (el) el.textContent = version; });
}

// ---- init ----
wireLogin();
wireApp();
boot();
