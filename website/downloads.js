// Renders the downloads section from the generated /versions.json, which the
// deploy workflow builds from the GitHub Releases API.
const OS_LABELS = { darwin: "macOS", linux: "Linux", windows: "Windows" };
const OS_ORDER = ["darwin", "linux", "windows"];

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

async function render() {
  const root = document.getElementById("downloads");
  let data;
  try {
    const res = await fetch("/versions.json", { cache: "no-store" });
    data = await res.json();
  } catch (_) {
    data = null;
  }

  if (!data || !data.latest || !Array.isArray(data.assets) || data.assets.length === 0) {
    root.innerHTML = `
      <div class="warn">No published release yet. Build the current <code>main</code> from source:</div>
      <pre class="code"><span class="p">$</span> git clone https://github.com/jfigge/keephippo
<span class="p">$</span> cd keephippo &amp;&amp; make build
<span class="p">$</span> ./build/keephippo version</pre>
      <p class="muted">Binaries will appear here automatically once the first
        <a href="https://github.com/jfigge/keephippo/releases">GitHub Release</a> is published.</p>`;
    return;
  }

  const rel = esc(data.latest);
  const relURL = esc(data.release_url || `https://github.com/jfigge/keephippo/releases/tag/${data.latest}`);
  let html = `<p class="muted">Latest release: <a href="${relURL}"><strong>${rel}</strong></a></p>`;

  // Package-manager / container install (if provided).
  if (data.install) {
    const rows = [];
    if (data.install.brew) rows.push(["Homebrew", data.install.brew]);
    if (data.install.scoop) rows.push(["Scoop (Windows)", data.install.scoop]);
    if (data.install.container) rows.push(["Container", data.install.container]);
    if (rows.length) {
      html += `<h2 style="margin-top:28px">Install</h2>`;
      for (const [label, cmd] of rows) {
        html += `<p class="muted" style="margin:14px 0 4px">${esc(label)}</p><pre class="code"><span class="p">$</span> ${esc(cmd)}</pre>`;
      }
    }
  }

  // Raw binaries grouped by OS.
  html += `<h2 style="margin-top:28px">Binaries</h2><div class="dl-grid">`;
  const byOS = {};
  for (const a of data.assets) (byOS[a.os] ||= []).push(a);
  for (const os of OS_ORDER) {
    const list = byOS[os];
    if (!list) continue;
    html += `<div class="dl"><div class="os">${esc(OS_LABELS[os] || os)}</div><h4>${rel}</h4>`;
    for (const a of list.sort((x, y) => x.arch.localeCompare(y.arch))) {
      html += `<a href="${esc(a.url)}">${esc(a.arch)} — ${esc(a.name)}</a>`;
    }
    html += `</div>`;
  }
  html += `</div>`;
  html += `<p class="muted" style="margin-top:18px">All assets are attached to the <a href="${relURL}">${rel} release</a>. Verify checksums against the release's <code>checksums.txt</code>.</p>`;
  root.innerHTML = html;
}

render();
