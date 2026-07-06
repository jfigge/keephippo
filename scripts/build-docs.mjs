// Converts docs/USER_GUIDE.md (Phase 10) into the hosted guide under
// website/docs/: an index plus one page per top-level section, styled to match
// the site, with the collapsible <details> option/example blocks intact and the
// 900x562 images copied across. Requires `marked`.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const guidePath = join(root, "docs", "USER_GUIDE.md");
const imgSrcDir = join(root, "docs", "images");
const outDir = join(root, "website", "docs");
const outImgDir = join(outDir, "images");

marked.setOptions({ gfm: true, headerIds: true, mangle: false });

const GH = "https://github.com/jfigge/keephippo/blob/main";

function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9 -]/g, "").trim().replace(/\s+/g, "-");
}

function rewriteRepoLinks(md) {
  return md
    .replaceAll("](../README.md)", `](${GH}/README.md)`)
    .replaceAll("](../SECURITY.md)", `](${GH}/SECURITY.md)`)
    .replaceAll("](API_COMPAT.md)", `](${GH}/docs/API_COMPAT.md)`)
    .replaceAll("](ARCHITECTURE.md)", `](${GH}/docs/ARCHITECTURE.md)`);
}

function page({ title, nav, body }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — keephippo docs</title>
  <meta name="description" content="keephippo user guide: ${title}.">
  <link rel="icon" type="image/png" sizes="32x32" href="/icons/32x32.png">
  <link rel="apple-touch-icon" href="/icons/256x256.png">
  <meta property="og:title" content="${title} — keephippo docs">
  <meta property="og:image" content="https://keephippo.com/og-image.png">
  <link rel="stylesheet" href="/site.css">
  <link rel="stylesheet" href="/docs/docs.css">
</head>
<body>
  <header class="site"><div class="wrap bar">
    <a class="brand" href="/"><img src="/icons/64x64.png" alt=""> keephippo</a>
    <nav>
      <a href="/features.html">Features</a>
      <a href="/docs/">Docs</a>
      <a href="/downloads.html">Downloads</a>
      <a href="/vs-vault.html" class="hide-sm">vs. Vault</a>
      <a href="https://github.com/jfigge/keephippo">GitHub</a>
      <a href="https://github.com/sponsors/jfigge" class="btn ghost">Sponsor</a>
    </nav>
  </div></header>
  <div class="docs-wrap">
    <aside class="docs-nav"><h4>User guide</h4>${nav}</aside>
    <main class="docs-body">${body}</main>
  </div>
  <footer class="site"><div class="wrap">
    <p class="fine">© 2026 keephippo · <a href="https://github.com/jfigge/keephippo">Source</a> · <a href="/privacy.html">Privacy</a> · MPL-2.0</p>
  </div></footer>
</body>
</html>
`;
}

const DOCS_CSS = `.docs-wrap { max-width: 1180px; margin: 0 auto; display: flex; gap: 32px; padding: 24px 20px 60px; }
.docs-nav { width: 220px; flex: 0 0 220px; position: sticky; top: 80px; align-self: flex-start; max-height: calc(100vh - 100px); overflow: auto; }
.docs-nav h4 { color: var(--muted); text-transform: uppercase; font-size: 12px; letter-spacing: .06em; margin: 0 0 10px; }
.docs-nav a { display: block; color: var(--muted); padding: 5px 10px; border-radius: 7px; font-size: 14px; }
.docs-nav a:hover { background: var(--panel-2); color: var(--text); text-decoration: none; }
.docs-nav a.active { background: var(--panel-2); color: var(--text); }
.docs-body { flex: 1; min-width: 0; }
.docs-body h1 { margin-top: 0; }
.docs-body h3, .docs-body h4 { margin-top: 28px; }
.docs-body h3 code, .docs-body h4 code { background: var(--panel-2); padding: 2px 8px; border-radius: 6px; font-size: .9em; }
.docs-body pre { background: var(--bg-2); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; overflow-x: auto; font-size: 13px; }
.docs-body code { font-family: var(--mono); }
.docs-body table { width: 100%; border-collapse: collapse; margin: 12px 0; }
.docs-body th, .docs-body td { border: 1px solid var(--border); padding: 7px 10px; text-align: left; font-size: 14px; }
.docs-body th { background: var(--panel-2); color: var(--muted); }
.docs-body details { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 8px 14px; margin: 10px 0; }
.docs-body summary { cursor: pointer; color: var(--accent); font-weight: 600; }
.docs-body img { border: 1px solid var(--border); border-radius: 10px; margin: 12px 0; }
.docs-body blockquote { border-left: 3px solid #4a3a1c; background: #2a1f12; color: #ffcf87; margin: 16px 0; padding: 10px 16px; border-radius: 0 8px 8px 0; }
@media (max-width: 820px) { .docs-wrap { flex-direction: column; } .docs-nav { position: static; width: auto; flex: none; } }
`;

function main() {
  const raw = rewriteRepoLinks(readFileSync(guidePath, "utf8"));
  const title = (raw.match(/^# (.+)/m) || [])[1] || "keephippo user guide";

  // Split into the intro (before the first "## ") and the "## " sections.
  const firstH2 = raw.indexOf("\n## ");
  const intro = raw.slice(0, firstH2);
  const rest = raw.slice(firstH2 + 1);
  const rawSections = rest.split(/\n(?=## )/);

  const sections = rawSections
    .map((s) => ({ heading: (s.match(/^## (.+)/) || [])[1], md: s }))
    .filter((s) => s.heading && s.heading.toLowerCase() !== "table of contents")
    .map((s) => ({ ...s, slug: slugify(s.heading) }));

  const navFor = (active) =>
    `<a href="/docs/"${active === "index" ? ' class="active"' : ""}>Overview</a>` +
    sections
      .map((s) => `<a href="/docs/${s.slug}.html"${active === s.slug ? ' class="active"' : ""}>${s.heading}</a>`)
      .join("");

  mkdirSync(outImgDir, { recursive: true });
  writeFileSync(join(outDir, "docs.css"), DOCS_CSS);

  // Index: the intro prose + a contents list.
  const contents =
    "<h2>Contents</h2><ul>" +
    sections.map((s) => `<li><a href="/docs/${s.slug}.html">${s.heading}</a></li>`).join("") +
    "</ul>";
  writeFileSync(
    join(outDir, "index.html"),
    page({ title, nav: navFor("index"), body: marked.parse(intro) + contents }),
  );

  // One page per section.
  for (const s of sections) {
    writeFileSync(
      join(outDir, `${s.slug}.html`),
      page({ title: s.heading, nav: navFor(s.slug), body: marked.parse(s.md) }),
    );
  }

  // Copy the 900x562 images.
  let copied = 0;
  for (const f of readdirSync(imgSrcDir)) {
    if (f.endsWith(".png")) {
      copyFileSync(join(imgSrcDir, f), join(outImgDir, f));
      copied++;
    }
  }

  console.log(`docs: ${sections.length + 1} pages, ${copied} images -> website/docs/`);
}

main();
