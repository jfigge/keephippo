// Generates website/versions.json from the GitHub Releases API so the Downloads
// page always tracks the latest published release. Runs with no npm dependencies
// (Node 18+ global fetch). If there is no release yet — or the API is
// unreachable — it writes a well-formed "no releases" file so the build still
// succeeds and the page shows the build-from-source fallback.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = "jfigge/keephippo";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outPath = join(root, "website", "versions.json");

function normArch(a) {
  if (!a) return "";
  a = a.toLowerCase();
  if (a === "x86_64") return "amd64";
  if (a === "aarch64") return "arm64";
  return a;
}

function parseAsset(name) {
  const os = (name.match(/(darwin|linux|windows|macos)/i) || [])[1];
  const arch = (name.match(/(amd64|arm64|x86_64|aarch64)/i) || [])[1];
  const norm = os ? (os.toLowerCase() === "macos" ? "darwin" : os.toLowerCase()) : "";
  return { os: norm, arch: normArch(arch) };
}

async function fetchLatest() {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "keephippo-site" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers });
  if (!res.ok) throw new Error(`releases API ${res.status}`);
  return res.json();
}

async function main() {
  let latest = null;
  let releaseURL = null;
  let assets = [];
  try {
    const rel = await fetchLatest();
    latest = rel.tag_name || null;
    releaseURL = rel.html_url || null;
    assets = (rel.assets || [])
      .map((a) => ({ ...parseAsset(a.name), name: a.name, url: a.browser_download_url }))
      .filter((a) => a.os && a.arch);
  } catch (err) {
    console.warn(`build-versions: no release resolved (${err.message}); writing fallback`);
  }

  const out = {
    generated: new Date().toISOString(),
    repo: REPO,
    latest,
    release_url: releaseURL,
    install: latest
      ? {
          brew: "brew install jfigge/tap/keephippo",
          scoop: "scoop install keephippo",
          container: `docker pull ghcr.io/jfigge/keephippo:${String(latest).replace(/^v/, "")}`,
        }
      : null,
    assets,
  };

  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
  console.log(`versions.json: latest=${latest || "(none)"} assets=${assets.length}`);
}

main();
