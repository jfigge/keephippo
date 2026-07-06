// Feature catalogue for features.html. Rendered client-side, no framework.
const GROUPS = [
  {
    title: "Secrets engines",
    items: [
      { name: "KV v1", tag: "kv", desc: "Simple unversioned key/value storage at any path." },
      { name: "KV v2", tag: "kv", desc: "Versioned key/value: history, soft-delete, undelete, destroy, check-and-set, max-versions." },
      { name: "Transit", tag: "crypto", desc: "Encryption-as-a-service: encrypt/decrypt/rewrap, sign/verify, HMAC, datakeys, and key rotation across aes256-gcm96, chacha20-poly1305, ed25519 and ecdsa-p256." },
      { name: "TOTP", tag: "otp", desc: "RFC 6238 time-based one-time passwords: generate or import keys, produce and validate codes." },
      { name: "Cubbyhole", tag: "token", desc: "A per-token private store, auto-mounted and destroyed when the token is revoked." },
    ],
  },
  {
    title: "Auth methods",
    items: [
      { name: "Token", tag: "built-in", desc: "Create, look up, renew, and revoke tokens with policies, TTLs, accessors, and use limits." },
      { name: "Userpass", tag: "login", desc: "Username + bcrypt-hashed password login issuing a policy-scoped token." },
      { name: "AppRole", tag: "machine", desc: "role_id + secret_id machine credentials with constant-time comparison and secret_id TTL/use limits." },
      { name: "TLS cert", tag: "mTLS", desc: "Authenticate by presenting a client certificate that matches a trusted cert or CA." },
    ],
  },
  {
    title: "Access control & identity",
    items: [
      { name: "ACL policies", tag: "hcl", desc: "HCL policies granting read/create/update/delete/list/sudo on path patterns; default-deny." },
      { name: "Identity", tag: "entity", desc: "Entities, groups, and aliases that map logins from different auth methods to one identity and resolve group policies." },
      { name: "Leases", tag: "lifecycle", desc: "A first-class expiration manager with background auto-revocation and sys/leases lookup/renew/revoke/revoke-prefix." },
    ],
  },
  {
    title: "Operations & security",
    items: [
      { name: "Seal / unseal", tag: "shamir", desc: "Shamir key shares protect the root key; the server starts sealed and unseals with a threshold of shares." },
      { name: "Auto-unseal", tag: "transit seal", desc: "Unseal automatically on boot from another transit engine — no manual key entry." },
      { name: "Audit devices", tag: "fail-closed", desc: "File and syslog devices log every request with secrets HMAC-obscured; requests fail closed if auditing fails." },
      { name: "Response wrapping", tag: "single-use", desc: "Wrap any response into a single-use token (X-Vault-Wrap-TTL) that unwraps exactly once." },
    ],
  },
  {
    title: "Interfaces",
    items: [
      { name: "CLI", tag: "keephippo", desc: "A full command-line client to Vault parity, with --format=json and Vault-style exit codes." },
      { name: "Web console", tag: "/ui", desc: "An embedded browser UI with login/unseal, mount and policy management, and an in-browser interactive console." },
      { name: "Wire compatibility", tag: "/v1/*", desc: "The /v1/ path model, X-Vault-Token header, port 8200, VAULT_ADDR/VAULT_TOKEN, and the standard JSON envelope." },
    ],
  },
];

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const root = document.getElementById("features");
for (const g of GROUPS) {
  const h = document.createElement("h2");
  h.textContent = g.title;
  h.style.marginTop = "40px";
  root.append(h);
  const grid = document.createElement("div");
  grid.className = "grid";
  for (const it of g.items) {
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `<h3>${esc(it.name)} <span class="tag">${esc(it.tag)}</span></h3><p>${esc(it.desc)}</p>`;
    grid.append(card);
  }
  root.append(grid);
}
