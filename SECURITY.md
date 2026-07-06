# Security Policy

keephippo is a secrets manager. We take security seriously — and we also want to
be honest about maturity.

> ⚠️ **keephippo has not been security-audited.** Until a release explicitly
> states otherwise, treat it as experimental and do not rely on it to protect
> production secrets.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Preferred: use GitHub's **[Private Vulnerability Reporting](https://github.com/jfigge/keephippo/security/advisories/new)**
(repository → Security → Report a vulnerability).

Alternatively, email **jason.figge@gmail.com** with:

- a description and impact assessment,
- steps to reproduce (a proof of concept if possible),
- the affected version / commit.

We aim to acknowledge within a few days and will coordinate a fix and a
disclosure timeline with you. Please allow a reasonable window before public
disclosure.

## Supported versions

While pre-1.0, only the latest release (and `main`) receives security fixes.

## Hardening posture

keephippo follows these rules (see the phase build prompts for detail):

- Never rolls its own crypto: AES-256-GCM, Shamir via a vetted library,
  HKDF/HMAC from `x/crypto`, randomness from `crypto/rand` only.
- Encrypts everything below the barrier; **sealed by default**.
- **Default-deny** ACLs; constant-time comparisons for tokens and secret-ids.
- **Audit-before-response, fail-closed.**
- CI runs `govulncheck` and CodeQL; dependencies are watched by Dependabot;
  releases are signed and checksummed.
