# Security Policy

The MACK Zero-Trust Rust Starter Kit is an open-source Community Edition of
the MACK pattern, maintained by a single developer. Security reports are
welcome and read personally by the maintainer.

## Reporting a vulnerability

Report privately by email: **a95674127@gmail.com**

Please include a description of the issue, the component involved
(default-deny token policy, SHA-256 fingerprints, the hash-chained audit
log, or the Axum API), steps to reproduce or a proof of concept, and the
version or commit you tested against.

Please do **not** open a public issue or post details publicly before
contacting the maintainer.

## What to expect

- **Acknowledgment:** within 5 business days. This is a solo-maintained
  project; every report is read by the maintainer personally.
- **Triage:** confirmed issues are fixed in priority order.
- **Disclosure:** coordinated disclosure is requested — please allow up to
  90 days for a fix before public disclosure. Reporters are credited in the
  release notes with their permission.

## Safe harbor

Good-faith security research conducted under this policy is authorized.
The maintainer will not pursue or support legal action against researchers
who, in good faith, test only against their own instance, avoid privacy
violations, data destruction, and service degradation, and give the
maintainer reasonable time to respond before disclosing.

## Scope

**In scope:** this repository's code — the token policy engine, fingerprint
verification, the tamper-evident audit log, and the HTTP API.

**Out of scope:**

- Vulnerabilities in third-party dependencies — please report those
  upstream.
- Social engineering, physical attacks, and denial-of-service testing.
- Reports generated without a working proof of concept or manual
  verification.

**Known design limits (documented, not vulnerabilities):** the audit log's
hash chain is unkeyed — it is tamper-evident, not tamper-proof. Tail
truncation and whole-chain rewrites are not detectable from the chain alone;
compare the chain tip against a value held outside the chain. See
`THREAT_MODEL.md` for the full model.

## Supported versions

| Version | Supported |
|---|---|
| v0.1.0 — Community Edition | Yes |
| Earlier / unreleased | Best effort |

— Allen Mack, AI Infinity Force One (sole proprietor)
