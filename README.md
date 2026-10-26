# 🛡️ MACK Zero-Trust Rust Starter Kit

> **Stop rebuilding auth from scratch.** A small, local-first zero-trust verification core in Rust — default-deny token policy, SHA-256 fingerprints, and a tamper-evident, hash-chained audit log. Community Edition.

![Rust](https://img.shields.io/badge/Language-Rust-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## What this actually is

A working starter core — not the full MACK vault, and it doesn't pretend to be. It gives you the pattern the MACK stack is built on, in a form you can read in one sitting:

- **Default-deny policy:** a token verifies only if it passes every rule — non-empty, minimum length (16), strict character set (`A–Z a–z 0–9 _ -`), and not on the revocation list. Any failure denies, with a named reason.
- **Fingerprinting:** tokens are never stored or logged. Only their SHA-256 fingerprint travels with the verdict.
- **Hash-chained audit log:** every verification appends an entry whose hash binds it to the entry before it. Edit, drop, or reorder history and the chain no longer verifies.
- **Local-first:** binds to `127.0.0.1` only. No external calls, no telemetry, no third-party identity round-trips.

Built on **Tokio + Axum**. Dependencies are deliberately few: tokio, axum, serde, serde_json, sha2.

---

## 🚀 Quickstart (Community Edition)

```bash
git clone https://github.com/a95674127-beep/mack-zerotrust-rust-starter.git
cd mack-zerotrust-rust-starter
cargo run
```

Verify a token:

```bash
curl -X POST http://127.0.0.1:8080/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "sample_local_token"}'
```

Actual response from a fresh server (first request it ever served):

```json
{
  "verified": true,
  "reason": "ok",
  "fingerprint": "e8a3898005271e68147308eee949b8a9fe7e7c7d0cdf250eff51312961d63512",
  "audit_entries": 1,
  "audit_tip": "37ca21f930844a97524191ebf020d95e97f3de15421e336a9be164b0cbe1ee8a"
}
```

Try a denied one — same endpoint, token `abc` — the verdict flips, the reason names the failed rule, and the audit chain still grows (denials are audited too):

```json
{
  "verified": false,
  "reason": "token_too_short",
  "fingerprint": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "audit_entries": 2,
  "audit_tip": "ed24488e9772360376d6c0a1201ebe3b26535e1d4196acb76bb5c7a3bca6c08f"
}
```

Health check: `GET http://127.0.0.1:8080/health`

Run the tests (policy unit tests, audit-chain tamper tests, and live HTTP tests against a spawned server):

```bash
cargo test
```

---

## 💎 Community Edition vs. Pro Kit

The Community Edition in this repo is complete and free. The Pro Kit is **in development — it is not for sale yet**, and there is no buy link until it exists.

| Feature | Community (Free) | Pro Kit |
| :--- | :---: | :---: |
| **Core zero-trust verification (default-deny)** | ✅ | ✅ |
| **SHA-256 hash-chained audit log** | ✅ | ✅ |
| **Production middleware integration** | ❌ (standalone node) | In development |
| **Local credential persistence (VaultLane integration)** | ❌ | In development |
| **Docker & systemd production templates** | ❌ | In development |
| **Multi-tenant policy engine (RBAC/ABAC)** | ❌ | In development |

---

## 🔒 Security notes

- The audit chain is tamper-**evident**, not tamper-proof: it detects edited history; it does not stop someone with write access from rewriting the whole chain. That distinction matters and is stated on purpose.
- The revocation list ships with one sample entry so the mechanism is visible; a production deployment loads its own.
- CI uses **only GitHub-owned actions** (`actions/checkout`) plus the runner's preinstalled Rust toolchain — no third-party actions, per the AI Infinity Force One Actions policy.

To report security issues, contact: **AI Infinity Force One Security Team**.

---

## 📜 License

MIT — see [LICENSE](LICENSE). The full MACK stack this starter is drawn from remains proprietary to AI Infinity Force One; this Community core is the free, open sample of the pattern.
