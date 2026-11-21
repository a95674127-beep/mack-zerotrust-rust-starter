# Changelog

All notable changes to the MACK Zero-Trust Rust Starter Kit (Community Edition) are recorded here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [0.1.0] — 2026-11-21

Initial open-source release of the Community Edition.

### Added

- Default-deny token policy (non-empty, minimum length 16, strict character set, sample revocation list) with a named reason for every denial.
- SHA-256 token fingerprinting — raw tokens are never stored or logged.
- Hash-chained audit log with `verify_chain`, plus a tamper laboratory: six mutation cases (modify, delete, reorder, insert, replay, corrupt) proven detected.
- HTTP API, loopback only: `GET /health` and `POST /v1/verify` (Tokio + Axum).
- End-to-end API tests that boot the real server and speak raw HTTP — 22 tests in total.
- `THREAT_MODEL.md`, `SECURITY.md`, `SBOM.md`, `CONTRIBUTING.md`, and a worked `examples/` quickstart.

### Known limitations (pinned as tests, stated on purpose)

- The audit chain is **unkeyed**: a whole-history rewrite can recompute valid links. The chain is tamper-evident against partial edits, not tamper-proof against a full rewrite. External anchoring of the chain tip is the countermeasure and is out of scope for this kit.
- **Tail truncation** leaves an internally valid prefix; detection requires comparing the tip or length against a value recorded outside the chain.
