# Threat Model — MACK Zero-Trust Rust Starter Kit (Community Edition)

**Scope of this document:** the code in this repository and nothing else —
a small, local-first token-verification node (Tokio + Axum) with a
default-deny policy, SHA-256 token fingerprinting, and an in-memory,
SHA-256 hash-chained audit log. This is the Community Edition *pattern*
drawn from the MACK platform; it is not the full MACK platform, and this
model claims none of MACK's controls (no Landlock-confined workers, no
YARA-X scanning, no encrypted vault, no STIX export, no signed release
attestation for this kit).

Every statement below traces to this repo's code or README.

## Assets

| Asset | Why it matters |
|---|---|
| Verdict integrity | A caller acts on `verified: true/false`; a forged or flipped verdict defeats the node's only purpose. |
| Audit history integrity | The hash-chained log is the record of what was decided. Its guarantee is *tamper-evidence* — see Limitations. |
| Token confidentiality | Raw tokens must never be stored or logged; only SHA-256 fingerprints travel (`policy::fingerprint`). |
| Availability of the node | A wedged or panicked audit chain must not silently take verification down with it. |

## Components and trust boundaries

```
HTTP caller ──► Axum router (127.0.0.1:8080, main.rs)
                  ├─ GET  /health     — no state
                  └─ POST /v1/verify  — policy::evaluate (default-deny)
                                        └─► AuditChain behind Arc<Mutex<_>>
                                            (in-memory only; src/audit.rs)
```

- **The HTTP boundary is unauthenticated by design.** Anyone who can
  reach the port can request a verification. The node binds loopback
  (`127.0.0.1`) only; rebinding it to a network interface is an operator
  decision that changes this model (the caller population becomes the
  network).
- **The policy is structural, not an identity system.** `evaluate`
  checks shape: non-empty, ≥ 16 chars, `[A-Za-z0-9_-]`, and not on the
  sample revocation list. A well-shaped token "verifies" — there is no
  issuer, signature, expiry, or holder check. Treat a verdict as "this
  token passes the demo policy," never as "this caller is who they
  claim."
- **The audit chain lives in process memory.** It is not persisted;
  restarting the node starts a new chain from `GENESIS`. Anything that
  can write the process's memory (host compromise, a debugger, root)
  is outside the boundary — and unnecessary: see the rewrite limitation.

## Attacker model

In scope:
- A caller submitting crafted tokens (oversized, malformed, revoked,
  boundary lengths) to flip a verdict or crash the handler.
- An attacker who obtains a copy of recorded history (e.g. an exported
  entry list) and edits, deletes, reorders, inserts, or replays entries
  before presenting it as genuine.
- A fault (panic) while the audit lock is held, as an availability
  attack on later requests.

Out of scope:
- Root / host compromise; kernel attacks; physical access.
- Network attackers beyond the loopback boundary the binary sets
  (no TLS is provided or claimed; do not expose the port directly).
- Denial of service by request flooding — there is no rate limiting,
  quota, or request-size policy in this kit.
- Supply-chain attacks on the dependency graph (see `SBOM.md` for the
  locked inventory; auditing it is the operator's step).

## Controls, mapped to code

| Threat | Control | Where |
|---|---|---|
| Token accepted that should not be | Default-deny: every rule must pass; any failure returns a named denial reason; denials are audited too | `src/policy.rs` |
| Raw token leaks into logs/records | Only the SHA-256 fingerprint is stored in the chain or returned in the response | `policy::fingerprint`, `src/audit.rs` |
| Edited / deleted / reordered / inserted / replayed history | Each entry's hash binds index, previous hash, fingerprint, and verdict; `verify_chain()` recomputes every link | `src/audit.rs` — detection pinned by the tamper-lab tests in that module |
| Corrupted stored hash or `prev_hash` field | Same recomputation detects either | tamper-lab tests |
| Panic while the audit lock is held wedges the node | Mutex poison recovery (`into_inner()`), the MACK vault's ConcurrentLedger policy: keep serving with the chain as left | `src/lib.rs` |
| Revoked token accepted | Revocation check against the sample list by fingerprint | `policy::is_revoked` |

## Stated limitations (not bugs — the honest edges of the design)

1. **The chain is unkeyed.** Anyone who knows the (public) hash
   construction can rewrite history *and recompute every link*, and
   the forged chain verifies. Pinned by
   `limitation_whole_chain_rewrite_is_not_detected` so the property is
   never overstated. Countermeasure — an externally anchored tip —
   belongs to the full platform pattern, not this kit.
2. **Tail truncation is invisible to `verify_chain()` alone.** A
   shortened chain is an internally valid prefix; detection requires
   comparing `tip()`/`len()` against a value kept outside the chain.
   Pinned by `limitation_tail_truncation_is_not_detected`.
3. **Tamper-evident ≠ tamper-proof** (as the README states): the chain
   detects partial edits; it cannot prevent a rewrite by someone with
   write access to the history.
4. **No persistence, no multi-tenancy, no RBAC/ABAC, no rate
   limiting, no TLS, no production revocation store** — the revocation
   list is one sample entry so the mechanism is visible. These are Pro
   Kit / full-platform territory and are non-goals here.
5. **Structural policy only** (see Trust boundaries): passing shape
   rules is not authentication of a person or a system.

## Non-goals, restated

This kit demonstrates a pattern in one sitting of reading. It does not
protect a production deployment by itself, does not authenticate users,
does not encrypt anything at rest (there is nothing at rest), and makes
no claim about the security of the full MACK platform — whose record
stands on its own published, signed evidence.
