# Examples

## Rust library examples

Two runnable examples that use the kit as a library — no server needed:

- **`verify_token.rs`** — the default-deny policy used directly:
  fingerprint a token, evaluate it, get a named verdict. Shows one
  allowed token and three denials (too short, invalid characters,
  revoked).

  ```bash
  cargo run --example verify_token
  ```

- **`audit_checkpoint.rs`** — the hash-chained audit log plus its
  external checkpoint: record verifications, export a checkpoint as
  JSON, and compare chains against saved checkpoints (`Match`,
  `Rewritten`, and `Truncated` verdicts). Mutating a chain's history
  from outside is impossible (entries are private), so the truncation
  and rewrite attacks themselves are exercised by the in-module tests
  in `src/audit.rs` — run `cargo test`.

  ```bash
  cargo run --example audit_checkpoint
  ```

## quickstart.sh

A four-call tour of the verification API against a locally running server:

1. `GET /health` — liveness.
2. `POST /v1/verify` with the README sample token — expect `"verified":true`, `"reason":"ok"`.
3. The same call with a short token — expect `"verified":false`, `"reason":"token_too_short"`.
4. The same call with the sample revoked token — expect `"verified":false`, `"reason":"token_revoked"`.

Watch `audit_entries` in the responses: every verification, allowed or denied, extends the hash-chained audit log by one entry.

Run it:

```bash
cargo run &            # or run the server in another terminal
bash examples/quickstart.sh
```

Set `BASE` to point at a different host/port if you changed the bind address in your own fork.
