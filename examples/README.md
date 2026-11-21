# Examples

## quickstart.sh

A three-call tour of the verification API against a locally running server:

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
