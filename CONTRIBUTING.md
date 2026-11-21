# Contributing

Thanks for looking. This is a small, deliberately scoped starter kit — contributions that keep it small, honest, and readable are the ones that fit.

## Ground rules

- **Scope.** This is the Community Edition starter. Production policy engines, persistence, and multi-tenant controls are Pro Kit territory and won't be merged here. Pull requests that grow the kit into a framework will be closed with thanks.
- **Honesty in docs and tests.** If a change alters a limitation, update the pinned limitation tests and the threat model in the same PR. Every claim in the README must match what `cargo test` proves.
- **No new dependencies without discussion.** The dependency list is deliberately short (tokio, axum, serde, serde_json, sha2). Open an issue first.

## Building and checking

```bash
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

All three must pass. CI runs exactly these commands.

## Reporting bugs

Open an issue with: what you ran, what you expected, what happened, and your `rustc --version`.

## Security issues

Don't open a public issue — see `SECURITY.md` for the private reporting address.

## License

By contributing, you agree that your contributions are licensed under the MIT License (see `LICENSE`).
