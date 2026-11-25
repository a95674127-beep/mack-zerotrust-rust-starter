//! Library-level token verification — the same default-deny policy the
//! HTTP endpoint runs, used directly without a server.
//!
//! Run it:
//!
//! ```bash
//! cargo run --example verify_token
//! ```
//!
//! Every token is fingerprinted (SHA-256) before evaluation; the raw
//! token is never stored or logged. Any rule failure denies, with a
//! named reason.

use mack_zerotrust_rust_starter::policy::{evaluate, fingerprint};

fn main() {
    let tokens = [
        "sample_local_token",      // the README sample — verifies
        "abc",                     // too short
        "token with spaces!!",     // invalid characters
        "revoked_demo_token_0001", // on the sample revocation list
    ];
    for token in tokens {
        let fp = fingerprint(token);
        let verdict = evaluate(token, &fp);
        println!(
            "token {token:?}\n  fingerprint: {fp}\n  allowed: {} (reason: {})\n",
            verdict.allowed, verdict.reason
        );
    }
}
