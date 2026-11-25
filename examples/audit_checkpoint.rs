//! The hash-chained audit log and its external checkpoint countermeasure.
//!
//! Run it:
//!
//! ```bash
//! cargo run --example audit_checkpoint
//! ```
//!
//! Flow: verify a few tokens, append each fingerprint + verdict to an
//! `AuditChain`, take a `Checkpoint` (length + tip as JSON — the part
//! you store somewhere the chain cannot reach), then compare the chain
//! against saved checkpoints to obtain a `CheckpointVerdict`.
//!
//! What this example cannot show: chopping entries off the end of a
//! chain. `AuditChain`'s entries are private, so outside code cannot
//! mutate history at all — the truncation and whole-chain-rewrite
//! attacks, and the checkpoint catching both, are exercised by the
//! in-module tests in `src/audit.rs` (`cargo test`). Here, a checkpoint
//! taken from a *different* history stands in for the rewrite case, and
//! a short chain compared against a longer checkpoint stands in for
//! the truncation case.

use mack_zerotrust_rust_starter::audit::{AuditChain, Checkpoint, CheckpointVerdict};
use mack_zerotrust_rust_starter::policy::{evaluate, fingerprint};

/// Verify one token and record the outcome in the chain.
fn record(chain: &mut AuditChain, token: &str) {
    let fp = fingerprint(token);
    let verdict = evaluate(token, &fp);
    chain.append(&fp, verdict.allowed);
}

fn main() {
    // Build a short history: two allowed, one denied (denials are
    // audited too).
    let mut chain = AuditChain::new();
    record(&mut chain, "sample_local_token");
    record(&mut chain, "another_sample_token");
    record(&mut chain, "abc");

    println!("entries: {}", chain.len());
    println!("tip: {}", chain.tip());
    println!("chain verifies internally: {}", chain.verify_chain());

    // Take a checkpoint and round-trip it through JSON — the form in
    // which you would store it outside this process.
    let saved = chain.checkpoint();
    let json = saved.to_json();
    println!("checkpoint JSON: {json}");
    let restored = Checkpoint::from_json(&json).expect("checkpoint JSON parses");
    println!(
        "verdict vs its own checkpoint: {:?}",
        chain.verify_checkpoint(&restored)
    );

    // Growth is not tampering: appends after the checkpoint still match.
    record(&mut chain, "a_third_sample_token");
    println!(
        "verdict after the chain grew: {:?}",
        chain.verify_checkpoint(&restored)
    );

    // A checkpoint anchored to a DIFFERENT history does not match this
    // chain's entry at the anchored length — the `Rewritten` verdict a
    // whole-chain rewrite produces.
    let mut other_history = AuditChain::new();
    record(&mut other_history, "a_different_token_1");
    let foreign = other_history.checkpoint();
    println!(
        "verdict vs a foreign checkpoint: {:?}",
        chain.verify_checkpoint(&foreign)
    );

    // A chain shorter than its checkpoint has lost entries from the
    // end — `Truncated`, invisible to `verify_chain` alone.
    let short_chain = AuditChain::new();
    println!(
        "empty chain vs the saved checkpoint: {:?} (expected {:?})",
        short_chain.verify_checkpoint(&restored),
        CheckpointVerdict::Truncated
    );
}
