//! SHA-256 hash-chained audit log.
//!
//! Every entry binds its own contents to the hash of the entry before
//! it, so editing, deleting, or reordering history breaks the chain and
//! is detectable by `verify_chain`. Only token fingerprints are stored —
//! never raw tokens.

use serde::{Deserialize, Serialize};

use crate::sha256_hex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub index: u64,
    pub prev_hash: String,
    pub fingerprint: String,
    pub allowed: bool,
    pub hash: String,
}

fn entry_hash(index: u64, prev_hash: &str, fingerprint: &str, allowed: bool) -> String {
    sha256_hex(format!("{index}|{prev_hash}|{fingerprint}|{allowed}").as_bytes())
}

/// An external anchor for the audit chain: its length and tip hash at
/// a moment in time, serialized as JSON so it can be stored somewhere
/// the chain itself cannot reach — another machine, a signed release
/// note, a different trust domain.
///
/// The chain alone cannot detect tail truncation or a whole-chain
/// rewrite (see the `limitation_*` tests). A checkpoint can — but only
/// if the checkpoint itself is kept out of the attacker's hands. A
/// checkpoint stored next to the chain, writable by the same attacker,
/// anchors nothing: they would rewrite it along with the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Number of entries in the chain when the checkpoint was taken.
    pub length: u64,
    /// Hash of the last entry at that moment ("GENESIS" when empty).
    pub tip: String,
}

impl Checkpoint {
    /// Serialize as JSON, e.g. `{"length":3,"tip":"<64 hex chars>"}`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("checkpoint serialization cannot fail")
    }

    /// Parse a checkpoint previously produced by `to_json`.
    pub fn from_json(s: &str) -> Option<Checkpoint> {
        serde_json::from_str(s).ok()
    }
}

/// The outcome of comparing a chain against a stored `Checkpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// The chain is internally valid and its entry at the checkpoint's
    /// length still hashes to the checkpoint's tip. The chain may have
    /// grown since the checkpoint; growth is not tampering.
    Match,
    /// The chain is now SHORTER than the checkpoint: entries were cut
    /// off the end. Invisible to `verify_chain` alone — the surviving
    /// prefix is internally valid — and exactly what the checkpoint
    /// exists to catch.
    Truncated,
    /// The chain is at least as long as the checkpoint, but the entry
    /// at the checkpoint's length no longer hashes to the checkpoint's
    /// tip: the recorded history up to that point is a different
    /// history than the one the checkpoint anchored — e.g. a
    /// whole-chain rewrite with every link recomputed.
    Rewritten,
    /// The anchored prefix matches, but the chain as it now stands
    /// fails `verify_chain`: entries were altered without recomputing
    /// the links.
    ChainInvalid,
}

#[derive(Debug, Default)]
pub struct AuditChain {
    entries: Vec<Entry>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Hash of the latest entry, or the genesis marker when empty.
    pub fn tip(&self) -> &str {
        self.entries
            .last()
            .map(|e| e.hash.as_str())
            .unwrap_or("GENESIS")
    }

    pub fn append(&mut self, fingerprint: &str, allowed: bool) -> &Entry {
        let index = self.entries.len() as u64;
        let prev_hash = self.tip().to_string();
        let hash = entry_hash(index, &prev_hash, fingerprint, allowed);
        self.entries.push(Entry {
            index,
            prev_hash,
            fingerprint: fingerprint.to_string(),
            allowed,
            hash,
        });
        self.entries.last().expect("just pushed")
    }

    /// Recompute every link; false means the recorded history was altered.
    pub fn verify_chain(&self) -> bool {
        let mut prev = "GENESIS".to_string();
        for (i, e) in self.entries.iter().enumerate() {
            if e.index != i as u64 || e.prev_hash != prev {
                return false;
            }
            if e.hash != entry_hash(e.index, &e.prev_hash, &e.fingerprint, e.allowed) {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }

    /// Take a checkpoint of the chain as it stands: its length and tip,
    /// ready to be stored outside the chain (see `Checkpoint`).
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            length: self.len() as u64,
            tip: self.tip().to_string(),
        }
    }

    /// Compare the chain against a checkpoint taken earlier. This is
    /// the comparison `verify_chain` cannot make on its own: it detects
    /// tail truncation and whole-chain rewrites, provided the
    /// checkpoint was stored where an attacker could not rewrite it
    /// along with the chain.
    pub fn verify_checkpoint(&self, cp: &Checkpoint) -> CheckpointVerdict {
        if (self.len() as u64) < cp.length {
            return CheckpointVerdict::Truncated;
        }
        let anchored_tip = if cp.length == 0 {
            "GENESIS"
        } else {
            self.entries[(cp.length - 1) as usize].hash.as_str()
        };
        if anchored_tip != cp.tip {
            return CheckpointVerdict::Rewritten;
        }
        if !self.verify_chain() {
            return CheckpointVerdict::ChainInvalid;
        }
        CheckpointVerdict::Match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_grows_and_verifies() {
        let mut chain = AuditChain::new();
        assert_eq!(chain.tip(), "GENESIS");
        chain.append("fp-one", true);
        chain.append("fp-two", false);
        assert_eq!(chain.len(), 2);
        assert!(chain.verify_chain());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let mut chain = AuditChain::new();
        chain.append("fp-one", true);
        chain.append("fp-two", false);
        // Rewrite history: flip a recorded verdict.
        chain.entries[0].allowed = false;
        assert!(!chain.verify_chain());
    }

    #[test]
    fn entries_link_to_their_predecessor() {
        let mut chain = AuditChain::new();
        let first_hash = chain.append("fp-one", true).hash.clone();
        let second = chain.append("fp-two", true);
        assert_eq!(second.prev_hash, first_hash);
    }

    // --- Tamper laboratory (adapted from the MACK vault's Phase 2 lab) ---
    //
    // The vault lab's cases, run against this kit's AuditChain API.
    // `entries` is private; these tests live in-module precisely so
    // they can perform the mutations an attacker with write access
    // to the recorded history could perform.

    fn three_entry_chain() -> AuditChain {
        let mut chain = AuditChain::new();
        chain.append("fp-one", true);
        chain.append("fp-two", false);
        chain.append("fp-three", true);
        chain
    }

    #[test]
    fn tamper_modify_fingerprint_is_detected() {
        let mut chain = three_entry_chain();
        chain.entries[1].fingerprint = "fp-forged".to_string();
        assert!(!chain.verify_chain());
    }

    #[test]
    fn tamper_delete_middle_entry_is_detected() {
        let mut chain = three_entry_chain();
        chain.entries.remove(1);
        assert!(!chain.verify_chain());
    }

    #[test]
    fn tamper_reorder_entries_is_detected() {
        let mut chain = three_entry_chain();
        chain.entries.swap(0, 1);
        assert!(!chain.verify_chain());
    }

    #[test]
    fn tamper_insert_forged_entry_is_detected() {
        let mut chain = three_entry_chain();
        // A forged entry with a made-up hash spliced into the middle.
        chain.entries.insert(
            1,
            Entry {
                index: 1,
                prev_hash: chain.entries[0].hash.clone(),
                fingerprint: "fp-forged".to_string(),
                allowed: true,
                hash: "0".repeat(64),
            },
        );
        assert!(!chain.verify_chain());
    }

    #[test]
    fn tamper_replay_valid_entry_is_detected() {
        let mut chain = three_entry_chain();
        // Replay entry 0 over entry 2's slot.
        chain.entries[2] = chain.entries[0].clone();
        assert!(!chain.verify_chain());
    }

    #[test]
    fn tamper_corrupt_stored_hash_is_detected() {
        let mut chain = three_entry_chain();
        chain.entries[1].hash = "f".repeat(64);
        assert!(!chain.verify_chain());
    }

    #[test]
    fn tamper_corrupt_prev_hash_link_is_detected() {
        let mut chain = three_entry_chain();
        chain.entries[2].prev_hash = "0".repeat(64);
        assert!(!chain.verify_chain());
    }

    #[test]
    fn limitation_tail_truncation_is_not_detected() {
        // KNOWN LIMITATION, pinned on purpose: chopping entries off
        // the END leaves an internally valid prefix, so verify_chain
        // alone cannot see it. Detection requires comparing `tip()`
        // or `len()` against a value recorded outside the chain —
        // the same external-anchoring gap the README states. If a
        // future change makes truncation detectable in-chain, this
        // test must be updated deliberately.
        let mut chain = three_entry_chain();
        chain.entries.pop();
        assert_eq!(chain.len(), 2);
        assert!(chain.verify_chain());
    }

    #[test]
    fn limitation_whole_chain_rewrite_is_not_detected() {
        // KNOWN LIMITATION, pinned on purpose: the chain is UNKEYED —
        // anyone who knows the (public) hash construction can rewrite
        // history and recompute every link, and the result verifies.
        // The chain is tamper-EVIDENT against partial edits, not
        // tamper-proof against a full rewrite; an externally anchored
        // tip is the countermeasure, and is out of scope for this kit.
        let mut chain = three_entry_chain();
        chain.entries[0].allowed = false; // rewrite the first verdict
        let mut prev = "GENESIS".to_string();
        for e in chain.entries.iter_mut() {
            e.prev_hash = prev.clone();
            e.hash = entry_hash(e.index, &e.prev_hash, &e.fingerprint, e.allowed);
            prev = e.hash.clone();
        }
        assert!(chain.verify_chain());
    }

    // --- External checkpoints ---
    //
    // The countermeasure the two limitation tests above point at:
    // record the chain's length + tip somewhere outside the chain,
    // then compare later. These tests run the SAME attacks the
    // limitation tests pin as undetectable in-chain, and show the
    // checkpoint catching them. The limitation tests stay as they
    // are: the raw chain alone still cannot do this.

    #[test]
    fn checkpoint_matches_the_chain_it_was_taken_from() {
        let chain = three_entry_chain();
        let cp = chain.checkpoint();
        assert_eq!(cp.length, 3);
        assert_eq!(cp.tip, chain.tip());
        assert_eq!(chain.verify_checkpoint(&cp), CheckpointVerdict::Match);
    }

    #[test]
    fn checkpoint_still_matches_after_the_chain_grows() {
        // A checkpoint anchors a prefix, not a final state: later
        // appends are growth, not tampering.
        let mut chain = three_entry_chain();
        let cp = chain.checkpoint();
        chain.append("fp-four", true);
        assert_eq!(chain.verify_checkpoint(&cp), CheckpointVerdict::Match);
    }

    #[test]
    fn checkpoint_detects_tail_truncation() {
        // The attack limitation_tail_truncation_is_not_detected pins
        // as invisible to verify_chain alone.
        let mut chain = three_entry_chain();
        let cp = chain.checkpoint();
        chain.entries.pop();
        assert!(chain.verify_chain()); // still invisible in-chain
        assert_eq!(chain.verify_checkpoint(&cp), CheckpointVerdict::Truncated);
    }

    #[test]
    fn checkpoint_detects_whole_chain_rewrite() {
        // The attack limitation_whole_chain_rewrite_is_not_detected
        // pins: rewrite history, recompute every link, and the result
        // verifies in-chain...
        let mut chain = three_entry_chain();
        let cp = chain.checkpoint();
        chain.entries[0].allowed = false;
        let mut prev = "GENESIS".to_string();
        for e in chain.entries.iter_mut() {
            e.prev_hash = prev.clone();
            e.hash = entry_hash(e.index, &e.prev_hash, &e.fingerprint, e.allowed);
            prev = e.hash.clone();
        }
        assert!(chain.verify_chain());
        // ...but the rewritten head at the anchored length no longer
        // equals the tip the checkpoint recorded.
        assert_eq!(chain.verify_checkpoint(&cp), CheckpointVerdict::Rewritten);
    }

    #[test]
    fn checkpoint_detects_internal_corruption() {
        // An edit that does NOT recompute the links leaves the stored
        // tip untouched, so the prefix still matches the checkpoint —
        // and the internal check is what catches it.
        let mut chain = three_entry_chain();
        let cp = chain.checkpoint();
        chain.entries[1].fingerprint = "fp-forged".to_string();
        assert_eq!(
            chain.verify_checkpoint(&cp),
            CheckpointVerdict::ChainInvalid
        );
    }

    #[test]
    fn checkpoint_json_round_trips() {
        let chain = three_entry_chain();
        let cp = chain.checkpoint();
        let json = cp.to_json();
        let back = Checkpoint::from_json(&json).expect("valid checkpoint json");
        assert_eq!(cp, back);
        assert_eq!(chain.verify_checkpoint(&back), CheckpointVerdict::Match);
    }

    #[test]
    fn empty_chain_checkpoint_anchors_genesis() {
        // A checkpoint of an empty chain records length 0 / "GENESIS".
        // It anchors nothing yet — stated plainly so nobody mistakes
        // it for protection.
        let chain = AuditChain::new();
        let cp = chain.checkpoint();
        assert_eq!(cp.length, 0);
        assert_eq!(cp.tip, "GENESIS");
        assert_eq!(chain.verify_checkpoint(&cp), CheckpointVerdict::Match);
    }
}
