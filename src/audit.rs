//! SHA-256 hash-chained audit log.
//!
//! Every entry binds its own contents to the hash of the entry before
//! it, so editing, deleting, or reordering history breaks the chain and
//! is detectable by `verify_chain`. Only token fingerprints are stored —
//! never raw tokens.

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
}
