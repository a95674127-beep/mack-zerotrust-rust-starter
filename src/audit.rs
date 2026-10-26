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
}
