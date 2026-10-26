//! Default-deny token policy (Community/demo rules).
//!
//! A token is verified only if it passes every rule; any failure denies.
//! Rules, in order: non-empty, minimum length, character set, and not on
//! the sample revocation list. The raw token is never stored anywhere —
//! only its SHA-256 fingerprint travels further.

use crate::sha256_hex;

pub const MIN_TOKEN_LEN: usize = 16;

/// Sample tokens revoked for demonstration. In a production deployment
/// this list comes from your own revocation store; here the fingerprints
/// are computed from the sample strings so the mechanism is visible.
const REVOKED_SAMPLE_TOKENS: &[&str] = &["revoked_demo_token_0001"];

pub struct Verdict {
    pub allowed: bool,
    pub reason: &'static str,
}

/// SHA-256 fingerprint of a token (hex). Safe to log; the token is not.
pub fn fingerprint(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

fn is_revoked(fp: &str) -> bool {
    REVOKED_SAMPLE_TOKENS.iter().any(|t| fingerprint(t) == fp)
}

pub fn evaluate(token: &str, fp: &str) -> Verdict {
    if token.is_empty() {
        return Verdict {
            allowed: false,
            reason: "empty_token",
        };
    }
    if token.chars().count() < MIN_TOKEN_LEN {
        return Verdict {
            allowed: false,
            reason: "token_too_short",
        };
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Verdict {
            allowed: false,
            reason: "invalid_characters",
        };
    }
    if is_revoked(fp) {
        return Verdict {
            allowed: false,
            reason: "token_revoked",
        };
    }
    Verdict {
        allowed: true,
        reason: "ok",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(token: &str) -> Verdict {
        evaluate(token, &fingerprint(token))
    }

    #[test]
    fn readme_sample_token_verifies() {
        // The exact token used in the README quickstart must pass.
        let v = check("sample_local_token");
        assert!(v.allowed, "reason: {}", v.reason);
    }

    #[test]
    fn empty_is_denied() {
        assert_eq!(check("").reason, "empty_token");
    }

    #[test]
    fn short_is_denied() {
        assert_eq!(check("abc123").reason, "token_too_short");
    }

    #[test]
    fn bad_characters_are_denied() {
        assert_eq!(check("token with spaces!!").reason, "invalid_characters");
    }

    #[test]
    fn revoked_is_denied() {
        assert_eq!(check("revoked_demo_token_0001").reason, "token_revoked");
    }

    #[test]
    fn fingerprint_is_deterministic_and_not_the_token() {
        let fp = fingerprint("sample_local_token");
        assert_eq!(fp, fingerprint("sample_local_token"));
        assert_eq!(fp.len(), 64);
        assert!(!fp.contains("sample"));
    }
}
