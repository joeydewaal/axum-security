use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::rand::random_b64;

/// Generates a fresh S256 `(challenge, verifier)` pair (RFC 7636 §4).
pub(crate) fn generate() -> (String, String) {
    let verifier = random_b64();
    let challenge = challenge_s256(&verifier);
    (challenge, verifier)
}

/// Derives the S256 code challenge from a verifier:
/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` (RFC 7636 §4.2).
pub(crate) fn challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B test vector.
    #[test]
    fn rfc_7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(challenge_s256(verifier), challenge);
    }

    #[test]
    fn generated_pair_matches() {
        let (challenge, verifier) = generate();
        assert_eq!(challenge, challenge_s256(&verifier));
        // 43 chars satisfies RFC 7636 §4.1 (43..=128).
        assert_eq!(verifier.len(), 43);
    }
}
