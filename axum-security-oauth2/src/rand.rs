use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Generates 32 bytes from the OS CSPRNG, base64url-nopad encoded.
pub(crate) fn random_b64() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("failed to read from the OS random source");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_is_43_chars_url_safe() {
        let value = random_b64();
        assert_eq!(value.len(), 43); // 32 bytes, base64 no pad
        assert!(
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(random_b64(), random_b64());
    }
}
