use std::fmt;

use subtle::ConstantTimeEq;

/// The CSRF token embedded in the authorization URL's `state` parameter.
///
/// On the callback, compare it against the `state` query parameter with
/// `==`: the comparison runs in constant time (via [`subtle`]), which
/// matters because an attacker controls one side of it.
///
/// It is a secret; `Debug` redacts it and there is no `Display`. Reach the
/// underlying string with [`as_str`](CsrfToken::as_str) or
/// [`into_string`](CsrfToken::into_string) when you need to persist it.
#[derive(Clone)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub(crate) fn new(token: String) -> Self {
        Self(token)
    }

    /// The token as a string slice, e.g. to store it in a cookie.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the token, returning the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for CsrfToken {
    fn from(token: String) -> Self {
        Self(token)
    }
}

/// Constant-time byte comparison of two strings.
fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

impl PartialEq for CsrfToken {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for CsrfToken {}

impl PartialEq<str> for CsrfToken {
    fn eq(&self, other: &str) -> bool {
        ct_eq(&self.0, other)
    }
}

impl PartialEq<&str> for CsrfToken {
    fn eq(&self, other: &&str) -> bool {
        ct_eq(&self.0, other)
    }
}

impl PartialEq<String> for CsrfToken {
    fn eq(&self, other: &String) -> bool {
        ct_eq(&self.0, other)
    }
}

impl PartialEq<CsrfToken> for str {
    fn eq(&self, other: &CsrfToken) -> bool {
        ct_eq(self, &other.0)
    }
}

impl PartialEq<CsrfToken> for String {
    fn eq(&self, other: &CsrfToken) -> bool {
        ct_eq(self, &other.0)
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfToken([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_value() {
        let token = CsrfToken::new("abc123".to_string());
        assert_eq!(token, *"abc123");
        assert_eq!(token, "abc123");
        assert_eq!(token, "abc123".to_string());
        assert_eq!(token, CsrfToken::new("abc123".to_string()));

        assert_ne!(token, "abc124");
        assert_ne!(token, "abc12"); // differing lengths
        assert_ne!(token, CsrfToken::new("nope".to_string()));
    }

    #[test]
    fn debug_redacts_the_token() {
        let debug = format!("{:?}", CsrfToken::new("super-secret".to_string()));
        assert!(!debug.contains("super-secret"), "{debug}");
    }
}
