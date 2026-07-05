use std::{fmt, time::Duration};

use serde::Deserialize;
use serde_json::{Map, Value};

/// A successful token-endpoint response (RFC 6749 §5.1).
///
/// Read-only; every field the server sent that isn't part of the standard
/// response lands in the extras map, reachable through
/// [`extra_field`](Tokens::extra_field) / [`extra_fields`](Tokens::extra_fields).
/// The tokens are secrets; `Debug` redacts them.
pub struct Tokens {
    access_token: String,
    token_type: String,
    expires_in: Option<Duration>,
    refresh_token: Option<String>,
    scopes: Option<Vec<String>>,
    extra: Map<String, Value>,
}

impl Tokens {
    /// The access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The `token_type` exactly as the server sent it.
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Whether the token type is `bearer` (case-insensitive, RFC 6749 §7.1).
    pub fn is_bearer(&self) -> bool {
        self.token_type.eq_ignore_ascii_case("bearer")
    }

    /// The lifetime of the access token, if the server sent `expires_in`.
    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_in
    }

    /// The refresh token, if the server sent one.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The granted scopes, if the server sent a `scope` parameter
    /// (space-delimited on the wire, RFC 6749 §3.3).
    pub fn scopes(&self) -> Option<&[String]> {
        self.scopes.as_deref()
    }

    /// Deserializes a single unrecognized response field, e.g.
    /// `tokens.extra_field::<String>("id_token")`.
    pub fn extra_field<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let value = self.extra.get(key)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Deserializes all unrecognized response fields into `T`.
    pub fn extra_fields<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(Value::Object(self.extra.clone()))
    }
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Extra fields can hold secrets (e.g. `id_token`) — print keys only.
        let extra_keys: Vec<&str> = self.extra.keys().map(String::as_str).collect();
        f.debug_struct("Tokens")
            .field("access_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("scopes", &self.scopes)
            .field("extra", &extra_keys)
            .finish()
    }
}

/// The wire shape of an RFC 6749 §5.1 response.
#[derive(Deserialize)]
pub(crate) struct TokensWire {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl TokensWire {
    pub(crate) fn into_tokens(self) -> Tokens {
        Tokens {
            access_token: self.access_token,
            token_type: self.token_type,
            expires_in: self.expires_in.map(Duration::from_secs),
            refresh_token: self.refresh_token,
            scopes: self
                .scope
                .map(|scope| scope.split_whitespace().map(String::from).collect()),
            extra: self.extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> Tokens {
        serde_json::from_str::<TokensWire>(body)
            .expect("valid token response")
            .into_tokens()
    }

    /// RFC 6749 §5.1 example response.
    #[test]
    fn rfc_6749_example() {
        let tokens = parse(
            r#"{
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "example",
                "expires_in": 3600,
                "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter": "example_value"
            }"#,
        );
        assert_eq!(tokens.access_token(), "2YotnFZFEjr1zCsicMWpAA");
        assert_eq!(tokens.token_type(), "example");
        assert!(!tokens.is_bearer());
        assert_eq!(tokens.expires_in(), Some(Duration::from_secs(3600)));
        assert_eq!(tokens.refresh_token(), Some("tGzv3JOkF0XG5Qx2TlKWIA"));
        assert_eq!(tokens.scopes(), None);
        assert_eq!(
            tokens.extra_field::<String>("example_parameter").as_deref(),
            Some("example_value")
        );
    }

    /// GitHub sends `scope` as a comma-free space/comma string and a
    /// lowercase `bearer`.
    #[test]
    fn github_style() {
        let tokens = parse(
            r#"{
                "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
                "scope": "repo gist",
                "token_type": "bearer"
            }"#,
        );
        assert!(tokens.is_bearer());
        assert_eq!(
            tokens.scopes(),
            Some(&["repo".to_string(), "gist".to_string()][..])
        );
        assert_eq!(tokens.refresh_token(), None);
        assert_eq!(tokens.expires_in(), None);
    }

    /// Google returns an `id_token` — how `axum-security-oidc` will pull
    /// the ID token out.
    #[test]
    fn google_id_token_in_extras() {
        let tokens = parse(
            r#"{
                "access_token": "ya29.a0Af",
                "token_type": "Bearer",
                "expires_in": 3599,
                "id_token": "eyJhbGciOiJSUzI1NiJ9.payload.sig"
            }"#,
        );
        assert!(tokens.is_bearer());
        assert_eq!(
            tokens.extra_field::<String>("id_token").as_deref(),
            Some("eyJhbGciOiJSUzI1NiJ9.payload.sig")
        );

        #[derive(Deserialize)]
        struct Extras {
            id_token: String,
        }
        let extras: Extras = tokens.extra_fields().unwrap();
        assert_eq!(extras.id_token, "eyJhbGciOiJSUzI1NiJ9.payload.sig");
    }

    #[test]
    fn debug_redacts_tokens_and_extras() {
        let tokens = parse(
            r#"{
                "access_token": "secret-access",
                "token_type": "bearer",
                "refresh_token": "secret-refresh",
                "id_token": "secret-id-token"
            }"#,
        );
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("secret-access"), "{debug}");
        assert!(!debug.contains("secret-refresh"), "{debug}");
        assert!(!debug.contains("secret-id-token"), "{debug}");
        assert!(debug.contains("id_token"), "{debug}"); // keys stay visible
    }
}
