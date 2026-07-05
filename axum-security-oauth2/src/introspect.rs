use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

/// A token introspection response (RFC 7662 §2.2).
///
/// [`is_active`](Introspection::is_active) is the only field the server
/// must send; everything else is optional and present only for an active
/// token. Any field outside the standard set lands in the extras map,
/// reachable through [`extra_field`](Introspection::extra_field).
///
/// The `exp`/`iat`/`nbf` timestamps are raw unix seconds
/// ([`i64`]); a datetime library is deliberately not required.
pub struct Introspection {
    active: bool,
    scopes: Option<Vec<String>>,
    client_id: Option<String>,
    username: Option<String>,
    token_type: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    nbf: Option<i64>,
    sub: Option<String>,
    aud: Option<Vec<String>>,
    iss: Option<String>,
    jti: Option<String>,
    extra: Map<String, Value>,
}

impl Introspection {
    /// Whether the token is active: valid, unexpired and unrevoked
    /// (RFC 7662 §2.2). `false` means reject it.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The granted scopes, if the server sent a `scope` parameter
    /// (space-delimited on the wire, RFC 6749 §3.3).
    pub fn scopes(&self) -> Option<&[String]> {
        self.scopes.as_deref()
    }

    /// The client the token was issued to.
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// A human-readable identifier for the resource owner.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The token type (e.g. `Bearer`).
    pub fn token_type(&self) -> Option<&str> {
        self.token_type.as_deref()
    }

    /// Expiry as unix seconds (`exp`).
    pub fn exp(&self) -> Option<i64> {
        self.exp
    }

    /// Issued-at as unix seconds (`iat`).
    pub fn iat(&self) -> Option<i64> {
        self.iat
    }

    /// Not-before as unix seconds (`nbf`).
    pub fn nbf(&self) -> Option<i64> {
        self.nbf
    }

    /// The subject of the token (`sub`).
    pub fn sub(&self) -> Option<&str> {
        self.sub.as_deref()
    }

    /// The intended audiences (`aud`). A single-string `aud` on the wire
    /// is normalized to a one-element slice.
    pub fn aud(&self) -> Option<&[String]> {
        self.aud.as_deref()
    }

    /// The issuer of the token (`iss`).
    pub fn iss(&self) -> Option<&str> {
        self.iss.as_deref()
    }

    /// The token's unique identifier (`jti`).
    pub fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
    }

    /// Deserializes a single unrecognized response field.
    pub fn extra_field<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let value = self.extra.get(key)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Deserializes all unrecognized response fields into `T`.
    pub fn extra_fields<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(Value::Object(self.extra.clone()))
    }
}

impl fmt::Debug for Introspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Extra fields can hold sensitive claims — print keys only.
        let extra_keys: Vec<&str> = self.extra.keys().map(String::as_str).collect();
        f.debug_struct("Introspection")
            .field("active", &self.active)
            .field("scopes", &self.scopes)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field("token_type", &self.token_type)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("nbf", &self.nbf)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("iss", &self.iss)
            .field("jti", &self.jti)
            .field("extra", &extra_keys)
            .finish()
    }
}

/// The wire shape of an RFC 7662 §2.2 response.
#[derive(Deserialize)]
pub(crate) struct IntrospectionWire {
    active: bool,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    sub: Option<String>,
    // `aud` may be a single string or an array of strings (JWT semantics).
    #[serde(default, deserialize_with = "string_or_vec")]
    aud: Option<Vec<String>>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl IntrospectionWire {
    pub(crate) fn into_introspection(self) -> Introspection {
        Introspection {
            active: self.active,
            scopes: self
                .scope
                .map(|scope| scope.split_whitespace().map(String::from).collect()),
            client_id: self.client_id,
            username: self.username,
            token_type: self.token_type,
            exp: self.exp,
            iat: self.iat,
            nbf: self.nbf,
            sub: self.sub,
            aud: self.aud,
            iss: self.iss,
            jti: self.jti,
            extra: self.extra,
        }
    }
}

/// Deserializes a field that is either a string or an array of strings into
/// `Option<Vec<String>>`.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<StringOrVec>::deserialize(deserializer)? {
        None => None,
        Some(StringOrVec::One(one)) => Some(vec![one]),
        Some(StringOrVec::Many(many)) => Some(many),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> Introspection {
        serde_json::from_str::<IntrospectionWire>(body)
            .expect("valid introspection response")
            .into_introspection()
    }

    /// RFC 7662 §2.2 example response.
    #[test]
    fn rfc_7662_example() {
        let introspection = parse(
            r#"{
                "active": true,
                "client_id": "l238j323ds-23ij4",
                "username": "jdoe",
                "scope": "read write dolphin",
                "sub": "Z5O3upPC88QrAjx00dis",
                "aud": "https://protected.example.net/resource",
                "iss": "https://server.example.com/",
                "exp": 1419356238,
                "iat": 1419350238,
                "token_type": "Bearer",
                "extension_field": "twenty-seven"
            }"#,
        );
        assert!(introspection.is_active());
        assert_eq!(introspection.client_id(), Some("l238j323ds-23ij4"));
        assert_eq!(introspection.username(), Some("jdoe"));
        assert_eq!(
            introspection.scopes(),
            Some(
                &[
                    "read".to_string(),
                    "write".to_string(),
                    "dolphin".to_string()
                ][..]
            )
        );
        assert_eq!(introspection.sub(), Some("Z5O3upPC88QrAjx00dis"));
        // A single-string `aud` normalizes to a one-element slice.
        assert_eq!(
            introspection.aud(),
            Some(&["https://protected.example.net/resource".to_string()][..])
        );
        assert_eq!(introspection.iss(), Some("https://server.example.com/"));
        assert_eq!(introspection.exp(), Some(1419356238));
        assert_eq!(introspection.iat(), Some(1419350238));
        assert_eq!(introspection.token_type(), Some("Bearer"));
        assert_eq!(
            introspection
                .extra_field::<String>("extension_field")
                .as_deref(),
            Some("twenty-seven")
        );
    }

    /// An inactive token: `active` is the only field.
    #[test]
    fn inactive_token() {
        let introspection = parse(r#"{ "active": false }"#);
        assert!(!introspection.is_active());
        assert_eq!(introspection.scopes(), None);
        assert_eq!(introspection.exp(), None);
        assert_eq!(introspection.aud(), None);
    }

    /// `aud` may already be an array.
    #[test]
    fn aud_as_array() {
        let introspection = parse(r#"{ "active": true, "aud": ["one", "two"] }"#);
        assert_eq!(
            introspection.aud(),
            Some(&["one".to_string(), "two".to_string()][..])
        );
    }

    /// A response missing the required `active` field is malformed.
    #[test]
    fn missing_active_fails_to_parse() {
        assert!(serde_json::from_str::<IntrospectionWire>(r#"{ "scope": "read" }"#).is_err());
    }
}
