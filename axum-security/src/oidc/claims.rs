use serde::{Deserialize, Deserializer, de, de::Error};

/// A UTC timestamp represented as seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTimestamp(i64);

impl<'de> serde::Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;

        #[cfg(feature = "jiff")]
        jiff::Timestamp::from_second(value).map_err(Error::custom)?;

        #[cfg(feature = "chrono")]
        if chrono::DateTime::<chrono::Utc>::from_timestamp(value, 0).is_none() {
            return Err(serde::de::Error::custom(
                "timestamp out of range for chrono",
            ));
        }

        #[cfg(feature = "time")]
        time::OffsetDateTime::from_unix_timestamp(value).map_err(Error::custom)?;

        Ok(UtcTimestamp(value))
    }
}

impl UtcTimestamp {
    pub fn as_secs(&self) -> i64 {
        self.0
    }

    #[cfg(feature = "jiff")]
    pub fn to_jiff(&self) -> jiff::Timestamp {
        jiff::Timestamp::from_second(self.0).expect("validated during deserialization")
    }

    #[cfg(feature = "chrono")]
    pub fn to_chrono(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(self.0, 0).expect("validated during deserialization")
    }

    #[cfg(feature = "time")]
    pub fn to_time(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0).expect("validated during deserialization")
    }
}

/// The `address` claim from an OpenID Connect ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcAddress {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

/// Claims from an OpenID Connect ID token.
///
/// Standard claims are exposed as public fields. Datetime fields are private
/// and accessed through methods that return [`UtcTimestamp`], which can be
/// converted to `jiff`, `chrono`, or `time` types via feature-gated methods.
///
/// Any non-standard claims are captured in the `extra` field via `#[serde(flatten)]`.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcClaims {
    // Required claims
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud", deserialize_with = "deserialize_audience")]
    pub audiences: Vec<String>,
    #[serde(rename = "sub")]
    pub subject: String,

    // Datetime claims (private)
    #[serde(rename = "exp")]
    exp: UtcTimestamp,
    #[serde(rename = "iat")]
    iat: UtcTimestamp,
    auth_time: Option<UtcTimestamp>,
    updated_at: Option<UtcTimestamp>,

    // Optional standard claims
    pub nonce: Option<String>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub azp: Option<String>,
    pub at_hash: Option<String>,

    // Profile claims
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,

    // Email claims
    pub email: Option<String>,
    pub email_verified: Option<bool>,

    // Phone claims
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,

    // Address claim
    pub address: Option<OidcAddress>,

    // Any additional/custom claims
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl OidcClaims {
    pub fn expiration(&self) -> &UtcTimestamp {
        &self.exp
    }

    pub fn issued_at(&self) -> &UtcTimestamp {
        &self.iat
    }

    pub fn auth_time(&self) -> Option<&UtcTimestamp> {
        self.auth_time.as_ref()
    }

    pub fn updated_at(&self) -> Option<&UtcTimestamp> {
        self.updated_at.as_ref()
    }

    /// Deserialize claims from a raw JWT string (header.payload.signature).
    ///
    /// Extracts the payload segment and base64url-decodes it, then deserializes
    /// into `OidcClaims`.
    pub(crate) fn from_jwt_payload(jwt: &str) -> Result<Self, JwtPayloadError> {
        let payload = jwt
            .split('.')
            .nth(1)
            .ok_or(JwtPayloadError::InvalidFormat)?;

        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .map_err(|_| JwtPayloadError::Base64)?;

        serde_json::from_slice(&bytes).map_err(|_| JwtPayloadError::Json)
    }
}

#[derive(Debug)]
pub(crate) enum JwtPayloadError {
    InvalidFormat,
    Base64,
    Json,
}

impl std::fmt::Display for JwtPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid JWT format"),
            Self::Base64 => write!(f, "base64 decode error"),
            Self::Json => write!(f, "JSON deserialization error"),
        }
    }
}

/// Deserializes the `aud` claim which can be either a single string or an array of strings.
fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AudienceVisitor;

    impl<'de> de::Visitor<'de> for AudienceVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(1));
            while let Some(v) = seq.next_element()? {
                values.push(v);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(AudienceVisitor)
}
