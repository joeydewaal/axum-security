use serde::{Deserialize, Deserializer, de};

/// A UTC timestamp represented as seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTimestamp(i64);

impl<'de> serde::Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;

        #[cfg(feature = "jiff")]
        jiff::Timestamp::from_second(value).map_err(de::Error::custom)?;

        #[cfg(feature = "chrono")]
        if chrono::DateTime::<chrono::Utc>::from_timestamp(value, 0).is_none() {
            return Err(de::Error::custom("timestamp out of range for chrono"));
        }

        #[cfg(feature = "time")]
        time::OffsetDateTime::from_unix_timestamp(value).map_err(de::Error::custom)?;

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
pub struct OidcAddress<'a> {
    pub formatted: Option<&'a str>,
    pub street_address: Option<&'a str>,
    pub locality: Option<&'a str>,
    pub region: Option<&'a str>,
    pub postal_code: Option<&'a str>,
    pub country: Option<&'a str>,
}

/// Claims from an OpenID Connect ID token.
///
/// Standard claims are exposed as public fields. Datetime fields are private
/// and accessed through methods that return [`UtcTimestamp`], which can be
/// converted to `jiff`, `chrono`, or `time` types via feature-gated methods.
///
/// Any non-standard claims are captured in the `extra` field via `#[serde(flatten)]`.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcClaims<'a> {
    // Required claims
    #[serde(rename = "iss")]
    pub issuer: &'a str,
    #[serde(rename = "aud", deserialize_with = "deserialize_audience")]
    pub audiences: Vec<&'a str>,
    #[serde(rename = "sub")]
    pub subject: &'a str,

    // Datetime claims (private)
    #[serde(rename = "exp")]
    exp: UtcTimestamp,
    #[serde(rename = "iat")]
    iat: UtcTimestamp,
    auth_time: Option<UtcTimestamp>,
    updated_at: Option<UtcTimestamp>,

    // Optional standard claims
    pub nonce: Option<&'a str>,
    pub acr: Option<&'a str>,
    pub amr: Option<Vec<&'a str>>,
    pub azp: Option<&'a str>,
    pub at_hash: Option<&'a str>,

    // Profile claims
    pub name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub middle_name: Option<&'a str>,
    pub nickname: Option<&'a str>,
    pub preferred_username: Option<&'a str>,
    pub profile: Option<&'a str>,
    pub picture: Option<&'a str>,
    pub website: Option<&'a str>,
    pub gender: Option<&'a str>,
    pub birthdate: Option<&'a str>,
    pub zoneinfo: Option<&'a str>,
    pub locale: Option<&'a str>,

    // Email claims
    pub email: Option<&'a str>,
    pub email_verified: Option<bool>,

    // Phone claims
    pub phone_number: Option<&'a str>,
    pub phone_number_verified: Option<bool>,

    // Address claim
    pub address: Option<OidcAddress<'a>>,

    // Any additional/custom claims
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl OidcClaims<'_> {
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

    pub(crate) fn from_decoded_payload<'a>(
        jwt: &'a [u8],
    ) -> Result<OidcClaims<'a>, JwtPayloadError> {
        serde_json::from_slice(jwt).map_err(move |_| JwtPayloadError::Json)
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
fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<&'de str>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AudienceVisitor;

    impl<'de> de::Visitor<'de> for AudienceVisitor {
        type Value = Vec<&'de str>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
            Ok(vec![v])
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
