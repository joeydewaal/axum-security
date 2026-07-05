use std::fmt;

/// A failure while verifying an ID token.
///
/// Every variant is a rejection reason — the token is not trusted. The
/// distinctions exist for diagnostics/logging; a caller should treat all of
/// them as "authentication failed".
#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyError {
    /// The JWT could not be parsed (bad header, wrong number of segments,
    /// non-base64url payload).
    MalformedToken,
    /// The token's `alg` header is not in the verifier's allow-list. Guards
    /// against algorithm-confusion / key-substitution attacks.
    AlgorithmNotAllowed,
    /// No key in the JWKS matches the token's `kid` (or the token carried no
    /// `kid` and the JWKS does not hold exactly one key).
    UnknownKey,
    /// The matched JWK could not be turned into a verification key.
    InvalidKey,
    /// The signature did not verify against the selected key.
    SignatureInvalid,
    /// The `iss` claim did not match the expected issuer.
    IssuerMismatch,
    /// The `aud` claim did not contain the expected audience (the client id).
    AudienceMismatch,
    /// The `exp` claim is in the past (outside the configured leeway).
    Expired,
    /// The `nbf` claim is in the future (outside the configured leeway).
    ImmatureToken,
    /// The `nonce` claim did not match the expected value — replay protection.
    NonceMismatch,
    /// The signing keys could not be fetched from the provider's `jwks_uri`
    /// (network error, non-2xx status, or unparsable JWK set), so the token
    /// could not be checked.
    JwksUnavailable,
    /// A standard-claim check failed for a reason not covered above.
    InvalidToken,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::MalformedToken => f.write_str("malformed ID token"),
            VerifyError::AlgorithmNotAllowed => {
                f.write_str("ID token signing algorithm is not allowed")
            }
            VerifyError::UnknownKey => f.write_str("no JWKS key matches the ID token"),
            VerifyError::InvalidKey => f.write_str("JWKS key could not be used for verification"),
            VerifyError::SignatureInvalid => f.write_str("ID token signature is invalid"),
            VerifyError::IssuerMismatch => f.write_str("ID token issuer does not match"),
            VerifyError::AudienceMismatch => f.write_str("ID token audience does not match"),
            VerifyError::Expired => f.write_str("ID token has expired"),
            VerifyError::ImmatureToken => f.write_str("ID token is not yet valid"),
            VerifyError::NonceMismatch => f.write_str("ID token nonce does not match"),
            VerifyError::JwksUnavailable => f.write_str("could not fetch the provider's JWKS"),
            VerifyError::InvalidToken => f.write_str("ID token failed verification"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// A failure while fetching OpenID Connect provider metadata from a
/// `.well-known/openid-configuration` document.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The issuer URL could not be turned into a discovery URL.
    InvalidIssuerUrl(url::ParseError),
    /// The metadata request failed at the transport layer.
    Http(axum_security_oauth2::HttpError),
    /// The discovery endpoint returned a non-2xx status.
    Status(u16),
    /// The metadata document could not be deserialized.
    Parse(serde_json::Error),
    /// The `issuer` in the metadata did not match the requested issuer URL
    /// (OpenID Connect Discovery §4.3) — a misconfigured or hostile provider.
    IssuerMismatch,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::InvalidIssuerUrl(e) => write!(f, "invalid issuer URL: {e}"),
            DiscoveryError::Http(e) => write!(f, "discovery request failed: {e}"),
            DiscoveryError::Status(status) => {
                write!(f, "discovery endpoint returned status {status}")
            }
            DiscoveryError::Parse(e) => write!(f, "could not parse provider metadata: {e}"),
            DiscoveryError::IssuerMismatch => {
                f.write_str("provider metadata issuer does not match the requested issuer")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiscoveryError::InvalidIssuerUrl(e) => Some(e),
            DiscoveryError::Http(e) => Some(e),
            DiscoveryError::Parse(e) => Some(e),
            DiscoveryError::Status(_) | DiscoveryError::IssuerMismatch => None,
        }
    }
}

/// A failure while deserializing a verified ID token's payload into
/// [`OidcClaims`](crate::OidcClaims).
///
/// Only reachable after verification succeeded, so the payload is already
/// valid JSON — this signals a claim whose shape does not match the standard
/// claim set (e.g. a missing required claim or a wrongly-typed field).
#[derive(Debug)]
pub enum ClaimsError {
    /// The payload did not deserialize into the standard claim set.
    Deserialize(serde_json::Error),
}

impl fmt::Display for ClaimsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimsError::Deserialize(e) => write!(f, "could not deserialize ID token claims: {e}"),
        }
    }
}

impl std::error::Error for ClaimsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClaimsError::Deserialize(e) => Some(e),
        }
    }
}
