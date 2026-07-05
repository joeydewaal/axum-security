use axum_security_oauth2::HttpClient;
use serde::Deserialize;
use url::Url;

use crate::error::DiscoveryError;

/// OpenID Connect provider metadata, from a `.well-known/openid-configuration`
/// document (OpenID Connect Discovery 1.0 §3).
///
/// Only the fields this crate uses are modelled as named fields; everything
/// else the provider publishes is kept in [`extra`](Self::extra).
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer identifier. Must match the requested issuer URL.
    pub issuer: String,
    /// The authorization endpoint (`authorization_endpoint`).
    pub authorization_endpoint: String,
    /// The token endpoint (`token_endpoint`).
    pub token_endpoint: String,
    /// The JWK Set URL (`jwks_uri`) — where ID-token signing keys live.
    pub jwks_uri: String,
    /// The UserInfo endpoint, if advertised.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// The RP-initiated logout endpoint, if advertised.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// The `id_token` signing algorithms the provider supports, if advertised.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// Every other field the metadata document carried.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ProviderMetadata {
    /// Fetch and validate provider metadata for `issuer_url`.
    ///
    /// Requests `{issuer_url}/.well-known/openid-configuration` over `http` and
    /// enforces the Discovery §4.3 issuer-match check: the `issuer` in the
    /// returned document must equal the requested issuer (a trailing slash on
    /// either side is ignored).
    pub async fn discover(
        issuer_url: &str,
        http: &HttpClient,
    ) -> Result<ProviderMetadata, DiscoveryError> {
        let config_url = discovery_url(issuer_url)?;

        let response = http.get(&config_url).await.map_err(DiscoveryError::Http)?;

        if !response.is_success() {
            return Err(DiscoveryError::Status(response.status));
        }

        let metadata: ProviderMetadata =
            serde_json::from_slice(&response.body).map_err(DiscoveryError::Parse)?;

        // Discovery §4.3: the issuer in the document must match the one we asked
        // for, or a hostile endpoint could point us at another provider's keys.
        if !issuer_matches(issuer_url, &metadata.issuer) {
            return Err(DiscoveryError::IssuerMismatch);
        }

        Ok(metadata)
    }
}

/// Build `{issuer}/.well-known/openid-configuration`, avoiding a double slash.
fn discovery_url(issuer_url: &str) -> Result<Url, DiscoveryError> {
    let base = issuer_url.trim_end_matches('/');
    Url::parse(&format!("{base}/.well-known/openid-configuration"))
        .map_err(DiscoveryError::InvalidIssuerUrl)
}

/// Compare issuer identifiers, tolerating a trailing slash on either side.
fn issuer_matches(requested: &str, returned: &str) -> bool {
    requested.trim_end_matches('/') == returned.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_discovery_url() {
        assert_eq!(
            discovery_url("https://accounts.google.com")
                .unwrap()
                .as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
        // Trailing slash does not double up.
        assert_eq!(
            discovery_url("https://accounts.google.com/")
                .unwrap()
                .as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn issuer_match_tolerates_trailing_slash() {
        assert!(issuer_matches(
            "https://issuer.example/",
            "https://issuer.example"
        ));
        assert!(issuer_matches(
            "https://issuer.example",
            "https://issuer.example/"
        ));
        assert!(!issuer_matches(
            "https://issuer.example",
            "https://evil.example"
        ));
    }

    #[test]
    fn deserializes_metadata_with_extra_fields() {
        let json = r#"{
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/auth",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
            "end_session_endpoint": "https://issuer.example/logout",
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "scopes_supported": ["openid", "email"]
        }"#;
        let m: ProviderMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(m.issuer, "https://issuer.example");
        assert_eq!(m.jwks_uri, "https://issuer.example/jwks");
        assert_eq!(
            m.end_session_endpoint.as_deref(),
            Some("https://issuer.example/logout")
        );
        assert_eq!(
            m.id_token_signing_alg_values_supported.as_deref(),
            Some(&["RS256".to_string(), "ES256".to_string()][..])
        );
        assert!(m.userinfo_endpoint.is_none());
        assert!(m.extra.contains_key("scopes_supported"));
    }
}
