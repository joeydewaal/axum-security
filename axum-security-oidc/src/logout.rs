use std::fmt;

use url::Url;

/// Builds an RP-Initiated Logout URL (OpenID Connect RP-Initiated Logout 1.0):
/// the provider's `end_session_endpoint` with the optional parameters appended
/// as query string.
///
/// Get one seeded with the client's endpoint and `client_id` from
/// [`OidcClient::logout_url`](crate::OidcClient::logout_url), or construct it
/// directly with [`new`](Self::new).
pub struct LogoutUrl {
    end_session_endpoint: Url,
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    logout_hint: Option<String>,
    client_id: Option<String>,
    state: Option<String>,
}

impl LogoutUrl {
    /// A logout URL for `end_session_endpoint` with no parameters set.
    pub fn new(end_session_endpoint: Url) -> Self {
        Self {
            end_session_endpoint,
            id_token_hint: None,
            post_logout_redirect_uri: None,
            logout_hint: None,
            client_id: None,
            state: None,
        }
    }

    /// The `id_token_hint` — the raw ID token from login, so the provider knows
    /// which session to end. Recommended by the spec.
    pub fn id_token_hint(mut self, id_token: impl Into<String>) -> Self {
        self.id_token_hint = Some(id_token.into());
        self
    }

    /// Where the provider redirects after logout (`post_logout_redirect_uri`).
    /// Must be pre-registered with the provider.
    pub fn post_logout_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.post_logout_redirect_uri = Some(uri.into());
        self
    }

    /// A hint about the user being logged out (`logout_hint`).
    pub fn logout_hint(mut self, hint: impl Into<String>) -> Self {
        self.logout_hint = Some(hint.into());
        self
    }

    /// The `client_id` — required by some providers when no `id_token_hint` is
    /// given. Seeded already when built via `OidcClient::logout_url`.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Opaque value echoed back on the post-logout redirect (`state`).
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// The finished logout URL, with the set parameters appended.
    pub fn build(mut self) -> Url {
        let mut pairs: Vec<(&str, &str)> = Vec::new();
        if let Some(hint) = &self.id_token_hint {
            pairs.push(("id_token_hint", hint.as_str()));
        }
        if let Some(uri) = &self.post_logout_redirect_uri {
            pairs.push(("post_logout_redirect_uri", uri.as_str()));
        }
        if let Some(client_id) = &self.client_id {
            pairs.push(("client_id", client_id.as_str()));
        }
        if let Some(hint) = &self.logout_hint {
            pairs.push(("logout_hint", hint.as_str()));
        }
        if let Some(state) = &self.state {
            pairs.push(("state", state.as_str()));
        }

        // Only touch the query when there's something to add — an empty
        // `query_pairs_mut()` would still append a bare `?`.
        if !pairs.is_empty() {
            let mut query = self.end_session_endpoint.query_pairs_mut();
            for (name, value) in &pairs {
                query.append_pair(name, value);
            }
        }
        self.end_session_endpoint
    }
}

impl fmt::Debug for LogoutUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The id_token_hint is a raw ID token — a bearer credential.
        f.debug_struct("LogoutUrl")
            .field("end_session_endpoint", &self.end_session_endpoint.as_str())
            .field(
                "id_token_hint",
                &self.id_token_hint.as_ref().map(|_| "[redacted]"),
            )
            .field("post_logout_redirect_uri", &self.post_logout_redirect_uri)
            .field("logout_hint", &self.logout_hint)
            .field("client_id", &self.client_id)
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Url {
        Url::parse("https://provider.example/logout").unwrap()
    }

    #[test]
    fn bare_endpoint_when_nothing_set() {
        let url = LogoutUrl::new(endpoint()).build();
        assert_eq!(url.as_str(), "https://provider.example/logout");
    }

    #[test]
    fn appends_parameters() {
        let url = LogoutUrl::new(endpoint())
            .id_token_hint("the.id.token")
            .post_logout_redirect_uri("https://app.example/")
            .client_id("client-123")
            .state("xyz")
            .build();

        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["id_token_hint"], "the.id.token");
        assert_eq!(query["post_logout_redirect_uri"], "https://app.example/");
        assert_eq!(query["client_id"], "client-123");
        assert_eq!(query["state"], "xyz");
        assert_eq!(url.path(), "/logout");
    }

    #[test]
    fn debug_redacts_id_token_hint() {
        let logout = LogoutUrl::new(endpoint()).id_token_hint("secret.jwt.value");
        let debug = format!("{logout:?}");
        assert!(!debug.contains("secret.jwt.value"), "{debug}");
        assert!(debug.contains("[redacted]"), "{debug}");
    }
}
