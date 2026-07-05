use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use url::Url;

use crate::{
    builder::OAuth2ClientBuilder,
    csrf::CsrfToken,
    error::{Error, ParseError, ServerErrorWire},
    http::{FormResponse, HttpClient},
    login::{Login, LoginNonPkce, LoginOptions},
    pkce,
    rand::random_b64,
    tokens::{Tokens, TokensWire},
};

/// How the client authenticates to the token endpoint (RFC 6749 §2.3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthType {
    /// HTTP Basic with form-urlencoded credentials. The default.
    #[default]
    BasicAuth,
    /// `client_id` and `client_secret` in the request body, for providers
    /// that don't support HTTP Basic.
    RequestBody,
}

/// An OAuth2 client for the authorization code flow with PKCE
/// (RFC 6749 §4.1 + RFC 7636).
///
/// One concrete type, no type parameters: the configuration is validated
/// once by [`try_build`](OAuth2ClientBuilder::try_build), so calls only
/// fail for reasons that can actually occur at request time.
pub struct OAuth2Client {
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) auth_url: Url,
    pub(crate) token_url: Url,
    pub(crate) redirect_url: Option<Url>,
    pub(crate) scopes: Vec<String>,
    pub(crate) auth_type: AuthType,
    pub(crate) http: HttpClient,
}

impl fmt::Debug for OAuth2Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field("auth_type", &self.auth_type)
            .field("http", &self.http)
            .finish()
    }
}

impl OAuth2Client {
    /// Returns a builder for a new client.
    pub fn builder() -> OAuth2ClientBuilder {
        OAuth2ClientBuilder::new()
    }

    /// A builder preconfigured with GitHub's endpoints.
    pub fn github() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://github.com/login/oauth/authorize")
            .token_url("https://github.com/login/oauth/access_token")
    }

    /// A builder preconfigured with Google's endpoints.
    pub fn google() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://accounts.google.com/o/oauth2/v2/auth")
            .token_url("https://oauth2.googleapis.com/token")
    }

    /// A builder preconfigured with Discord's endpoints.
    pub fn discord() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://discord.com/api/oauth2/authorize")
            .token_url("https://discord.com/api/oauth2/token")
    }

    /// A builder preconfigured with Spotify's endpoints.
    pub fn spotify() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://accounts.spotify.com/authorize")
            .token_url("https://accounts.spotify.com/api/token")
    }

    /// A builder preconfigured with Twitch's endpoints.
    pub fn twitch() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://id.twitch.tv/oauth2/authorize")
            .token_url("https://id.twitch.tv/oauth2/token")
    }

    /// A builder preconfigured with Microsoft's multi-tenant (`common`)
    /// endpoints, accepting both work/school and personal accounts.
    ///
    /// Single-tenant apps need their tenant ID in the endpoint paths —
    /// use [`builder()`](Self::builder) with explicit URLs for that.
    pub fn microsoft() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
            .token_url("https://login.microsoftonline.com/common/oauth2/v2.0/token")
    }

    /// A builder preconfigured with gitlab.com's endpoints. Self-hosted
    /// instances use [`builder()`](Self::builder) with their own URLs.
    pub fn gitlab() -> OAuth2ClientBuilder {
        Self::builder()
            .auth_url("https://gitlab.com/oauth/authorize")
            .token_url("https://gitlab.com/oauth/token")
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    pub fn token_url(&self) -> &Url {
        &self.token_url
    }

    pub fn redirect_url(&self) -> Option<&Url> {
        self.redirect_url.as_ref()
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn auth_type(&self) -> AuthType {
        self.auth_type
    }

    /// Starts the login flow: generates the CSRF token and the PKCE S256
    /// challenge/verifier pair, and builds the authorization URL.
    ///
    /// Pure — no I/O, infallible.
    pub fn start_login(&self) -> Login {
        self.start_login_with(LoginOptions::default())
    }

    /// Like [`start_login`](Self::start_login), with extra authorization
    /// parameters — e.g. an oidc `nonce`, `prompt` or `login_hint`:
    ///
    /// ```ignore
    /// let login = client.start_login_with(LoginOptions::new().param("nonce", &nonce));
    /// ```
    ///
    /// Pure — no I/O, infallible.
    pub fn start_login_with(&self, options: LoginOptions) -> Login {
        let csrf_token = random_b64();
        let (challenge, pkce_verifier) = pkce::generate();

        let mut url = self.authorize_url(&csrf_token, &options);
        url.query_pairs_mut()
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");

        Login {
            url,
            csrf_token: CsrfToken::new(csrf_token),
            pkce_verifier,
        }
    }

    /// Starts the login flow without PKCE: generates the CSRF token and
    /// builds the authorization URL.
    ///
    /// Prefer [`start_login`](Self::start_login) — compliant providers
    /// ignore the PKCE parameters (RFC 6749 §3.1), so PKCE against a
    /// provider that doesn't support it is harmless. This exists for
    /// providers that reject requests carrying a `code_challenge`. Finish
    /// with [`finish_login_non_pkce`](Self::finish_login_non_pkce) — the
    /// two legs must agree on the flow.
    ///
    /// Pure — no I/O, infallible.
    pub fn start_login_non_pkce(&self) -> LoginNonPkce {
        self.start_login_non_pkce_with(LoginOptions::default())
    }

    /// Like [`start_login_non_pkce`](Self::start_login_non_pkce), with
    /// extra authorization parameters (see
    /// [`start_login_with`](Self::start_login_with)).
    ///
    /// Pure — no I/O, infallible.
    pub fn start_login_non_pkce_with(&self, options: LoginOptions) -> LoginNonPkce {
        let csrf_token = random_b64();
        let url = self.authorize_url(&csrf_token, &options);
        LoginNonPkce {
            url,
            csrf_token: CsrfToken::new(csrf_token),
        }
    }

    /// The authorization URL with everything but the PKCE parameters.
    fn authorize_url(&self, csrf_token: &str, options: &LoginOptions) -> Url {
        let mut url = self.auth_url.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.client_id);
            if let Some(redirect_url) = &self.redirect_url {
                query.append_pair("redirect_uri", redirect_url.as_str());
            }
            if !self.scopes.is_empty() {
                query.append_pair("scope", &self.scopes.join(" "));
            }
            query.append_pair("state", csrf_token);
            for (name, value) in &options.params {
                query.append_pair(name, value);
            }
        }
        url
    }

    /// Finishes the login flow: exchanges the authorization code for
    /// tokens at the token endpoint (RFC 6749 §4.1.3).
    ///
    /// `code` is the `code` query parameter from the callback;
    /// `pkce_verifier` is the verifier persisted from
    /// [`start_login`](Self::start_login). Both are plain strings — mind
    /// the argument order.
    pub async fn finish_login(&self, code: &str, pkce_verifier: &str) -> Result<Tokens, Error> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", pkce_verifier),
        ];
        if let Some(redirect_url) = &self.redirect_url {
            form.push(("redirect_uri", redirect_url.as_str()));
        }

        self.token_request(form).await
    }

    /// Finishes a login started with
    /// [`start_login_non_pkce`](Self::start_login_non_pkce): exchanges the
    /// authorization code for tokens without a PKCE verifier.
    pub async fn finish_login_non_pkce(&self, code: &str) -> Result<Tokens, Error> {
        let mut form: Vec<(&str, &str)> =
            vec![("grant_type", "authorization_code"), ("code", code)];
        if let Some(redirect_url) = &self.redirect_url {
            form.push(("redirect_uri", redirect_url.as_str()));
        }

        self.token_request(form).await
    }

    /// Exchanges a refresh token for fresh tokens (RFC 6749 §6).
    ///
    /// The server may answer without a new refresh token
    /// ([`Tokens::refresh_token`] is `None`) — keep using the old one then.
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<Tokens, Error> {
        let form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        self.token_request(form).await
    }

    async fn token_request<'a>(
        &'a self,
        mut form: Vec<(&'a str, &'a str)>,
    ) -> Result<Tokens, Error> {
        // Client auth per RFC 6749 §2.3.1: HTTP Basic when a secret is
        // set (credentials in the body instead under
        // `AuthType::RequestBody`), bare `client_id` in the body otherwise.
        let authorization = match (self.auth_type, &self.client_secret) {
            (AuthType::BasicAuth, Some(secret)) => Some(basic_auth_header(&self.client_id, secret)),
            (AuthType::RequestBody, secret) => {
                form.push(("client_id", &self.client_id));
                if let Some(secret) = secret {
                    form.push(("client_secret", secret));
                }
                None
            }
            (AuthType::BasicAuth, None) => {
                form.push(("client_id", &self.client_id));
                None
            }
        };

        let response = self
            .http
            .post_form(&self.token_url, &form, authorization.as_deref())
            .await
            .map_err(Error::Http)?;

        parse_token_response(&self.token_url, response)
    }
}

/// `Basic` authorization header value with form-urlencoded credentials
/// (RFC 6749 §2.3.1).
fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let id: String = url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
    let secret: String = url::form_urlencoded::byte_serialize(client_secret.as_bytes()).collect();
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

fn parse_token_response(url: &Url, response: FormResponse) -> Result<Tokens, Error> {
    let success = (200..300).contains(&response.status);

    if success {
        match serde_json::from_slice::<TokensWire>(&response.body) {
            Ok(tokens) => return Ok(tokens.into_tokens()),
            Err(parse_error) => {
                // Some providers (GitHub) send §5.2 error bodies with a
                // 2xx status.
                if let Ok(server_error) = serde_json::from_slice::<ServerErrorWire>(&response.body)
                {
                    return Err(Error::Server(
                        server_error.into_server_error(response.status),
                    ));
                }
                return Err(Error::Parse(parse_error_from(url, response, parse_error)));
            }
        }
    }

    match serde_json::from_slice::<ServerErrorWire>(&response.body) {
        Ok(server_error) => Err(Error::Server(
            server_error.into_server_error(response.status),
        )),
        Err(parse_error) => Err(Error::Parse(parse_error_from(url, response, parse_error))),
    }
}

fn parse_error_from(url: &Url, response: FormResponse, source: serde_json::Error) -> ParseError {
    ParseError {
        url: url.as_str().to_string(),
        status: response.status,
        content_type: response.content_type,
        body: response.body,
        source,
    }
}

// Building a client requires an HTTP backend, so these tests need one.
#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn base_builder() -> OAuth2ClientBuilder {
        OAuth2Client::builder()
            .client_id("test_client_id")
            .client_secret("test_client_secret")
            .auth_url("https://provider.example/authorize")
            .token_url("https://provider.example/token")
            .redirect_url("https://app.example/callback")
    }

    fn query_map(url: &Url) -> HashMap<String, String> {
        url.query_pairs().into_owned().collect()
    }

    #[test]
    fn start_login_builds_the_authorize_url() {
        let client = base_builder().scopes(&["read:user", "user:email"]).build();

        let login = client.start_login();
        let url = &login.url;

        assert_eq!(
            url.origin().ascii_serialization(),
            "https://provider.example"
        );
        assert_eq!(url.path(), "/authorize");

        let query = query_map(url);
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "test_client_id");
        assert_eq!(query["redirect_uri"], "https://app.example/callback");
        assert_eq!(query["scope"], "read:user user:email");
        assert_eq!(login.csrf_token, query["state"]);

        // The PKCE challenge matches the verifier.
        assert_eq!(
            query["code_challenge"],
            crate::pkce::challenge_s256(&login.pkce_verifier)
        );
        assert_eq!(query["code_challenge_method"], "S256");
    }

    #[test]
    fn start_login_with_appends_extra_params() {
        let client = base_builder().build();

        let login = client.start_login_with(
            LoginOptions::new()
                .param("nonce", "test-nonce")
                .param("hd", "example.com"),
        );
        let query = query_map(&login.url);

        assert_eq!(query["nonce"], "test-nonce");
        assert_eq!(query["hd"], "example.com");
        // The standard parameters are still present.
        assert_eq!(query["response_type"], "code");
        assert_eq!(login.csrf_token, query["state"]);
        assert!(query.contains_key("code_challenge"));

        let login =
            client.start_login_non_pkce_with(LoginOptions::new().param("nonce", "test-nonce"));
        let query = query_map(&login.url);
        assert_eq!(query["nonce"], "test-nonce");
        assert!(!query.contains_key("code_challenge"));
    }

    #[test]
    fn login_options_debug_redacts_values() {
        let options = crate::LoginOptions::default().param("nonce", "secret-nonce");
        let debug = format!("{options:?}");
        assert!(debug.contains("nonce"), "{debug}");
        assert!(!debug.contains("secret-nonce"), "{debug}");
    }

    #[test]
    fn auth_type_defaults_to_basic() {
        let client = base_builder().build();
        assert_eq!(client.auth_type(), AuthType::BasicAuth);

        let client = base_builder().request_body().build();
        assert_eq!(client.auth_type(), AuthType::RequestBody);
    }

    #[test]
    fn provider_shortcuts_set_endpoints() {
        let cases = [
            (
                OAuth2Client::github(),
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
            ),
            (
                OAuth2Client::google(),
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
            ),
            (
                OAuth2Client::discord(),
                "https://discord.com/api/oauth2/authorize",
                "https://discord.com/api/oauth2/token",
            ),
            (
                OAuth2Client::spotify(),
                "https://accounts.spotify.com/authorize",
                "https://accounts.spotify.com/api/token",
            ),
            (
                OAuth2Client::twitch(),
                "https://id.twitch.tv/oauth2/authorize",
                "https://id.twitch.tv/oauth2/token",
            ),
            (
                OAuth2Client::microsoft(),
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            ),
            (
                OAuth2Client::gitlab(),
                "https://gitlab.com/oauth/authorize",
                "https://gitlab.com/oauth/token",
            ),
        ];

        for (builder, auth_url, token_url) in cases {
            let client = builder.client_id("test_client_id").build();
            assert_eq!(client.auth_url().as_str(), auth_url);
            assert_eq!(client.token_url().as_str(), token_url);
        }
    }

    #[test]
    fn start_login_non_pkce_omits_challenge() {
        let client = base_builder().scopes(&["read:user"]).build();

        let login = client.start_login_non_pkce();
        let query = query_map(&login.url);

        assert!(!query.contains_key("code_challenge"));
        assert!(!query.contains_key("code_challenge_method"));
        // Everything else matches the PKCE leg.
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "test_client_id");
        assert_eq!(query["redirect_uri"], "https://app.example/callback");
        assert_eq!(query["scope"], "read:user");
        assert_eq!(login.csrf_token, query["state"]);
    }

    #[test]
    fn start_login_minimal_client() {
        // No redirect_url or scopes: neither parameter is sent.
        let client = OAuth2Client::builder()
            .client_id("test_client_id")
            .auth_url("https://provider.example/authorize")
            .token_url("https://provider.example/token")
            .build();

        let query = query_map(&client.start_login().url);
        assert!(!query.contains_key("redirect_uri"));
        assert!(!query.contains_key("scope"));
    }

    #[test]
    fn start_login_keeps_existing_query() {
        let client = OAuth2Client::builder()
            .client_id("test_client_id")
            .auth_url("https://provider.example/authorize?audience=api")
            .token_url("https://provider.example/token")
            .build();

        let query = query_map(&client.start_login().url);
        assert_eq!(query["audience"], "api");
        assert_eq!(query["response_type"], "code");
    }

    #[test]
    fn missing_config() {
        use crate::ConfigError;

        let result = OAuth2Client::builder()
            .auth_url("https://provider.example/authorize")
            .token_url("https://provider.example/token")
            .try_build();
        assert!(matches!(result, Err(ConfigError::MissingClientId)));

        let result = OAuth2Client::builder()
            .client_id("id")
            .token_url("https://provider.example/token")
            .try_build();
        assert!(matches!(result, Err(ConfigError::MissingAuthUrl)));

        let result = OAuth2Client::builder()
            .client_id("id")
            .auth_url("https://provider.example/authorize")
            .try_build();
        assert!(matches!(result, Err(ConfigError::MissingTokenUrl)));
    }

    #[test]
    fn invalid_urls() {
        use crate::ConfigError;

        let result = base_builder().auth_url("not an url").try_build();
        assert!(matches!(result, Err(ConfigError::InvalidAuthUrl(_))));

        let result = base_builder().token_url("not an url").try_build();
        assert!(matches!(result, Err(ConfigError::InvalidTokenUrl(_))));

        let result = base_builder().redirect_url("not an url").try_build();
        assert!(matches!(result, Err(ConfigError::InvalidRedirectUrl(_))));
    }

    #[test]
    fn getters() {
        let client = base_builder().scopes(&["a"]).build();
        assert_eq!(client.client_id(), "test_client_id");
        assert_eq!(
            client.auth_url().as_str(),
            "https://provider.example/authorize"
        );
        assert_eq!(
            client.token_url().as_str(),
            "https://provider.example/token"
        );
        // axum-security reads the callback route path off this getter.
        assert_eq!(client.redirect_url().unwrap().path(), "/callback");
        assert_eq!(client.scopes(), ["a"]);
    }

    #[test]
    fn basic_auth_header_encodes_credentials() {
        // Plain credentials pass through form-urlencoding unchanged.
        assert_eq!(
            basic_auth_header("my-client", "my-secret"),
            format!("Basic {}", STANDARD.encode("my-client:my-secret"))
        );
        // Reserved characters are form-urlencoded before base64 (§2.3.1).
        assert_eq!(
            basic_auth_header("client id", "s:cret+"),
            format!("Basic {}", STANDARD.encode("client+id:s%3Acret%2B"))
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let client = base_builder().build();
        let debug = format!("{client:?}");
        assert!(!debug.contains("test_client_secret"), "{debug}");
        assert!(debug.contains("test_client_id"), "{debug}");

        let login = client.start_login();
        let debug = format!("{login:?}");
        assert!(!debug.contains(login.csrf_token.as_str()), "{debug}");
        assert!(!debug.contains(login.pkce_verifier.as_str()), "{debug}");

        let login = client.start_login_non_pkce();
        let debug = format!("{login:?}");
        assert!(!debug.contains(login.csrf_token.as_str()), "{debug}");
    }
}
