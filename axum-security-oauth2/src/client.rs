use base64::{Engine as _, engine::general_purpose::STANDARD};
use url::Url;

use crate::{
    builder::OAuth2ClientBuilder,
    error::{Endpoint, Error, ParseError, ServerErrorWire},
    http::{FormResponse, HttpClient},
    login::Login,
    pkce,
    secret::{AuthorizationCode, ClientSecret, CsrfToken, PkceVerifier, random_b64},
    tokens::{Tokens, TokensWire},
};

/// An OAuth2 client for the authorization code flow (RFC 6749 §4.1).
///
/// One concrete type, no type parameters: endpoints are optional and a
/// call whose endpoint is missing fails at call time with
/// [`Error::MissingEndpoint`].
#[derive(Debug)]
pub struct OAuth2Client {
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<ClientSecret>,
    pub(crate) auth_url: Option<Url>,
    pub(crate) token_url: Option<Url>,
    pub(crate) redirect_url: Option<Url>,
    pub(crate) scopes: Vec<String>,
    pub(crate) pkce: bool,
    pub(crate) http: Option<HttpClient>,
}

impl OAuth2Client {
    /// Returns a builder for a new client.
    pub fn builder() -> OAuth2ClientBuilder {
        OAuth2ClientBuilder::new()
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn auth_url(&self) -> Option<&Url> {
        self.auth_url.as_ref()
    }

    pub fn token_url(&self) -> Option<&Url> {
        self.token_url.as_ref()
    }

    pub fn redirect_url(&self) -> Option<&Url> {
        self.redirect_url.as_ref()
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn is_pkce(&self) -> bool {
        self.pkce
    }

    /// Starts the login flow: generates the CSRF token (and, when PKCE is
    /// on, the S256 challenge/verifier pair) and builds the authorization
    /// URL.
    ///
    /// Pure — no I/O; works with no HTTP backend configured. Fails only
    /// when no authorization endpoint is configured.
    pub fn start_login(&self) -> Result<Login, Error> {
        let auth_url = self
            .auth_url
            .as_ref()
            .ok_or(Error::MissingEndpoint(Endpoint::Auth))?;

        let csrf_token = CsrfToken::new(random_b64());
        let (challenge, pkce_verifier) = if self.pkce {
            let (challenge, verifier) = pkce::generate();
            (Some(challenge), Some(verifier))
        } else {
            (None, None)
        };

        let mut url = auth_url.clone();
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
            query.append_pair("state", csrf_token.secret());
            if let Some(challenge) = &challenge {
                query.append_pair("code_challenge", challenge);
                query.append_pair("code_challenge_method", "S256");
            }
        }

        Ok(Login {
            url,
            csrf_token,
            pkce_verifier,
        })
    }

    /// Finishes the login flow: exchanges the authorization code for
    /// tokens at the token endpoint (RFC 6749 §4.1.3).
    ///
    /// `pkce_verifier` is the verifier persisted from
    /// [`start_login`](Self::start_login); when PKCE is enabled on the
    /// client and it is `None`, the call fails with
    /// [`Error::MissingPkceVerifier`] before any I/O.
    pub async fn finish_login(
        &self,
        code: AuthorizationCode,
        pkce_verifier: Option<&PkceVerifier>,
    ) -> Result<Tokens, Error> {
        let token_url = self
            .token_url
            .as_ref()
            .ok_or(Error::MissingEndpoint(Endpoint::Token))?;
        let http = self.http.as_ref().ok_or(Error::NoHttpClient)?;
        if self.pkce && pkce_verifier.is_none() {
            return Err(Error::MissingPkceVerifier);
        }

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code.secret()),
        ];
        if let Some(verifier) = pkce_verifier {
            form.push(("code_verifier", verifier.secret()));
        }
        if let Some(redirect_url) = &self.redirect_url {
            form.push(("redirect_uri", redirect_url.as_str()));
        }

        // Client auth per RFC 6749 §2.3.1: HTTP Basic when a secret is
        // set, `client_id` in the body otherwise.
        let authorization = match &self.client_secret {
            Some(secret) => Some(basic_auth_header(&self.client_id, secret.secret())),
            None => {
                form.push(("client_id", &self.client_id));
                None
            }
        };

        let response = http
            .post_form(token_url, &form, authorization.as_deref())
            .await
            .map_err(Error::Http)?;

        parse_token_response(token_url, response)
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

#[cfg(test)]
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
        let client = base_builder()
            .scopes(&["read:user", "user:email"])
            .build()
            .unwrap();

        let login = client.start_login().unwrap();
        let url = login.url();

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
        assert!(*login.csrf_token() == query["state"]);

        // PKCE is on by default: challenge matches the verifier.
        let verifier = login.pkce_verifier().expect("pkce on by default");
        assert_eq!(
            query["code_challenge"],
            crate::pkce::challenge_s256(verifier.secret())
        );
        assert_eq!(query["code_challenge_method"], "S256");
    }

    #[test]
    fn start_login_without_pkce() {
        let client = base_builder().set_pkce(false).build().unwrap();

        let login = client.start_login().unwrap();
        let query = query_map(login.url());

        assert!(login.pkce_verifier().is_none());
        assert!(!query.contains_key("code_challenge"));
        assert!(!query.contains_key("code_challenge_method"));
    }

    #[test]
    fn start_login_minimal_client() {
        // Only client_id + auth_url: no redirect_uri or scope params.
        let client = OAuth2Client::builder()
            .client_id("test_client_id")
            .auth_url("https://provider.example/authorize")
            .build()
            .unwrap();

        let login = client.start_login().unwrap();
        let query = query_map(login.url());
        assert!(!query.contains_key("redirect_uri"));
        assert!(!query.contains_key("scope"));
    }

    #[test]
    fn start_login_keeps_existing_query() {
        let client = OAuth2Client::builder()
            .client_id("test_client_id")
            .auth_url("https://provider.example/authorize?audience=api")
            .build()
            .unwrap();

        let query = query_map(client.start_login().unwrap().url());
        assert_eq!(query["audience"], "api");
        assert_eq!(query["response_type"], "code");
    }

    #[test]
    fn start_login_requires_auth_url() {
        let client = OAuth2Client::builder()
            .client_id("test_client_id")
            .build()
            .unwrap();

        assert!(matches!(
            client.start_login(),
            Err(Error::MissingEndpoint(Endpoint::Auth))
        ));
    }

    #[test]
    fn missing_client_id() {
        let result = OAuth2Client::builder()
            .auth_url("https://provider.example/authorize")
            .build();
        assert!(matches!(result, Err(crate::ConfigError::MissingClientId)));
    }

    #[test]
    fn invalid_urls() {
        use crate::ConfigError;

        let result = OAuth2Client::builder()
            .client_id("id")
            .auth_url("not an url")
            .build();
        assert!(matches!(result, Err(ConfigError::InvalidAuthUrl(_))));

        let result = OAuth2Client::builder()
            .client_id("id")
            .token_url("not an url")
            .build();
        assert!(matches!(result, Err(ConfigError::InvalidTokenUrl(_))));

        let result = OAuth2Client::builder()
            .client_id("id")
            .redirect_url("not an url")
            .build();
        assert!(matches!(result, Err(ConfigError::InvalidRedirectUrl(_))));
    }

    #[test]
    fn getters() {
        let client = base_builder().scopes(&["a"]).build().unwrap();
        assert_eq!(client.client_id(), "test_client_id");
        assert_eq!(
            client.auth_url().unwrap().as_str(),
            "https://provider.example/authorize"
        );
        assert_eq!(
            client.token_url().unwrap().as_str(),
            "https://provider.example/token"
        );
        // axum-security reads the callback route path off this getter.
        assert_eq!(client.redirect_url().unwrap().path(), "/callback");
        assert_eq!(client.scopes(), ["a"]);
        assert!(client.is_pkce());
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
        let client = base_builder().build().unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains("test_client_secret"), "{debug}");
        assert!(debug.contains("test_client_id"), "{debug}");

        let login = client.start_login().unwrap();
        let debug = format!("{login:?}");
        assert!(!debug.contains(login.csrf_token().secret()), "{debug}");
        assert!(
            !debug.contains(login.pkce_verifier().unwrap().secret()),
            "{debug}"
        );
    }
}
