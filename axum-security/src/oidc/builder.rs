use std::{borrow::Cow, error::Error, fmt::Display, sync::Arc, time::Duration};

use cookie_monster::CookieBuilder;
use openidconnect::{
    AuthUrl, ClientId, ClientSecret, EndSessionUrl, IssuerUrl, JsonWebKeySetUrl,
    PostLogoutRedirectUrl, ProviderMetadataWithLogout, RedirectUrl, ResponseTypes, Scope, TokenUrl,
    core::{
        CoreClient, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    reqwest::Client as HttpClient,
};

use crate::utils::get_env;

use super::{OidcContext, OidcHandler, context::OidcContextInner, cookie::OidcCookieBuilder};

fn default_oidc_http_client() -> HttpClient {
    openidconnect::reqwest::Client::builder()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

pub struct OidcContextBuilder {
    cookie_builder: OidcCookieBuilder,
    login_path: Option<Cow<'static, str>>,
    logout_path: Option<Cow<'static, str>>,
    post_logout_redirect_url: Option<String>,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Vec<Scope>,
    http_client: Option<HttpClient>,

    // Provider metadata (filled by discover, or set manually)
    issuer_url: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    jwks_url: Option<String>,
    end_session_url: Option<String>,
    provider_metadata: Option<ProviderMetadataWithLogout>,
}

impl OidcContextBuilder {
    pub fn new(provider_name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            cookie_builder: OidcCookieBuilder::new(provider_name.into()),
            login_path: None,
            logout_path: None,
            post_logout_redirect_url: None,
            redirect_url: None,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            http_client: None,
            issuer_url: None,
            auth_url: None,
            token_url: None,
            jwks_url: None,
            end_session_url: None,
            provider_metadata: None,
        }
    }

    pub(crate) async fn discover(
        provider_name: Cow<'static, str>,
        issuer_url: &str,
    ) -> Result<Self, OidcBuilderError> {
        let issuer =
            IssuerUrl::new(issuer_url.to_string()).map_err(OidcBuilderError::InvalidIssuerUrl)?;

        let http_client = default_oidc_http_client();

        let metadata = ProviderMetadataWithLogout::discover_async(issuer, &http_client)
            .await
            .map_err(|e| OidcBuilderError::DiscoveryError(e.to_string()))?;

        Ok(Self {
            cookie_builder: OidcCookieBuilder::new(provider_name),
            login_path: None,
            logout_path: None,
            post_logout_redirect_url: None,
            redirect_url: None,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            http_client: Some(http_client),
            issuer_url: None,
            auth_url: None,
            token_url: None,
            jwks_url: None,
            end_session_url: None,
            provider_metadata: Some(metadata),
        })
    }

    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.redirect_url = Some(url.into());
        self
    }

    pub fn redirect_uri_env(self, name: &str) -> Self {
        self.redirect_url(get_env(name))
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn client_id_env(self, name: &str) -> Self {
        self.client_id(get_env(name))
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    pub fn client_secret_env(self, name: &str) -> Self {
        self.client_secret(get_env(name))
    }

    pub fn issuer_url(mut self, url: impl Into<String>) -> Self {
        self.issuer_url = Some(url.into());
        self
    }

    pub fn auth_url(mut self, url: impl Into<String>) -> Self {
        self.auth_url = Some(url.into());
        self
    }

    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    pub fn jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| Scope::new(s.to_string())).collect();
        self
    }

    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_builder.cookie_builder.apply_cookie(f);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_builder.cookie_builder.apply_dev_cookie(f);
        self
    }

    pub fn login_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.login_path = Some(path.into());
        self
    }

    pub fn logout_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.logout_path = Some(path.into());
        self
    }

    pub fn post_logout_redirect_url(mut self, url: impl Into<String>) -> Self {
        self.post_logout_redirect_url = Some(url.into());
        self
    }

    pub fn end_session_url(mut self, url: impl Into<String>) -> Self {
        self.end_session_url = Some(url.into());
        self
    }

    pub fn use_dev_cookies(mut self, dev: bool) -> Self {
        self.cookie_builder.cookie_builder.dev = dev;
        self
    }

    pub fn http_client(mut self, http_client: HttpClient) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn cookie_secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.cookie_builder.secret = Some(secret.as_ref().to_vec());
        self
    }

    pub fn max_login_duration(mut self, duration: Duration) -> Self {
        self.cookie_builder
            .set_max_login_duration_secs(duration.as_secs());
        self
    }

    pub fn max_login_duration_minutes(self, minutes: u64) -> Self {
        self.max_login_duration(Duration::from_mins(minutes))
    }

    pub fn build<T>(self, handler: T) -> OidcContext<T>
    where
        T: OidcHandler,
    {
        self.try_build(handler).unwrap()
    }

    pub fn try_build<T>(mut self, handler: T) -> Result<OidcContext<T>, OidcBuilderError>
    where
        T: OidcHandler,
    {
        let client_id = self
            .client_id
            .take()
            .ok_or(OidcBuilderError::MissingClientId)
            .map(ClientId::new)?;

        let redirect_url = self
            .redirect_url
            .take()
            .ok_or(OidcBuilderError::MissingRedirectUrl)?;

        let redirect_url =
            RedirectUrl::new(redirect_url).map_err(OidcBuilderError::InvalidRedirectUrl)?;

        let client_secret = self.client_secret.take().map(ClientSecret::new);
        let explicit_end_session = self
            .end_session_url
            .take()
            .map(|u| EndSessionUrl::new(u).expect("invalid end_session_url"));

        let (client, end_session_url) = if let Some(metadata) = self.provider_metadata.take() {
            // Discovery path — extract end_session_endpoint before consuming metadata
            let discovered_end_session =
                metadata.additional_metadata().end_session_endpoint.clone();

            let client = CoreClient::from_provider_metadata(metadata, client_id, client_secret)
                .set_redirect_uri(redirect_url);

            // Explicit end_session_url takes priority over discovered one
            let end_session_url = explicit_end_session.or(discovered_end_session);

            (client, end_session_url)
        } else {
            // Manual path — require all endpoints
            let issuer_url = self
                .issuer_url
                .take()
                .ok_or(OidcBuilderError::MissingIssuerUrl)?;
            let issuer_url =
                IssuerUrl::new(issuer_url).map_err(OidcBuilderError::InvalidIssuerUrl)?;

            let auth_url = self
                .auth_url
                .take()
                .ok_or(OidcBuilderError::MissingAuthUrl)?;
            let auth_url = AuthUrl::new(auth_url).map_err(OidcBuilderError::InvalidAuthUrl)?;

            let token_url = self
                .token_url
                .take()
                .ok_or(OidcBuilderError::MissingTokenUrl)?;
            let token_url = TokenUrl::new(token_url).map_err(OidcBuilderError::InvalidTokenUrl)?;

            let jwks_url = self
                .jwks_url
                .take()
                .ok_or(OidcBuilderError::MissingJwksUrl)?;
            let jwks_url =
                JsonWebKeySetUrl::new(jwks_url).map_err(OidcBuilderError::InvalidJwksUrl)?;

            let metadata = CoreProviderMetadata::new(
                issuer_url,
                auth_url,
                jwks_url,
                vec![ResponseTypes::new(vec![CoreResponseType::Code])],
                vec![CoreSubjectIdentifierType::Public],
                vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
                Default::default(),
            )
            .set_token_endpoint(Some(token_url));

            let client = CoreClient::from_provider_metadata(metadata, client_id, client_secret)
                .set_redirect_uri(redirect_url);

            (client, explicit_end_session)
        };

        // Ensure "openid" is always present
        let openid = Scope::new("openid".to_string());
        if !self.scopes.contains(&openid) {
            self.scopes.insert(0, openid);
        }

        let post_logout_redirect_url = self
            .post_logout_redirect_url
            .take()
            .map(|u| PostLogoutRedirectUrl::new(u).expect("invalid post_logout_redirect_url"));

        Ok(OidcContext(Arc::new(OidcContextInner {
            client,
            handler,
            session: self.cookie_builder.try_build()?,
            login_path: self.login_path,
            logout_path: self.logout_path,
            end_session_url,
            post_logout_redirect_url,
            http_client: self.http_client.unwrap_or_else(default_oidc_http_client),
            scopes: self.scopes,
        })))
    }
}

#[derive(Debug)]
pub enum OidcBuilderError {
    MissingClientId,
    MissingRedirectUrl,
    MissingAuthUrl,
    MissingTokenUrl,
    MissingIssuerUrl,
    MissingJwksUrl,
    InvalidRedirectUrl(openidconnect::url::ParseError),
    InvalidAuthUrl(openidconnect::url::ParseError),
    InvalidTokenUrl(openidconnect::url::ParseError),
    InvalidIssuerUrl(openidconnect::url::ParseError),
    InvalidJwksUrl(openidconnect::url::ParseError),
    WhitespaceInProviderName,
    DiscoveryError(String),
}

impl Error for OidcBuilderError {}

impl Display for OidcBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcBuilderError::MissingClientId => f.write_str("client id is missing"),
            OidcBuilderError::MissingRedirectUrl => f.write_str("redirect url is missing"),
            OidcBuilderError::MissingAuthUrl => f.write_str("authorization url is missing"),
            OidcBuilderError::MissingTokenUrl => f.write_str("token url is missing"),
            OidcBuilderError::MissingIssuerUrl => f.write_str("issuer url is missing"),
            OidcBuilderError::MissingJwksUrl => f.write_str("JWKS url is missing"),
            OidcBuilderError::InvalidRedirectUrl(e) => {
                write!(f, "could not parse redirect url: {e}")
            }
            OidcBuilderError::InvalidAuthUrl(e) => {
                write!(f, "could not parse authorization url: {e}")
            }
            OidcBuilderError::InvalidTokenUrl(e) => {
                write!(f, "could not parse token url: {e}")
            }
            OidcBuilderError::InvalidIssuerUrl(e) => {
                write!(f, "could not parse issuer url: {e}")
            }
            OidcBuilderError::InvalidJwksUrl(e) => {
                write!(f, "could not parse JWKS url: {e}")
            }
            OidcBuilderError::WhitespaceInProviderName => {
                f.write_str("provider name can't contain whitespaces")
            }
            OidcBuilderError::DiscoveryError(e) => {
                write!(f, "OIDC discovery failed: {e}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        after_login::AfterLoginCookies,
        oidc::{OidcBuilderError, OidcContext, OidcHandler, OidcTokenResponse},
    };
    use axum::response::IntoResponse;

    const CLIENT_ID: &str = "test_client_id";
    const CLIENT_SECRET: &str = "test_client_secret";
    const REDIRECT_URL: &str = "http://localhost:3000/auth/callback";
    const ISSUER_URL: &str = "https://accounts.google.com";
    const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

    struct TestHandler;

    impl OidcHandler for TestHandler {
        async fn after_login(
            &self,
            _token_res: OidcTokenResponse<'_>,
            _context: &mut AfterLoginCookies<'_>,
        ) -> impl IntoResponse {
            ()
        }
    }

    #[test]
    fn builder_ok_manual() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(res.is_ok());
    }

    #[test]
    fn missing_client_id() {
        let res = OidcContext::builder("google")
            .client_secret(CLIENT_SECRET)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingClientId)));
    }

    #[test]
    fn missing_redirect_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingRedirectUrl)));
    }

    #[test]
    fn missing_issuer_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingIssuerUrl)));
    }

    #[test]
    fn missing_auth_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingAuthUrl)));
    }

    #[test]
    fn missing_token_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingTokenUrl)));
    }

    #[test]
    fn missing_jwks_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingJwksUrl)));
    }

    #[test]
    fn invalid_redirect_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url("not an url")
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::InvalidRedirectUrl(_))));
    }

    #[test]
    fn provider_name_whitespace() {
        let res = OidcContext::builder("google ")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(
            res,
            Err(OidcBuilderError::WhitespaceInProviderName)
        ));
    }
}
