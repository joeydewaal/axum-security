#[cfg(feature = "reqwest")]
pub(crate) mod dep_reqwest;

use std::fmt;

use url::Url;

use crate::error::HttpError;

/// The HTTP backend used for token requests.
///
/// A feature-gated enum rather than a trait: enabling a backend feature
/// adds a variant, and the client stays free of type parameters. Backends
/// must never follow redirects; the ones this crate constructs don't.
///
/// `Clone` is cheap — the reqwest backend shares one connection pool across
/// clones — so a single backend can be handed to several clients (e.g.
/// `axum-security-oidc` reuses the login client's backend for discovery and
/// JWKS fetches).
#[derive(Clone)]
#[non_exhaustive]
pub enum HttpClient {
    #[cfg(feature = "reqwest")]
    Reqwest(reqwest::Client),
}

#[cfg(feature = "reqwest")]
impl HttpClient {
    /// The default reqwest backend: redirects never followed, 10 second
    /// timeout — the same client the builder installs when none is given.
    pub fn default_reqwest() -> Self {
        HttpClient::Reqwest(dep_reqwest::default_client())
    }
}

#[cfg(feature = "reqwest")]
impl From<reqwest::Client> for HttpClient {
    fn from(client: reqwest::Client) -> Self {
        HttpClient::Reqwest(client)
    }
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        match *self {
            #[cfg(feature = "reqwest")]
            HttpClient::Reqwest(_) => f.write_str("HttpClient::Reqwest(..)"),
        }
    }
}

/// What the protocol layer needs back from a backend: status, content type
/// and the raw body.
pub(crate) struct FormResponse {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) body: Vec<u8>,
}

/// The response from [`HttpClient::get`]: the HTTP status and the raw body.
///
/// A non-2xx status is not an error here — the caller decides. Reach for this
/// to fetch small JSON documents (OIDC discovery metadata, a JWK set).
pub struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl HttpResponse {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Whether the status is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The raw response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response, returning the owned body.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl HttpClient {
    /// POSTs `application/x-www-form-urlencoded` and returns the raw
    /// response — the one seam every backend implements.
    #[cfg_attr(not(feature = "reqwest"), allow(unused_variables))]
    pub(crate) async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        authorization: Option<&str>,
    ) -> Result<FormResponse, HttpError> {
        match *self {
            #[cfg(feature = "reqwest")]
            HttpClient::Reqwest(ref client) => {
                dep_reqwest::post_form(client, url, form, authorization).await
            }
        }
    }

    /// GETs `url` with `Accept: application/json` and returns the status and
    /// raw body. Redirects are not followed (the backends this crate builds
    /// enforce that). Used by `axum-security-oidc` for discovery and JWKS.
    #[cfg_attr(not(feature = "reqwest"), allow(unused_variables))]
    pub async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
        match *self {
            #[cfg(feature = "reqwest")]
            HttpClient::Reqwest(ref client) => dep_reqwest::get(client, url).await,
        }
    }
}
