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
#[non_exhaustive]
pub enum HttpClient {
    #[cfg(feature = "reqwest")]
    Reqwest(reqwest::Client),
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
}
