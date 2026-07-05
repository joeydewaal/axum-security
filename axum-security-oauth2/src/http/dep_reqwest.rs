use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION};
use url::Url;

use crate::{
    error::{HttpError, HttpErrorKind},
    http::{FormResponse, HttpResponse},
};

/// The default backend: redirects never followed, 10 second timeout.
pub(crate) fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to construct the default reqwest client")
}

pub(crate) async fn post_form(
    client: &reqwest::Client,
    url: &Url,
    form: &[(&str, &str)],
    authorization: Option<&str>,
) -> Result<FormResponse, HttpError> {
    let mut request = client
        .post(url.clone())
        .header(ACCEPT, "application/json")
        .form(form);

    if let Some(authorization) = authorization {
        request = request.header(AUTHORIZATION, authorization);
    }

    let response = request.send().await.map_err(wrap)?;

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    let body = response.bytes().await.map_err(wrap)?.to_vec();

    Ok(FormResponse {
        status,
        content_type,
        body,
    })
}

pub(crate) async fn get(client: &reqwest::Client, url: &Url) -> Result<HttpResponse, HttpError> {
    let response = client
        .get(url.clone())
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(wrap)?;

    let status = response.status().as_u16();
    let body = response.bytes().await.map_err(wrap)?.to_vec();

    Ok(HttpResponse { status, body })
}

fn wrap(error: reqwest::Error) -> HttpError {
    HttpError(HttpErrorKind::Reqwest(error))
}
