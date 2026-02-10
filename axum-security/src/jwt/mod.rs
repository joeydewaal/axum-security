mod builder;
mod service;
mod session;

use std::{borrow::Cow, convert::Infallible, marker::PhantomData, sync::Arc};

use axum::extract::{FromRef, FromRequestParts};
pub use builder::{JwtBuilderError, JwtContextBuilder};
#[cfg(feature = "cookie")]
use cookie_monster::{Cookie, CookieBuilder};
use http::{HeaderMap, HeaderName, request::Parts};
use jsonwebtoken::{TokenData, decode, encode};
use serde::{Serialize, de::DeserializeOwned};
pub use session::Jwt;

pub use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
    get_current_timestamp,
};

pub struct JwtContext<T>(Arc<JwtContextInner<T>>);

struct JwtContextInner<T> {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    jwt_header: Header,
    validation: Validation,
    data: PhantomData<T>,
    extract: ExtractFrom,
}

pub(crate) enum ExtractFrom {
    #[cfg(feature = "cookie")]
    Cookie(Box<CookieBuilder>),
    Header {
        header: HeaderName,
        prefix: Cow<'static, str>,
    },
}
impl JwtContext<()> {
    pub fn builder() -> JwtContextBuilder {
        JwtContextBuilder::new()
    }
}

impl<T: Serialize> JwtContext<T> {
    pub fn encode_token(&self, data: &T) -> jsonwebtoken::errors::Result<String> {
        encode(&self.0.jwt_header, data, &self.0.encoding_key)
    }

    #[cfg(feature = "cookie")]
    pub fn encode_token_to_cookie(&self, data: &T) -> jsonwebtoken::errors::Result<Cookie> {
        let token = encode(&self.0.jwt_header, data, &self.0.encoding_key)?;
        match &self.0.extract {
            ExtractFrom::Cookie(cookie_builder) => Ok(cookie_builder.clone().value(token).build()),
            ExtractFrom::Header { .. } => panic!("no cookie config set"),
        }
    }
}

impl<T: DeserializeOwned> JwtContext<T> {
    pub fn decode(&self, jwt: impl AsRef<[u8]>) -> Result<TokenData<T>, JwtError> {
        decode(jwt.as_ref(), &self.0.decoding_key, &self.0.validation)
    }

    pub(crate) fn decode_from_headers(&self, headers: &HeaderMap) -> Option<T> {
        let result = match &self.0.extract {
            #[cfg(feature = "cookie")]
            ExtractFrom::Cookie(cookie) => {
                let jar = cookie_monster::CookieJar::from_headers(headers);
                let cookie = jar.get(cookie.get_name())?;

                self.decode(cookie.value())
            }
            ExtractFrom::Header { header, prefix } => {
                let authorization_header = headers.get(header)?.to_str().ok()?;

                let jwt = jwt_from_header_value(authorization_header, prefix)?;
                self.decode(jwt)
            }
        };

        result.ok().map(|t| t.claims)
    }
}

fn jwt_from_header_value<'a>(header: &'a str, prefix: &str) -> Option<&'a str> {
    let prefix_len = prefix.len();

    if header.len() < prefix_len {
        return None;
    }

    if !header[..prefix_len].eq_ignore_ascii_case(prefix) {
        return None;
    }

    Some(&header[prefix_len..])
}

impl<S, U> FromRequestParts<S> for JwtContext<U>
where
    JwtContext<U>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}

impl<T> Clone for JwtContext<T> {
    fn clone(&self) -> Self {
        JwtContext(self.0.clone())
    }
}
