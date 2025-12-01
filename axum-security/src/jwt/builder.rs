use std::{borrow::Cow, marker::PhantomData, sync::Arc};

use axum::http::{HeaderMap, HeaderName, header::AUTHORIZATION};
use cookie_monster::CookieJar;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Serialize, de::DeserializeOwned};

use crate::utils::get_env;

static BEARER_PREFIX: &str = "Bearer ";
static EMPTY_PREFIX: &str = "";

pub struct JwtContext<T>(Arc<JwtContextInner<T>>);

impl<T> Clone for JwtContext<T> {
    fn clone(&self) -> Self {
        JwtContext(self.0.clone())
    }
}

struct JwtContextInner<T> {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    jwt_header: Header,
    validation: Validation,
    data: PhantomData<T>,
    extract: ExtractFrom,
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
}

impl<T: DeserializeOwned> JwtContext<T> {
    fn decode(&self, jwt: &str) -> jsonwebtoken::errors::Result<TokenData<T>> {
        decode(jwt, &self.0.decoding_key, &self.0.validation)
    }

    pub fn decode_from_headers(&self, headers: &HeaderMap) -> Option<T> {
        let result = match &self.0.extract {
            ExtractFrom::Cookie(cow) => {
                let jar = CookieJar::from_headers(headers);
                let cookie = jar.get(cow)?;

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

pub fn jwt_from_header_value<'a>(header: &'a str, prefix: &str) -> Option<&'a str> {
    let prefix_len = prefix.len();

    if header.len() < prefix_len {
        return None;
    }

    if !header[..prefix_len].eq_ignore_ascii_case(prefix) {
        return None;
    }

    Some(&header[prefix_len..])
}

pub struct JwtContextBuilder {
    encoding_key: Option<EncodingKey>,
    decoding_key: Option<DecodingKey>,
    jwt_header: Header,
    validation: Validation,
    extract: ExtractFrom,
}

impl Default for JwtContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtContextBuilder {
    pub fn new() -> Self {
        JwtContextBuilder {
            encoding_key: None,
            decoding_key: None,
            jwt_header: Header::default(),
            validation: Validation::default(),
            extract: ExtractFrom::header_with_prefix(AUTHORIZATION, BEARER_PREFIX),
        }
    }

    pub fn encoding_key(mut self, encoding_key: EncodingKey) -> Self {
        self.encoding_key = Some(encoding_key);
        self
    }

    pub fn decoding_key(mut self, decoding_key: DecodingKey) -> Self {
        self.decoding_key = Some(decoding_key);
        self
    }

    pub fn jwt_secret(self, jwt_secret: impl AsRef<[u8]>) -> Self {
        let jwt_secret = jwt_secret.as_ref();
        self.encoding_key(EncodingKey::from_secret(jwt_secret))
            .decoding_key(DecodingKey::from_secret(jwt_secret))
    }

    pub fn jwt_secret_env(self, name: &str) -> Self {
        self.jwt_secret(get_env(name))
    }

    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = validation;
        self
    }

    pub fn jwt_header(mut self, header: Header) -> Self {
        self.jwt_header = header;
        self
    }

    pub fn extract_header_with_prefix(
        mut self,
        header: impl AsRef<[u8]>,
        prefix: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.extract = ExtractFrom::header_with_prefix(
            HeaderName::from_bytes(header.as_ref()).unwrap(),
            prefix.into(),
        );
        self
    }

    pub fn extract_header(mut self, header: impl AsRef<str>) -> Self {
        self.extract = ExtractFrom::header_with_prefix(
            HeaderName::from_bytes(header.as_ref().as_bytes()).unwrap(),
            EMPTY_PREFIX,
        );
        self
    }

    pub fn extract_cookie(mut self, cookie_name: impl Into<Cow<'static, str>>) -> Self {
        self.extract = ExtractFrom::cookie(cookie_name.into());
        self
    }

    pub fn build<T>(self) -> JwtContext<T> {
        JwtContext(Arc::new(JwtContextInner {
            encoding_key: self.encoding_key.unwrap(),
            decoding_key: self.decoding_key.unwrap(),
            jwt_header: self.jwt_header,
            validation: self.validation,
            extract: self.extract,
            data: PhantomData,
        }))
    }
}

pub(crate) enum ExtractFrom {
    Cookie(Cow<'static, str>),
    Header {
        header: HeaderName,
        prefix: Cow<'static, str>,
    },
}

impl ExtractFrom {
    fn cookie(name: Cow<'static, str>) -> Self {
        ExtractFrom::Cookie(name)
    }

    fn header_with_prefix(header: HeaderName, prefix: impl Into<Cow<'static, str>>) -> Self {
        ExtractFrom::Header {
            header,
            prefix: prefix.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    use crate::jwt::JwtContext;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct AT {
        first: usize,
        second: usize,
        exp: u64,
    }

    #[test]
    fn test_prefix_default() {}
}
