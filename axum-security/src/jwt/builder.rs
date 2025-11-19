use std::{borrow::Cow, marker::PhantomData, sync::Arc};

use axum::http::{
    HeaderMap, HeaderName,
    header::{AUTHORIZATION, AsHeaderName, IntoHeaderName},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Serialize, de::DeserializeOwned};

use crate::utils::get_env;

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
    header: HeaderName,
    prefix: Cow<'static, str>,
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
    pub fn decode_from_header_value(&self, header: impl AsRef<str>) -> Option<T> {
        let mut header = header.as_ref();

        let prefix_len = self.0.prefix.len();

        if header.len() < prefix_len {
            return None;
        }

        if !header[..prefix_len].eq_ignore_ascii_case(&self.0.prefix) {
            return None;
        }

        header = &header[prefix_len..];

        decode(header, &self.0.decoding_key, &self.0.validation)
            .ok()
            .map(|t| t.claims)
    }

    pub fn decode_from_headers(&self, headers: &HeaderMap) -> Option<T> {
        let mut authorization_header = headers.get(&self.0.header)?.to_str().ok()?;

        self.decode_from_header_value(authorization_header)
    }
}

pub struct JwtContextBuilder {
    encoding_key: Option<EncodingKey>,
    decoding_key: Option<DecodingKey>,
    jwt_header: Header,
    validation: Validation,
    header: HeaderName,
    prefix: Cow<'static, str>,
}

impl JwtContextBuilder {
    pub fn new() -> Self {
        JwtContextBuilder {
            encoding_key: None,
            decoding_key: None,
            jwt_header: Header::default(),
            validation: Validation::default(),
            header: AUTHORIZATION,
            prefix: Cow::Borrowed("Bearer "),
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

    pub fn header(mut self, header: impl AsRef<[u8]>) -> Self {
        self.header = HeaderName::from_bytes(header.as_ref()).unwrap();
        self
    }

    pub fn prefix(mut self, prefix: impl Into<Cow<'static, str>>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn build<T>(self) -> JwtContext<T> {
        JwtContext(Arc::new(JwtContextInner {
            encoding_key: self.encoding_key.unwrap(),
            decoding_key: self.decoding_key.unwrap(),
            jwt_header: self.jwt_header,
            validation: self.validation,
            header: self.header,
            data: PhantomData {},
            prefix: self.prefix,
        }))
    }
}

#[cfg(test)]
mod test {
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use serde::{Deserialize, Serialize};

    use crate::jwt::JwtContext;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct AT {
        first: usize,
        second: usize,
        exp: u64,
    }

    #[test]
    fn test_prefix_default() {
        let context = JwtContext::builder().jwt_secret("TEST").build::<AT>();

        let at = AT {
            first: 1,
            second: 2,
            exp: jsonwebtoken::get_current_timestamp() + 10_000,
        };

        let token = context.encode_token(&at).unwrap();

        assert_eq!(
            at,
            context
                .decode_from_header_value(format!("Bearer {token}"))
                .unwrap()
        );
        assert_eq!(
            at,
            context
                .decode_from_header_value(format!("bearer {token}"))
                .unwrap()
        );

        assert!(
            context
                .decode_from_header_value(format!("bearer{token}"))
                .is_none()
        );

        assert!(
            context
                .decode_from_header_value(format!("beare {token}"))
                .is_none()
        );
    }
}
