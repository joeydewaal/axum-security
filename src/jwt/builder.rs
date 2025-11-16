use std::{marker::PhantomData, sync::Arc};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Serialize, de::DeserializeOwned};

pub struct JwtContext<T>(Arc<JwtContextInner<T>>);

impl<T> Clone for JwtContext<T> {
    fn clone(&self) -> Self {
        JwtContext(self.0.clone())
    }
}

struct JwtContextInner<T> {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    header: Header,
    validation: Validation,
    data: PhantomData<T>,
}

impl JwtContext<()> {
    pub fn builder() -> JwtContextBuilder {
        JwtContextBuilder::new()
    }
}

impl<T: Serialize> JwtContext<T> {
    pub fn encode_token(&self, data: &T) -> jsonwebtoken::errors::Result<String> {
        encode(&self.0.header, data, &self.0.encoding_key)
    }
}

impl<T: DeserializeOwned> JwtContext<T> {
    pub fn decode_token(&self, headers: &HeaderMap) -> Option<T> {
        let mut authorization_header = headers.get(AUTHORIZATION)?.to_str().ok()?;

        if !authorization_header.starts_with("Bearer ") {
            return None;
        }
        authorization_header = &authorization_header[7..];

        decode(
            authorization_header,
            &self.0.decoding_key,
            &self.0.validation,
        )
        .ok()
        .map(|t| t.claims)
    }
}

#[derive(Default)]
pub struct JwtContextBuilder {
    encoding_key: Option<EncodingKey>,
    decoding_key: Option<DecodingKey>,
    header: Header,
    validation: Validation,
}

impl JwtContextBuilder {
    pub fn new() -> Self {
        JwtContextBuilder::default()
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

    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = validation;
        self
    }

    pub fn header(mut self, header: Header) -> Self {
        self.header = header;
        self
    }

    pub fn build<T>(self) -> JwtContext<T> {
        JwtContext(Arc::new(JwtContextInner {
            encoding_key: self.encoding_key.unwrap(),
            decoding_key: self.decoding_key.unwrap(),
            header: self.header,
            validation: self.validation,
            data: PhantomData {},
        }))
    }
}
