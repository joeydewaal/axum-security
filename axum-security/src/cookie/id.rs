use std::borrow::Cow;

use cookie_monster::Cookie;
use uuid::Uuid;

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct SessionId(Box<str>);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::now_v7().to_string().into_boxed_str())
    }

    pub fn from_cookie(cookie: &Cookie) -> Self {
        SessionId(cookie.value().into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<SessionId> for Cow<'static, str> {
    fn from(value: SessionId) -> Self {
        Cow::Owned(value.0.into_string())
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self(value.into_boxed_str())
    }
}
