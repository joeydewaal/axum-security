use std::borrow::Cow;

use cookie_monster::Cookie;
use uuid::Uuid;

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::now_v7().to_string())
    }

    pub fn from_cookie(cookie: &Cookie) -> Self {
        SessionId(cookie.value().to_string())
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<SessionId> for Cow<'static, str> {
    fn from(value: SessionId) -> Self {
        Cow::Owned(value.0)
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self(value)
    }
}
