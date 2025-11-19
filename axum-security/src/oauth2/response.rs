pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

impl TokenResponse {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
}
