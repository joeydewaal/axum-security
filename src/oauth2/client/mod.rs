use std::sync::Arc;

pub struct OAuth2Client {
    inner: Arc<OAuth2ClientInner>,
}

impl OAuth2Client {
    pub fn build() -> OAuth2ClientBuilder {
        OAuth2ClientBuilder::default()
    }

    pub fn callback_url(&self) -> &str {
        &self.inner.callback_url
    }

    pub fn authorization_url(&self, state: &str) -> (String, String) {
        todo!();
    }

    pub async fn exchange_code(&self, code: &str) -> TokenResponse {
        todo!();
    }
}

struct OAuth2ClientInner {
    client_id: String,
    client_secret: String,
    callback_url: String,
    scopes: Vec<String>,
}

pub struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

impl TokenResponse {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
}

#[derive(Default)]
pub struct OAuth2ClientBuilder {
    client_id: Option<String>,
    client_secret: Option<String>,
    callback_url: Option<String>,
    scopes: Vec<String>,
}

impl OAuth2ClientBuilder {
    pub fn build(self) -> OAuth2Client {
        OAuth2Client {
            inner: Arc::new(OAuth2ClientInner {
                client_id: self.client_id.unwrap(),
                client_secret: self.client_secret.unwrap(),
                callback_url: self.callback_url.unwrap(),
                scopes: self.scopes,
            }),
        }
    }

    pub fn callback_url(mut self, url: impl Into<String>) -> Self {
        self.callback_url = Some(url.into());
        self
    }

    pub fn set_callback_url(&mut self, url: impl Into<String>) {
        self.callback_url = Some(url.into());
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn set_client_id(&mut self, client_id: impl Into<String>) {
        self.client_id = Some(client_id.into());
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    pub fn set_client_secret(&mut self, client_secret: impl Into<String>) {
        self.client_secret = Some(client_secret.into());
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn set_scopes(&mut self, scopes: &[&str]) {
        self.scopes = scopes.iter().map(|s| s.to_string()).collect();
    }
}
