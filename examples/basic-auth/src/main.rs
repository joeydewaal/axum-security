use std::error::Error;

use axum::{Router, http::StatusCode, routing::get};
use axum_security::basic_auth::{BasicAuth, BasicAuthLayer, BasicAuthenticator};
use tokio::net::TcpListener;

#[derive(Clone)]
struct User {
    username: String,
}

struct MyAuth;

impl BasicAuthenticator for MyAuth {
    type User = User;
    type Error = StatusCode;

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, StatusCode> {
        // Replace this with a real database lookup.
        if username == "admin" && password == "secret" {
            Ok(Some(User {
                username: username.to_owned(),
            }))
        } else {
            Ok(None)
        }
    }
}

async fn hello(BasicAuth(user): BasicAuth<User>) -> String {
    format!("Hello, {}!", user.username)
}

async fn greet(auth: Option<BasicAuth<User>>) -> String {
    if let Some(BasicAuth(user)) = auth {
        format!("Welcome back, {}!", user.username)
    } else {
        "Welcome, guest!".to_owned()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let router = Router::new()
        .route("/", get(greet))
        .route("/hello", get(hello))
        .layer(BasicAuthLayer::new(MyAuth));

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    println!("Listening on http://0.0.0.0:3000");
    println!("Try: curl -u admin:secret http://localhost:3000/hello");

    axum::serve(listener, router).await?;
    Ok(())
}
