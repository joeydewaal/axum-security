use std::error::Error;

use axum::{Router, response::IntoResponse, routing::get};
use axum_security::headers::{CrossOriginOpenerPolicy, SecurityHeaders, XssProtection};
use tokio::net::TcpListener;

async fn index() -> impl IntoResponse {
    "Hello, world"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Multiple headers
    let security_layer = SecurityHeaders::recommended()
        .use_dev_headers(cfg!(debug_assertions))
        .add(XssProtection::ZERO);

    // Use an individual header.
    let coop_layer = CrossOriginOpenerPolicy::SAME_ORIGIN;

    let router = Router::new()
        .route("/", get(index))
        .layer(security_layer)
        .layer(coop_layer);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    Ok(())
}
