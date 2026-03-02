use std::error::Error;

use axum::{Router, response::IntoResponse, routing::get};
use axum_security::rate_limit::RateLimitLayer;
use tokio::net::TcpListener;

async fn index() -> impl IntoResponse {
    "Hello, world"
}

async fn api() -> impl IntoResponse {
    "API response"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Fixed window: 100 requests per 60 seconds (default algorithm)
    let global_limiter = RateLimitLayer::builder()
        .max_requests(100)
        .window_secs(60)
        .for_smart_ip()
        .build();

    // Token bucket: burst of 10, refill 2 tokens/sec — stricter per-route limit
    let api_limiter = RateLimitLayer::builder()
        .token_bucket(10, 2.0)
        .for_smart_ip()
        .build();

    let router = Router::new()
        .route("/", get(index))
        .route("/api", get(api).layer(api_limiter))
        .layer(global_limiter);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
