use axum_security::rbac::requires;

#[requires("admin")]
async fn handler() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

fn main() {}
