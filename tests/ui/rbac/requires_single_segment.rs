use axum_security::rbac::requires;

#[requires(Admin)]
async fn handler() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

fn main() {}
