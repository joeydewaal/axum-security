use std::error::Error;

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};
use axum_security::csrf::{CsrfLayer, CsrfToken};
use tokio::net::TcpListener;

async fn form(token: CsrfToken) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CSRF Example</title></head>
<body>
    <h1>CSRF Protected Form</h1>
    <form method="POST" action="/submit">
        <input type="hidden" name="_csrf" value="{csrf}" />
        <label>Message: <input type="text" name="message" /></label>
        <button type="submit">Submit (form)</button>
    </form>

    <hr />
    <h2>Submit via fetch (header)</h2>
    <button id="fetch-btn">Submit with fetch</button>
    <pre id="result"></pre>
    <script>
        document.getElementById("fetch-btn").addEventListener("click", async () => {{
            const res = await fetch("/submit", {{
                method: "POST",
                headers: {{ "x-csrf-token": "{csrf}" }},
            }});
            document.getElementById("result").textContent = res.status + " " + await res.text();
        }});
    </script>
</body>
</html>"#,
        csrf = token.as_str()
    ))
}

async fn submit() -> &'static str {
    "Form submitted successfully!"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let csrf = CsrfLayer::builder()
        .secret("change-me-to-a-real-secret")
        .use_dev_cookie(cfg!(debug_assertions))
        .build();

    let router = Router::new()
        .route("/", get(form))
        .route("/submit", post(submit))
        .layer(csrf);

    println!("Listening on http://localhost:3000");
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    Ok(())
}
