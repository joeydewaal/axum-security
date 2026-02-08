# axum-security
A security toolbox for the Axum library.

### Features
* `cookie`, adds support for cookie sessions.
* `jwt`, adds support for jwt sessions.
* `oauth2`, adds support for oauth2.
* `jiff`, adds support for the [jiff](https://docs.rs/jiff/latest/jiff/) crate.
* `chrono`, adds support for the [chrono](https://docs.rs/chrono/latest/chrono/) crate.
* `time`, adds support for the [time](https://docs.rs/time/latest/time/index.html) crate.


## Cookie sessions

```rust
use axum::response::IntoResponse;
use cookie_monster::{Cookie, CookieJar, SameSite};

static COOKIE_NAME: &str = "session";

async fn handler(mut jar: CookieJar) -> impl IntoResponse {
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        // Remove cookie
        println!("Removing cookie {cookie:?}");
        jar.remove(Cookie::named(COOKIE_NAME));
    } else {
        // Set cookie.
        let cookie = Cookie::build(COOKIE_NAME, "hello, world")
        .http_only()
        .same_site(SameSite::Strict);

        println!("Setting cookie {cookie:?}");
        jar.add(cookie);
    }
    // Return the jar so the cookies are updated
   jar
}
```

### Honorable mention
This crate takes a lot of inspiration from the [cookie](https://crates.io/crates/cookie) crate.


### License
This project is licensed under the [MIT license].

[MIT license]: https://github.com/joeydewaal/axum-security/blob/main/LICENSE
