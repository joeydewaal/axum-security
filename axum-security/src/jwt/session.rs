use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

#[derive(Clone, Debug)]
pub struct Jwt<T>(pub T);

impl<S, T> FromRequestParts<S> for Jwt<T>
where
    S: Send + Sync,
    T: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(session) = parts.extensions.remove::<Jwt<T>>() {
            Ok(session)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod extract_jwt {
    use axum::{
        extract::FromRequestParts,
        http::{Request, StatusCode},
    };

    use crate::jwt::Jwt;

    #[tokio::test]
    async fn extract() {
        let jwt = Jwt(1i32);

        let (mut parts, _) = Request::builder()
            .extension(jwt.clone())
            .body(())
            .unwrap()
            .into_parts();

        let extracted_jwt = Jwt::<i32>::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert!(jwt.0 == extracted_jwt.0);
    }

    #[tokio::test]
    async fn extract_rejection() {
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();

        let rejection = Jwt::<i32>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();

        assert!(rejection == StatusCode::UNAUTHORIZED);
    }
}
