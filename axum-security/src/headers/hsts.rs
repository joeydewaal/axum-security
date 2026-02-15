use std::time::Duration;

use axum::http::{HeaderValue, header::STRICT_TRANSPORT_SECURITY};
use http::HeaderName;
use tower::Layer;

use crate::{headers::IntoSecurityHeader, utils::headers::InsertHeadersService};

const PRELOAD_MIN_MAX_AGE: u64 = 365 * 24 * 60 * 60;

#[derive(Clone)]
pub struct StrictTransportSecurity {
    header_value: HeaderValue,
}

impl StrictTransportSecurity {
    pub fn builder() -> HstsBuilder {
        HstsBuilder {
            max_age: None,
            include_subdomains: false,
            preload: false,
        }
    }
}

pub struct HstsBuilder {
    max_age: Option<u64>,
    include_subdomains: bool,
    preload: bool,
}

impl HstsBuilder {
    pub fn max_age(mut self, duration: Duration) -> Self {
        self.max_age = Some(duration.as_secs());
        self
    }

    pub fn max_age_seconds(mut self, max_age: u64) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// 24h in a day
    pub fn max_age_days(self, max_age: u64) -> Self {
        self.max_age_seconds(max_age * 24 * 60 * 60)
    }

    /// 365 days in a year
    pub fn max_age_years(self, max_age: u64) -> Self {
        self.max_age_days(max_age * 365)
    }

    pub fn include_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }

    pub fn preload(mut self) -> Self {
        self.preload = true;
        self
    }

    pub fn try_build(self) -> Result<StrictTransportSecurity, StrictTransportSecurityBuilderError> {
        let Some(max_age) = self.max_age else {
            return Err(StrictTransportSecurityBuilderError::NoMaxAge);
        };

        let mut header = format!("max-age={max_age}");

        if self.include_subdomains {
            header.push_str("; includeSubDomains");
        }

        if self.preload {
            if max_age < PRELOAD_MIN_MAX_AGE {
                return Err(StrictTransportSecurityBuilderError::InvalidMaxAge);
            } else if !self.include_subdomains {
                return Err(StrictTransportSecurityBuilderError::IncludeSubdomainsRequired);
            }

            header.push_str("; preload");
        }

        let header_value =
            HeaderValue::from_str(&header).expect("Hsts header does not contain invalid bytes");

        Ok(StrictTransportSecurity { header_value })
    }

    pub fn build(self) -> StrictTransportSecurity {
        self.try_build().unwrap()
    }
}

#[derive(Debug)]
pub enum StrictTransportSecurityBuilderError {
    NoMaxAge,
    InvalidMaxAge,
    IncludeSubdomainsRequired,
}

impl<S> Layer<S> for StrictTransportSecurity {
    type Service = InsertHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InsertHeadersService {
            inner,
            header_name: STRICT_TRANSPORT_SECURITY,
            header_value: self.header_value.clone(),
        }
    }
}

impl IntoSecurityHeader for StrictTransportSecurity {
    fn into_header(self) -> (HeaderName, HeaderValue) {
        (STRICT_TRANSPORT_SECURITY, self.header_value)
    }
}

impl IntoSecurityHeader for HstsBuilder {
    fn into_header(self) -> (HeaderName, HeaderValue) {
        self.build().into_header()
    }
}

#[cfg(test)]
mod hsts_tests {
    use axum::{Router, body::Body, extract::Request, http::header::STRICT_TRANSPORT_SECURITY};

    use crate::headers::{StrictTransportSecurity, StrictTransportSecurityBuilderError};
    use tower::ServiceExt;

    #[test]
    fn builder() {
        let hsts = StrictTransportSecurity::builder().try_build();
        assert!(matches!(
            hsts,
            Err(StrictTransportSecurityBuilderError::NoMaxAge)
        ));

        let hsts = StrictTransportSecurity::builder()
            .max_age_days(364)
            .preload()
            .try_build();
        assert!(matches!(
            hsts,
            Err(StrictTransportSecurityBuilderError::InvalidMaxAge)
        ));

        let hsts = StrictTransportSecurity::builder()
            .max_age_years(1)
            .preload()
            .try_build();
        assert!(matches!(
            hsts,
            Err(StrictTransportSecurityBuilderError::IncludeSubdomainsRequired)
        ));
    }

    #[test]
    fn header() {
        let hsts = StrictTransportSecurity::builder()
            .max_age_seconds(1)
            .build();
        assert!(hsts.header_value == "max-age=1");

        let hsts = StrictTransportSecurity::builder()
            .max_age_seconds(1)
            .include_subdomains()
            .build();
        assert!(hsts.header_value == "max-age=1; includeSubDomains");

        let hsts = StrictTransportSecurity::builder()
            .max_age_years(1)
            .include_subdomains()
            .preload()
            .build();
        assert!(hsts.header_value == "max-age=31536000; includeSubDomains; preload");
    }

    #[tokio::test]
    async fn basic() {
        let hsts = StrictTransportSecurity::builder()
            .max_age_years(1)
            .include_subdomains()
            .preload()
            .build();

        let router = Router::<()>::new().layer(hsts);

        let res = router
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            res.headers()[STRICT_TRANSPORT_SECURITY],
            "max-age=31536000; includeSubDomains; preload"
        );
    }
}
