// mod csp;
mod hsts;

pub use hsts::{StrictTransportSecurity, StrictTransportSecurityBuilderError};

#[macro_export]
macro_rules! define_header {
    (
        $struct_name:ident($header_name:ident = $header_value:literal),
        $($const_name:ident => $value:literal),+ $(,)?
    ) => {
        const $header_name: ::http::HeaderName = ::http::HeaderName::from_static($header_value);


        #[derive(Clone)]
        pub struct $struct_name {
            header_value: ::http::HeaderValue,
        }

        impl $struct_name {
            $(
                pub const $const_name: $struct_name = Self {
                    header_value: ::http::HeaderValue::from_static($value),
                };
            )+
        }

        impl<S> tower::Layer<S> for $struct_name {
            type Service = $crate::utils::headers::InsertHeadersService<S>;

            fn layer(&self, inner: S) -> Self::Service {
                $crate::utils::headers::InsertHeadersService {
                    header_name: $header_name,
                    header_value: self.header_value.clone(),
                    inner,
                }
            }
        }
    };
}

define_header!(
    CrossOriginEmbedderPolicy(CROSS_ORIGIN_EMBEDDER_POLICY = "cross-origin-embedder-policy"),
    UNSAFE_NONE => "unsafe-none",
    REQUIRE_CORP => "require-corp",
    CREDENTIALLESS => "credentialless",
);

define_header!(
    CrossOriginOpenerPolicy(CROSS_ORIGIN_OPENER_POLICY = "cross-origin-opener-policy"),
    UNSAFE_NONE => "unsafe-none",
    SAME_ORIGIN_ALLOW_POPUPS => "same-origin-allow-popups",
    SAME_ORIGIN => "same-origin",
    NOOPENER_ALLOW_POPUPS => "noopener-allow-popups"
);

define_header!(
    CrossOriginResourcePolicy(CROSS_ORIGIN_RESOURCE_POLICY = "cross-origin-resource-policy"),
    SAME_SITE => "same-site",
    SAME_ORIGIN => "same-origin",
    CROSS_ORIGIN => "cross-origin",
);

define_header!(
    OriginAgentCluster(ORIGIN_AGENT_CLUSTER = "origin-agent-cluster"),
    ON => "?1",
    OFF => "?0",
);

define_header!(
    ReferrerPolicy(REFERRER_POLICY = "referer-policy"),
    NO_REFERRER => "no-referrer",
    NO_REFERRER_WHEN_DOWNGRADE => "no-referrer-when-downgrade",
    ORIGIN => "origin",
    ORIGIN_WHEN_CROSS_ORIGIN => "origin-when-cross-origin",
    SAME_ORIGIN => "same-origin",
    STRICT_ORIGIN => "strict-origin",
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN => "strict-origin-when-cross-origin",
    UNSAFE_URL => "unsafe-url",
);

define_header!(
    ContentTypeOptions(X_CONTENT_TYPE_OPTIONS = "x-content-type-options"),
    NO_SNIFF => "nosniff"
);

define_header!(
    DnsPrefetchControl(X_DNS_PREFETCH_CONTROL = "x-dns-prefetch-control"),
    ON => "ON",
    OFF => "OFF",
);

define_header!(
    FrameOptions(X_FRAME_OPTIONS= "x-frame-options"),
    DENY => "DENY",
    SAMEORIGIN => "SAMEORIGIN",
);
