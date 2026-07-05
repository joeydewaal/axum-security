//! Issuer URLs for common OpenID Connect providers, used by the
//! [`OidcClient`](crate::OidcClient) discovery shortcuts.

pub mod google {
    pub const ISSUER_URL: &str = "https://accounts.google.com";
}

pub mod microsoft {
    /// The multi-tenant (`common`) issuer, accepting work/school and personal
    /// accounts. Single-tenant apps discover their tenant-specific issuer.
    pub const ISSUER_URL_COMMON: &str = "https://login.microsoftonline.com/common/v2.0";
}

pub mod apple {
    pub const ISSUER_URL: &str = "https://appleid.apple.com";
}
