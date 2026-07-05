pub mod github {
    pub const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
    pub const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
}

pub mod google {
    pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
}

/// Microsoft's multi-tenant (`common`) v2.0 endpoints, accepting both
/// work/school and personal accounts. Single-tenant apps need their
/// tenant ID in the paths instead of `common`.
pub mod microsoft {
    pub const AUTH_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    pub const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
}

/// gitlab.com's endpoints; self-hosted instances have their own URLs.
pub mod gitlab {
    pub const AUTH_URL: &str = "https://gitlab.com/oauth/authorize";
    pub const TOKEN_URL: &str = "https://gitlab.com/oauth/token";
}

pub mod discord {
    pub const AUTH_URL: &str = "https://discord.com/api/oauth2/authorize";
    pub const TOKEN_URL: &str = "https://discord.com/api/oauth2/token";
}

pub mod spotify {
    pub const AUTH_URL: &str = "https://accounts.spotify.com/authorize";
    pub const TOKEN_URL: &str = "https://accounts.spotify.com/api/token";
}

pub mod twitch {
    pub const AUTH_URL: &str = "https://id.twitch.tv/oauth2/authorize";
    pub const TOKEN_URL: &str = "https://id.twitch.tv/oauth2/token";
}
