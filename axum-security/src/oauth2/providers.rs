pub mod github {
    pub const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
    pub const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
}

pub mod google {
    pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
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
