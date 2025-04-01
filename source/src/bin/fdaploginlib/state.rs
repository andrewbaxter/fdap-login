use {
    loga::Log,
    moka::future::Cache,
    openidconnect::{
        core::CoreEdDsaPrivateSigningKey,
        Nonce,
    },
    std::{
        net::IpAddr,
        path::PathBuf,
        sync::Arc,
    },
};

pub struct Session {
    pub user_id: String,
}

pub struct AuthorizationCodeData {
    pub nonce: Option<Nonce>,
    pub client_id: String,
    pub session: Arc<Session>,
}

pub struct State {
    pub log: Log,
    pub static_dir: Option<PathBuf>,
    pub fdap: fdap::Client,
    pub sessions: Cache<String, Arc<Session>>,
    pub authorization_codes: Cache<String, Arc<AuthorizationCodeData>>,
    pub authorize_ratelimit: governor::DefaultKeyedRateLimiter<IpAddr>,
    /// Not meaningfully used due to TLS but required by OIDC spec so...
    pub jwt_key: CoreEdDsaPrivateSigningKey,
}
