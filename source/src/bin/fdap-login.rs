use {
    aargvark::{
        traits_impls::AargvarkJson,
        vark,
        Aargvark,
    },
    argon2::{
        Argon2,
        PasswordHasher,
    },
    ed25519_dalek::pkcs8::EncodePrivateKey,
    fdap_login::{
        interface::config::Config,
        oidc,
        state::State,
        static_,
    },
    governor::Quota,
    http::Uri,
    htwrap::htserve::{
        self,
        handler::PathRouter,
    },
    loga::{
        fatal,
        ErrContext,
        Log,
        ResultContext,
    },
    moka::future::Cache,
    openidconnect::core::CoreEdDsaPrivateSigningKey,
    password_hash::SaltString,
    rand::{
        rngs::OsRng,
        thread_rng,
    },
    std::{
        collections::BTreeMap,
        sync::Arc,
        time::Duration,
    },
    taskmanager::TaskManager,
    tokio::net::TcpListener,
    tokio_stream::wrappers::TcpListenerStream,
};

#[derive(Aargvark)]
struct RunArgs {
    config: AargvarkJson<Config>,
    validate: Option<()>,
}

#[derive(Aargvark)]
enum Command {
    HashPassword,
    Run(RunArgs),
}

#[derive(Aargvark)]
struct Args {
    command: Command,
}

async fn main1() -> Result<(), loga::Error> {
    let args = vark::<Args>();
    match args.command {
        Command::HashPassword => {
            let pw = rpassword::prompt_password("Enter your password: ")?;
            let pw2 = rpassword::prompt_password("Confirm your password: ")?;
            if pw != pw2 {
                return Err(loga::err("Passwords don't match"));
            }
            println!(
                "{}",
                Argon2::default()
                    .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))
                    .context("Error hashing password")?
            );
        },
        Command::Run(args) => {
            let config = args.config.value;
            if args.validate.is_some() {
                return Ok(());
            }
            let tm = TaskManager::new();
            let log = Log::new_root(if config.debug {
                loga::DEBUG
            } else {
                loga::INFO
            });
            let state = Arc::new(State {
                log: log.clone(),
                fdap: fdap::Client::builder()
                    .with_base_url(Uri::try_from(config.fdap_base_url.0).context("Invalid FDAP base URL")?)
                    .with_token(config.fdap_token)
                    .with_log(log.clone())
                    .build()?,
                sessions: Cache::builder().time_to_idle(Duration::from_secs(60 * 60 * 24 * 90)).build(),
                authorization_codes: Cache::builder().time_to_idle(Duration::from_secs(30)).build(),
                authorize_ratelimit: governor::RateLimiter::keyed(Quota::per_minute(2.try_into().unwrap())),
                jwt_key: CoreEdDsaPrivateSigningKey::from_ed25519_pem(
                    &ed25519_dalek::SigningKey::generate(&mut thread_rng())
                        .to_pkcs8_pem(pkcs8::LineEnding::LF)
                        .unwrap(),
                    None,
                ).unwrap(),
                static_dir: config.static_dir,
                static_etags: Cache::builder().build(),
            });
            tm.critical_stream(
                format!("Http server - {}", config.bind_addr),
                TcpListenerStream::new(
                    TcpListener::bind(&config.bind_addr).await.stack_context(&log, "Error binding to address")?,
                ),
                {
                    let log = log.clone();
                    let state = state.clone();
                    let mut routes = BTreeMap::new();
                    routes.insert("/static".to_string(), static_::endpoint(&state));
                    for (k, v) in oidc::endpoints(&state) {
                        routes.insert(k, v);
                    }
                    let routes =
                        Arc::new(
                            PathRouter::new(
                                routes,
                            ).map_err(
                                |e| loga::agg_err("Invalid paths in router", e.into_iter().map(loga::err).collect()),
                            )?,
                        );
                    move |stream| {
                        let log = log.clone();
                        let routes = routes.clone();
                        async move {
                            let stream = match stream {
                                Ok(s) => s,
                                Err(e) => {
                                    log.log_err(loga::DEBUG, e.context("Error opening peer stream"));
                                    return Ok(());
                                },
                            };
                            tokio::task::spawn({
                                let log = log.clone();
                                async move {
                                    match htserve::handler::root_handle_http(&log, routes, stream).await {
                                        Ok(_) => (),
                                        Err(e) => {
                                            log.log_err(loga::DEBUG, e.context("Error serving connection"));
                                        },
                                    }
                                }
                            });
                            return Ok(());
                        }
                    }
                },
            );
            tm.join(&log).await?;
        },
    }
    return Ok(());
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match main1().await {
        Ok(_) => (),
        Err(e) => {
            fatal(e);
        },
    }
}
