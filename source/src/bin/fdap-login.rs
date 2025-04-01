pub mod fdaploginlib;

use {
    aargvark::{
        traits_impls::AargvarkJson,
        vark,
        Aargvark,
    },
    ed25519_dalek::pkcs8::EncodePrivateKey,
    fdap_oidc::interface::config::Config,
    fdaploginlib::state::State,
    governor::Quota,
    http::{
        Uri,
    },
    htwrap::{
        htserve::{
            self,
            forwarded::get_original_base_url,
            handler::{
                HandlerArgs,
                PathRouter,
            },
        },
        url::UriJoin,
    },
    loga::{
        ea,
        fatal,
        ErrContext,
        Log,
        ResultContext,
    },
    moka::future::Cache,
    openidconnect::core::CoreEdDsaPrivateSigningKey,
    rand::thread_rng,
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
struct Args {
    config: AargvarkJson<Config>,
    validate: Option<()>,
}

fn get_base_url(args: &HandlerArgs) -> Result<Uri, loga::Error> {
    let forwarded = htserve::forwarded::parse_all_forwarded(&args.head.headers).unwrap_or_default();
    let original_url = get_original_base_url(&forwarded).unwrap_or(args.head.uri.clone());
    let mut path = args.head.uri.path();
    if path == "/" {
        path = "";
    }
    return Ok(
        original_url
            .trim_suffix(path)
            .context_with(
                "Invalid forwarded header/current URL missing subpath",
                ea!(original_url = original_url, subpath = args.subpath),
            )?,
    );
}

async fn main1() -> Result<(), loga::Error> {
    let args = vark::<Args>();
    let config = args.config.value;
    if args.validate.is_some() {
        return Ok(());
    }
    let tm = TaskManager::new();
    let log = Log::new_root(loga::INFO);
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
            &ed25519_dalek::SigningKey::generate(&mut thread_rng()).to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap(),
            None,
        ).unwrap(),
        static_dir: config.static_dir,
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
            for (k, v) in fdaploginlib::oidc::endpoints(&state) {
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
