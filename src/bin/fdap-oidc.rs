use {
    aargvark::{
        traits_impls::AargvarkJson,
        vark,
        Aargvark,
    },
    askama::DynTemplate,
    chrono::Utc,
    cookie::{
        Cookie,
        CookieBuilder,
    },
    ed25519_dalek::pkcs8::EncodePrivateKey,
    fdap_oidc::interface::{
        self,
        config::Config,
    },
    flowcontrol::{
        shed,
        ta_return,
    },
    governor::Quota,
    http::{
        header::{
            CONTENT_TYPE,
            COOKIE,
        },
        Method,
        Response,
        StatusCode,
        Uri,
    },
    http_body_util::BodyExt,
    htwrap::{
        handler,
        htserve::{
            self,
            forwarded::get_original_base_url,
            handler::{
                Handler,
                HandlerArgs,
            },
            responses::{
                body_empty,
                body_full,
                response_200_json,
                response_400,
                response_404,
                response_429,
                response_503,
                Body,
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
    openidconnect::{
        core::{
            CoreEdDsaPrivateSigningKey,
            CoreIdTokenFields,
            CoreJwsSigningAlgorithm,
            CoreProviderMetadata,
            CoreResponseType,
            CoreSubjectIdentifierType,
        },
        Audience,
        AuthUrl,
        EmptyAdditionalClaims,
        EmptyAdditionalProviderMetadata,
        EmptyExtraTokenFields,
        IdToken,
        IdTokenClaims,
        IssuerUrl,
        JsonWebKeySetUrl,
        PrivateSigningKey,
        ResponseTypes,
        Scope,
        StandardClaims,
        SubjectIdentifier,
        TokenUrl,
    },
    password_hash::PasswordHash,
    path_absolutize::Absolutize,
    rand::{
        distributions::DistString,
        thread_rng,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    serde_json::json,
    std::{
        net::{
            IpAddr,
        },
        path::PathBuf,
        sync::Arc,
        time::Duration,
    },
    taskmanager::TaskManager,
    tokio::net::TcpListener,
    tokio_stream::wrappers::TcpListenerStream,
};

struct Session {
    user_id: String,
}

struct AuthorizationCodeData {
    client_id: String,
    session: Arc<Session>,
}

struct State {
    log: Log,
    static_dir: Option<PathBuf>,
    fdap: fdap::Client,
    sessions: Cache<String, Arc<Session>>,
    authorization_codes: Cache<String, Arc<AuthorizationCodeData>>,
    authorize_ratelimit: governor::DefaultKeyedRateLimiter<IpAddr>,
    /// Not meaningfully used due to TLS but required by OIDC spec so...
    jwt_key: CoreEdDsaPrivateSigningKey,
}

#[derive(Aargvark)]
struct Args {
    config: AargvarkJson<Config>,
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
    let tm = TaskManager::new();
    let args = vark::<Args>();
    let config = args.config.value;
    let log = Log::new_root(loga::INFO);
    const PATH_AUTHORIZE: &str = "authorize";
    const PATH_JWKS: &str = "jwks";
    const PATH_TOKEN: &str = "token";
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
            let routes =
                Arc::new(
                    htserve::handler::PathRouter::new(
                        [
                            //. .
                            ("/.well-known/openid-configuration".to_string(), {
                                Box::new(handler!(()(args -> Body) {
                                    let Ok(base_url) = get_base_url(&args) else {
                                        return response_400("Invalid URL");
                                    };
                                    let well_known =
                                        CoreProviderMetadata::new(
                                            IssuerUrl::new(base_url.to_string()).unwrap(),
                                            AuthUrl::new(base_url.join(PATH_AUTHORIZE).to_string()).unwrap(),
                                            JsonWebKeySetUrl::new(base_url.join(PATH_JWKS).to_string()).unwrap(),
                                            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
                                            vec![CoreSubjectIdentifierType::Public],
                                            vec![CoreJwsSigningAlgorithm::EdDsaEd25519],
                                            EmptyAdditionalProviderMetadata {},
                                        )
                                            .set_token_endpoint(
                                                Some(TokenUrl::new(base_url.join(PATH_TOKEN).to_string()).unwrap()),
                                            )
                                            .set_scopes_supported(Some(vec![Scope::new("openid".to_string())]));
                                    return response_200_json(&well_known);
                                })) as Box<dyn Handler<Body>>
                            }),
                            (format!("/{}", PATH_JWKS), {
                                Box::new(handler!((state: Arc < State >)(_args -> Body) {
                                    return response_200_json(json!({
                                        "keys": vec ![state.jwt_key.as_verification_key()]
                                    }));
                                }))
                            }),
                            (format!("/{}", PATH_AUTHORIZE), {
                                Box::new(handler!((state: Arc < State >)(args -> Body) {
                                    let forwarded =
                                        htserve::forwarded::parse_all_forwarded(
                                            &args.head.headers,
                                        ).unwrap_or_default();
                                    let peer_ip =
                                        forwarded
                                            .iter()
                                            .flat_map(|x| x.for_.iter())
                                            .map(|x| x.0)
                                            .next()
                                            .unwrap_or(args.peer_addr.ip());
                                    if !state.authorize_ratelimit.check_key(&peer_ip).is_ok() {
                                        return response_429();
                                    };
                                    const COOKIE_SESSION: &str = "session";

                                    #[derive(Serialize, Deserialize)]
                                    struct OidcParams {
                                        client_id: String,
                                        response_type: String,
                                        state: String,
                                        scope: String,
                                        #[serde(with = "http_serde::uri")]
                                        redirect_uri: Uri,
                                    }

                                    let oidc_params = match serde_json::from_str::<OidcParams>(&args.query) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            return response_400(
                                                format_args!("Invalid OIDC parameters in request query string: {}", e),
                                            );
                                        },
                                    };
                                    if oidc_params.response_type != "code" {
                                        return response_400(
                                            format_args!(
                                                "Unsupported OIDC response type [{}]",
                                                oidc_params.response_type
                                            ),
                                        );
                                    }
                                    if oidc_params.scope != "openid" {
                                        return response_400(
                                            format_args!("Unsupported OIDC scopes [{}]", oidc_params.response_type),
                                        );
                                    }

                                    fn resp_auth_redirect(
                                        oidc_params: &OidcParams,
                                        session_id: Option<&str>,
                                        authorization_code: &str,
                                    ) -> Response<Body> {
                                        let mut resp =
                                            http::Response::builder().status(http::StatusCode::TEMPORARY_REDIRECT);
                                        if let Some(session_id) = session_id {
                                            resp =
                                                resp.header(
                                                    http::header::SET_COOKIE,
                                                    CookieBuilder::new(COOKIE_SESSION, session_id)
                                                        .http_only(true)
                                                        .secure(true)
                                                        .permanent()
                                                        .build()
                                                        .to_string(),
                                                );
                                        }

                                        #[derive(Serialize)]
                                        struct OidcReturnParams<'a> {
                                            state: &'a str,
                                            code: &'a str,
                                        }

                                        resp =
                                            resp.header(
                                                http::header::LOCATION,
                                                format!(
                                                    "{}?{}",
                                                    oidc_params.redirect_uri,
                                                    serde_urlencoded::to_string(&OidcReturnParams {
                                                        state: &oidc_params.state,
                                                        code: &authorization_code,
                                                    }).unwrap()
                                                ),
                                            );
                                        return resp.body(body_empty()).unwrap();
                                    }

                                    shed!{
                                        let Some(cookies) = args.head.headers.get(COOKIE) else {
                                            break;
                                        };
                                        let Ok(cookies) = cookies.to_str() else {
                                            break;
                                        };
                                        for c in Cookie::split_parse(cookies) {
                                            let Ok(c) = c else {
                                                continue;
                                            };
                                            if c.name() != COOKIE_SESSION {
                                                continue;
                                            };
                                            let Some(session) = state.sessions.get(c.value()).await else {
                                                break;
                                            };
                                            let authorization_code =
                                                rand
                                                ::distributions
                                                ::Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
                                            let out = resp_auth_redirect(&oidc_params, None, &authorization_code);
                                            state
                                                .authorization_codes
                                                .insert(authorization_code, Arc::new(AuthorizationCodeData {
                                                    client_id: oidc_params.client_id,
                                                    session: session,
                                                }))
                                                .await;
                                            return out;
                                        }
                                    }
                                    shed!{
                                        if args.head.method == Method::POST {
                                            #[derive(Deserialize)]
                                            struct FormResp {
                                                user: String,
                                                password: String,
                                            }

                                            let Ok(body) = args.body.collect().await else {
                                                break;
                                            };
                                            let body = body.to_bytes();
                                            let resp = match serde_urlencoded::from_bytes::<FormResp>(&body) {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    state
                                                        .log
                                                        .log_err(
                                                            loga::DEBUG,
                                                            e.context_with(
                                                                "Failed to parse login form response",
                                                                ea!(body = String::from_utf8_lossy(&body)),
                                                            ),
                                                        );
                                                    break;
                                                },
                                            };
                                            let user =
                                                match state
                                                    .fdap
                                                    .user_get::<&str, _>(&resp.user, ["fdap-oidc"], 10000)
                                                    .await {
                                                    Ok(Some(p)) => p,
                                                    Ok(None) => {
                                                        break;
                                                    },
                                                    Err(e) => {
                                                        state
                                                            .log
                                                            .log_err(
                                                                loga::WARN,
                                                                e.context("Error looking up user in FDAP"),
                                                            );
                                                        break;
                                                    },
                                                };
                                            let user = match serde_json::from_value::<interface::fdap::User>(user) {
                                                Ok(u) => u,
                                                Err(e) => {
                                                    state
                                                        .log
                                                        .log_err(
                                                            loga::WARN,
                                                            e.context_with(
                                                                "Password returned from FDAP is not a string",
                                                                ea!(user = resp.user),
                                                            ),
                                                        );
                                                    break;
                                                },
                                            };
                                            let password = match PasswordHash::new(&user.password) {
                                                Ok(p) => p,
                                                Err(e) => {
                                                    state
                                                        .log
                                                        .log_err(
                                                            loga::WARN,
                                                            loga::err(
                                                                e,
                                                            ).context_with(
                                                                "Password for user in FDAP is not in valid PWC format",
                                                                ea!(user = resp.user),
                                                            ),
                                                        );
                                                    break;
                                                },
                                            };
                                            if password
                                                .verify_password(
                                                    &[&argon2::Argon2::default(), &scrypt::Scrypt],
                                                    &resp.password,
                                                )
                                                .is_err() {
                                                break;
                                            }
                                            let session_id =
                                                rand
                                                ::distributions
                                                ::Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
                                            let authorization_code =
                                                rand
                                                ::distributions
                                                ::Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
                                            let out =
                                                resp_auth_redirect(
                                                    &oidc_params,
                                                    Some(&session_id),
                                                    &authorization_code,
                                                );
                                            let session = Arc::new(Session { user_id: resp.user });
                                            state.sessions.insert(session_id, session.clone()).await;
                                            state
                                                .authorization_codes
                                                .insert(authorization_code, Arc::new(AuthorizationCodeData {
                                                    client_id: oidc_params.client_id,
                                                    session: session,
                                                }))
                                                .await;
                                            return out;
                                        }
                                    }

                                    #[derive(askama::Template)]
                                    #[template(path = "auth_form.html")]
                                    struct AuthFormParams<'a> {
                                        oidc_params: &'a str,
                                    }

                                    return http::Response::builder()
                                        .status(http::StatusCode::OK)
                                        .header(CONTENT_TYPE, "text/html")
                                        .body(
                                            body_full(
                                                AuthFormParams { oidc_params: &args.query }
                                                    .dyn_render()
                                                    .unwrap()
                                                    .into_bytes(),
                                            ),
                                        )
                                        .unwrap();
                                }))
                            }),
                            (format!("/{}", PATH_TOKEN), {
                                Box::new(handler!((state: Arc < State >)(args -> Body) {
                                    fn resp_err() -> Response<Body> {
                                        return Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .header(CONTENT_TYPE, "application/json")
                                            .body(body_full(b"{\"error\": \"invalid_request\"}".to_vec()))
                                            .unwrap();
                                    }

                                    let Ok(base_url) = get_base_url(&args) else {
                                        return resp_err();
                                    };
                                    let Ok(body) = args.body.collect().await else {
                                        return resp_err();
                                    };

                                    #[derive(Deserialize)]
                                    struct OidcParams {
                                        code: String,
                                    }

                                    let Ok(oidc_params) =
                                        serde_urlencoded::from_bytes::<OidcParams>(&body.to_bytes()) else {
                                            return resp_err();
                                        };
                                    let Some(code_data) =
                                        state.authorization_codes.remove(&oidc_params.code).await else {
                                            return resp_err();
                                        };

                                    #[derive(Serialize)]
                                    struct OidcReturnParams<'a> {
                                        access_token: &'a str,
                                        token_type: &'a str,
                                        refresh_token: &'a str,
                                        expires_in: u32,
                                        id_token: CoreIdTokenFields,
                                    }

                                    return response_200_json(OidcReturnParams {
                                        access_token: "",
                                        token_type: "bearer",
                                        refresh_token: "",
                                        expires_in: 1,
                                        id_token: CoreIdTokenFields::new(
                                            Some(
                                                IdToken::new(
                                                    IdTokenClaims::new(
                                                        IssuerUrl::new(base_url.to_string()).unwrap(),
                                                        vec![Audience::new(code_data.client_id.clone())],
                                                        Utc::now() + chrono::Duration::hours(24),
                                                        Utc::now(),
                                                        StandardClaims::new(
                                                            SubjectIdentifier::new(code_data.session.user_id.clone()),
                                                        ),
                                                        EmptyAdditionalClaims {},
                                                    ),
                                                    &state.jwt_key,
                                                    CoreJwsSigningAlgorithm::None,
                                                    None,
                                                    None,
                                                ).unwrap(),
                                            ),
                                            EmptyExtraTokenFields {},
                                        ),
                                    });
                                }))
                            }),
                            ("".to_string(), {
                                Box::new(handler!((state: Arc < State >)(args -> Body) {
                                    let Some(static_dir) = &state.static_dir else {
                                        return response_404();
                                    };
                                    match async {
                                        ta_return!(Response < Body >, loga::Error);
                                        let subpath = args.subpath.strip_prefix("/").unwrap_or(&args.subpath);
                                        let path = static_dir.join(subpath).absolutize().unwrap().to_path_buf();
                                        if !path.starts_with(&static_dir) {
                                            return Ok(response_404());
                                        }
                                        let mime = mime_guess::from_path(&path).first_or_octet_stream();
                                        return Ok(
                                            htserve::responses::response_file(
                                                &args.head.headers,
                                                &mime.to_string(),
                                                &path,
                                            ).await?,
                                        );
                                    }.await {
                                        Ok(r) => r,
                                        Err(e) => {
                                            state
                                                .log
                                                .log_err(loga::WARN, e.context("Error serving static response"));
                                            return response_503();
                                        },
                                    }
                                }))
                            }),
                        ].into_iter().collect(),
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
