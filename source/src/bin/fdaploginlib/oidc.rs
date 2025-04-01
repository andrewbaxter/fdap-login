use {
    super::static_,
    crate::{
        fdaploginlib::state::{
            AuthorizationCodeData,
            Session,
            State,
        },
        get_base_url,
    },
    askama::DynTemplate,
    chrono::Utc,
    cookie::{
        Cookie,
        CookieBuilder,
    },
    fdap_oidc::interface::{
        self,
    },
    flowcontrol::{
        shed,
        ta_return,
    },
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
            handler::{
                Handler,
                HandlerArgs,
            },
            responses::{
                body_empty,
                body_full,
                response_200_json,
                response_400,
                response_429,
                response_503,
                Body,
            },
        },
        url::UriJoin,
    },
    loga::{
        ea,
        ResultContext,
    },
    openidconnect::{
        core::{
            CoreIdToken,
            CoreJwsSigningAlgorithm,
            CoreProviderMetadata,
            CoreResponseType,
            CoreSubjectIdentifierType,
        },
        Audience,
        AuthUrl,
        EmptyAdditionalClaims,
        EmptyAdditionalProviderMetadata,
        IdTokenClaims,
        IssuerUrl,
        JsonWebKeySetUrl,
        Nonce,
        PrivateSigningKey,
        ResponseTypes,
        Scope,
        StandardClaims,
        SubjectIdentifier,
        TokenUrl,
    },
    password_hash::PasswordHash,
    rand::distributions::DistString,
    serde::{
        Deserialize,
        Serialize,
    },
    serde_json::json,
    std::{
        collections::BTreeMap,
        sync::Arc,
    },
};

const JWS_SIGNING_ALG: CoreJwsSigningAlgorithm = CoreJwsSigningAlgorithm::EdDsaEd25519;
const PATH_AUTHORIZE: &str = "oidc/authorize";
const PATH_JWKS: &str = "oidc/jwks";
const PATH_TOKEN: &str = "oidc/token";

pub async fn handle_authorize<
    'a,
>(state: &'a Arc<State>, args: HandlerArgs<'a>) -> Result<Response<Body>, loga::Error> {
    let forwarded = htserve::forwarded::parse_all_forwarded(&args.head.headers).unwrap_or_default();
    let peer_ip = forwarded.iter().flat_map(|x| x.for_.iter()).map(|x| x.0).next().unwrap_or(args.peer_addr.ip());
    if !state.authorize_ratelimit.check_key(&peer_ip).is_ok() {
        return Ok(response_429());
    };
    const COOKIE_SESSION: &str = "fdap_oidc_session";
    let mut error = false;

    #[derive(Serialize, Deserialize)]
    struct OidcParams {
        client_id: String,
        response_type: String,
        state: String,
        scope: String,
        nonce: Option<Nonce>,
        #[serde(with = "http_serde::uri")]
        redirect_uri: Uri,
    }

    let oidc_params =
        serde_urlencoded::from_str::<OidcParams>(
            &args.query,
        ).context("Invalid OIDC parameters in request query string")?;
    if oidc_params.response_type != "code" {
        return Err(loga::err(format!("Unsupported OIDC response type [{}]", oidc_params.response_type)));
    }
    if oidc_params.scope != "openid" {
        return Err(loga::err(format!("Unsupported OIDC scopes [{}]", oidc_params.response_type)));
    }

    fn resp_auth_redirect(
        oidc_params: &OidcParams,
        session_id: Option<&str>,
        authorization_code: &str,
    ) -> Response<Body> {
        let mut resp = http::Response::builder().status(http::StatusCode::TEMPORARY_REDIRECT);
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
                format!("{}?{}", oidc_params.redirect_uri, serde_urlencoded::to_string(&OidcReturnParams {
                    state: &oidc_params.state,
                    code: &authorization_code,
                }).unwrap()),
            );
        return resp.body(body_empty()).unwrap();
    }

    // Already identified (cookie), return early
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
            let authorization_code = rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
            let out = resp_auth_redirect(&oidc_params, None, &authorization_code);
            state.authorization_codes.insert(authorization_code, Arc::new(AuthorizationCodeData {
                nonce: oidc_params.nonce,
                client_id: oidc_params.client_id,
                session: session,
            })).await;
            return Ok(out);
        }
    }

    // Handle login form response
    if args.head.method == Method::POST {
        match async {
            ta_return!(Response < Body >, Option < loga:: Error >);

            #[derive(Deserialize)]
            struct FormResp {
                user: String,
                password: String,
            }

            let Ok(body) = args.body.collect().await else {
                return Err(None);
            };
            let body = body.to_bytes();
            let resp =
                serde_urlencoded::from_bytes::<FormResp>(&body)
                    .context_with("Failed to parse login form response", ea!(body = String::from_utf8_lossy(&body)))
                    .map_err(Some)?;
            let user =
                state
                    .fdap
                    .user_get::<&str, _>(&resp.user, ["fdap-login"], 10000)
                    .await
                    .context_with("Error looking up user in FDAP", ea!(user = resp.user))
                    .map_err(Some)?
                    .context_with("No user found in FDAP", ea!(user = resp.user))
                    .map_err(Some)?;
            let user =
                serde_json::from_value::<interface::fdap::User>(user)
                    .context_with("Password returned from FDAP is not a string", ea!(user = resp.user))
                    .map_err(Some)?;
            let password =
                PasswordHash::new(&user.password)
                    .context_with("Password for user in FDAP is not in valid PWC format", ea!(user = resp.user))
                    .map_err(Some)?;
            if password.verify_password(&[&argon2::Argon2::default(), &scrypt::Scrypt], &resp.password).is_err() {
                return Err(None);
            }
            let session_id = rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
            let authorization_code = rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
            let out = resp_auth_redirect(&oidc_params, Some(&session_id), &authorization_code);
            let session = Arc::new(Session { user_id: resp.user });
            state.sessions.insert(session_id, session.clone()).await;
            state.authorization_codes.insert(authorization_code, Arc::new(AuthorizationCodeData {
                nonce: oidc_params.nonce,
                client_id: oidc_params.client_id,
                session: session,
            })).await;
            return Ok(out);
        }.await {
            Ok(r) => return Ok(r),
            Err(e) => {
                if let Some(e) = e {
                    state.log.log_err(loga::DEBUG, e.context("Unexpected error validating user"));
                }
                error = true;
            },
        }
    }

    // New login or login failed, show login form
    #[derive(askama::Template)]
    #[template(path = "auth_form.html")]
    struct AuthFormParams<'a> {
        error: bool,
        oidc_params: &'a str,
    }

    return Ok(
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(CONTENT_TYPE, "text/html")
            .body(body_full(AuthFormParams {
                error: error,
                oidc_params: &args.query,
            }.dyn_render().unwrap().into_bytes()))
            .unwrap(),
    );
}

pub fn endpoints(state: &Arc<State>) -> BTreeMap<String, Box<dyn Handler<Body>>> {
    return [
        //. .
        ("/oidc/static".to_string(), static_::endpoint(state)),
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
                        vec![JWS_SIGNING_ALG],
                        EmptyAdditionalProviderMetadata {},
                    )
                        .set_token_endpoint(Some(TokenUrl::new(base_url.join(PATH_TOKEN).to_string()).unwrap()))
                        .set_scopes_supported(Some(vec![Scope::new("openid".to_string())]));
                return response_200_json(&well_known);
            })) as Box<dyn Handler<Body>>
        }),
        (format!("/{}", PATH_JWKS), {
            Box::new(handler!((state: Arc < State >)(_args -> Body) {
                return response_200_json(json!({
                    "keys": vec ![state.jwt_key.as_verification_key()]
                }));
            })) as Box<dyn Handler<Body>>
        }),
        (format!("/{}", PATH_AUTHORIZE), {
            Box::new(handler!((state: Arc < State >)(args -> Body) {
                match handle_authorize(&state, args).await {
                    Ok(r) => return r,
                    Err(e) => {
                        state.log.log_err(loga::DEBUG, e.context("Error during authorize endpoint handling"));
                        return response_503();
                    },
                }
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

                let Ok(oidc_params) = serde_urlencoded::from_bytes::<OidcParams>(&body.to_bytes()) else {
                    return resp_err();
                };
                let Some(code_data) = state.authorization_codes.remove(&oidc_params.code).await else {
                    return resp_err();
                };

                #[derive(Serialize)]
                struct OidcReturnParams<'a> {
                    access_token: &'a str,
                    token_type: &'a str,
                    refresh_token: &'a str,
                    expires_in: u32,
                    id_token: CoreIdToken,
                }

                return response_200_json(OidcReturnParams {
                    access_token: "",
                    token_type: "bearer",
                    refresh_token: "",
                    expires_in: 1,
                    id_token: CoreIdToken::new(
                        IdTokenClaims::new(
                            IssuerUrl::new(base_url.to_string()).unwrap(),
                            vec![Audience::new(code_data.client_id.clone())],
                            Utc::now() + chrono::Duration::hours(24),
                            Utc::now(),
                            StandardClaims::new(SubjectIdentifier::new(code_data.session.user_id.clone())),
                            EmptyAdditionalClaims {},
                        ).set_nonce(code_data.nonce.clone()),
                        &state.jwt_key,
                        JWS_SIGNING_ALG,
                        None,
                        None,
                    ).unwrap(),
                });
            }))
        }),
    ].into_iter().collect();
}
