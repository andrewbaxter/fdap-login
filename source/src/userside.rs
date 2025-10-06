use {
    crate::{
        interface,
        state::State,
    },
    argon2::PasswordHash,
    askama::DynTemplate,
    http::{
        header::CONTENT_TYPE,
        Response,
        Uri,
    },
    htwrap::htserve::responses::{
        body_full,
        response_429,
        Body,
    },
    hyper::body::Bytes,
    loga::{
        ea,
        ResultContext,
    },
    serde::Deserialize,
    std::{
        net::IpAddr,
        sync::Arc,
    },
};

pub fn show_login(base_url: Uri, query: &str, error: bool) -> Response<Body> {
    // New login or login failed, show login form
    #[derive(askama::Template)]
    #[template(path = "auth_form.html")]
    struct AuthFormParams<'a> {
        error: bool,
        oidc_params: &'a str,
        base_url: Uri,
    }

    return http::Response::builder()
        .status(http::StatusCode::OK)
        .header(CONTENT_TYPE, "text/html")
        .body(body_full(AuthFormParams {
            error: error,
            oidc_params: query,
            base_url: base_url,
        }.dyn_render().unwrap().into_bytes()))
        .unwrap();
}

pub struct CheckLoginResPass {
    pub user: String,
}

pub enum CheckLoginRes {
    Resp(Response<Body>),
    Pass(CheckLoginResPass),
    Fail,
}

pub async fn check_login<
    'a,
>(state: &Arc<State>, body: Bytes, peer_addr: IpAddr) -> Result<CheckLoginRes, loga::Error> {
    #[derive(Deserialize)]
    struct FormResp {
        user: String,
        password: String,
    }

    let resp =
        serde_urlencoded::from_bytes::<FormResp>(
            &body,
        ).context_with("Failed to parse login form response", ea!(body = String::from_utf8_lossy(&body)))?;
    let user =
        state
            .fdap
            .user_get::<&str, _>(&resp.user, ["fdap-login"], 10000)
            .await
            .context_with("Error looking up user in FDAP", ea!(user = resp.user))?
            .context_with("No user found in FDAP", ea!(user = resp.user))?;
    let user =
        serde_json::from_value::<interface::fdap::User>(
            user,
        ).context_with("Password returned from FDAP is not a string", ea!(user = resp.user))?;
    let password =
        PasswordHash::new(
            &user.password,
        ).context_with("Password for user in FDAP is not in valid PWC format", ea!(user = resp.user))?;
    if !state.authorize_ratelimit.check_key(&peer_addr).is_ok() {
        return Ok(CheckLoginRes::Resp(response_429()));
    };
    if password.verify_password(&[&argon2::Argon2::default(), &scrypt::Scrypt], &resp.password).is_err() {
        return Ok(CheckLoginRes::Fail);
    }
    return Ok(CheckLoginRes::Pass(CheckLoginResPass { user: resp.user }));
}
