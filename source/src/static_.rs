use {
    crate::state::State,
    flowcontrol::ta_return,
    http::{
        header::{
            ETAG,
            IF_NONE_MATCH,
        },
        HeaderMap,
        Response,
    },
    htwrap::{
        handler,
        htserve::{
            self,
            handler::Handler,
            responses::{
                body_full,
                response_404,
                response_503,
                Body,
            },
        },
    },
    path_absolutize::Absolutize,
    std::{
        hash::{
            DefaultHasher,
            Hasher,
        },
        path::PathBuf,
        sync::Arc,
    },
};

pub fn endpoint(state: &Arc<State>) -> Box<dyn Handler<Body>> {
    return Box::new(handler!((state: Arc < State >)(args -> Body) {
        let Some(static_dir) = &state.static_dir else {
            return response_404();
        };
        match async {
            ta_return!(Response < Body >, loga::Error);
            let subpath = args.subpath.strip_prefix("/").unwrap_or(&args.subpath);
            let Ok(path) = static_dir.join(subpath).absolutize().map(|x| x.to_path_buf()) else {
                return Ok(response_404());
            };
            if !path.starts_with(&static_dir) {
                return Ok(response_404());
            }
            let etag = state.static_etags.try_get_with_by_ref::<_, std::io::Error, PathBuf>(&path, {
                let path = path.clone();
                async move {
                    let mut h = DefaultHasher::new();
                    let data = match tokio::fs::read(path).await {
                        Ok(d) => d,
                        Err(e) => {
                            match e.kind() {
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
                                    return Ok(None);
                                },
                                _ => {
                                    return Err(e);
                                },
                            }
                        },
                    };
                    h.write(&data);
                    return Ok(Some(format!("\"{}\"", h.finish())));
                }
            }).await?;
            let Some(etag) = etag else {
                return Ok(response_404());
            };
            if let Some(h) = args.head.headers.get(IF_NONE_MATCH) {
                if h == etag.as_bytes() {
                    return Ok(Response::builder().status(304).body(body_full(vec![])).unwrap());
                }
            }
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            return Ok(htserve::responses::response_file(&args.head.headers, &mime.to_string(), &path, false, &{
                let mut m = HeaderMap::with_capacity(1);
                m.insert(ETAG, http::HeaderValue::from_str(&etag).unwrap());
                m
            }).await?);
        }.await {
            Ok(r) => r,
            Err(e) => {
                state.log.log_err(loga::WARN, e.context("Error serving static response"));
                return response_503();
            },
        }
    }));
}
