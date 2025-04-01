use {
    crate::fdaploginlib::state::State,
    flowcontrol::ta_return,
    http::Response,
    htwrap::{
        handler,
        htserve::{
            self,
            handler::Handler,
            responses::{
                response_404,
                response_503,
                Body,
            },
        },
    },
    loga::DebugDisplay,
    path_absolutize::Absolutize,
    std::sync::Arc,
};

pub fn endpoint(state: &Arc<State>) -> Box<dyn Handler<Body>> {
    return Box::new(handler!((state: Arc < State >)(args -> Body) {
        eprintln!("at static");
        let Some(static_dir) = &state.static_dir else {
            eprintln!("static - no static dir");
            return response_404();
        };
        match async {
            ta_return!(Response < Body >, loga::Error);
            let subpath = args.subpath.strip_prefix("/").unwrap_or(&args.subpath);
            let Ok(path) = static_dir.join(subpath).absolutize().map(|x| x.to_path_buf()) else {
                eprintln!("static - req path invalid aboslute: {}", static_dir.join(subpath).to_string_lossy());
                return Ok(response_404());
            };
            if !path.starts_with(&static_dir) {
                eprintln!(
                    "static - resolved req path not in static dir {} v {}",
                    path.to_string_lossy(),
                    static_dir.to_string_lossy()
                );
                return Ok(response_404());
            }
            eprintln!("path is {:?}", path.dbg_str());
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            return Ok(htserve::responses::response_file(&args.head.headers, &mime.to_string(), &path).await?);
        }.await {
            Ok(r) => r,
            Err(e) => {
                state.log.log_err(loga::WARN, e.context("Error serving static response"));
                return response_503();
            },
        }
    }));
}
