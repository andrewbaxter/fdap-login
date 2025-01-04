use {
    aargvark::{
        vark,
        Aargvark,
    },
    fdap_oidc::interface,
    schemars::schema_for,
    std::{
        fs::{
            create_dir_all,
            write,
        },
        path::PathBuf,
    },
};

#[derive(Aargvark)]
struct Args {
    dir: PathBuf,
}

fn main() {
    let args = vark::<Args>();
    create_dir_all(&args.dir).unwrap();
    write(
        args.dir.join("config.schema.json"),
        serde_json::to_vec_pretty(&schema_for!(interface::config::Config)).unwrap(),
    ).unwrap();
    write(
        args.dir.join("fdap_user.schema.json"),
        serde_json::to_vec_pretty(&schema_for!(interface::fdap::User)).unwrap(),
    ).unwrap();
}
