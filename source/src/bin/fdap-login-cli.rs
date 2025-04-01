use {
    aargvark::{
        vark,
        Aargvark,
    },
    argon2::{
        Argon2,
        PasswordHasher,
    },
    fdap_oidc::interface::fdap::User,
    loga::ResultContext,
    password_hash::{
        SaltString,
    },
    rand::rngs::OsRng,
};

#[derive(Aargvark)]
enum Command {
    /// Prompt for a password and create an FDAP user JSON payload
    BuildFdapUser,
}

#[derive(Aargvark)]
struct Args {
    command: Command,
}

fn main() -> Result<(), loga::Error> {
    let args = vark::<Args>();
    match args.command {
        Command::BuildFdapUser => {
            let pw = rpassword::prompt_password("Enter your password: ")?;
            let pw2 = rpassword::prompt_password("Confirm your password: ")?;
            if pw != pw2 {
                return Err(loga::err("Passwords don't match"));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &User {
                        password: Argon2::default()
                            .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))
                            .context("Error hashing password")?
                            .to_string(),
                    },
                ).unwrap()
            );
            return Ok(());
        },
    }
}
