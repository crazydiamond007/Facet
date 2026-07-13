//! `facet setup`: generate every secret the server needs, then write a config.
//!
//! Nothing here is baked into the binary: this command is the only thing that
//! creates credentials, and it puts them in a file you own.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};

use crate::auth::{password, totp};
use crate::config::{Auth, Config, Tls};
use crate::tls;

pub fn run(config_path: &Path, force: bool) -> anyhow::Result<()> {
    if config_path.exists() && !force {
        bail!(
            "{} already exists. Re-running setup would issue a new TOTP secret and invalidate \
             your authenticator. Pass --force if that is what you want.",
            config_path.display()
        );
    }

    println!("facet setup\n");

    let password = read_new_password()?;

    println!("\nHashing password (argon2id)...");
    let password_hash = password::hash(&password).context("hashing password")?;

    let totp_secret = totp::generate_secret();
    let jwt_secret = random_base64_32()?;

    let mut config = Config {
        auth: Some(Auth {
            password_hash,
            totp_secret: totp_secret.clone(),
            jwt_secret,
            session_ttl_minutes: 12 * 60,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        }),
        tls: Tls::default(),
        ..Config::default()
    };

    // TLS material, unless the user already pointed the config at their own.
    let (cert_path, key_path) = (config.tls.cert.clone(), config.tls.key.clone());
    if cert_path.exists() || key_path.exists() {
        println!(
            "\nTLS: keeping the existing certificate at {}",
            cert_path.display()
        );
    } else {
        println!("Generating a self-signed certificate for localhost...");
        let (cert_pem, key_pem) = tls::generate_self_signed(Vec::new())?;
        write_private(&cert_path, cert_pem.as_bytes()).context("writing certificate")?;
        write_private(&key_path, key_pem.as_bytes()).context("writing private key")?;
    }
    config.server.audit_log = Some("facet-audit.log".into());

    let toml = toml::to_string_pretty(&config).context("serialising config")?;
    write_private(config_path, toml.as_bytes())
        .with_context(|| format!("writing {}", config_path.display()))?;

    enrol_totp(&totp_secret)?;

    println!("\n  Wrote {}", config_path.display());
    println!("  Wrote {} and {}", cert_path.display(), key_path.display());
    println!("\nThat file holds your password hash, TOTP secret and JWT key.");
    println!("It is chmod 600. Do not commit it.\n");
    println!("Start the server with:  facet run");
    println!(
        "Then open:              https://localhost:{}\n",
        config.server.port
    );
    println!("Your browser will warn about the self-signed certificate. That is expected");
    println!("on loopback. See the README before exposing this beyond your machine.");

    Ok(())
}

/// Print the enrolment QR straight into the terminal, so the secret never has
/// to make a round trip through a screenshot or a clipboard.
fn enrol_totp(secret: &str) -> anyhow::Result<()> {
    let totp = totp::build(secret, "owner").context("building TOTP")?;
    let url = totp.get_url();

    println!("\nScan this with your authenticator app:\n");
    if let Err(err) = qr2term::print_qr(&url) {
        // A terminal that cannot render the QR is not a failure; the URL works.
        eprintln!("(could not draw the QR code: {err})");
    }

    println!("\nOr enter the secret by hand:\n");
    println!("  {secret}\n");
    println!("If neither works, this is the enrolment URL:\n");
    println!("  {url}");

    Ok(())
}

const MIN_PASSWORD_LEN: usize = 12;

fn read_new_password() -> anyhow::Result<String> {
    use std::io::IsTerminal as _;

    // Not a terminal (a pipe, a Dockerfile, CI): take one line from stdin and
    // do not try to prompt or confirm. rpassword would otherwise go looking for
    // /dev/tty and fail.
    if !std::io::stdin().is_terminal() {
        let mut password = String::new();
        std::io::stdin()
            .read_line(&mut password)
            .context("reading the password from stdin")?;

        let password = password.trim_end_matches(['\r', '\n']).to_string();
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("password must be at least {MIN_PASSWORD_LEN} characters");
        }
        return Ok(password);
    }

    loop {
        let password = rpassword::prompt_password("Choose a password: ")?;

        if password.chars().count() < MIN_PASSWORD_LEN {
            eprintln!(
                "  Too short. Use at least {MIN_PASSWORD_LEN} characters. This guards a shell.\n"
            );
            continue;
        }

        let again = rpassword::prompt_password("Confirm password: ")?;
        if password != again {
            eprintln!("  Passwords did not match.\n");
            continue;
        }

        return Ok(password);
    }
}

fn random_base64_32() -> anyhow::Result<String> {
    use base64::Engine as _;

    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).context("reading from the OS random number generator")?;

    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Write a file only the owner can read. The mode is set *before* the secret
/// goes in, so there is no window where it sits on disk world-readable.
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.flush()?;

    // On Windows there is no mode bit to set at open time. Inherited ACLs on a
    // user profile directory are already owner-only; anyone putting the config
    // somewhere world-readable is opting out deliberately.
    Ok(())
}
