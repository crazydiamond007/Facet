use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use facet::config::Config;
use facet::state::AppState;
use facet::{audit, tls, web};

#[derive(Parser)]
#[command(
    name = "facet",
    version,
    about = "Authenticated web terminal, one binary."
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long, short, global = true, default_value = "facet.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the web terminal. (Default when no subcommand is given.)
    Run,

    /// Generate credentials, a TLS certificate and a config file.
    Setup {
        /// Overwrite an existing config. This issues a new TOTP secret, so your
        /// authenticator app will need to be re-enrolled.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Run) {
        Command::Setup { force } => facet::setup::run(&cli.config, force),
        Command::Run => run(&cli.config).await,
    }
}

async fn run(config_path: &Path) -> anyhow::Result<()> {
    // `Config::load` refuses to return a config that would serve an
    // unauthenticated or unencrypted-off-loopback shell, so by the time we have
    // one, the dangerous deployments have already been ruled out.
    let config = Config::load(config_path).with_context(|| {
        format!(
            "could not load {}. Run `facet setup` if you have not yet",
            config_path.display()
        )
    })?;

    audit::init(config.server.audit_log.as_deref()).context("opening the audit log")?;

    let addr = config.server.addr();
    let tls_enabled = config.tls.enabled;
    let (cert, key) = (config.tls.cert.clone(), config.tls.key.clone());

    if !config.server.is_loopback() {
        tracing::warn!(
            %addr,
            "bound beyond loopback: anyone who can reach this address can reach the login page"
        );
    }

    let state = AppState::new(config).context("building application state")?;
    let app = web::router(state);

    // ConnectInfo gives the audit log a peer address to record.
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    if tls_enabled {
        tls::install_provider();
        let tls_config = tls::config(&cert, &key).await?;

        tracing::info!(%addr, "facet listening (https)");
        axum_server::bind_rustls(addr, tls_config)
            .serve(service)
            .await
            .context("server error")?;
    } else {
        // Only reachable on loopback; `Config::validate` rejects it otherwise.
        tracing::warn!(%addr, "facet listening (http, no TLS, loopback only)");
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("could not bind {addr}"))?;

        axum::serve(listener, service)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("server error")?;
    }

    Ok(())
}

/// Ctrl-C tears the listener down; in-flight sessions are dropped, which kills
/// their child shells via `Pty`'s `Drop` impl.
async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(%err, "could not install ctrl-c handler");
        std::future::pending::<()>().await;
    }
    tracing::info!("shutting down");
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_env("FACET_LOG")
        .unwrap_or_else(|_| EnvFilter::new("facet=info,audit=info,tower_http=warn,warn"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}
