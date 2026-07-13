//! TLS via rustls, with the `ring` provider.
//!
//! `ring` rather than the `aws-lc-rs` default on purpose: aws-lc-rs needs CMake
//! and NASM to build on Windows, and "one binary that builds on Windows" is a
//! hard requirement here. `ring` is pure-Rust-plus-assembly and needs neither.

use std::path::Path;

use axum_server::tls_rustls::RustlsConfig;

use crate::error::{Error, Result};

/// Install the process-wide crypto provider. Must run before any TLS work, or
/// rustls will refuse to build a config at runtime.
pub fn install_provider() {
    // Errs only if a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn config(cert: &Path, key: &Path) -> Result<RustlsConfig> {
    for (label, path) in [("certificate", cert), ("private key", key)] {
        if !path.exists() {
            return Err(Error::Config(format!(
                "TLS {label} not found at {}. Run `facet setup` to generate a self-signed \
                 pair, or point tls.cert / tls.key at your own.",
                path.display()
            )));
        }
    }

    RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|e| Error::Config(format!("could not load TLS material: {e}")))
}

/// A self-signed certificate for `localhost` and the loopback IPs.
///
/// Browsers will warn on this, and that warning is doing its job: a self-signed
/// cert gives you encryption but not identity. It is the right default for
/// loopback, where you are not relying on the cert to prove who you are talking
/// to. Put a real certificate here (or terminate TLS at a tunnel) before you
/// depend on it across a network. See the README.
pub fn generate_self_signed(hostnames: Vec<String>) -> Result<(String, String)> {
    let names = if hostnames.is_empty() {
        vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]
    } else {
        hostnames
    };

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| Error::Config(format!("could not generate key pair: {e}")))?;

    let mut params = rcgen::CertificateParams::new(names)
        .map_err(|e| Error::Config(format!("invalid hostname for certificate: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "facet");

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Config(format!("could not self-sign certificate: {e}")))?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}
