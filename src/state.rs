//! Shared application state, cloned into every handler.

use std::sync::Arc;

use crate::auth::Authenticator;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::terminal::Manager;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub auth: Arc<Authenticator>,
    pub terminals: Arc<Manager>,
}

impl AppState {
    /// Fails if the config carries no usable credentials, so a server that
    /// would serve an unauthenticated shell cannot be constructed at all.
    pub fn new(config: Config) -> Result<Self> {
        let auth_config = config
            .auth
            .as_ref()
            .ok_or_else(|| Error::Config("no [auth] section. Run `facet setup`".into()))?;

        // Cookies are only marked Secure when the connection actually is; a
        // Secure cookie over plaintext http is silently dropped by browsers,
        // which would make loopback development mysteriously fail to log in.
        let auth = Authenticator::new(auth_config, config.tls.enabled)?;

        let config = Arc::new(config);

        Ok(Self {
            auth: Arc::new(auth),
            terminals: Manager::new(Arc::clone(&config)),
            config,
        })
    }
}
