use std::fs;
use std::path::Path;
use std::sync::Arc;

use rcgen::{Issuer, KeyPair};

use crate::error::{ApostilleError, Result};

/// Loaded CA — intermediate cert + key, ready to sign device certificates.
/// Wrapped in Arc so it can be shared across handler tasks.
pub struct CaStore {
    /// rcgen Issuer: combines the intermediate CA cert + key for signing.
    pub issuer: Issuer<'static, KeyPair>,
    /// Full PEM chain to return to enrolling clients (root + intermediate).
    /// Clients store this as `ca-chain.crt` to verify the broker's identity.
    pub chain_pem: String,
}

impl CaStore {
    pub fn load(
        ca_cert_path: &Path,
        ca_key_path: &Path,
        ca_chain_path: Option<&Path>,
    ) -> Result<Arc<Self>> {
        let cert_pem = fs::read_to_string(ca_cert_path).map_err(|e| {
            ApostilleError::Config(format!("Cannot read CA cert {:?}: {}", ca_cert_path, e))
        })?;

        let key_pem = fs::read_to_string(ca_key_path).map_err(|e| {
            ApostilleError::Config(format!("Cannot read CA key {:?}: {}", ca_key_path, e))
        })?;

        let key_pair = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;

        // Build the chain PEM that we return to devices:
        // root CA (if provided) + intermediate CA, so clients can verify
        // the broker's server cert and trust the full chain.
        let chain_pem = match ca_chain_path {
            Some(chain_path) => {
                let root_pem = fs::read_to_string(chain_path).map_err(|e| {
                    ApostilleError::Config(format!(
                        "Cannot read CA chain {:?}: {}",
                        chain_path, e
                    ))
                })?;
                // root first, then intermediate
                format!("{}\n{}", root_pem.trim(), cert_pem.trim())
            }
            None => cert_pem.trim().to_string(),
        };

        Ok(Arc::new(Self { issuer, chain_pem }))
    }
}
