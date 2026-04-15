use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::error::{ApostilleError, Result};

/// Apostille configuration, parsed from a Mosquitto-style key-value file.
#[derive(Debug, Clone)]
pub struct ApostilleConfig {
    /// Intermediate CA certificate (the one that signs device certs)
    pub ca_cert: PathBuf,
    /// Intermediate CA private key
    pub ca_key: PathBuf,
    /// Root CA certificate (prepended to responses as chain)
    pub ca_chain: Option<PathBuf>,

    /// Enrollment server listen address
    pub listen: SocketAddr,
    /// Server certificate for the enrollment endpoint (Let's Encrypt recommended)
    pub server_cert: PathBuf,
    /// Server private key for the enrollment endpoint
    pub server_key: PathBuf,

    /// Organization name embedded in issued certificates
    pub org_name: String,
    /// Validity of operational certificates in days
    pub operational_ttl_days: u32,
    /// Validity of bootstrap certificates in hours
    pub bootstrap_ttl_hours: u32,
}

impl Default for ApostilleConfig {
    fn default() -> Self {
        Self {
            ca_cert: PathBuf::from("ca/intermediate.crt"),
            ca_key: PathBuf::from("ca/intermediate.key"),
            ca_chain: Some(PathBuf::from("ca/root.crt")),
            listen: "0.0.0.0:8443".parse().unwrap(),
            server_cert: PathBuf::from("server.crt"),
            server_key: PathBuf::from("server.key"),
            org_name: String::from("Captain Suite"),
            operational_ttl_days: 365,
            bootstrap_ttl_hours: 24,
        }
    }
}

impl ApostilleConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            ApostilleError::Config(format!("Cannot read config {:?}: {}", path, e))
        })?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> Result<Self> {
        let mut cfg = ApostilleConfig::default();

        for (idx, raw) in content.lines().enumerate() {
            let line_num = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = split_kv(line);

            match key {
                "ca_cert" => cfg.ca_cert = PathBuf::from(value),
                "ca_key" => cfg.ca_key = PathBuf::from(value),
                "ca_chain" => cfg.ca_chain = Some(PathBuf::from(value)),

                "listen" => {
                    cfg.listen = value.parse().map_err(|_| ApostilleError::ConfigParse {
                        line: line_num,
                        message: format!("Invalid listen address: '{}'", value),
                    })?;
                }
                "server_cert" => cfg.server_cert = PathBuf::from(value),
                "server_key" => cfg.server_key = PathBuf::from(value),

                "org_name" => cfg.org_name = value.to_string(),
                "operational_ttl_days" => {
                    cfg.operational_ttl_days = value.parse().unwrap_or(365)
                }
                "bootstrap_ttl_hours" => {
                    cfg.bootstrap_ttl_hours = value.parse().unwrap_or(24)
                }

                other => {
                    tracing::debug!("Unknown directive '{}' at line {} — ignored", other, line_num);
                }
            }
        }

        Ok(cfg)
    }
}

fn split_kv(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(pos) => (&line[..pos], line[pos..].trim()),
        None => (line, ""),
    }
}
