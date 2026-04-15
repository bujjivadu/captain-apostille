mod ca;
mod config;
mod enrollment;
mod error;
mod server;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;

use crate::ca::{CaStore, init_ca, issue_bootstrap};
use crate::config::ApostilleConfig;
use crate::enrollment::router;
use crate::error::Result;
use crate::server::{build_tls_config, run};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "captain-apostille",
    about = "Mutually-authenticated certificate notary for the captain suite",
    version
)]
struct Cli {
    #[arg(short, long, default_value = "apostille.conf")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the enrollment server
    Serve,
    /// Certificate Authority management
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Generate a new CA hierarchy (root CA + intermediate CA).
    /// Keep the root CA key offline after generation.
    Init {
        /// Output directory for CA artifacts
        #[arg(short, long, default_value = "ca")]
        out: PathBuf,
        /// Common name prefix for the CA (e.g. "Serpentine Labs")
        #[arg(long, default_value = "Captain Apostille")]
        cn: String,
        /// Organization name embedded in CA certs
        #[arg(long, default_value = "Captain Suite")]
        org: String,
    },
    /// Issue a bootstrap certificate for a device.
    /// Outputs: bootstrap.crt  bootstrap.key  ca-chain.crt
    Bootstrap {
        /// Unique device identifier (used as CN in the certificate)
        #[arg(long)]
        device_id: String,
        /// Directory to write certificate artifacts into
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
        /// Bootstrap cert validity in hours (default 24)
        #[arg(long, default_value = "24")]
        ttl_hours: u32,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ca { action } => ca_cmd(action, &cli.config),

        Commands::Serve => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new(
                            "captain_apostille=info,tower_http=warn",
                        )
                    }),
                )
                .init();

            let config = ApostilleConfig::load(&cli.config)?;
            let config = Arc::new(config);

            // Load CA (intermediate cert + key)
            info!("Loading CA from {:?}", config.ca_cert);
            let ca = CaStore::load(
                &config.ca_cert,
                &config.ca_key,
                config.ca_chain.as_deref(),
            )?;

            // Build mTLS server config
            // CA chain PEM is used to verify incoming client (device) certs
            info!("Building mTLS server config");
            let tls_config = build_tls_config(
                &ca.chain_pem,
                &config.server_cert,
                &config.server_key,
            )?;

            // Build axum router with enrollment handlers
            let app = router(Arc::clone(&ca), Arc::clone(&config));

            // Run
            info!(
                listen = %config.listen,
                "captain-apostille enrollment server starting"
            );
            run(config.listen, tls_config, app).await
        }
    }
}

// ── CA subcommands ────────────────────────────────────────────────────────────

fn ca_cmd(action: CaAction, config_path: &PathBuf) -> Result<()> {
    // Basic logging for CLI commands
    tracing_subscriber::fmt()
        .with_env_filter("captain_apostille=info")
        .init();

    match action {
        CaAction::Init { out, cn, org } => {
            fs::create_dir_all(&out)?;

            info!("Generating CA hierarchy for '{}' / '{}'", cn, org);
            let artifacts = init_ca(&cn, &org)?;

            let root_cert_path = out.join("root.crt");
            let root_key_path  = out.join("root.key");
            let int_cert_path  = out.join("intermediate.crt");
            let int_key_path   = out.join("intermediate.key");

            fs::write(&root_cert_path, &artifacts.root_cert_pem)?;
            fs::write(&root_key_path,  &artifacts.root_key_pem)?;
            fs::write(&int_cert_path,  &artifacts.int_cert_pem)?;
            fs::write(&int_key_path,   &artifacts.int_key_pem)?;

            println!("CA hierarchy created in {:?}", out);
            println!();
            println!("  Root CA cert : {:?}  ← keep this, move key offline", root_cert_path);
            println!("  Root CA key  : {:?}  ← MOVE OFFLINE, never put on server", root_key_path);
            println!("  Intermediate : {:?}  ← goes in apostille.conf as ca_cert", int_cert_path);
            println!("  Intermediate : {:?}  ← goes in apostille.conf as ca_key", int_key_path);
            println!();
            println!("  captain-mast cafile  = {:?}", root_cert_path);
            println!("  captain-mast certfile = your server cert (Let's Encrypt)");
        }

        CaAction::Bootstrap { device_id, out, ttl_hours } => {
            fs::create_dir_all(&out)?;

            // Load CA from config
            let config = ApostilleConfig::load(config_path)?;
            let ca = CaStore::load(
                &config.ca_cert,
                &config.ca_key,
                config.ca_chain.as_deref(),
            )?;

            info!("Issuing bootstrap cert for device '{}'", device_id);
            let bootstrap = issue_bootstrap(
                &device_id,
                &config.org_name,
                ttl_hours,
                &ca,
            )?;

            let cert_path  = out.join("bootstrap.crt");
            let key_path   = out.join("bootstrap.key");
            let chain_path = out.join("ca-chain.crt");

            fs::write(&cert_path,  &bootstrap.cert_pem)?;
            fs::write(&key_path,   &bootstrap.key_pem)?;
            fs::write(&chain_path, &ca.chain_pem)?;

            println!("Bootstrap cert issued for '{}'", device_id);
            println!();
            println!("  bootstrap.crt  → flash to device  (cert, valid {}h)", ttl_hours);
            println!("  bootstrap.key  → flash to device  (private key)");
            println!("  ca-chain.crt   → flash to device  (verify enrollment endpoint + broker)");
            println!();
            println!("  Device will use these at first boot to call:");
            println!("  POST https://<host>/.well-known/est/simpleenroll");
        }
    }

    Ok(())
}
