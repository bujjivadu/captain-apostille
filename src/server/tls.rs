use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::Extension;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::error::{ApostilleError, Result};

/// Client certificate extracted from the mTLS handshake.
/// Injected into every request via axum's Extension layer.
/// Handlers use `Extension(ClientCert(cert)): Extension<ClientCert>`
/// to obtain the peer certificate and extract the device ID from its CN.
#[derive(Clone)]
pub struct ClientCert(pub Option<CertificateDer<'static>>);

/// Build an mTLS-capable `rustls::ServerConfig`.
///
/// - `ca_cert_pem`: the CA that signs client (device) certs — used to verify
///   the peer during the TLS handshake.
/// - `server_cert_path` / `server_key_path`: the enrollment endpoint's own
///   TLS certificate (should be a Let's Encrypt cert so devices trust it
///   without bundling a custom CA).
pub fn build_tls_config(
    ca_cert_pem: &str,
    server_cert_path: &Path,
    server_key_path: &Path,
) -> Result<Arc<ServerConfig>> {
    // ── Client-cert verifier (mTLS) ──────────────────────────────────────
    // Load CA cert that signed the device bootstrap / operational certs.
    let ca_der: CertificateDer<'static> = {
        let mut pem = ca_cert_pem.as_bytes();
        let der = rustls_pemfile::certs(&mut pem)
            .next()
            .ok_or_else(|| ApostilleError::Config("CA cert PEM is empty".into()))??
            .into_owned();
        der
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).map_err(|e| {
        ApostilleError::Config(format!("Cannot add CA cert to root store: {}", e))
    })?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    // ── Server certificate (Let's Encrypt / own cert) ────────────────────
    let server_certs: Vec<CertificateDer<'static>> = {
        let f = File::open(server_cert_path).map_err(|e| {
            ApostilleError::Config(format!("Cannot open server cert {:?}: {}", server_cert_path, e))
        })?;
        rustls_pemfile::certs(&mut BufReader::new(f))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ApostilleError::Config(format!("Invalid server cert PEM: {}", e)))?
    };

    let server_key: PrivateKeyDer<'static> = {
        let f = File::open(server_key_path).map_err(|e| {
            ApostilleError::Config(format!("Cannot open server key {:?}: {}", server_key_path, e))
        })?;
        rustls_pemfile::private_key(&mut BufReader::new(f))
            .map_err(|e| ApostilleError::Config(format!("Cannot read server key: {}", e)))?
            .ok_or_else(|| ApostilleError::Config("No private key found in server key file".into()))?
    };

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)?;

    Ok(Arc::new(config))
}

/// Run the mTLS HTTP server.
///
/// For each accepted TCP connection:
/// 1. Perform TLS handshake (requires client cert signed by our CA).
/// 2. Extract peer certificate from TLS session.
/// 3. Inject it as `Extension<ClientCert>` into every request on that
///    connection — handlers can inspect it to get the device ID.
/// 4. Serve with axum over hyper.
pub async fn run(
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    app: Router,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        ApostilleError::Server(format!("Cannot bind to {}: {}", addr, e))
    })?;

    tracing::info!("Enrollment endpoint listening on {}", addr);

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("TCP accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            // TLS handshake — the peer MUST present a valid client cert
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(%peer_addr, "TLS handshake failed: {}", e);
                    return;
                }
            };

            // Extract peer certificate (always Some here because
            // WebPkiClientVerifier requires one)
            let client_cert: Option<CertificateDer<'static>> = {
                let (_, session) = tls_stream.get_ref();
                session
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .cloned()
            };

            tracing::debug!(%peer_addr, has_cert = client_cert.is_some(), "TLS accepted");

            // Per-connection axum app with this connection's client cert
            // injected as an Extension so handlers can extract it.
            let svc = TowerToHyperService::new(
                app.layer(Extension(ClientCert(client_cert)))
                    .into_service::<Incoming>(),
            );

            let io = TokioIo::new(tls_stream);
            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(%peer_addr, "Connection closed: {}", e);
            }
        });
    }
}
