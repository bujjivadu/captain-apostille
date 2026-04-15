use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use rustls::pki_types::CertificateDer;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use x509_parser::prelude::*;

use crate::ca::{CaStore, sign_csr};
use crate::config::ApostilleConfig;
use crate::server::ClientCert;

// ── App state shared across handlers ─────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub ca: Arc<CaStore>,
    pub config: Arc<ApostilleConfig>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(ca: Arc<CaStore>, config: Arc<ApostilleConfig>) -> Router {
    let state = AppState { ca, config };

    Router::new()
        // EST-compatible endpoints under /.well-known/est/
        .route("/.well-known/est/cacerts", get(get_cacerts))
        .route("/.well-known/est/simpleenroll", post(simple_enroll))
        .route("/.well-known/est/simplereenroll", post(simple_reenroll))
        .with_state(state)
}

// ── GET /.well-known/est/cacerts ──────────────────────────────────────────────
//
// No authentication required.  Returns the CA cert chain as PEM so devices
// can verify the enrollment endpoint's server cert and captain-mast's broker
// cert (which are both signed by the same CA).

async fn get_cacerts(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        state.ca.chain_pem.clone(),
    )
}

// ── POST /.well-known/est/simpleenroll ───────────────────────────────────────
//
// First-time enrollment.  The client authenticates via mTLS using its
// BOOTSTRAP certificate (OU=bootstrap, short TTL).
// Body: PKCS#10 CSR — either:
//   - raw DER bytes (Content-Type: application/pkcs10)
//   - base64-encoded DER (Content-Type: application/pkcs10 with base64 body)
//   - PEM-encoded CSR
//
// Response: JSON { certificate, ca_chain }

async fn simple_enroll(
    State(state): State<AppState>,
    Extension(ClientCert(peer_cert)): Extension<ClientCert>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Verify the peer cert is a bootstrap cert
    let device_id = match verify_bootstrap_cert(peer_cert.as_ref()) {
        Ok(id) => id,
        Err(msg) => {
            tracing::warn!("simpleenroll rejected: {}", msg);
            return (StatusCode::FORBIDDEN, msg).into_response();
        }
    };

    tracing::info!(device_id, "simpleenroll: issuing operational cert");

    // 2. Decode CSR
    let csr_der = match decode_csr_body(&headers, &body) {
        Ok(d) => d,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    // 3. Sign with CA
    match sign_csr(&csr_der, state.config.operational_ttl_days, &state.ca) {
        Ok(cert_pem) => {
            tracing::info!(device_id, "operational cert issued");
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({
                    "device_id":   device_id,
                    "certificate": cert_pem,
                    "ca_chain":    state.ca.chain_pem,
                }))
                .unwrap(),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(device_id, "cert signing failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Signing failed").into_response()
        }
    }
}

// ── POST /.well-known/est/simplereenroll ─────────────────────────────────────
//
// Certificate renewal.  The client authenticates using its current OPERATIONAL
// certificate.  A device approaching expiry calls this to get a fresh cert.

async fn simple_reenroll(
    State(state): State<AppState>,
    Extension(ClientCert(peer_cert)): Extension<ClientCert>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Verify the peer cert is an operational cert (NOT a bootstrap cert)
    let device_id = match verify_operational_cert(peer_cert.as_ref()) {
        Ok(id) => id,
        Err(msg) => {
            tracing::warn!("simplereenroll rejected: {}", msg);
            return (StatusCode::FORBIDDEN, msg).into_response();
        }
    };

    tracing::info!(device_id, "simplereenroll: renewing operational cert");

    let csr_der = match decode_csr_body(&headers, &body) {
        Ok(d) => d,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    match sign_csr(&csr_der, state.config.operational_ttl_days, &state.ca) {
        Ok(cert_pem) => {
            tracing::info!(device_id, "cert renewed");
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({
                    "device_id":   device_id,
                    "certificate": cert_pem,
                    "ca_chain":    state.ca.chain_pem,
                }))
                .unwrap(),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(device_id, "renewal failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Signing failed").into_response()
        }
    }
}

// ── Certificate inspection helpers ───────────────────────────────────────────

/// Returns the device ID (CN) if the cert is a bootstrap cert (OU=bootstrap).
fn verify_bootstrap_cert(cert: Option<&CertificateDer>) -> std::result::Result<String, String> {
    let der = cert.ok_or_else(|| "No client certificate presented".to_string())?;
    let (_, parsed) = X509Certificate::from_der(der.as_ref())
        .map_err(|_| "Cannot parse client certificate".to_string())?;

    let subject = parsed.subject();

    // Must have OU=bootstrap
    let has_bootstrap_ou = subject
        .iter_organizational_unit()
        .any(|ou| ou.as_str().map(|s| s == "bootstrap").unwrap_or(false));

    if !has_bootstrap_ou {
        return Err("Client cert is not a bootstrap certificate (OU≠bootstrap)".into());
    }

    // Extract CN as device ID — bind to local so `parsed` can be dropped cleanly
    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from)
        .ok_or_else(|| "No CN in bootstrap certificate".into());
    cn
}

/// Returns the device ID (CN) if the cert is an operational cert (no OU=bootstrap).
fn verify_operational_cert(
    cert: Option<&CertificateDer>,
) -> std::result::Result<String, String> {
    let der = cert.ok_or_else(|| "No client certificate presented".to_string())?;
    let (_, parsed) = X509Certificate::from_der(der.as_ref())
        .map_err(|_| "Cannot parse client certificate".to_string())?;

    let subject = parsed.subject();

    // Must NOT be a bootstrap cert
    let has_bootstrap_ou = subject
        .iter_organizational_unit()
        .any(|ou| ou.as_str().map(|s| s == "bootstrap").unwrap_or(false));

    if has_bootstrap_ou {
        return Err("Bootstrap certificates cannot re-enroll — use simpleenroll".into());
    }

    // Extract CN as device ID — bind to local so `parsed` can be dropped cleanly
    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from)
        .ok_or_else(|| "No CN in operational certificate".into());
    cn
}

// ── CSR decoding ──────────────────────────────────────────────────────────────

/// Accept CSR bodies in three formats:
/// 1. Raw DER bytes
/// 2. Base64-encoded DER (EST spec)
/// 3. PEM (-----BEGIN CERTIFICATE REQUEST-----)
fn decode_csr_body(headers: &HeaderMap, body: &Bytes) -> std::result::Result<Vec<u8>, String> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // PEM path
    if content_type.contains("text/plain") || body.starts_with(b"-----") {
        let pem_str = std::str::from_utf8(body)
            .map_err(|_| "CSR body is not valid UTF-8".to_string())?;
        return pem_to_der(pem_str);
    }

    // If body looks like base64 (all printable ASCII, no binary header bytes)
    if body.iter().all(|&b| b.is_ascii_graphic() || b == b'\n' || b == b'\r') {
        let trimmed = std::str::from_utf8(body)
            .map(|s| s.trim())
            .unwrap_or("");

        // Might be PEM
        if trimmed.starts_with("-----BEGIN") {
            return pem_to_der(trimmed);
        }

        // Try base64 decode
        if let Ok(der) = B64.decode(trimmed) {
            return Ok(der);
        }
    }

    // Fall through: treat as raw DER
    Ok(body.to_vec())
}

fn pem_to_der(pem: &str) -> std::result::Result<Vec<u8>, String> {
    // Strip PEM headers and base64-decode the body
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    B64.decode(b64.trim())
        .map_err(|e| format!("Invalid PEM base64: {}", e))
}
