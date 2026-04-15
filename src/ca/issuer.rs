use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::CertificateSigningRequestDer;
use time::{Duration, OffsetDateTime};

use super::store::CaStore;
use crate::error::Result;

/// A bootstrap certificate issued for a new device at provisioning time.
pub struct BootstrapCert {
    /// PEM-encoded certificate (signed by intermediate CA).
    pub cert_pem: String,
    /// PEM-encoded private key (generated server-side, written to device flash).
    pub key_pem: String,
}

/// Sign an incoming PKCS#10 CSR (DER bytes) from a device.
/// Returns the signed operational certificate as PEM.
pub fn sign_csr(
    csr_der: &[u8],
    ttl_days: u32,
    ca: &CaStore,
) -> Result<String> {
    let csr_der = CertificateSigningRequestDer::from(csr_der.to_vec());
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der)?;

    // Enforce operational cert policy on top of whatever the CSR requested
    let mut params = csr_params.params.clone();
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(ttl_days as i64);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    // Re-build as a CertificateSigningRequestParams with the policy-enforced params
    let csr_params_enforced = CertificateSigningRequestParams {
        params,
        public_key: csr_params.public_key,
    };

    let cert = csr_params_enforced.signed_by(&ca.issuer)?;
    Ok(cert.pem())
}

/// Generate a bootstrap certificate server-side for a specific device.
/// Used by `captain-apostille ca bootstrap --device-id <id>`.
///
/// The bootstrap cert has a short TTL and is tagged with OU=bootstrap so the
/// enrollment endpoint can distinguish it from operational certs.  The private
/// key is returned here and written to device flash by cr_flash_lite — after
/// that the key exists nowhere except the device.
pub fn issue_bootstrap(
    device_id: &str,
    org_name: &str,
    ttl_hours: u32,
    ca: &CaStore,
) -> Result<BootstrapCert> {
    let now = OffsetDateTime::now_utc();

    // Build cert params for the bootstrap identity
    let mut params = CertificateParams::new(vec![])?;
    params.not_before = now;
    params.not_after = now + Duration::hours(ttl_hours as i64);
    params.distinguished_name.push(DnType::CommonName, device_id);
    params.distinguished_name.push(DnType::OrganizationName, org_name);
    // OU=bootstrap is the marker the enrollment endpoint checks
    params.distinguished_name.push(
        DnType::OrganizationalUnitName,
        "bootstrap",
    );
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    // Generate the device key pair (server-side, for provisioning)
    let device_key = KeyPair::generate()?;

    // Serialize to a CSR internally, then sign with CA
    let csr = params.serialize_request(&device_key)?;
    let csr_der = CertificateSigningRequestDer::from(csr.der().to_vec());
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der)?;
    let cert = csr_params.signed_by(&ca.issuer)?;

    Ok(BootstrapCert {
        cert_pem: cert.pem(),
        key_pem: device_key.serialize_pem(),
    })
}

/// Initialize a new CA hierarchy: Root CA (self-signed) + Intermediate CA
/// (signed by Root).  Returns PEM strings for all four artifacts.
pub fn init_ca(
    common_name: &str,
    org_name: &str,
) -> Result<CaArtifacts> {
    let now = OffsetDateTime::now_utc();

    // ── Root CA (self-signed, offline key) ───────────────────────────────
    let root_key = KeyPair::generate()?;
    let mut root_params = CertificateParams::new(vec![])?;
    root_params.not_before = now;
    root_params.not_after = now + Duration::days(365 * 10); // 10 years
    root_params.distinguished_name.push(
        DnType::CommonName,
        format!("{} Root CA", common_name),
    );
    root_params
        .distinguished_name
        .push(DnType::OrganizationName, org_name);
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let root_cert = root_params.self_signed(&root_key)?;

    // ── Intermediate CA (signed by Root, used online for device cert signing) ─
    let int_key = KeyPair::generate()?;
    let mut int_params = CertificateParams::new(vec![])?;
    int_params.not_before = now;
    int_params.not_after = now + Duration::days(365 * 5); // 5 years
    int_params.distinguished_name.push(
        DnType::CommonName,
        format!("{} Intermediate CA", common_name),
    );
    int_params
        .distinguished_name
        .push(DnType::OrganizationName, org_name);
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); // can only sign leaf certs
    int_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    // Sign intermediate CA with root
    let int_csr = int_params.serialize_request(&int_key)?;
    let int_csr_der = CertificateSigningRequestDer::from(int_csr.der().to_vec());
    let int_csr_params = CertificateSigningRequestParams::from_der(&int_csr_der)?;

    // Serialize root key before moving it into the issuer
    let root_key_pem = root_key.serialize_pem();

    // Build a root issuer from the just-generated root cert
    let root_issuer =
        rcgen::Issuer::from_ca_cert_pem(&root_cert.pem(), root_key)?;
    let int_cert = int_csr_params.signed_by(&root_issuer)?;

    Ok(CaArtifacts {
        root_cert_pem: root_cert.pem(),
        root_key_pem,
        int_cert_pem: int_cert.pem(),
        int_key_pem: int_key.serialize_pem(),
    })
}

pub struct CaArtifacts {
    pub root_cert_pem: String,
    pub root_key_pem: String,
    pub int_cert_pem: String,
    pub int_key_pem: String,
}
