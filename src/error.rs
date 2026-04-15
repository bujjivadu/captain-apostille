use thiserror::Error;

pub type Result<T> = std::result::Result<T, ApostilleError>;

#[derive(Debug, Error)]
pub enum ApostilleError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Config parse error at line {line}: {message}")]
    ConfigParse { line: usize, message: String },

    #[error("Certificate error: {0}")]
    Cert(#[from] rcgen::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("TLS verifier error: {0}")]
    TlsVerifier(#[from] rustls::server::VerifierBuilderError),

    #[error("Server error: {0}")]
    Server(String),

    #[error("Enrollment error: {0}")]
    #[allow(dead_code)]
    Enrollment(String),
}
