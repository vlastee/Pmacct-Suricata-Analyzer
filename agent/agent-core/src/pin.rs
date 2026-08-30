//! Certificate pinning helpers: the server publishes `ca_spki_sha256` (base64 of the SHA-256 of
//! the CA's SubjectPublicKeyInfo); the agent verifies the CA it fetched matches before trusting it.
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};

fn first_cert_der(pem: &str) -> Result<Vec<u8>> {
    let (_, doc) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("bad PEM: {e}"))?;
    Ok(doc.contents)
}

/// base64(sha256(SubjectPublicKeyInfo)) of the first certificate in `pem`.
pub fn spki_sha256_base64(pem: &str) -> Result<String> {
    let der = first_cert_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).context("parse certificate")?;
    let spki = cert.tbs_certificate.subject_pki.raw;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki)))
}

/// Colon-separated upper-case SHA-256 of the DER certificate (what the UI shows).
pub fn fingerprint_sha256(pem: &str) -> Result<String> {
    let der = first_cert_der(pem)?;
    let sum = Sha256::digest(&der);
    Ok(sum.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

/// Subject common name of the first certificate, for display.
pub fn subject(pem: &str) -> Result<String> {
    let der = first_cert_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).context("parse certificate")?;
    Ok(cert.subject().to_string())
}
