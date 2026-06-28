//! X.509 v3 → human-friendly summary.
//!
//! We keep our own summary type (instead of re-exporting `x509_cert::Certificate`)
//! because the public surface needs to be Serde-able for the WASM bindings
//! and the CLI's JSON output.

use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub version: u8,
    pub serial_hex: String,
    pub signature_algorithm: String,
    pub issuer: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_algorithm: String,
    pub public_key_size_bits: Option<u32>,
    pub fingerprint_sha256_hex: String,
    pub extensions: Vec<ExtensionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSummary {
    pub oid: String,
    pub name: Option<String>,
    pub critical: bool,
    pub value_hex: String,
}

pub fn parse_der(bytes: &[u8]) -> Result<CertSummary> {
    let cert = Certificate::from_der(bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    summarise(&cert, bytes)
}

fn summarise(cert: &Certificate, raw_der: &[u8]) -> Result<CertSummary> {
    let tbs = &cert.tbs_certificate;

    let version = match tbs.version {
        x509_cert::Version::V1 => 1,
        x509_cert::Version::V2 => 2,
        x509_cert::Version::V3 => 3,
    };

    let serial_hex = hex::encode(tbs.serial_number.as_bytes());
    let signature_algorithm = oid_label(&tbs.signature.oid);
    let issuer = tbs.issuer.to_string();
    let subject = tbs.subject.to_string();
    let not_before = tbs.validity.not_before.to_string();
    let not_after = tbs.validity.not_after.to_string();

    let spki = &tbs.subject_public_key_info;
    let public_key_algorithm = oid_label(&spki.algorithm.oid);
    let public_key_size_bits = estimate_key_size_bits(spki);

    let fingerprint_sha256_hex = sha256_hex(raw_der);

    let extensions = tbs
        .extensions
        .as_ref()
        .map(|exts| {
            exts.iter()
                .map(|ext| ExtensionSummary {
                    oid: ext.extn_id.to_string(),
                    name: oid_name(&ext.extn_id),
                    critical: ext.critical,
                    value_hex: hex::encode(ext.extn_value.as_bytes()),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(CertSummary {
        version,
        serial_hex,
        signature_algorithm,
        issuer,
        subject,
        not_before,
        not_after,
        public_key_algorithm,
        public_key_size_bits,
        fingerprint_sha256_hex,
        extensions,
    })
}

fn oid_label(oid: &const_oid::ObjectIdentifier) -> String {
    oid_name(oid).unwrap_or_else(|| oid.to_string())
}

pub(crate) fn oid_name(oid: &const_oid::ObjectIdentifier) -> Option<String> {
    const_oid::db::DB.by_oid(oid).map(|s| s.to_string())
}

fn estimate_key_size_bits(spki: &spki::SubjectPublicKeyInfoOwned) -> Option<u32> {
    // The raw bit string includes the leading "0 unused bits" byte; subtract.
    let raw = spki.subject_public_key.raw_bytes();
    if raw.is_empty() {
        return None;
    }
    Some((raw.len() as u32) * 8)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
