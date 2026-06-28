//! X.509 CRL parsing.

use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::crl::CertificateList;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlSummary {
    pub issuer: String,
    pub this_update: String,
    pub next_update: Option<String>,
    pub revoked: Vec<RevokedEntry>,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedEntry {
    pub serial_hex: String,
    pub revocation_date: String,
}

pub fn parse_der(bytes: &[u8]) -> Result<CrlSummary> {
    let crl = CertificateList::from_der(bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let tbs = &crl.tbs_cert_list;
    Ok(CrlSummary {
        issuer: tbs.issuer.to_string(),
        this_update: tbs.this_update.to_string(),
        next_update: tbs.next_update.as_ref().map(|t| t.to_string()),
        signature_algorithm: tbs.signature.oid.to_string(),
        revoked: tbs
            .revoked_certificates
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|r| RevokedEntry {
                        serial_hex: hex::encode(r.serial_number.as_bytes()),
                        revocation_date: r.revocation_date.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}
