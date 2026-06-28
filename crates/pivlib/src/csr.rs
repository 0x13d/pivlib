//! PKCS#10 Certificate Signing Request parsing.

use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::request::CertReq;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrSummary {
    pub subject: String,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub attributes: Vec<AttributeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSummary {
    pub oid: String,
    pub value_hex: String,
}

pub fn parse_der(bytes: &[u8]) -> Result<CsrSummary> {
    let csr = CertReq::from_der(bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let info = &csr.info;
    Ok(CsrSummary {
        subject: info.subject.to_string(),
        public_key_algorithm: info.public_key.algorithm.oid.to_string(),
        signature_algorithm: csr.algorithm.oid.to_string(),
        attributes: info
            .attributes
            .iter()
            .map(|a| AttributeSummary {
                oid: a.oid.to_string(),
                value_hex: hex::encode(
                    a.values
                        .iter()
                        .flat_map(|v| v.value().to_vec())
                        .collect::<Vec<u8>>(),
                ),
            })
            .collect(),
    })
}
