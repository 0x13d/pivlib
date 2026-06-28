//! PKCS#7 / CMS SignedData enumeration.
//!
//! We enumerate the embedded certificates and signers, but we don't try to
//! verify the signature — that's a downstream concern with its own trust
//! anchor question.

use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{cert::parse::CertSummary, error::{Error, Result}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs7Summary {
    pub digest_algorithms: Vec<String>,
    pub encap_content_type: String,
    pub certificates: Vec<CertSummary>,
    pub signers: Vec<SignerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSummary {
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub issuer: Option<String>,
    pub serial_hex: Option<String>,
}

pub fn enumerate(der: &[u8]) -> Result<Pkcs7Summary> {
    let ci = ContentInfo::from_der(der).map_err(|e| Error::Asn1(e.to_string()))?;
    let signed_der = ci.content.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
    let signed = SignedData::from_der(&signed_der).map_err(|e| Error::Asn1(e.to_string()))?;

    let digest_algorithms = signed
        .digest_algorithms
        .iter()
        .map(|a| a.oid.to_string())
        .collect();

    let encap_content_type = signed.encap_content_info.econtent_type.to_string();

    let mut certificates = Vec::new();
    if let Some(set) = signed.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                if let Ok(der) = c.to_der() {
                    if let Ok(summary) = crate::cert::parse::parse_der(&der) {
                        certificates.push(summary);
                    }
                }
            }
        }
    }

    let signers = signed
        .signer_infos
        .0
        .iter()
        .map(|s| {
            let (issuer, serial) = match &s.sid {
                cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(iasn) => (
                    Some(iasn.issuer.to_string()),
                    Some(hex::encode(iasn.serial_number.as_bytes())),
                ),
                cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(_) => (None, None),
            };
            SignerSummary {
                digest_algorithm: s.digest_alg.oid.to_string(),
                signature_algorithm: s.signature_algorithm.oid.to_string(),
                issuer,
                serial_hex: serial,
            }
        })
        .collect();

    Ok(Pkcs7Summary {
        digest_algorithms,
        encap_content_type,
        certificates,
        signers,
    })
}
