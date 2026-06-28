//! PKCS#8 private-key **metadata** — algorithm, parameters, encryption envelope.
//!
//! **Never** returns the actual key material. The whole point of inspecting a
//! key in a PKI tool is to figure out what it is, not to leak its contents.

use der::{Decode, Encode};
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySummary {
    pub algorithm: String,
    pub parameter_oid: Option<String>,
    pub encrypted: bool,
    pub kdf_algorithm: Option<String>,
    pub encryption_algorithm: Option<String>,
    pub raw_key_length: usize,
}

pub fn parse_metadata(bytes: &[u8]) -> Result<KeySummary> {
    // Try unencrypted first.
    if let Ok(pki) = PrivateKeyInfo::from_der(bytes) {
        return Ok(KeySummary {
            algorithm: pki.algorithm.oid.to_string(),
            parameter_oid: pki.algorithm.parameters.as_ref().and_then(|p| {
                // Best-effort: parameters is an ANY; try to decode as an OID.
                der::asn1::ObjectIdentifier::from_der(&p.to_der().ok()?)
                    .ok()
                    .map(|o| o.to_string())
            }),
            encrypted: false,
            kdf_algorithm: None,
            encryption_algorithm: None,
            raw_key_length: pki.private_key.len(),
        });
    }

    // Then encrypted.
    if let Ok(enc) = EncryptedPrivateKeyInfo::try_from(bytes) {
        let alg_oid = enc.encryption_algorithm.oid().to_string();
        // PBES2 carries the KDF + cipher in parameters; we surface the outer
        // OID and let the caller decide whether to unwrap.
        return Ok(KeySummary {
            algorithm: "encrypted".into(),
            parameter_oid: None,
            encrypted: true,
            kdf_algorithm: None,
            encryption_algorithm: Some(alg_oid),
            raw_key_length: enc.encrypted_data.len(),
        });
    }

    Err(Error::wrong_type(
        "PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo",
        "neither variant parsed",
    ))
}
