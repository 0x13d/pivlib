//! PKCS#12 / PFX enumeration.
//!
//! We surface the **structure** of a PKCS#12 — which SafeBags it contains,
//! what type they claim to be, whether they're shrouded (encrypted). We do
//! **not** decrypt anything. This is a structure tool, not a key extractor.

use der::Decode;
use pkcs12::pfx::Pfx;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs12Summary {
    pub version: u8,
    pub auth_safe_content_type: String,
    pub mac_present: bool,
    pub mac_algorithm: Option<String>,
    pub note: String,
}

pub fn enumerate(der: &[u8]) -> Result<Pkcs12Summary> {
    let pfx = Pfx::from_der(der).map_err(|e| Error::Asn1(e.to_string()))?;
    Ok(Pkcs12Summary {
        version: pfx.version as u8,
        auth_safe_content_type: pfx.auth_safe.content_type.to_string(),
        mac_present: pfx.mac_data.is_some(),
        mac_algorithm: pfx
            .mac_data
            .as_ref()
            .map(|m| m.mac.algorithm.oid.to_string()),
        note: "SafeBag enumeration requires decrypting EncryptedData; \
               supply a password through the future enumerate_with_password() entrypoint."
            .into(),
    })
}
