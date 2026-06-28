//! PIV Security Object — NIST SP 800-73 Part 1, §3.5.5.
//!
//! Structurally a **CMS SignedData** wrapping an `LDSSecurityObject` (a list
//! of `(container_id, hashAlgorithm, hash)` triples — borrowed from the ICAO
//! 9303 MRTD security object). pivlib surfaces the signer + the embedded
//! container hashes.

use cms::{content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pkcs7::SignerSummary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityObject {
    pub encap_content_type: String,
    pub hash_algorithm: Option<String>,
    pub container_hashes: Vec<ContainerHash>,
    pub signers: Vec<SignerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerHash {
    pub container_id: u8,
    pub hash_hex: String,
}

pub fn parse(bytes: &[u8]) -> Result<SecurityObject> {
    let ci = ContentInfo::from_der(bytes).map_err(|e| Error::Asn1(e.to_string()))?;
    let signed_der = ci.content.to_der().map_err(|e| Error::Asn1(e.to_string()))?;
    let signed = SignedData::from_der(&signed_der).map_err(|e| Error::Asn1(e.to_string()))?;

    let encap_content_type = signed.encap_content_info.econtent_type.to_string();

    // The eContent is an LDSSecurityObject; we don't have a typed decoder for
    // it (it's a SP 800-73-flavored ICAO 9303 structure), so we surface the
    // container_id → hash pairs by walking the inner DER.
    let mut container_hashes = Vec::new();
    let mut hash_algorithm: Option<String> = None;

    if let Some(econtent) = &signed.encap_content_info.econtent {
        let inner_bytes = econtent.value();
        // Best-effort BER walk: SEQUENCE { version, hashAlgorithm, SEQUENCE OF { container_id, hash } }
        // We extract the OCTET STRING fragments — they're the hashes — and
        // pair them with the preceding INTEGER (container_id).
        let mut prev_int: Option<u8> = None;
        walk_for_container_hashes(inner_bytes, &mut prev_int, &mut container_hashes, &mut hash_algorithm);
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

    Ok(SecurityObject {
        encap_content_type,
        hash_algorithm,
        container_hashes,
        signers,
    })
}

fn walk_for_container_hashes(
    bytes: &[u8],
    prev_int: &mut Option<u8>,
    out: &mut Vec<ContainerHash>,
    hash_algorithm: &mut Option<String>,
) {
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let tag = bytes[i];
        i += 1;
        let first_len = bytes[i];
        i += 1;
        let len = if first_len & 0x80 == 0 {
            first_len as usize
        } else {
            let n = (first_len & 0x7F) as usize;
            if n == 0 || i + n > bytes.len() {
                return;
            }
            let mut acc = 0usize;
            for &b in &bytes[i..i + n] {
                acc = (acc << 8) | b as usize;
            }
            i += n;
            acc
        };
        if i + len > bytes.len() {
            return;
        }
        let value = &bytes[i..i + len];
        match tag {
            0x02 => {
                // INTEGER — candidate container id.
                if value.len() == 1 {
                    *prev_int = Some(value[0]);
                }
            }
            0x04 => {
                // OCTET STRING — candidate hash.
                if let Some(cid) = prev_int.take() {
                    out.push(ContainerHash {
                        container_id: cid,
                        hash_hex: hex::encode(value),
                    });
                }
            }
            0x06 => {
                // OBJECT IDENTIFIER — first one is the hash algorithm.
                if hash_algorithm.is_none() {
                    if let Ok(oid) = const_oid::ObjectIdentifier::from_bytes(value) {
                        *hash_algorithm = Some(oid.to_string());
                    }
                }
            }
            // Recurse into constructed forms.
            0x30 | 0x31 | 0xA0 | 0xA1 | 0xA2 | 0xA3 => {
                walk_for_container_hashes(value, prev_int, out, hash_algorithm);
            }
            _ => {}
        }
        i += len;
    }
}
