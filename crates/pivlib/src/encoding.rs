//! Encoding detection cascade.
//!
//! See SPEC.md §"Encoding detection cascade" for the precedence table.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "label", rename_all = "kebab-case")]
pub enum Format {
    Der,
    Pem(String),
    Base64OfDer,
    HexOfDer,
    GzipOfDer,
    Pkcs7,
    Pkcs12,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub format: Format,
    #[serde(with = "serde_bytes_b64")]
    pub normalized_der: Vec<u8>,
    pub warnings: Vec<String>,
}

mod serde_bytes_b64 {
    use base64::Engine;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Walk the cascade and return the first matching format.
pub fn detect(bytes: &[u8]) -> Result<DetectResult> {
    if bytes.is_empty() {
        return Err(Error::Empty);
    }
    detect_with_depth(bytes, 0)
}

fn detect_with_depth(bytes: &[u8], depth: u8) -> Result<DetectResult> {
    if depth > 3 {
        return Err(Error::UnknownEncoding);
    }

    if looks_like_der_sequence(bytes) {
        let format = classify_der(bytes);
        return Ok(DetectResult {
            format,
            normalized_der: bytes.to_vec(),
            warnings: vec![],
        });
    }

    if let Some((label, inner)) = try_decode_pem(bytes)? {
        let mut inner_result = detect_with_depth(&inner, depth + 1)?;
        // Outer format wins for reporting purposes; inner DER bytes are
        // already normalised.
        inner_result.format = Format::Pem(label);
        return Ok(inner_result);
    }

    if let Some((decoded, warnings)) = try_decode_base64(bytes) {
        if looks_like_der_sequence(&decoded) {
            let format = classify_der(&decoded);
            return Ok(DetectResult {
                format: if matches!(format, Format::Pkcs7 | Format::Pkcs12) {
                    format
                } else {
                    Format::Base64OfDer
                },
                normalized_der: decoded,
                warnings,
            });
        }
    }

    if let Some(decoded) = try_decode_hex(bytes) {
        if looks_like_der_sequence(&decoded) {
            return Ok(DetectResult {
                format: Format::HexOfDer,
                normalized_der: decoded,
                warnings: vec!["input was hex-encoded DER".into()],
            });
        }
    }

    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        // gzip envelope. We don't bundle a gzip dep — flag for the caller.
        return Err(Error::wrong_type(
            "der",
            "input looks gzipped (1f 8b magic); decompress and re-detect",
        ));
    }

    Err(Error::UnknownEncoding)
}

/// True if `bytes` starts with `0x30, 0x82` (SEQUENCE, definite long-form
/// 2-byte length) AND the encoded length matches the buffer.
fn looks_like_der_sequence(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    if bytes[0] != 0x30 {
        return false;
    }
    match bytes[1] {
        0x81 => {
            // 1-byte length
            let len = bytes[2] as usize;
            bytes.len() == 3 + len
        }
        0x82 => {
            // 2-byte length
            let len = ((bytes[2] as usize) << 8) | bytes[3] as usize;
            bytes.len() == 4 + len
        }
        0x83 => {
            // 3-byte length
            if bytes.len() < 5 {
                return false;
            }
            let len = ((bytes[2] as usize) << 16)
                | ((bytes[3] as usize) << 8)
                | bytes[4] as usize;
            bytes.len() == 5 + len
        }
        n if n < 0x80 => {
            // Short-form length
            let len = n as usize;
            bytes.len() == 2 + len
        }
        _ => false,
    }
}

/// Identify whether a DER blob is a PKCS#7 ContentInfo, a PKCS#12 PFX, or a
/// generic DER object. We do *shallow* OID matching; the content-type OID
/// lives at a fixed early offset for ContentInfo / PFX.
fn classify_der(bytes: &[u8]) -> Format {
    // PKCS#7 SignedData ContentInfo: SEQUENCE { contentType OID, content [0] ... }
    // OID id-data            = 1.2.840.113549.1.7.1
    // OID id-signedData      = 1.2.840.113549.1.7.2
    // PKCS#12 PFX: SEQUENCE { version INTEGER, authSafe ContentInfo, macData ... }
    //   the embedded contentType OID is id-data inside id-signedData / id-encryptedData.
    //
    // Heuristic: scan a window for these OID byte patterns.
    const SIGNED_DATA_OID: &[u8] =
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    const PKCS12_VERSION_3: &[u8] = &[0x02, 0x01, 0x03]; // INTEGER 3 — PFX version

    if window_contains(bytes, SIGNED_DATA_OID, 64) {
        // Could be PKCS#12 (which wraps SignedData) — check for the PFX version
        // marker near the start.
        if bytes.len() > 8 && bytes[4..8].windows(3).any(|w| w == PKCS12_VERSION_3) {
            return Format::Pkcs12;
        }
        return Format::Pkcs7;
    }

    Format::Der
}

fn window_contains(haystack: &[u8], needle: &[u8], limit: usize) -> bool {
    let end = haystack.len().min(limit);
    haystack[..end].windows(needle.len()).any(|w| w == needle)
}

fn try_decode_pem(bytes: &[u8]) -> Result<Option<(String, Vec<u8>)>> {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return Ok(None);
    };
    let trimmed = s.trim();
    if !trimmed.starts_with("-----BEGIN ") {
        return Ok(None);
    }
    // pem-rfc7468 will accept a single block; we keep the first.
    let (label, der) = pem_rfc7468::decode_vec(trimmed.as_bytes())
        .map_err(|e| Error::Pem(e.to_string()))?;
    Ok(Some((label.to_string(), der)))
}

fn try_decode_base64(bytes: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    // We accept whitespace inside the envelope — a common copy-paste artefact.
    let mut compact: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut had_whitespace = false;
    for &b in bytes {
        if b.is_ascii_whitespace() {
            had_whitespace = true;
            continue;
        }
        if !is_base64_alpha(b) {
            return None;
        }
        compact.push(b);
    }
    if compact.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
        .ok()?;
    let warnings = if had_whitespace {
        vec!["base64 envelope contained whitespace (newlines or spaces)".to_string()]
    } else {
        Vec::new()
    };
    Some((decoded, warnings))
}

fn is_base64_alpha(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_' | b'='
    )
}

fn try_decode_hex(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut compact: Vec<u8> = Vec::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_whitespace() {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return None;
        }
        compact.push(b);
    }
    if compact.len() < 8 || compact.len() % 2 != 0 {
        return None;
    }
    hex::decode(&compact).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_der_short_form() {
        // SEQUENCE, length 2, OCTET STRING 0x04 0x00
        let bytes = vec![0x30, 0x02, 0x04, 0x00];
        let r = detect(&bytes).unwrap();
        assert_eq!(r.format, Format::Der);
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(detect(&[]), Err(Error::Empty)));
    }

    #[test]
    fn rejects_truly_unknown() {
        assert!(detect(b"hello world").is_err());
    }
}
