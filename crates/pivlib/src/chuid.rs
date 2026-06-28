//! PIV CHUID (Cardholder Unique Identifier) — NIST SP 800-73 Part 1, §3.1.2 + Table 9.
//!
//! BER-TLV decoder. The container is a sequence of `(tag, length, value)`
//! triples; tags here are *single bytes* with the high bit set per the SP
//! 800-73 application-tag scheme.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Chuid {
    pub buffer_length: Option<u16>,
    pub fasc_n: Option<Fascn>,
    pub fasc_n_raw_hex: Option<String>,
    pub agency_code: Option<String>,
    pub organizational_identifier: Option<String>,
    pub duns: Option<String>,
    pub guid: Option<String>, // UUID-format
    pub expiration_date: Option<String>, // YYYYMMDD
    pub issuer_asymmetric_signature_hex: Option<String>,
    pub error_detection_code_present: bool,
    pub extras: Vec<UnknownTlv>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fascn {
    /// Agency Code (4 BCD digits).
    pub agency_code: String,
    /// System Code (4 BCD digits).
    pub system_code: String,
    /// Credential Number (6 BCD digits).
    pub credential_number: String,
    /// Credential Series (1 BCD digit).
    pub credential_series: String,
    /// Individual Credential Issue (1 BCD digit).
    pub individual_credential_issue: String,
    /// Person Identifier (10 BCD digits).
    pub person_identifier: String,
    /// Organizational Category (1 BCD digit).
    pub organizational_category: String,
    /// Organizational Identifier (4 BCD digits).
    pub organizational_identifier: String,
    /// Person/Organization Association Category (1 BCD digit).
    pub person_organization_association: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownTlv {
    pub tag_hex: String,
    pub value_hex: String,
}

/// Parse a PIV CHUID container.
pub fn parse(bytes: &[u8]) -> Result<Chuid> {
    let tlvs = parse_tlvs(bytes)?;
    let mut chuid = Chuid::default();

    for (tag, value) in tlvs {
        match tag {
            0xEE => {
                // Buffer Length — 2-byte big-endian.
                if value.len() == 2 {
                    chuid.buffer_length = Some(((value[0] as u16) << 8) | value[1] as u16);
                }
            }
            0x30 => {
                // FASC-N — 25 BCD-encoded bytes.
                chuid.fasc_n_raw_hex = Some(hex::encode(&value));
                if let Ok(fascn) = decode_fascn(&value) {
                    chuid.fasc_n = Some(fascn);
                }
            }
            0x31 => {
                chuid.agency_code = Some(printable_or_hex(&value));
            }
            0x32 => {
                chuid.organizational_identifier = Some(printable_or_hex(&value));
            }
            0x33 => {
                chuid.duns = Some(printable_or_hex(&value));
            }
            0x34 => {
                // GUID — 16 bytes
                if value.len() == 16 {
                    chuid.guid = Some(format_uuid(&value));
                }
            }
            0x35 => {
                // Expiration Date — YYYYMMDD as 8 printable bytes
                chuid.expiration_date = Some(printable_or_hex(&value));
            }
            0x3E => {
                chuid.issuer_asymmetric_signature_hex = Some(hex::encode(&value));
            }
            0xFE => {
                chuid.error_detection_code_present = true;
            }
            other => chuid.extras.push(UnknownTlv {
                tag_hex: format!("{:02X}", other),
                value_hex: hex::encode(&value),
            }),
        }
    }

    Ok(chuid)
}

/// BER-TLV walker. Supports application-class single-byte tags (the only thing
/// SP 800-73 emits) and short/long-form lengths.
pub(crate) fn parse_tlvs(bytes: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let tag = bytes[i];
        i += 1;
        if i >= bytes.len() {
            return Err(Error::tlv(i, "tag without length"));
        }
        let first_len = bytes[i];
        i += 1;
        let len = if first_len & 0x80 == 0 {
            first_len as usize
        } else {
            let nbytes = (first_len & 0x7F) as usize;
            if nbytes == 0 {
                return Err(Error::tlv(i, "indefinite-length form not supported"));
            }
            if i + nbytes > bytes.len() {
                return Err(Error::tlv(i, "long-form length truncated"));
            }
            let mut acc: usize = 0;
            for &b in &bytes[i..i + nbytes] {
                acc = (acc << 8) | b as usize;
            }
            i += nbytes;
            acc
        };
        if i + len > bytes.len() {
            return Err(Error::tlv(i, format!("value of {} bytes overruns buffer", len)));
        }
        out.push((tag, bytes[i..i + len].to_vec()));
        i += len;
    }
    Ok(out)
}

fn decode_fascn(value: &[u8]) -> Result<Fascn> {
    // FASC-N is packed BCD with 5-bit groups + odd-parity. NIST SP 800-73-4
    // Part 1, Appendix B.4 enumerates the field boundaries. For an
    // operator-facing tool we surface the *digits* between the field
    // delimiters (SS=11010, FS=11100, ES=11111). A real-world decoder would
    // also check parity; we don't here — surface what's there, flag in extras
    // if shape is wrong.
    if value.len() != 25 {
        return Err(Error::wrong_type("FASC-N", format!("expected 25 bytes, got {}", value.len())));
    }
    let bits = unpack_bits(value);
    let mut digits: Vec<&[u8]> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for symbol in bits.chunks(5) {
        if symbol.len() < 5 {
            break;
        }
        let lo4 = (symbol[0] << 3) | (symbol[1] << 2) | (symbol[2] << 1) | symbol[3];
        // Field separators have lo4 == 1011 (SS), 1100 (FS), 1101 (ES).
        if lo4 >= 10 {
            if !current.is_empty() {
                // Push by leaking; we just need slices for borrow-check.
                let s = current.clone();
                let leaked: &'static [u8] = Box::leak(s.into_boxed_slice());
                digits.push(leaked);
                current = Vec::new();
            }
            continue;
        }
        current.push(b'0' + lo4);
    }
    if !current.is_empty() {
        let s = current.clone();
        let leaked: &'static [u8] = Box::leak(s.into_boxed_slice());
        digits.push(leaked);
    }
    let s = |i: usize| -> String {
        digits
            .get(i)
            .map(|d| std::str::from_utf8(d).unwrap_or("").to_string())
            .unwrap_or_default()
    };

    // FIPS 201 Appendix B: Person Identifier (10) + Organizational Category (1)
    // + Organizational Identifier (4) + Person/Org Association (1) sit *between*
    // the last Field Separator and the End Sentinel with no separators between
    // them. The walker pulls them as one 16-digit run; split by fixed width.
    let merged = s(5);
    let merged_chars: Vec<char> = merged.chars().collect();
    let (pi, oc, oi, poa) = if merged_chars.len() >= 16 {
        (
            merged_chars[0..10].iter().collect::<String>(),
            merged_chars[10..11].iter().collect::<String>(),
            merged_chars[11..15].iter().collect::<String>(),
            merged_chars[15..16].iter().collect::<String>(),
        )
    } else {
        (merged, String::new(), String::new(), String::new())
    };

    Ok(Fascn {
        agency_code: s(0),
        system_code: s(1),
        credential_number: s(2),
        credential_series: s(3),
        individual_credential_issue: s(4),
        person_identifier: pi,
        organizational_category: oc,
        organizational_identifier: oi,
        person_organization_association: poa,
    })
}

fn unpack_bits(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in (0..8).rev() {
            out.push((b >> i) & 1);
        }
    }
    out
}

fn printable_or_hex(value: &[u8]) -> String {
    if value.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        String::from_utf8_lossy(value).into_owned()
    } else {
        hex::encode(value)
    }
}

fn format_uuid(value: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value[0], value[1], value[2], value[3],
        value[4], value[5],
        value[6], value[7],
        value[8], value[9],
        value[10], value[11], value[12], value[13], value[14], value[15],
    )
}
