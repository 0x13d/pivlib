//! Build a synthetic PIV Card Capability Container per SP 800-73 §3.1.3.
//!
//! Sequence of BER-TLVs the parser surfaces by tag. We populate the canonical
//! identifiers the spec marks as mandatory (card_id, version, grammar version,
//! data model, EDC) and leave the rest absent.

pub fn build_ccc() -> Vec<u8> {
    let mut out = Vec::new();
    // 0xF0 — Card Identifier (21 bytes per GSC-IS 2.1: 1-byte GSC-RID || 1-byte
    // mfr || 1-byte card-type || 14 random bytes). We use a synthetic recipe.
    push_tlv(&mut out, 0xF0, &[
        0xA0, 0x00, 0x00, 0x01, 0x16, // RID (NIST PIV applet)
        0xDB, 0x00,                    // manufacturer + card type
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    push_tlv(&mut out, 0xF1, &[0x21]); // Capability Container Version
    push_tlv(&mut out, 0xF2, &[0x21]); // Capability Grammar Version
    push_tlv(&mut out, 0xF3, &[]);     // Applications CardURL — not used
    push_tlv(&mut out, 0xF4, &[0x00]); // PKCS#15 indicator
    push_tlv(&mut out, 0xF5, &[0x10]); // Registered Data Model Number (PIV = 0x10)
    push_tlv(&mut out, 0xF6, &[]);
    push_tlv(&mut out, 0xF7, &[]);
    push_tlv(&mut out, 0xFA, &[]);
    push_tlv(&mut out, 0xFB, &[]);
    push_tlv(&mut out, 0xFC, &[]);
    push_tlv(&mut out, 0xFD, &[]);
    push_tlv(&mut out, 0xFE, &[]); // EDC marker
    out
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        out.push(0x81);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
}
