//! Build a synthetic PIV CHUID container per SP 800-73-4 Part 1 §3.1.2 (Table 9).
//!
//! BER-TLV with single-byte application-class tags. Pivlib's parser expects
//! tags 0xEE, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x3E, 0xFE.

pub fn build_chuid() -> Vec<u8> {
    let mut body = Vec::new();

    push_tlv(&mut body, 0x30, &synthetic_fascn());
    push_tlv(&mut body, 0x34, &synthetic_guid());
    push_tlv(&mut body, 0x35, b"20300101"); // expiration: 2030-01-01
    push_tlv(&mut body, 0x3E, &synthetic_signature_blob());
    push_tlv(&mut body, 0xFE, &[]); // Error Detection Code (LRC) — empty

    // Buffer length tag wraps the running length of the rest of the message.
    let mut out = Vec::new();
    push_tlv(&mut out, 0xEE, &(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    encode_length(out, value.len());
    out.extend_from_slice(value);
}

fn encode_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// 25-byte FASC-N matching FIPS 201 Appendix B encoding, with synthetic
/// demo-clean field values:
///   agency=9999, system=0001, credential=000042, series=0, issue=1,
///   person=0000000001, org_cat=1, org_id=9999, assoc=1.
///
/// Each 5-bit symbol carries a 4-bit BCD value MSB-first plus an odd-parity
/// bit. Separators: SS=0b1011, FS=0b1100, ES=0b1101. Pivlib's decoder reads
/// the 4 high bits and treats anything ≥10 as a separator.
fn synthetic_fascn() -> Vec<u8> {
    let mut writer = BitWriter::new();

    writer.symbol(0b1011); // SS
    for d in [9, 9, 9, 9] { writer.symbol(d); }
    writer.symbol(0b1100); // FS
    for d in [0, 0, 0, 1] { writer.symbol(d); }
    writer.symbol(0b1100);
    for d in [0, 0, 0, 0, 4, 2] { writer.symbol(d); }
    writer.symbol(0b1100);
    writer.symbol(0); // credential series
    writer.symbol(0b1100);
    writer.symbol(1); // individual credential issue
    writer.symbol(0b1100);
    for d in [0, 0, 0, 0, 0, 0, 0, 0, 0, 1] { writer.symbol(d); }
    writer.symbol(1);                   // organizational category
    for d in [9, 9, 9, 9] { writer.symbol(d); }
    writer.symbol(1);                   // person/org association
    writer.symbol(0b1101);              // ES
    writer.symbol(0);                   // LRC (parity check, decoder ignores)

    let out = writer.finish();
    debug_assert_eq!(out.len(), 25, "FASC-N must be 25 bytes");
    out
}

/// MSB-first bit packer for 5-bit FASC-N symbols.
struct BitWriter { buf: Vec<u8>, byte: u8, bit_pos: u8 }

impl BitWriter {
    fn new() -> Self { Self { buf: Vec::with_capacity(25), byte: 0, bit_pos: 0 } }

    /// Push a 4-bit BCD/separator value plus an odd-parity bit (5 bits total).
    fn symbol(&mut self, lo4: u8) {
        // High 4 bits MSB-first, then parity to keep total ones count odd.
        let parity = if (lo4.count_ones() & 1) == 1 { 0 } else { 1 };
        for i in (0..4).rev() {
            self.push_bit((lo4 >> i) & 1);
        }
        self.push_bit(parity);
    }

    fn push_bit(&mut self, b: u8) {
        self.byte = (self.byte << 1) | (b & 1);
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.buf.push(self.byte);
            self.byte = 0;
            self.bit_pos = 0;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.byte <<= 8 - self.bit_pos;
            self.buf.push(self.byte);
        }
        self.buf
    }
}

/// 16-byte UUID (RFC 4122 v4). Fixed value so the fixture is stable.
fn synthetic_guid() -> Vec<u8> {
    vec![
        0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x46, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF,
        0xF0,
    ]
}

/// Stub CMS SignedData blob — pivlib enumerates presence, doesn't verify. 64
/// bytes of 0xAA so the fixture is obviously not a real signature.
fn synthetic_signature_blob() -> Vec<u8> {
    vec![0xAA; 64]
}
