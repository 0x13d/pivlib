/// CBEFF — Common Biometric Exchange Formats Framework
/// ISO/IEC 19785-1:2006 / NIST SP 800-76
///
/// A CBEFF structure wraps one or more Biometric Data Blocks (BDBs).
/// Each BDB is preceded by a Standard Biometric Header (SBH).
///
/// Minimal SBH layout used here (patron format: INCITS 398-2008):
///
/// ┌──────────────────────────────────────────────────────────┐
/// │ Patron Header Version     2 bytes  0x0100                │
/// │ SBH Security Options      1 byte   0x00 (no integrity)   │
/// │ BDB Length                4 bytes  byte count of BDB     │
/// │ SB Format Owner           2 bytes  see FormatOwner enum  │
/// │ SB Format Type            2 bytes  see FormatType enum   │
/// │ BDB Creation Date/Time    8 bytes  0x00…(unset)          │
/// │ BDB Validity Period From  8 bytes  0x00…(unset)          │
/// │ BDB Validity Period To    8 bytes  0x00…(unset)          │
/// │ BDB Creator PID           4 bytes  0x00000000            │
/// │ FASC-N / SBAM ID          25 bytes 0x00…(not used)       │
/// │ Reserved                  4 bytes  0x00000000            │
/// │ SBH Challenge Response    8 bytes  0x00…(not used)       │
/// │ BDB Index                 2 bytes  1-based               │
/// │ BDB Encryption Options    2 bytes  0x0000 (none)         │
/// ├──────────────────────────────────────────────────────────┤
/// │ Biometric Type            4 bytes  see BiometricType enum│
/// │ Biometric Subtype         1 byte   0x00                  │
/// │ Processed Level           1 byte   0x00                  │
/// │ Products                  4 bytes  0x00000000            │
/// │ Capture Date/Time         8 bytes  0x00…                 │
/// │ Quality                   1 byte   255 = unset           │
/// └──────────────────────────────────────────────────────────┘

use bytes::{BufMut, BytesMut};

// ---------------------------------------------------------------------------
// Constants / enums
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum BiometricType {
    NoInformation = 0x00000000,
    MultipleTypes = 0x00000001,
    Face = 0x00000008,
    Fingerprint = 0x00000010,
    Iris = 0x00000040,
}

#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Copy)]
pub enum FormatOwner {
    /// INCITS (formerly X9/ANSI)
    INCITS = 0x001B,
    /// NIST
    NIST = 0x0101,
}

#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Copy)]
pub enum FormatType {
    /// INCITS 378 — Finger Minutiae
    INCITS378 = 0x0201,
    /// INCITS 381 — Finger Image
    INCITS381 = 0x0401,
    /// INCITS 385 — Face Image
    INCITS385 = 0x0501,
}

// 80-byte INCITS 398 patron header + 19-byte biometric information block
// (see the ASCII diagram above). Each byte is accounted for in `write_sbh`.
const SBH_LEN: usize = 99;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Wrap a single BDB in a CBEFF SBH container.
pub fn wrap(
    biometric_type: BiometricType,
    format_owner: FormatOwner,
    format_type: FormatType,
    bdb: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(SBH_LEN + bdb.len());
    write_sbh(
        &mut buf,
        biometric_type,
        format_owner,
        format_type,
        bdb.len() as u32,
        1,
    );
    buf.put_slice(bdb);
    buf.to_vec()
}

/// Wrap multiple BDBs (each with its own SBH) concatenated in one buffer.
pub fn wrap_multi(
    records: Vec<(BiometricType, FormatOwner, FormatType, Vec<u8>)>,
) -> Vec<u8> {
    let total = records
        .iter()
        .map(|(_, _, _, bdb)| SBH_LEN + bdb.len())
        .sum();
    let mut buf = BytesMut::with_capacity(total);

    for (idx, (biometric_type, format_owner, format_type, bdb)) in
        records.into_iter().enumerate()
    {
        write_sbh(
            &mut buf,
            biometric_type,
            format_owner,
            format_type,
            bdb.len() as u32,
            (idx + 1) as u16,
        );
        buf.put_slice(&bdb);
    }

    buf.to_vec()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn write_sbh(
    buf: &mut BytesMut,
    biometric_type: BiometricType,
    format_owner: FormatOwner,
    format_type: FormatType,
    bdb_len: u32,
    bdb_index: u16,
) {
    buf.put_u16(0x0100);      // patron header version
    buf.put_u8(0x00);         // SBH security options: none
    buf.put_u32(bdb_len);     // BDB length
    buf.put_u16(format_owner as u16);
    buf.put_u16(format_type as u16);
    buf.put_bytes(0x00, 8);   // creation date: unset
    buf.put_bytes(0x00, 8);   // validity from: unset
    buf.put_bytes(0x00, 8);   // validity to: unset
    buf.put_u32(0x00000000);  // BDB creator PID
    buf.put_bytes(0x00, 25);  // FASC-N / SBAM ID: unused
    buf.put_u32(0x00000000);  // reserved
    buf.put_bytes(0x00, 8);   // challenge response: unused
    buf.put_u16(bdb_index);   // BDB index (1-based)
    buf.put_u16(0x0000);      // encryption options: none

    // Biometric information block (part of SBH in INCITS 398)
    buf.put_u32(biometric_type as u32);
    buf.put_u8(0x00);         // biometric subtype: unspecified
    buf.put_u8(0x00);         // processed level
    buf.put_u32(0x00000000);  // products
    buf.put_bytes(0x00, 8);   // capture date/time: unset
    buf.put_u8(0xFF);         // quality: 255 = no attempt
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbh_is_correct_length() {
        let bdb = vec![0xAAu8; 10];
        let record = wrap(
            BiometricType::Face,
            FormatOwner::INCITS,
            FormatType::INCITS385,
            &bdb,
        );
        assert_eq!(record.len(), SBH_LEN + bdb.len());
    }

    #[test]
    fn patron_header_version() {
        let record = wrap(
            BiometricType::Fingerprint,
            FormatOwner::INCITS,
            FormatType::INCITS378,
            &[0x00],
        );
        assert_eq!(record[0], 0x01);
        assert_eq!(record[1], 0x00);
    }

    #[test]
    fn wrap_multi_concatenates_sbhs() {
        let result = wrap_multi(vec![
            (BiometricType::Fingerprint, FormatOwner::INCITS, FormatType::INCITS381, vec![0xBBu8; 5]),
            (BiometricType::Fingerprint, FormatOwner::INCITS, FormatType::INCITS378, vec![0xCCu8; 7]),
        ]);
        assert_eq!(result.len(), (SBH_LEN + 5) + (SBH_LEN + 7));
    }
}
