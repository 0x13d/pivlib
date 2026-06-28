/// INCITS 381-2004 / ISO 19794-4 — Finger Image Data Record
///
/// Record layout (big-endian):
///
/// ┌──────────────────────────────────────────────────────────┐
/// │ Format Identifier          4 bytes  "FIR\0"              │
/// │ Version Number             4 bytes  "010\0"              │
/// │ Record Length              4 bytes  total bytes          │
/// │ CBEFF Product Identifier   4 bytes  0x00000000           │
/// │ Capture Device ID          2 bytes  0x0000               │
/// │ Image Acquisition Level    2 bytes  (see Table 1)        │
/// │ Number of Fingers/Palms    1 byte                        │
/// │ Scale Units                1 byte   1=PPI, 2=PPCM        │
/// │ Scan Resolution (H)        2 bytes  500 typical          │
/// │ Scan Resolution (V)        2 bytes  500 typical          │
/// │ Image Resolution (H)       2 bytes                       │
/// │ Image Resolution (V)       2 bytes                       │
/// │ Pixel Depth                1 byte   8                    │
/// │ Image Compression          1 byte   0=raw,2=WSQ,3=JPEG   │
/// │ Reserved                   2 bytes  0x0000               │
/// ├──────────────── Finger Image Header (per finger) ────────┤
/// │ Finger/Palm Position       1 byte                        │
/// │ Count of Views             1 byte                        │
/// │ View Number                1 byte                        │
/// │ Finger Image Quality       1 byte   0=unspecified        │
/// │ Impression Type            1 byte                        │
/// │ Horizontal Line Length     2 bytes  (width)              │
/// │ Vertical Line Length       2 bytes  (height)             │
/// │ Reserved                   1 byte   0x00                 │
/// ├──────────────── Image Data ──────────────────────────────┤
/// │ Raw pixel bytes (or WSQ)   variable                      │
/// └──────────────────────────────────────────────────────────┘

use super::wsq::DecodedImage;
use bytes::{BufMut, BytesMut};

// Image compression algorithm codes (INCITS 381 Table 10)
pub const COMPRESSION_RAW: u8 = 0;
pub const COMPRESSION_WSQ: u8 = 2;
pub const COMPRESSION_JPEG: u8 = 3;
pub const COMPRESSION_JPEG2000: u8 = 4;

/// Build an INCITS 381 Finger Image Record from a decoded WSQ image.
/// The raw pixel data is stored (no re-compression at this stage).
pub fn build_finger_image_record(
    img: &DecodedImage,
    finger_position: u8,
    impression_type: u8,
) -> Result<Vec<u8>, String> {
    validate_finger_position(finger_position)?;
    validate_impression_type(impression_type)?;

    let pixel_bytes = &img.pixels;
    let image_data_len = pixel_bytes.len();

    // General record header: 32 bytes
    // Finger image header:    9 bytes
    let record_len = 32 + 9 + image_data_len;

    let mut buf = BytesMut::with_capacity(record_len);

    // --- General Record Header ---
    buf.put_slice(b"FIR\0");          // format identifier
    buf.put_slice(b"010\0");          // version
    buf.put_u32(record_len as u32);
    buf.put_u32(0x00000000);          // CBEFF product ID: unspecified
    buf.put_u16(0x0000);              // capture device ID: unspecified
    buf.put_u16(0x0045);              // acquisition level 45 (plain, 500ppi, no features)
    buf.put_u8(1);                    // number of fingers
    buf.put_u8(1);                    // scale units: 1 = PPI
    buf.put_u16(img.ppi);            // scan resolution H
    buf.put_u16(img.ppi);            // scan resolution V
    buf.put_u16(img.width as u16);   // image resolution H
    buf.put_u16(img.height as u16);  // image resolution V
    buf.put_u8(8);                    // pixel depth: 8 bits
    buf.put_u8(COMPRESSION_RAW);     // compression: raw
    buf.put_u16(0x0000);             // reserved

    // --- Finger Image Header ---
    buf.put_u8(finger_position);
    buf.put_u8(1);                    // count of views
    buf.put_u8(1);                    // view number
    buf.put_u8(0x00);                 // quality: unspecified
    buf.put_u8(impression_type);
    buf.put_u16(img.width as u16);
    buf.put_u16(img.height as u16);
    buf.put_u8(0x00);                 // reserved

    // --- Image Data ---
    buf.put_slice(pixel_bytes);

    Ok(buf.to_vec())
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// INCITS 381 Table 5 — finger position codes 0–10.
fn validate_finger_position(pos: u8) -> Result<(), String> {
    if pos > 10 {
        Err(format!(
            "Invalid finger position {pos}. Must be 0–10 per INCITS 381 Table 5."
        ))
    } else {
        Ok(())
    }
}

/// INCITS 381 Table 6 — impression type codes 0–8.
fn validate_impression_type(imp: u8) -> Result<(), String> {
    if imp > 8 {
        Err(format!(
            "Invalid impression type {imp}. Must be 0–8 per INCITS 381 Table 6."
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_image() -> DecodedImage {
        DecodedImage {
            pixels: vec![128u8; 4], // 2×2
            width: 2,
            height: 2,
            ppi: 500,
        }
    }

    #[test]
    fn record_header_magic() {
        let rec = build_finger_image_record(&dummy_image(), 1, 0).unwrap();
        assert_eq!(&rec[0..4], b"FIR\0");
        assert_eq!(&rec[4..8], b"010\0");
    }

    #[test]
    fn invalid_finger_position_rejected() {
        let result = build_finger_image_record(&dummy_image(), 11, 0);
        assert!(result.is_err());
    }
}
