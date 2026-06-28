/// INCITS 378-2004 / ISO 19794-2 — Finger Minutiae Data Record
///
/// Record layout (big-endian):
///
/// ┌──────────────────────────────────────────────────────────┐
/// │ Format Identifier         2 bytes  0x464D ("FM")         │
/// │ Version Number            2 bytes  0x2020 (" 20")        │
/// │ Record Length             4 bytes  total bytes           │
/// │ CBEFF Product Identifier  4 bytes  0x00000000            │
/// │ Capture Equipment Comp.   2 bytes  0x0000                │
/// │ Capture Equipment ID      2 bytes  0x0000                │
/// │ Size X                    2 bytes  image width (100ths mm)│
/// │ Size Y                    2 bytes  image height           │
/// │ Resolution X              2 bytes  197 = 500 ppi          │
/// │ Resolution Y              2 bytes  197 = 500 ppi          │
/// │ Number of Finger Views    1 byte                         │
/// │ Reserved                  1 byte   0x00                  │
/// ├──────────────── Finger View (per view) ──────────────────┤
/// │ Finger Position           1 byte                         │
/// │ View Number / Impression  1 byte  (packed nibbles)       │
/// │ Finger Quality            1 byte   0=unspecified         │
/// │ Number of Minutiae        1 byte                         │
/// ├──────────────── Minutia Records (per minutia) ───────────┤
/// │ Type / X                  2 bytes  2-bit type + 14-bit X │
/// │ Y / Quality               2 bytes  2-bit qual + 14-bit Y │
/// │ Angle                     1 byte   0–179 (2° steps)      │
/// │ Quality                   1 byte   0–100                 │
/// ├──────────────── Extended Data Block ─────────────────────┤
/// │ Extended Data Length      2 bytes  0 = absent            │
/// └──────────────────────────────────────────────────────────┘

use super::wsq::DecodedImage;
use bytes::{BufMut, BytesMut};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single minutia point.
#[derive(Debug, Clone)]
pub struct Minutia {
    pub minutia_type: MinutiaType, // ridge ending or bifurcation
    pub x: u16,                    // pixel coordinate
    pub y: u16,
    pub angle: u8,   // 0–179 (each unit = 2°)
    pub quality: u8, // 0–100
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MinutiaType {
    Other = 0,
    RidgeEnding = 1,
    Bifurcation = 2,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Build an INCITS 378 Finger Minutiae Record.
///
/// When NBIS is integrated, `extract_minutiae` will call `mindtct` via FFI.
/// Until then it returns an empty minutiae list so the record is structurally
/// valid (zero-minutiae record is legal per the standard).
pub fn build_finger_minutiae_record(
    img: &DecodedImage,
    finger_position: u8,
    impression_type: u8,
) -> Result<Vec<u8>, String> {
    let minutiae = extract_minutiae(img)?;
    encode_record(img, finger_position, impression_type, &minutiae)
}

// ---------------------------------------------------------------------------
// Minutiae extraction (stubbed until NBIS FFI is wired)
// ---------------------------------------------------------------------------

fn extract_minutiae(img: &DecodedImage) -> Result<Vec<Minutia>, String> {
    #[cfg(feature = "nbis")]
    return nbis_extract(img);

    #[cfg(not(feature = "nbis"))]
    {
        let _ = img;
        // Return empty list — valid per INCITS 378 §7.1
        Ok(vec![])
    }
}

#[cfg(feature = "nbis")]
fn nbis_extract(img: &DecodedImage) -> Result<Vec<Minutia>, String> {
    use std::ffi::c_int;
    use std::os::raw::c_uchar;
    use std::ptr;

    /// Mirrors MinutiaePoint in nbis/shims/mindtct_mem.h (must stay in sync).
    #[repr(C)]
    struct CMinutiaePoint {
        x: c_int,
        y: c_int,
        direction: c_uchar,
        quality: c_uchar,
        minutia_type: c_uchar,
    }

    extern "C" {
        /// Defined in nbis/shims/mindtct_mem.c, compiled into libmindtct.
        fn mindtct_mem(
            idata: *const c_uchar,
            iwidth: c_int,
            iheight: c_int,
            out_points: *mut *mut CMinutiaePoint,
            out_count: *mut c_int,
        ) -> c_int;

        /// Free the array returned by mindtct_mem.
        fn mindtct_mem_free(points: *mut CMinutiaePoint);
    }

    let mut out_points: *mut CMinutiaePoint = ptr::null_mut();
    let mut out_count: c_int = 0;

    let ret = unsafe {
        mindtct_mem(
            img.pixels.as_ptr(),
            img.width as c_int,
            img.height as c_int,
            &mut out_points,
            &mut out_count,
        )
    };

    if ret != 0 {
        return Err(format!("mindtct_mem failed (code {})", ret));
    }

    let count = out_count.max(0) as usize;
    let mut minutiae = Vec::with_capacity(count);

    for i in 0..count {
        let m = unsafe { &*out_points.add(i) };

        let minutia_type = match m.minutia_type {
            1 => MinutiaType::RidgeEnding,
            2 => MinutiaType::Bifurcation,
            _ => MinutiaType::Other,
        };

        // NBIS direction: index 0–15 over a semicircle (11.25° per step).
        // INCITS 378 angle: 2° steps, range 0–179 (covers 0–358°).
        // Conversion: incits = round(nbis_dir * 11.25 / 2) = round(nbis_dir * 5.625)
        let angle = ((m.direction as f32) * 5.625_f32).round() as u8;

        minutiae.push(Minutia {
            minutia_type,
            x: m.x.max(0) as u16,
            y: m.y.max(0) as u16,
            angle,
            quality: m.quality,
        });
    }

    unsafe { mindtct_mem_free(out_points) };

    Ok(minutiae)
}

// ---------------------------------------------------------------------------
// Binary record encoder
// ---------------------------------------------------------------------------

fn encode_record(
    img: &DecodedImage,
    finger_position: u8,
    impression_type: u8,
    minutiae: &[Minutia],
) -> Result<Vec<u8>, String> {
    let num_minutiae = minutiae.len();
    if num_minutiae > 255 {
        return Err("Too many minutiae (max 255 per INCITS 378)".to_string());
    }

    // Convert pixel dimensions to 100ths of mm using image PPI
    let ppi = img.ppi as f32;
    let size_x_mm100 = ((img.width as f32 / ppi) * 2540.0).round() as u16;
    let size_y_mm100 = ((img.height as f32 / ppi) * 2540.0).round() as u16;
    // Resolution in pixels per cm (INCITS 378 uses ppcm; 500ppi ≈ 197 ppcm)
    let res_x = ((ppi / 25.4) * 10.0).round() as u16;
    let res_y = res_x;

    // General header: 24 bytes
    // Finger view header: 4 bytes
    // Minutia records: 6 bytes each
    // Extended data length field: 2 bytes
    let record_len = 24 + 4 + num_minutiae * 6 + 2;

    let mut buf = BytesMut::with_capacity(record_len);

    // --- General Record Header ---
    buf.put_u8(b'F');
    buf.put_u8(b'M');
    buf.put_u8(b' ');
    buf.put_u8(b'2');
    buf.put_u8(b'0');
    buf.put_u8(0x00); // version null terminator padding (6 bytes total: "FM 20\0")
    buf.put_u32(record_len as u32);
    buf.put_u32(0x00000000); // CBEFF product ID
    buf.put_u16(0x0000);     // capture equipment compliance
    buf.put_u16(0x0000);     // capture equipment ID
    buf.put_u16(size_x_mm100);
    buf.put_u16(size_y_mm100);
    buf.put_u16(res_x);
    buf.put_u16(res_y);
    buf.put_u8(1);    // number of finger views
    buf.put_u8(0x00); // reserved

    // --- Finger View Header ---
    buf.put_u8(finger_position);
    // Packed nibble: upper = view number (1), lower = impression type
    buf.put_u8((1 << 4) | (impression_type & 0x0F));
    buf.put_u8(0x00); // finger quality: unspecified
    buf.put_u8(num_minutiae as u8);

    // --- Minutia Records ---
    for m in minutiae {
        let type_bits = (m.minutia_type as u16) & 0x03;
        let x_field = (type_bits << 14) | (m.x & 0x3FFF);
        let y_field = m.y & 0x3FFF;
        buf.put_u16(x_field);
        buf.put_u16(y_field);
        buf.put_u8(m.angle);
        buf.put_u8(m.quality);
    }

    // --- Extended Data Block (absent) ---
    buf.put_u16(0x0000);

    Ok(buf.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finger::wsq::DecodedImage;

    fn dummy_image() -> DecodedImage {
        DecodedImage {
            pixels: vec![128u8; 100 * 100],
            width: 100,
            height: 100,
            ppi: 500,
        }
    }

    #[test]
    fn empty_minutiae_record_is_valid() {
        let rec = build_finger_minutiae_record(&dummy_image(), 1, 0).unwrap();
        // Check format identifier "FM"
        assert_eq!(rec[0], b'F');
        assert_eq!(rec[1], b'M');
        // Extended data length at end should be 0x0000
        let last_two = &rec[rec.len() - 2..];
        assert_eq!(last_two, &[0x00, 0x00]);
    }
}
