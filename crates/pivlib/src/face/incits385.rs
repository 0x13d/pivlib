/// INCITS 385-2004 / ISO 19794-5 — Face Image Data Record
///
/// Record layout (all multi-byte fields are big-endian):
///
/// ┌─────────────────────────────────────────────────────────┐
/// │ Format Identifier         4 bytes  "FAC\0"              │
/// │ Version Number            4 bytes  "010\0"              │
/// │ Length of Record          4 bytes  total byte count     │
/// │ Number of Facial Images   2 bytes                       │
/// ├─────────────────── Facial Record Header ────────────────┤
/// │ Facial Record Data Length 4 bytes                       │
/// │ Number of Feature Points  2 bytes                       │
/// │ Gender                    1 byte   0=unspecified        │
/// │ Eye Color                 1 byte   0=unspecified        │
/// │ Hair Color                1 byte   0=unspecified        │
/// │ Feature Mask              3 bytes                       │
/// │ Expression                2 bytes  0=neutral/unspec     │
/// │ Pose Angle                3 bytes  yaw/pitch/roll       │
/// │ Pose Angle Uncertainty    3 bytes                       │
/// ├─────────────────── Feature Points (0..N) ───────────────┤
/// │ Feature Point Type        1 byte                        │
/// │ Feature Point Major       1 byte                        │
/// │ Feature Point Minor       1 byte  (packed)              │
/// │ X Coordinate              2 bytes                       │
/// │ Y Coordinate              2 bytes                       │
/// │ Reserved                  1 byte  0x00                  │
/// ├─────────────────── Image Information ───────────────────┤
/// │ Face Image Type           1 byte  0=basic               │
/// │ Image Data Type           1 byte  0=JPEG, 1=JPEG2000    │
/// │ Width                     2 bytes                       │
/// │ Height                    2 bytes                       │
/// │ Colour Space              1 byte  0=unspecified         │
/// │ Source Type               1 byte  0=unspecified         │
/// │ Device Type               2 bytes 0x0000=unspecified    │
/// │ Quality                   2 bytes 0=unspecified         │
/// ├─────────────────── Image Data ──────────────────────────┤
/// │ JPEG/JPEG2000 bytes       variable                      │
/// └─────────────────────────────────────────────────────────┘

use bytes::{BufMut, BytesMut};
use image::GenericImageView;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct FacialLandmarks {
    /// Feature points in INCITS 385 encoding.
    /// Each entry: (feature_type, major_code, x, y)
    pub points: Vec<(u8, u8, u16, u16)>,
}

#[derive(Debug, Deserialize)]
struct MediaPipeKeypoint {
    x: f32,
    y: f32,
    #[allow(dead_code)]
    z: f32,
}

#[derive(Debug, Deserialize)]
struct MediaPipeResult {
    keypoints: Vec<MediaPipeKeypoint>,
}

// ---------------------------------------------------------------------------
// MediaPipe → INCITS 385 landmark mapping
// ---------------------------------------------------------------------------

/// Parse the JSON emitted by MediaPipe Face Mesh and map a subset of keypoints
/// to INCITS 385 feature point codes.
///
/// MediaPipe indices used (canonical 468-point mesh):
///   33  → left eye outer corner
///  263  → right eye outer corner
///  159  → left eye upper lid
///  386  → right eye upper lid
///    1  → nose tip
///   13  → mouth upper lip center
///   14  → mouth lower lip center
pub fn parse_mediapipe_landmarks(json: &str) -> Result<FacialLandmarks, String> {
    let result: MediaPipeResult =
        serde_json::from_str(json).map_err(|e| format!("landmark JSON parse error: {e}"))?;

    // INCITS 385 Table 2 feature point codes (abbreviated subset)
    // Major type 0x01 = right eye corner, 0x02 = left eye corner, etc.
    // We use type 0x00 (other landmark) with sequential minor codes for now
    // until the full feature point table is implemented.
    let mappings: &[(usize, u8, u8)] = &[
        (33,  0x01, 0x01), // left  eye outer corner
        (263, 0x01, 0x02), // right eye outer corner
        (159, 0x02, 0x01), // left  eye pupil (approx)
        (386, 0x02, 0x02), // right eye pupil (approx)
        (1,   0x03, 0x01), // nose tip
        (13,  0x04, 0x01), // mouth upper
        (14,  0x04, 0x02), // mouth lower
    ];

    let mut points = Vec::new();
    for &(idx, major, minor) in mappings {
        if let Some(kp) = result.keypoints.get(idx) {
            // MediaPipe returns normalized [0,1] coords; we store them as
            // 10000-scale fixed-point (deferred to image-dimension scaling
            // at record build time — use placeholder dimensions here).
            let x = (kp.x * 10000.0) as u16;
            let y = (kp.y * 10000.0) as u16;
            // Pack major/minor: feature_type byte = 0x01 (landmark)
            points.push((0x01, (major << 4) | (minor & 0x0F), x, y));
        }
    }

    Ok(FacialLandmarks { points })
}

// ---------------------------------------------------------------------------
// Record builder
// ---------------------------------------------------------------------------

/// Build a binary INCITS 385 Facial Record from raw JPEG bytes and optional
/// pre-extracted landmarks.
pub fn build_facial_record(
    jpeg_bytes: &[u8],
    landmarks: Option<&FacialLandmarks>,
) -> Result<Vec<u8>, String> {
    // Decode just enough to get image dimensions — do not keep pixel data.
    let img = image::load_from_memory_with_format(jpeg_bytes, image::ImageFormat::Jpeg)
        .map_err(|e| format!("JPEG decode error: {e}"))?;
    let (width, height) = img.dimensions();
    drop(img);

    let feature_points = landmarks
        .map(|l| l.points.as_slice())
        .unwrap_or(&[]);
    let num_fp = feature_points.len() as u16;

    // Sizes
    let fp_block_size = num_fp as usize * 8; // 8 bytes per feature point
    let image_info_size = 12;
    let facial_header_size = 20;
    let facial_data_length =
        (facial_header_size + fp_block_size + image_info_size + jpeg_bytes.len()) as u32;

    // Total record = format header (14 bytes) + facial data
    let total_length = 14 + facial_data_length as usize;

    let mut buf = BytesMut::with_capacity(total_length);

    // --- Format header ---
    buf.put_slice(b"FAC\0");       // format identifier
    buf.put_slice(b"010\0");       // version
    buf.put_u32(total_length as u32);
    buf.put_u16(1);                 // number of facial images

    // --- Facial Record Header ---
    buf.put_u32(facial_data_length);
    buf.put_u16(num_fp);
    buf.put_u8(0x00); // gender: unspecified
    buf.put_u8(0x00); // eye color: unspecified
    buf.put_u8(0x00); // hair color: unspecified
    buf.put_u8(0x00); // feature mask byte 1
    buf.put_u8(0x00); // feature mask byte 2
    buf.put_u8(0x00); // feature mask byte 3
    buf.put_u16(0x0000); // expression: neutral/unspecified
    buf.put_u8(0x00); // pose yaw
    buf.put_u8(0x00); // pose pitch
    buf.put_u8(0x00); // pose roll
    buf.put_u8(0x00); // pose yaw uncertainty
    buf.put_u8(0x00); // pose pitch uncertainty
    buf.put_u8(0x00); // pose roll uncertainty

    // --- Feature Points ---
    for &(fp_type, code, x, y) in feature_points {
        buf.put_u8(fp_type);
        buf.put_u8(code);
        buf.put_u16(x);
        buf.put_u16(y);
        buf.put_u8(0x00); // reserved
    }

    // --- Image Information ---
    buf.put_u8(0x00); // face image type: basic
    buf.put_u8(0x00); // image data type: JPEG
    buf.put_u16(width as u16);
    buf.put_u16(height as u16);
    buf.put_u8(0x00); // colour space: unspecified
    buf.put_u8(0x00); // source type: unspecified
    buf.put_u16(0x0000); // device type: unspecified
    buf.put_u16(0x0000); // quality: unspecified

    // --- Image Data ---
    buf.put_slice(jpeg_bytes);

    Ok(buf.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facial_record_header_magic() {
        // Tiny 1×1 JPEG (minimal valid file)
        let jpeg = include_bytes!("../../tests/fixtures/portrait_1x1.jpg");
        let record = build_facial_record(jpeg, None).unwrap();
        assert_eq!(&record[0..4], b"FAC\0");
        assert_eq!(&record[4..8], b"010\0");
    }

    #[test]
    fn parse_empty_landmarks() {
        let json = r#"{"keypoints":[]}"#;
        let lm = parse_mediapipe_landmarks(json).unwrap();
        assert!(lm.points.is_empty());
    }
}
