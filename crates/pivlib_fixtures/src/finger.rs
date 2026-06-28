//! Generate a synthetic WSQ fixture for the FingerprintEncoder demo.
//!
//! Source image is a 256×256 8-bit grayscale gradient — obviously not a real
//! fingerprint, but a valid input for NBIS's `wsq_encode_mem`. We round-trip
//! through `wsq_decode_mem` immediately to confirm the output is
//! decodable end-to-end (which is what the web demo will do).
//!
//! Requires `pivlib` built with `--features nbis`.

use pivlib::finger::wsq::{self, DecodedImage};

const W: u32 = 256;
const H: u32 = 256;
const PPI: u16 = 500; // FBI IAFIS standard

pub fn build_wsq() -> Result<Vec<u8>, String> {
    let img = synth_gradient();
    let wsq = wsq::encode(&img)?;
    // Round-trip — if our own decoder can't read what our own encoder emitted
    // there's no point shipping the fixture.
    let _decoded = wsq::decode(&wsq)?;
    Ok(wsq)
}

fn synth_gradient() -> DecodedImage {
    let mut pixels = Vec::with_capacity((W * H) as usize);
    for y in 0..H {
        for x in 0..W {
            // Diagonal gradient with a couple of low-frequency rings so the
            // wavelet transform has structure to compress, not pure noise.
            let dx = x as i32 - (W as i32) / 2;
            let dy = y as i32 - (H as i32) / 2;
            let r = ((dx * dx + dy * dy) as f32).sqrt();
            let base = ((x + y) as f32) * 0.5;
            let ring = (r * 0.15).sin() * 40.0;
            let v = (base + ring).clamp(0.0, 255.0) as u8;
            pixels.push(v);
        }
    }
    DecodedImage {
        pixels,
        width: W,
        height: H,
        ppi: PPI,
    }
}
