/// WSQ (Wavelet Scalar Quantization) decoder
///
/// WSQ is defined by FBI IAFIS-IC-0110(V3) and is the standard lossy
/// compression format for 8-bit grayscale fingerprint images.
///
/// When NBIS is present (see nbis/ and build.rs), the real `wsq_decode_mem`
/// C function is linked in via FFI below.  Until then, the stub returns an
/// error so that the rest of the codebase compiles and the WASM module loads.

#[derive(Debug, Clone)]
pub struct DecodedImage {
    pub pixels: Vec<u8>, // row-major, 8-bit grayscale
    pub width: u32,
    pub height: u32,
    pub ppi: u16, // pixels-per-inch (500 or 1000 typical)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn decode(wsq_bytes: &[u8]) -> Result<DecodedImage, String> {
    #[cfg(feature = "nbis")]
    return nbis_decode(wsq_bytes);

    #[cfg(not(feature = "nbis"))]
    stub_decode(wsq_bytes)
}

/// Encode an 8-bit grayscale image as WSQ. FBI IAFIS target bitrate is
/// 0.75 bpp (≈15:1). NBIS-only — same gating as `decode`.
pub fn encode(img: &DecodedImage) -> Result<Vec<u8>, String> {
    #[cfg(feature = "nbis")]
    return nbis_encode(img);

    #[cfg(not(feature = "nbis"))]
    {
        let _ = img;
        Err("WSQ encoding requires NBIS. Rebuild with `--features nbis`.".to_string())
    }
}

// ---------------------------------------------------------------------------
// Stub (no NBIS)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "nbis"))]
fn stub_decode(_wsq_bytes: &[u8]) -> Result<DecodedImage, String> {
    Err("WSQ decoding requires NBIS. This build was compiled without it; \
         rebuild with `--features nbis` (sources are already vendored under \
         nbis/imgtools/) or use the pivlib CLI."
        .to_string())
}

// ---------------------------------------------------------------------------
// NBIS FFI (feature = "nbis")
// ---------------------------------------------------------------------------

#[cfg(feature = "nbis")]
mod ffi {
    use std::ffi::c_int;
    use std::os::raw::c_char;
    use std::os::raw::c_uchar;

    extern "C" {
        /// wsq_decode_mem — NBIS native in-memory WSQ decoder.
        ///
        /// Defined in nbis/imgtools/src/lib/wsq/decoder.c.
        /// Output parameters come first (NBIS convention), input last.
        /// Returns 0 on success; caller must free `*odata` via wsq_free_buf.
        pub fn wsq_decode_mem(
            odata: *mut *mut c_uchar,
            owidth: *mut c_int,
            oheight: *mut c_int,
            odepth: *mut c_int,
            oppi: *mut c_int,      // pixels per inch (not ppmm)
            lossyflag: *mut c_int,
            idata: *mut c_uchar,   // NBIS takes *mut; only reads the buffer
            ilen: c_int,
        ) -> c_int;

        /// wsq_encode_mem — NBIS native in-memory WSQ encoder.
        /// nbis/imgtools/src/lib/wsq/encoder.c.
        /// Returns 0 on success; caller frees `*odata` via wsq_free_buf.
        pub fn wsq_encode_mem(
            odata: *mut *mut c_uchar,
            olen: *mut c_int,
            r_bitrate: f32,
            idata: *mut c_uchar,
            w: c_int,
            h: c_int,
            d: c_int,
            ppi: c_int,
            comment_text: *mut c_char,
        ) -> c_int;

        /// Free a buffer allocated by wsq_decode_mem / wsq_encode_mem.
        ///
        /// A bare `extern "C" { fn free() }` in Rust becomes a WASM "env"
        /// import that browsers cannot resolve.  wsq_free_buf() is compiled
        /// into the WASM binary (nbis/shims/wsq_mem.c) so the symbol stays
        /// internal.
        pub fn wsq_free_buf(ptr: *mut core::ffi::c_void);
    }
}

#[cfg(feature = "nbis")]
fn nbis_decode(wsq_bytes: &[u8]) -> Result<DecodedImage, String> {
    use std::ptr;

    let mut odata: *mut u8 = ptr::null_mut();
    let mut width: i32 = 0;
    let mut height: i32 = 0;
    let mut depth: i32 = 0;
    let mut ppi: i32 = 0;
    let mut lossyflag: i32 = 0;

    let ret = unsafe {
        ffi::wsq_decode_mem(
            &mut odata,
            &mut width,
            &mut height,
            &mut depth,
            &mut ppi,
            &mut lossyflag,
            wsq_bytes.as_ptr() as *mut u8, // NBIS API is *mut; buffer is read-only
            wsq_bytes.len() as i32,
        )
    };

    if ret != 0 || odata.is_null() {
        return Err(format!("wsq_decode_mem failed (code {})", ret));
    }

    let pixel_count = (width * height) as usize;
    let pixels = unsafe { std::slice::from_raw_parts(odata, pixel_count).to_vec() };

    // Free the C-allocated buffer via the compiled-in wrapper.
    unsafe { ffi::wsq_free_buf(odata as *mut core::ffi::c_void) };

    Ok(DecodedImage {
        pixels,
        width: width as u32,
        height: height as u32,
        ppi: ppi as u16, // NBIS returns pixels per inch directly
    })
}

#[cfg(feature = "nbis")]
fn nbis_encode(img: &DecodedImage) -> Result<Vec<u8>, String> {
    use std::ptr;

    // FBI IAFIS-IC-0110(V3) default: 0.75 bits per pixel (~15:1).
    const TARGET_BITRATE: f32 = 0.75;

    let expected = (img.width as usize) * (img.height as usize);
    if img.pixels.len() != expected {
        return Err(format!(
            "pixel buffer length {} doesn't match {}x{} grayscale",
            img.pixels.len(),
            img.width,
            img.height
        ));
    }

    let mut odata: *mut u8 = ptr::null_mut();
    let mut olen: i32 = 0;
    let mut idata = img.pixels.clone(); // NBIS API is *mut; buffer is read

    let ret = unsafe {
        ffi::wsq_encode_mem(
            &mut odata,
            &mut olen,
            TARGET_BITRATE,
            idata.as_mut_ptr(),
            img.width as i32,
            img.height as i32,
            8,                // bit depth: 8-bit grayscale
            img.ppi as i32,
            ptr::null_mut(),  // no embedded comment
        )
    };

    if ret != 0 || odata.is_null() {
        return Err(format!("wsq_encode_mem failed (code {})", ret));
    }

    let out = unsafe { std::slice::from_raw_parts(odata, olen as usize).to_vec() };
    unsafe { ffi::wsq_free_buf(odata as *mut core::ffi::c_void) };
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_error_without_nbis() {
        #[cfg(not(feature = "nbis"))]
        {
            let result = decode(&[0x00]);
            assert!(result.is_err());
        }
    }
}
