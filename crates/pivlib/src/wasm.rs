//! WASM bindings for the npm package surface.
//!
//! Each entrypoint takes either raw bytes or a JSON string and returns a
//! JS-friendly value. We keep the surface small and stable — the TypeScript
//! wrappers add ergonomic types on top.

use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// --- Encoding ---------------------------------------------------------------

#[wasm_bindgen]
pub fn detect(bytes: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::encoding::detect(bytes).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

// --- Cert -------------------------------------------------------------------

#[wasm_bindgen]
pub fn parse_cert(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::cert::parse::parse_der(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn classify_piv_role(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::cert::piv_role::classify(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

// --- CSR / CRL / Key --------------------------------------------------------

#[wasm_bindgen]
pub fn parse_csr(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::csr::parse_der(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn parse_crl(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::crl::parse_der(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn parse_key_metadata(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::key::parse_metadata(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

// --- PKCS#7 / #12 -----------------------------------------------------------

#[wasm_bindgen]
pub fn enumerate_pkcs7(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::pkcs7::enumerate(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn enumerate_pkcs12(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::pkcs12::enumerate(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

// --- PIV containers ---------------------------------------------------------

#[wasm_bindgen]
pub fn parse_chuid(bytes: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::chuid::parse(bytes).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn parse_ccc(bytes: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::ccc::parse(bytes).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn parse_security_object(der: &[u8]) -> Result<JsValue, JsError> {
    let r = crate::security_object::parse(der).map_err(to_js_err)?;
    to_value(&r).map_err(to_js_err)
}

// --- Biometric (moved from app.pivlib) -------------------------------------

/// Process a portrait JPEG and return a CBEFF record containing an INCITS 385
/// Facial Record.
#[wasm_bindgen]
pub fn process_face(
    jpeg_bytes: &[u8],
    landmarks_json: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let landmarks = landmarks_json
        .as_deref()
        .map(crate::face::incits385::parse_mediapipe_landmarks)
        .transpose()
        .map_err(|e| JsError::new(&e.to_string()))?;

    let facial_record =
        crate::face::incits385::build_facial_record(jpeg_bytes, landmarks.as_ref())
            .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(crate::cbeff::wrap(
        crate::cbeff::BiometricType::Face,
        crate::cbeff::FormatOwner::INCITS,
        crate::cbeff::FormatType::INCITS385,
        &facial_record,
    ))
}

/// Process a fingerprint WSQ image and return a CBEFF record containing both
/// an INCITS 381 Finger Image Record and an INCITS 378 Finger Minutiae Record.
#[wasm_bindgen]
pub fn process_fingerprint(
    wsq_bytes: &[u8],
    finger_position: u8,
    impression_type: u8,
) -> Result<Vec<u8>, JsError> {
    let decoded = crate::finger::wsq::decode(wsq_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let image_record = crate::finger::incits381::build_finger_image_record(
        &decoded,
        finger_position,
        impression_type,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    let minutiae_record = crate::finger::incits378::build_finger_minutiae_record(
        &decoded,
        finger_position,
        impression_type,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(crate::cbeff::wrap_multi(vec![
        (
            crate::cbeff::BiometricType::Fingerprint,
            crate::cbeff::FormatOwner::INCITS,
            crate::cbeff::FormatType::INCITS381,
            image_record,
        ),
        (
            crate::cbeff::BiometricType::Fingerprint,
            crate::cbeff::FormatOwner::INCITS,
            crate::cbeff::FormatType::INCITS378,
            minutiae_record,
        ),
    ]))
}

fn to_js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}
