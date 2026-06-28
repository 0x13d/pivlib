//! Export the PIV Auth EE's signer as PKCS#8 PrivateKeyInfo (DER).
//! pivlib's key parser surfaces metadata only — algorithm, curve, length — and
//! never the key material, so shipping a synthetic key here is safe.

use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;

pub fn build_piv_auth_pkcs8(signer: &SigningKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let doc = signer.to_pkcs8_der()?;
    Ok(doc.as_bytes().to_vec())
}
