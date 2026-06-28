//! Build a minimal PKCS#12 / PFX bundle. pivlib's parser surfaces structure
//! only (version, AuthSafe content type, MAC presence) — it doesn't decode
//! the inner SafeBags — so a degenerate PFX with an empty `id-data` content
//! payload is enough to demonstrate the tool.

use cms::content_info::ContentInfo;
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Any, Decode, Encode};
use pkcs12::pfx::{Pfx, Version};

const OID_ID_DATA: &str = "1.2.840.113549.1.7.1";

pub fn build_pfx() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Inner content: an OCTET STRING that PKCS#12 callers would normally fill
    // with a DER-encoded AuthenticatedSafe (SEQUENCE OF ContentInfo). We ship
    // an empty SEQUENCE so the structure is valid but there are no SafeBags.
    let auth_safe_payload = OctetString::new(vec![0x30, 0x00])?; // empty SEQUENCE
    let payload_der = auth_safe_payload.to_der()?;
    let content = Any::from_der(&payload_der)?;

    let auth_safe = ContentInfo {
        content_type: ObjectIdentifier::new(OID_ID_DATA)?,
        content,
    };

    let pfx = Pfx {
        version: Version::V3,
        auth_safe,
        mac_data: None,
    };

    Ok(pfx.to_der()?)
}
