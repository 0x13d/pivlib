//! Build a degenerate certs-only PKCS#7 SignedData bundling the demo chain.
//! `cms::ContentInfo::try_from(PkiPath)` does the heavy lifting — empty
//! signers, empty content, just a SET of certificates.

use cms::content_info::ContentInfo;
use der::{Decode, Encode};
use x509_cert::Certificate;

pub fn build_pkcs7_chain(cert_ders: &[&[u8]]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let certs: Result<Vec<Certificate>, _> = cert_ders
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect();
    let info = ContentInfo::try_from(certs?)?;
    Ok(info.to_der()?)
}
