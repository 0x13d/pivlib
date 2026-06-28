//! Build a PKCS#10 CertificationRequest (CSR) using the PIV Auth EE's signer.
//! Carries a UPN-style SAN; the CSR's subject mirrors the EE cert's subject.

use std::str::FromStr;

use der::asn1::Ia5String;
use der::Encode;
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;

pub fn build_piv_auth_csr(signer: &SigningKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let subject = Name::from_str(
        "CN=DEMO PIV Authentication CSR,OU=pivlib synthetic fixtures,O=ariugwu,C=US",
    )?;

    let mut builder = RequestBuilder::new(subject, signer)?;
    builder.add_extension(&SubjectAltName(vec![GeneralName::Rfc822Name(
        Ia5String::new("piv-auth-csr@pivlib.synthetic")?,
    )]))?;

    let req = builder.build::<DerSignature>()?;
    Ok(req.to_der()?)
}
