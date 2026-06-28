//! Synthesize a PIV-shaped certificate chain.
//!
//!   Root CA  ─signs─▶  PIV CA  ─signs─▶  5 end-entity certs, one per PIV role
//!
//! Every key is freshly generated P-256. Every cert is self-consistent
//! (subjects/issuers chain back to the root). Nothing here is a real PIV cert
//! — all subjects say DEMO, all signatures are over synthetic key material —
//! but each EE cert carries the OIDs / KU bits / policies pivlib's
//! classifier matches against, so the role on the chip lights up correctly.

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{Ia5String, ObjectIdentifier};
use der::Encode;
use p256::ecdsa::{DerSignature, SigningKey};
use rand_core::OsRng;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    certpolicy::{CertificatePolicies, PolicyInformation},
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

const OID_PIV_CARD_AUTH: &str = "2.16.840.1.101.3.6.8";
const OID_PIV_CONTENT_SIGNING: &str = "2.16.840.1.101.3.6.7";
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const OID_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const OID_FPKI_COMMON_AUTH: &str = "2.16.840.1.101.3.2.1.3.13";

const VALIDITY: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 3);

/// Materialized chain — owning the signing keys so PKCS#7/CRL/CSR builders
/// can reuse them.
pub struct Chain {
    pub root_ca_cert: Vec<u8>,
    pub piv_ca_cert: Vec<u8>,
    pub piv_auth_cert: Vec<u8>,
    pub card_auth_cert: Vec<u8>,
    pub digital_signature_cert: Vec<u8>,
    pub key_management_cert: Vec<u8>,
    pub content_signing_cert: Vec<u8>,

    /// PIV CA signer — needed by CRL builder.
    pub piv_ca_signer: SigningKey,
    pub piv_ca_subject: Name,

    /// PIV Auth EE signer — needed by CSR / PKCS#8 fixtures.
    pub piv_auth_signer: SigningKey,
}

pub fn build_chain() -> Result<Chain, Box<dyn std::error::Error>> {
    let (root_signer, root_subject) = mint_ca("CN=DEMO Root CA")?;
    let (piv_ca_signer, piv_ca_subject) = mint_ca("CN=DEMO PIV CA")?;

    // --- Root CA: self-signed Profile::Root ----------------------------------
    let root_ca_cert = sign_cert(
        &root_signer,
        Profile::Root,
        SerialNumber::from(0x0100u32),
        root_subject.clone(),
        &root_signer,
        |_| Ok(()),
    )?;

    // --- PIV CA: signed by Root, Profile::SubCA ------------------------------
    let piv_ca_cert = sign_cert(
        &root_signer,
        Profile::SubCA {
            issuer: root_subject.clone(),
            path_len_constraint: Some(0),
        },
        SerialNumber::from(0x0200u32),
        piv_ca_subject.clone(),
        &piv_ca_signer,
        |_| Ok(()),
    )?;

    // --- PIV Auth EE: FPKI common-auth policy + clientAuth EKU --------------
    let (piv_auth_signer, _, piv_auth_cert) = mint_ee(
        &piv_ca_signer,
        &piv_ca_subject,
        SerialNumber::from(0x0301u32),
        "CN=DEMO PIV Authentication,OU=pivlib synthetic fixtures,O=ariugwu,C=US",
        Profile::Leaf {
            issuer: piv_ca_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
            include_subject_key_identifier: true,
        },
        |b| {
            b.add_extension(&ExtendedKeyUsage(vec![oid(OID_CLIENT_AUTH)?]))?;
            b.add_extension(&CertificatePolicies(vec![PolicyInformation {
                policy_identifier: oid(OID_FPKI_COMMON_AUTH)?,
                policy_qualifiers: None,
            }]))?;
            b.add_extension(&SubjectAltName(vec![GeneralName::Rfc822Name(
                Ia5String::new("piv-auth@pivlib.synthetic")?,
            )]))?;
            Ok(())
        },
    )?;

    // --- Card Auth EE: id-PIV-cardAuth EKU ----------------------------------
    let (_, _, card_auth_cert) = mint_ee(
        &piv_ca_signer,
        &piv_ca_subject,
        SerialNumber::from(0x0302u32),
        "CN=DEMO Card Authentication,OU=pivlib synthetic fixtures,O=ariugwu,C=US",
        Profile::Leaf {
            issuer: piv_ca_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
            include_subject_key_identifier: true,
        },
        |b| {
            b.add_extension(&ExtendedKeyUsage(vec![oid(OID_PIV_CARD_AUTH)?]))?;
            Ok(())
        },
    )?;

    // --- Digital Signature EE: nonRepudiation KU + emailProtection EKU ------
    // Leaf profile already enables nonRepudiation by default.
    let (_, _, digital_signature_cert) = mint_ee(
        &piv_ca_signer,
        &piv_ca_subject,
        SerialNumber::from(0x0303u32),
        "CN=DEMO Digital Signature,OU=pivlib synthetic fixtures,O=ariugwu,C=US",
        Profile::Leaf {
            issuer: piv_ca_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
            include_subject_key_identifier: true,
        },
        |b| {
            b.add_extension(&ExtendedKeyUsage(vec![oid(OID_EMAIL_PROTECTION)?]))?;
            Ok(())
        },
    )?;

    // --- Key Management EE: keyEncipherment KU + emailProtection EKU --------
    // Profile::Manual is the only way to opt out of the default
    // (DigitalSignature | NonRepudiation) KU that Profile::Leaf forces — the
    // classifier checks DigitalSignature (Rule 4: NonRep + emailProtection)
    // before KeyManagement (Rule 5: KeyEnc + emailProtection), so leaving
    // NonRep on would flip the role.
    let (_, _, key_management_cert) = mint_ee(
        &piv_ca_signer,
        &piv_ca_subject,
        SerialNumber::from(0x0304u32),
        "CN=DEMO Key Management,OU=pivlib synthetic fixtures,O=ariugwu,C=US",
        Profile::Manual { issuer: Some(piv_ca_subject.clone()) },
        |b| {
            b.add_extension(&BasicConstraints { ca: false, path_len_constraint: None })?;
            b.add_extension(&KeyUsage(KeyUsages::KeyEncipherment.into()))?;
            b.add_extension(&ExtendedKeyUsage(vec![oid(OID_EMAIL_PROTECTION)?]))?;
            Ok(())
        },
    )?;

    // --- Content Signing EE: id-PIV-content-signing EKU ---------------------
    let (_, _, content_signing_cert) = mint_ee(
        &piv_ca_signer,
        &piv_ca_subject,
        SerialNumber::from(0x0305u32),
        "CN=DEMO Content Signing,OU=pivlib synthetic fixtures,O=ariugwu,C=US",
        Profile::Leaf {
            issuer: piv_ca_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
            include_subject_key_identifier: true,
        },
        |b| {
            b.add_extension(&ExtendedKeyUsage(vec![oid(OID_PIV_CONTENT_SIGNING)?]))?;
            Ok(())
        },
    )?;

    Ok(Chain {
        root_ca_cert,
        piv_ca_cert,
        piv_auth_cert,
        card_auth_cert,
        digital_signature_cert,
        key_management_cert,
        content_signing_cert,
        piv_ca_signer,
        piv_ca_subject,
        piv_auth_signer,
    })
}

// ----- helpers -------------------------------------------------------------

fn mint_ca(subject_dn: &str) -> Result<(SigningKey, Name), Box<dyn std::error::Error>> {
    let signer = SigningKey::random(&mut OsRng);
    let subject = Name::from_str(subject_dn)?;
    Ok((signer, subject))
}

/// Mint an EE cert: generate a fresh keypair, build + sign with `issuer_signer`.
fn mint_ee<F>(
    issuer_signer: &SigningKey,
    _issuer_subject: &Name,
    serial: SerialNumber,
    subject_dn: &str,
    profile: Profile,
    add_extensions: F,
) -> Result<(SigningKey, Name, Vec<u8>), Box<dyn std::error::Error>>
where
    F: FnOnce(&mut CertificateBuilder<'_, SigningKey>) -> Result<(), Box<dyn std::error::Error>>,
{
    let ee_signer = SigningKey::random(&mut OsRng);
    let ee_subject = Name::from_str(subject_dn)?;
    let der = sign_cert(
        issuer_signer,
        profile,
        serial,
        ee_subject.clone(),
        &ee_signer,
        add_extensions,
    )?;
    Ok((ee_signer, ee_subject, der))
}

/// Build a TBSCertificate with `subject` + `subject_spki`, run user extensions,
/// then sign with `issuer_signer`.
fn sign_cert<F>(
    issuer_signer: &SigningKey,
    profile: Profile,
    serial: SerialNumber,
    subject: Name,
    subject_signer: &SigningKey,
    add_extensions: F,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    F: FnOnce(&mut CertificateBuilder<'_, SigningKey>) -> Result<(), Box<dyn std::error::Error>>,
{
    let subject_spki = SubjectPublicKeyInfoOwned::from_key(*subject_signer.verifying_key())?;
    let validity = Validity::from_now(VALIDITY)?;

    let mut builder = CertificateBuilder::new(
        profile,
        serial,
        validity,
        subject,
        subject_spki,
        issuer_signer,
    )?;
    add_extensions(&mut builder)?;

    let cert = builder.build::<DerSignature>()?;
    Ok(cert.to_der()?)
}

fn oid(s: &str) -> Result<ObjectIdentifier, Box<dyn std::error::Error>> {
    Ok(ObjectIdentifier::new(s)?)
}
