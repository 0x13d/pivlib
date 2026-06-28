//! Build a small X.509 CRL: issued by the PIV CA, revoking the PIV Auth EE.
//!
//! x509-cert 0.2 has the CRL types but no builder, so this constructs the
//! TBS by hand and signs it with the PIV CA's P-256 ECDSA key.

use std::time::{Duration, SystemTime};

use der::asn1::BitString;
use der::{DateTime, Encode};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;
use x509_cert::Version;

pub fn build_piv_ca_crl(
    issuer_signer: &SigningKey,
    issuer_subject: &Name,
    revoked_serial: SerialNumber,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let this_update = Time::GeneralTime(DateTime::from_system_time(now)?.into());
    let next_update = Time::GeneralTime(DateTime::from_system_time(
        now + Duration::from_secs(60 * 60 * 24 * 30),
    )?.into());
    let revocation_date = Time::GeneralTime(DateTime::from_system_time(
        now - Duration::from_secs(60 * 60 * 24),
    )?.into());

    let signature_alg = issuer_signer.signature_algorithm_identifier()?;

    let tbs = TbsCertList {
        version: Version::V2,
        signature: signature_alg.clone(),
        issuer: issuer_subject.clone(),
        this_update,
        next_update: Some(next_update),
        revoked_certificates: Some(vec![RevokedCert {
            serial_number: revoked_serial,
            revocation_date,
            crl_entry_extensions: None,
        }]),
        crl_extensions: None,
    };

    let tbs_der = tbs.to_der()?;
    let sig: DerSignature = issuer_signer.try_sign(&tbs_der)?;
    let signature = BitString::from_bytes(sig.to_bytes().as_ref())?;

    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: signature_alg,
        signature,
    };

    Ok(crl.to_der()?)
}
