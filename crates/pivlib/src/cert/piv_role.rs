//! PIV key-role classification — see SPEC.md §"PIV key-role classification".
//!
//! The classifier reads policy OIDs, EKUs, KeyUsage bits, and PIV SAN OIDs,
//! then returns one of {PivAuth, CardAuth, DigitalSignature, KeyManagement,
//! ContentSigning, Unknown} along with the evidence used.

use der::Decode;
use flagset::FlagSet;
use serde::{Deserialize, Serialize};
use x509_cert::{
    ext::pkix::{
        name::GeneralName, CertificatePolicies, ExtendedKeyUsage, KeyUsage, KeyUsages,
        SubjectAltName,
    },
    Certificate,
};

use crate::error::{Error, Result};

// --- PIV / FPKI OID constants (NIST SP 800-78) -----------------------------

/// `id-PIV-cardAuth` — Card Authentication EKU.
const OID_PIV_CARD_AUTH: &str = "2.16.840.1.101.3.6.8";
/// `id-PIV-content-signing` — signs CHUID / facial / fingerprint containers.
const OID_PIV_CONTENT_SIGNING: &str = "2.16.840.1.101.3.6.7";
/// `id-PIV-FASC-N` — Subject Alternative Name OID carrying the FASC-N.
const OID_PIV_FASCN_SAN: &str = "2.16.840.1.101.3.6.6";
/// `id-fpki-common-authentication` policy.
const OID_FPKI_COMMON_AUTH: &str = "2.16.840.1.101.3.2.1.3.13";
/// `id-fpki-common-piv-authentication` policy (newer common policy framework).
const OID_FPKI_COMMON_PIV_AUTH: &str = "2.16.840.1.101.3.2.1.3.40";
/// `emailProtection` EKU.
const OID_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
/// `clientAuth` EKU.
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PivRole {
    PivAuth,
    CardAuth,
    DigitalSignature,
    KeyManagement,
    ContentSigning,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub policy_oids: Vec<String>,
    pub extended_key_usages: Vec<String>,
    pub key_usage: Vec<String>,
    pub san_oids: Vec<String>,
    pub fascn_present: bool,
    pub piv_card_uuid_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub role: PivRole,
    pub evidence: Evidence,
}

pub fn classify(der: &[u8]) -> Result<Classification> {
    let cert = Certificate::from_der(der).map_err(|e| Error::Asn1(e.to_string()))?;
    classify_cert(&cert)
}

pub fn classify_cert(cert: &Certificate) -> Result<Classification> {
    let mut evidence = Evidence::default();
    let mut key_usage_bits: Option<FlagSet<KeyUsages>> = None;

    if let Some(exts) = cert.tbs_certificate.extensions.as_ref() {
        for ext in exts {
            let oid = ext.extn_id.to_string();
            match oid.as_str() {
                "2.5.29.32" => {
                    // certificatePolicies
                    if let Ok(policies) =
                        CertificatePolicies::from_der(ext.extn_value.as_bytes())
                    {
                        for pi in policies.0 {
                            evidence.policy_oids.push(pi.policy_identifier.to_string());
                        }
                    }
                }
                "2.5.29.37" => {
                    // extKeyUsage
                    if let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                        for k in eku.0 {
                            evidence.extended_key_usages.push(k.to_string());
                        }
                    }
                }
                "2.5.29.15" => {
                    // keyUsage
                    if let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes()) {
                        let usages = ku.0;
                        key_usage_bits = Some(usages);
                        push_key_usage_labels(usages, &mut evidence.key_usage);
                    }
                }
                "2.5.29.17" => {
                    // subjectAltName
                    if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                        for gn in san.0 {
                            if let GeneralName::OtherName(other) = gn {
                                let oid = other.type_id.to_string();
                                evidence.san_oids.push(oid.clone());
                                if oid == OID_PIV_FASCN_SAN {
                                    evidence.fascn_present = true;
                                }
                                // PIV card UUID OID — 1.3.6.1.1.16.4 (RFC 4122)
                                if oid == "1.3.6.1.1.16.4" {
                                    evidence.piv_card_uuid_present = true;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let role = decide(&evidence, key_usage_bits);
    Ok(Classification { role, evidence })
}

fn push_key_usage_labels(ku: FlagSet<KeyUsages>, out: &mut Vec<String>) {
    let pairs: &[(KeyUsages, &str)] = &[
        (KeyUsages::DigitalSignature, "digitalSignature"),
        (KeyUsages::NonRepudiation, "nonRepudiation"),
        (KeyUsages::KeyEncipherment, "keyEncipherment"),
        (KeyUsages::DataEncipherment, "dataEncipherment"),
        (KeyUsages::KeyAgreement, "keyAgreement"),
        (KeyUsages::KeyCertSign, "keyCertSign"),
        (KeyUsages::CRLSign, "crlSign"),
        (KeyUsages::EncipherOnly, "encipherOnly"),
        (KeyUsages::DecipherOnly, "decipherOnly"),
    ];
    for (flag, label) in pairs {
        if ku.contains(*flag) {
            out.push((*label).to_string());
        }
    }
}

fn decide(ev: &Evidence, ku: Option<FlagSet<KeyUsages>>) -> PivRole {
    // Rule 1: CardAuth — id-PIV-cardAuth EKU
    if ev.extended_key_usages.iter().any(|e| e == OID_PIV_CARD_AUTH) {
        return PivRole::CardAuth;
    }
    // Rule 2: ContentSigning — id-PIV-content-signing EKU
    if ev.extended_key_usages.iter().any(|e| e == OID_PIV_CONTENT_SIGNING) {
        return PivRole::ContentSigning;
    }
    // Rule 3: PivAuth — fpki-common-auth/piv-auth policy OR fascn SAN + clientAuth EKU
    let has_common_auth = ev
        .policy_oids
        .iter()
        .any(|p| p == OID_FPKI_COMMON_AUTH || p == OID_FPKI_COMMON_PIV_AUTH);
    let has_client_auth = ev.extended_key_usages.iter().any(|e| e == OID_CLIENT_AUTH);
    if has_common_auth || (ev.fascn_present && has_client_auth) {
        return PivRole::PivAuth;
    }
    // Rule 4: DigitalSignature — nonRepudiation + emailProtection
    let has_email = ev.extended_key_usages.iter().any(|e| e == OID_EMAIL_PROTECTION);
    if let Some(ku) = ku {
        if ku.contains(KeyUsages::NonRepudiation) && has_email {
            return PivRole::DigitalSignature;
        }
        // Rule 5: KeyManagement — keyEncipherment/keyAgreement + emailProtection
        if (ku.contains(KeyUsages::KeyEncipherment) || ku.contains(KeyUsages::KeyAgreement))
            && has_email
        {
            return PivRole::KeyManagement;
        }
    }
    PivRole::Unknown
}
