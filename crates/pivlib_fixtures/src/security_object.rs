//! Build a synthetic PIV Security Object per SP 800-73 §3.5.5.
//!
//! Structurally CMS SignedData wrapping an LDSSecurityObject. We emit a
//! degenerate (signer-less) SignedData; pivlib's parser surfaces the embedded
//! container_id → hash pairs regardless of signer count.

use cms::content_info::{CmsVersion, ContentInfo};
use cms::revocation::RevocationInfoChoices;
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence};

const OID_ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// id-icao-ldsSecurityObject (used by PIV per SP 800-73-4).
const OID_LDS_SO: &str = "2.23.136.1.1.1";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";

#[derive(Sequence)]
struct DataGroupHash {
    container_id: u8,
    hash: OctetString,
}

#[derive(Sequence)]
struct AlgorithmId {
    algorithm: ObjectIdentifier,
}

#[derive(Sequence)]
struct LdsSecurityObject {
    version: u8,
    hash_algorithm: AlgorithmId,
    data_group_hashes: Vec<DataGroupHash>,
}

pub fn build_security_object() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let lds = LdsSecurityObject {
        version: 0,
        hash_algorithm: AlgorithmId {
            algorithm: ObjectIdentifier::new(OID_SHA256)?,
        },
        data_group_hashes: vec![
            // Container 0x01 = CHUID (synthetic SHA-256 hash)
            DataGroupHash { container_id: 0x01, hash: OctetString::new(vec![0x11u8; 32])? },
            // Container 0x02 = Fingerprint
            DataGroupHash { container_id: 0x02, hash: OctetString::new(vec![0x22u8; 32])? },
            // Container 0x03 = Portrait
            DataGroupHash { container_id: 0x03, hash: OctetString::new(vec![0x33u8; 32])? },
        ],
    };

    let lds_der = lds.to_der()?;

    // eContent is an `[0] EXPLICIT OCTET STRING (CONTAINING LDSSecurityObject)`.
    // Build the OCTET STRING with the LDS DER inside, encode it, then re-wrap
    // as an Any so the SEQUENCE field accepts it.
    let lds_octets = OctetString::new(lds_der)?;
    let lds_octets_der = lds_octets.to_der()?;
    let econtent_any = Any::from_der(&lds_octets_der)?;

    let encap = EncapsulatedContentInfo {
        econtent_type: ObjectIdentifier::new(OID_LDS_SO)?,
        econtent: Some(econtent_any),
    };

    let signed = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::default(),
        encap_content_info: encap,
        certificates: Some(CertificateSet(SetOfVec::default())),
        crls: Some(RevocationInfoChoices(SetOfVec::default())),
        signer_infos: SignerInfos(SetOfVec::default()),
    };

    let signed_der = signed.to_der()?;
    let content = Any::from_der(&signed_der)?;
    let info = ContentInfo {
        content_type: ObjectIdentifier::new(OID_ID_SIGNED_DATA)?,
        content,
    };
    Ok(info.to_der()?)
}
