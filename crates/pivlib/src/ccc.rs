//! PIV CCC (Card Capability Container) — NIST SP 800-73 Part 1, §3.1.1 + Table 8.
//!
//! BER-TLV decoder. CCCs are mostly free-form tag soup carrying card vendor
//! capability tuples — pivlib decodes the named tags and pushes the rest into
//! `extras` so operators can see what's there.

use serde::{Deserialize, Serialize};

use crate::error::Result;

use crate::chuid::{parse_tlvs, UnknownTlv};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ccc {
    pub card_identifier_hex: Option<String>,
    pub capability_container_version: Option<u8>,
    pub capability_grammar_version: Option<u8>,
    pub applications_cardurl_hex: Option<String>,
    pub pkcs15_indicator: Option<u8>,
    pub registered_data_model_number: Option<u8>,
    pub access_control_rule_table_hex: Option<String>,
    pub card_apdus_hex: Option<String>,
    pub redirection_tag_hex: Option<String>,
    pub capability_tuples_hex: Option<String>,
    pub status_tuples_hex: Option<String>,
    pub next_ccc_hex: Option<String>,
    pub extended_application_cardurl_hex: Option<String>,
    pub security_object_buffer_hex: Option<String>,
    pub error_detection_code_present: bool,
    pub extras: Vec<UnknownTlv>,
}

pub fn parse(bytes: &[u8]) -> Result<Ccc> {
    let tlvs = parse_tlvs(bytes)?;
    let mut ccc = Ccc::default();

    for (tag, value) in tlvs {
        match tag {
            0xF0 => ccc.card_identifier_hex = Some(hex::encode(&value)),
            0xF1 => ccc.capability_container_version = value.first().copied(),
            0xF2 => ccc.capability_grammar_version = value.first().copied(),
            0xF3 => ccc.applications_cardurl_hex = Some(hex::encode(&value)),
            0xF4 => ccc.pkcs15_indicator = value.first().copied(),
            0xF5 => ccc.registered_data_model_number = value.first().copied(),
            0xF6 => ccc.access_control_rule_table_hex = Some(hex::encode(&value)),
            0xF7 => ccc.card_apdus_hex = Some(hex::encode(&value)),
            0xFA => ccc.redirection_tag_hex = Some(hex::encode(&value)),
            0xFB => ccc.capability_tuples_hex = Some(hex::encode(&value)),
            0xFC => ccc.status_tuples_hex = Some(hex::encode(&value)),
            0xFD => ccc.next_ccc_hex = Some(hex::encode(&value)),
            0xE3 => ccc.extended_application_cardurl_hex = Some(hex::encode(&value)),
            0xB4 => ccc.security_object_buffer_hex = Some(hex::encode(&value)),
            0xFE => ccc.error_detection_code_present = true,
            other => ccc.extras.push(UnknownTlv {
                tag_hex: format!("{:02X}", other),
                value_hex: hex::encode(&value),
            }),
        }
    }
    Ok(ccc)
}
