export type Format =
  | { kind: 'der' }
  | { kind: 'pem'; label: string }
  | { kind: 'base64-of-der' }
  | { kind: 'hex-of-der' }
  | { kind: 'gzip-of-der' }
  | { kind: 'pkcs7' }
  | { kind: 'pkcs12' }
  | { kind: 'unknown' };

export interface DetectResult {
  format: Format;
  /** Base64 of the normalized DER form. Decode with `atob` or `Buffer.from`. */
  normalized_der: string;
  warnings: string[];
}

export interface CertSummary {
  version: number;
  serial_hex: string;
  signature_algorithm: string;
  issuer: string;
  subject: string;
  not_before: string;
  not_after: string;
  public_key_algorithm: string;
  public_key_size_bits: number | null;
  fingerprint_sha256_hex: string;
  extensions: ExtensionSummary[];
}

export interface ExtensionSummary {
  oid: string;
  name: string | null;
  critical: boolean;
  value_hex: string;
}

export type PivRole =
  | 'PivAuth'
  | 'CardAuth'
  | 'DigitalSignature'
  | 'KeyManagement'
  | 'ContentSigning'
  | 'Unknown';

export interface Evidence {
  policy_oids: string[];
  extended_key_usages: string[];
  key_usage: string[];
  san_oids: string[];
  fascn_present: boolean;
  piv_card_uuid_present: boolean;
}

export interface Classification {
  role: PivRole;
  evidence: Evidence;
}

export interface CsrSummary {
  subject: string;
  public_key_algorithm: string;
  signature_algorithm: string;
  attributes: { oid: string; value_hex: string }[];
}

export interface CrlSummary {
  issuer: string;
  this_update: string;
  next_update: string | null;
  revoked: { serial_hex: string; revocation_date: string }[];
  signature_algorithm: string;
}

export interface KeySummary {
  algorithm: string;
  parameter_oid: string | null;
  encrypted: boolean;
  kdf_algorithm: string | null;
  encryption_algorithm: string | null;
  raw_key_length: number;
}

export interface Pkcs7Summary {
  digest_algorithms: string[];
  encap_content_type: string;
  certificates: CertSummary[];
  signers: SignerSummary[];
}

export interface SignerSummary {
  digest_algorithm: string;
  signature_algorithm: string;
  issuer: string | null;
  serial_hex: string | null;
}

export interface Pkcs12Summary {
  version: number;
  auth_safe_content_type: string;
  mac_present: boolean;
  mac_algorithm: string | null;
  note: string;
}

export interface Chuid {
  buffer_length: number | null;
  fasc_n: Fascn | null;
  fasc_n_raw_hex: string | null;
  agency_code: string | null;
  organizational_identifier: string | null;
  duns: string | null;
  guid: string | null;
  expiration_date: string | null;
  issuer_asymmetric_signature_hex: string | null;
  error_detection_code_present: boolean;
  extras: { tag_hex: string; value_hex: string }[];
}

export interface Fascn {
  agency_code: string;
  system_code: string;
  credential_number: string;
  credential_series: string;
  individual_credential_issue: string;
  person_identifier: string;
  organizational_category: string;
  organizational_identifier: string;
  person_organization_association: string;
}

export interface Ccc {
  card_identifier_hex: string | null;
  capability_container_version: number | null;
  capability_grammar_version: number | null;
  applications_cardurl_hex: string | null;
  pkcs15_indicator: number | null;
  registered_data_model_number: number | null;
  access_control_rule_table_hex: string | null;
  card_apdus_hex: string | null;
  redirection_tag_hex: string | null;
  capability_tuples_hex: string | null;
  status_tuples_hex: string | null;
  next_ccc_hex: string | null;
  extended_application_cardurl_hex: string | null;
  security_object_buffer_hex: string | null;
  error_detection_code_present: boolean;
  extras: { tag_hex: string; value_hex: string }[];
}

export interface SecurityObject {
  encap_content_type: string;
  hash_algorithm: string | null;
  container_hashes: { container_id: number; hash_hex: string }[];
  signers: SignerSummary[];
}
