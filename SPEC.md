# SPEC — pivlib

> **Status:** authoritative for the runtime behavior. Code is the source of
> truth; this document explains the contract behind it. For build commands,
> repository layout, and Claude-specific operational notes, see
> [CLAUDE.md](./CLAUDE.md). For release history, see
> [CHANGELOG.md](./CHANGELOG.md).

---

## Pipeline

```text
bytes ─► encoding::detect ─► Format + canonical DER
                              │
                              ├─► cert::parse + cert::piv_role::classify
                              ├─► csr::parse
                              ├─► crl::parse
                              ├─► key::parse_metadata
                              ├─► pkcs7::enumerate
                              ├─► pkcs12::enumerate
                              └─► (chuid | ccc | security_object)::parse

JPEG ─► face::incits385::build_facial_record ─► CBEFF
WSQ  ─► finger::wsq::decode ─► (incits381 image + incits378 minutiae) ─► CBEFF multi-BDB
```

Three families of pure functions. The PKI side has no IO. The biometric side
calls into NBIS C via FFI when the `nbis` feature is enabled; without it, WSQ
paths return a stub error.

---

## Encoding detection cascade

`encoding::detect(bytes)` walks a fixed cascade and returns the first match:

| Step | Test | `Format` value | Action |
|------|------|----------------|--------|
| 1 | `bytes[0..2] == [0x30, 0x82]` and total length matches the ASN.1 length field | `Format::Der` | passthrough |
| 2 | starts with `-----BEGIN ` and ends with `-----END ` | `Format::Pem(<label>)` | strip armor + base64 decode |
| 3 | all bytes in `[A-Za-z0-9+/=]` and base64-decodes to a valid `Der` shape | `Format::Base64OfDer` | base64 decode + re-detect |
| 4 | all bytes in `[0-9a-fA-F]` (length even) and hex-decodes to a valid `Der` shape | `Format::HexOfDer` | hex decode + re-detect |
| 5 | gzip magic `[0x1f, 0x8b]` and inflates to a valid `Der` shape | `Format::GzipOfDer` | inflate + re-detect |
| 6 | DER shape matches PKCS#7 SignedData OID (`1.2.840.113549.1.7.2`) | `Format::Pkcs7` | passthrough |
| 7 | DER shape matches PKCS#12 PFX (`1.2.840.113549.1.12.10.1.x`) | `Format::Pkcs12` | passthrough |
| ∞ | none of the above | `Format::Unknown` | error |

Returns:

```rust
pub struct DetectResult {
    pub format: Format,
    pub normalized_der: Vec<u8>,
    pub warnings: Vec<String>,
}
```

`warnings` carries human-readable observations ("file was base64-of-DER but
had whitespace inside the base64 envelope — common when copy-pasted from a
terminal").

Precedence rationale: a DER cert starts `0x30 0x82` which is valid base64
("MIICqg…"). We check DER first by inspecting the length field, so we don't
mis-classify naked DER as base64.

---

## PIV key-role classification

`cert::piv_role::classify(&Certificate) -> Classification` returns:

```rust
pub enum PivRole {
    PivAuth,
    CardAuth,
    DigitalSignature,
    KeyManagement,
    ContentSigning,
    Unknown,
}

pub struct Classification {
    pub role: PivRole,
    pub evidence: Evidence,
}

pub struct Evidence {
    pub policy_oids: Vec<String>,
    pub extended_key_usages: Vec<String>,
    pub key_usage: Vec<&'static str>,
    pub san_oids: Vec<String>,
    pub fascn_present: bool,
    pub piv_card_uuid_present: bool,
}
```

### Rules

Rules are evaluated in order; the first matching rule wins.

1. `CardAuth` — `id-PIV-cardAuth` EKU (`2.16.840.1.101.3.6.8`) is present.
2. `ContentSigning` — `id-PIV-content-signing` EKU
   (`2.16.840.1.101.3.6.7`) is present.
3. `PivAuth` — either the policy OID `id-fpki-common-authentication`
   (`2.16.840.1.101.3.2.1.3.13`) or `id-fpki-common-piv-authentication`
   (`2.16.840.1.101.3.2.1.3.40`) is present; *or* the SAN includes the PIV
   `id-PIV-FASC-N` OID (`2.16.840.1.101.3.6.6`) and `clientAuth` EKU.
4. `DigitalSignature` — KeyUsage `nonRepudiation` is asserted **and**
   `emailProtection` EKU is present.
5. `KeyManagement` — KeyUsage `keyEncipherment` or `keyAgreement` is asserted
   **and** `emailProtection` EKU is present, **and** rule 4 did not match.
6. `Unknown` — none of the above.

`evidence` is populated regardless of the matched role, so callers can
override the classifier with their own rules.

---

## SP 800-73 BER-TLV containers

Each container is decoded by reading the outer tag, length, then walking the
sub-TLVs. All three return a typed struct plus an `extras: Vec<UnknownTlv>`
for tags pivlib doesn't recognise yet.

### CHUID (Card Holder Unique Identifier)

Decoded fields (NIST SP 800-73 Part 1, Table 9):

| Tag (hex) | Name | Type |
|-----------|------|------|
| `0x30` | Buffer Length | u16 |
| `0x32` | FASC-N | 25 bytes BCD |
| `0x33` | Agency Code | string |
| `0x34` | Organizational Identifier | string |
| `0x35` | DUNS | string |
| `0x36` | GUID | 16 bytes (UUID) |
| `0x3E` | Issuer Asymmetric Signature | bytes (CMS SignedData) |
| `0x35` (alt) | Expiration Date | YYYYMMDD |
| `0xFE` | Error Detection Code | LRC byte |

The FASC-N is BCD-decoded into its named fields (Agency Code, System Code,
Credential Number, CS, ICI, PI, OC, OI, POA).

### CCC (Card Capability Container)

NIST SP 800-73 Part 1, Table 8. Decoded fields:

| Tag | Name |
|-----|------|
| `0xF0` | Card Identifier |
| `0xF1` | Capability Container Version Number |
| `0xF2` | Capability Grammar Version Number |
| `0xF3` | Applications CardURL |
| `0xF4` | PKCS#15 Indicator |
| `0xF5` | Registered Data Model Number |
| `0xF6` | Access Control Rule Table |
| `0xF7` | Card APDUs |
| `0xFA` | Redirection Tag |
| `0xFB` | Capability Tuples |
| `0xFC` | Status Tuples |
| `0xFD` | Next CCC |
| `0xE3` | Extended Application CardURL |
| `0xB4` | Security Object Buffer |
| `0xFE` | Error Detection Code |

### Security Object

NIST SP 800-73 Part 1, §3.5.5. The Security Object is a **CMS SignedData**
wrapping a `LDSSecurityObject` that hashes each PIV data container. pivlib
returns the signer, the algorithm, and the per-container `(container_id,
hash_algorithm, hash)` triples.

---

## CBEFF wrapping

`cbeff::wrap` and `cbeff::wrap_multi` (carried over from app.pivlib) emit a
patron-format CBEFF header followed by one or more BDBs (Biometric Data
Blocks). The patron format is hardcoded to ISO/IEC 19785 Patron Format A
(NIST) as in the original; the BDB type uses INCITS format owners
(`0x001B`).

`wrap_multi` is used when a single CBEFF carries both the INCITS 381 image
and the INCITS 378 minutiae for a single fingerprint capture.

---

## Stability of outputs

- `detect()` output is part of the public contract. Adding a new `Format`
  variant is MINOR; reclassifying existing inputs is MAJOR.
- PIV role classification is part of the contract. Changing what evidence
  flips which role on existing certs is MAJOR.
- BER-TLV decoder output is part of the contract. Renaming a field is MAJOR;
  adding a recognized tag (moving it from `extras` to a typed slot) is MINOR.
- The CBEFF encoder output is **byte-for-byte stable**. The whole point of
  the wrapping is to make later validation reproducible — see the snapshot
  tests in `crates/pivlib/tests/`.
