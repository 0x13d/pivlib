//! Synthetic fixture generator for pivlib.
//!
//! Run via `make fixtures` (or `cargo run -p pivlib_fixtures -- --out-dir tests/fixtures`).
//! Generates the demo corpus consumed by:
//!
//! 1. Rust integration tests under `crates/pivlib/tests/`
//! 2. The web demo's `apps/web/src/samples.ts`
//! 3. The VS Code extension's example payloads
//!
//! Everything here is **synthetic** — no real PII, no real biometrics, no real
//! issuer signatures. The generator self-verifies each fixture by round-
//! tripping it through pivlib's parser; a parser regression that breaks a
//! fixture surfaces here, not in CI for the web app.

use std::path::{Path, PathBuf};

mod ccc;
mod cert;
mod chuid;
mod crl;
mod csr;
mod finger;
mod key;
mod pkcs7;
mod pkcs12;
mod portrait;
mod security_object;

use pivlib::cert::piv_role::PivRole;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = parse_out_dir();
    std::fs::create_dir_all(&out_dir)?;

    let chain = cert::build_chain()?;

    write_cert(&out_dir, "root_ca.cer", &chain.root_ca_cert, None)?;
    write_cert(&out_dir, "piv_ca.cer", &chain.piv_ca_cert, None)?;
    write_cert(&out_dir, "piv_auth.cer", &chain.piv_auth_cert, Some(PivRole::PivAuth))?;
    write_cert(&out_dir, "card_auth.cer", &chain.card_auth_cert, Some(PivRole::CardAuth))?;
    write_cert(&out_dir, "digital_signature.cer", &chain.digital_signature_cert, Some(PivRole::DigitalSignature))?;
    write_cert(&out_dir, "key_management.cer", &chain.key_management_cert, Some(PivRole::KeyManagement))?;
    write_cert(&out_dir, "content_signing.cer", &chain.content_signing_cert, Some(PivRole::ContentSigning))?;

    // CSR
    let csr_der = csr::build_piv_auth_csr(&chain.piv_auth_signer)?;
    pivlib::csr::parse_der(&csr_der)
        .map_err(|e| format!("piv_auth.csr fails parse: {e}"))?;
    write(&out_dir, "piv_auth.csr", &csr_der)?;

    // PKCS#8 private key (metadata-only parser; no key material is surfaced)
    let key_der = key::build_piv_auth_pkcs8(&chain.piv_auth_signer)?;
    pivlib::key::parse_metadata(&key_der)
        .map_err(|e| format!("piv_auth.p8 fails parse_metadata: {e}"))?;
    write(&out_dir, "piv_auth.p8", &key_der)?;

    // CRL signed by PIV CA, revoking the PIV Auth EE (serial 0x0301)
    let crl_der = crl::build_piv_ca_crl(
        &chain.piv_ca_signer,
        &chain.piv_ca_subject,
        x509_cert::serial_number::SerialNumber::from(0x0301u32),
    )?;
    pivlib::crl::parse_der(&crl_der)
        .map_err(|e| format!("revocation_list.crl fails parse: {e}"))?;
    write(&out_dir, "revocation_list.crl", &crl_der)?;

    // PKCS#7 SignedData (certs-only) wrapping the entire chain
    let pkcs7_der = pkcs7::build_pkcs7_chain(&[
        &chain.root_ca_cert,
        &chain.piv_ca_cert,
        &chain.piv_auth_cert,
        &chain.card_auth_cert,
        &chain.digital_signature_cert,
        &chain.key_management_cert,
        &chain.content_signing_cert,
    ])?;
    pivlib::pkcs7::enumerate(&pkcs7_der)
        .map_err(|e| format!("chain.p7b fails enumerate: {e}"))?;
    write(&out_dir, "chain.p7b", &pkcs7_der)?;

    // PKCS#12 PFX (structure only, no SafeBags — pivlib's parser surfaces
    // structure metadata without decryption)
    let pfx_der = pkcs12::build_pfx()?;
    pivlib::pkcs12::enumerate(&pfx_der)
        .map_err(|e| format!("demo.p12 fails enumerate: {e}"))?;
    write(&out_dir, "demo.p12", &pfx_der)?;

    let chuid_blob = chuid::build_chuid();
    let parsed_chuid = pivlib::chuid::parse(&chuid_blob)
        .map_err(|e| format!("generated chuid.bin fails parse: {e}"))?;
    let fascn = parsed_chuid.fasc_n.as_ref()
        .ok_or_else(|| "chuid.bin parsed but FASC-N did not decode".to_string())?;
    verify(fascn.agency_code == "9999",
        format!("FASC-N agency_code={:?}, expected 9999", fascn.agency_code))?;
    verify(fascn.system_code == "0001",
        format!("FASC-N system_code={:?}, expected 0001", fascn.system_code))?;
    verify(fascn.credential_number == "000042",
        format!("FASC-N credential_number={:?}, expected 000042", fascn.credential_number))?;
    verify(fascn.person_identifier == "0000000001",
        format!("FASC-N person_identifier={:?}, expected 0000000001", fascn.person_identifier))?;
    verify(fascn.organizational_identifier == "9999",
        format!("FASC-N organizational_identifier={:?}, expected 9999", fascn.organizational_identifier))?;
    verify(parsed_chuid.expiration_date.as_deref() == Some("20300101"),
        format!("chuid.bin expiration {:?}, expected 20300101", parsed_chuid.expiration_date))?;
    write(&out_dir, "chuid.bin", &chuid_blob)?;

    let ccc_blob = ccc::build_ccc();
    pivlib::ccc::parse(&ccc_blob)
        .map_err(|e| format!("ccc.bin fails parse: {e}"))?;
    write(&out_dir, "ccc.bin", &ccc_blob)?;

    let so_blob = security_object::build_security_object()?;
    pivlib::security_object::parse(&so_blob)
        .map_err(|e| format!("security_object.bin fails parse: {e}"))?;
    write(&out_dir, "security_object.bin", &so_blob)?;

    let wsq_blob = finger::build_wsq()
        .map_err(|e| format!("fingerprint WSQ build: {e}"))?;
    write(&out_dir, "fingerprint_synthetic.wsq", &wsq_blob)?;

    let portrait_jpeg = portrait::build_portrait_jpeg()
        .map_err(|e| format!("portrait JPEG encode: {e}"))?;
    // Verify by feeding it through the actual portrait encoder; if INCITS 385
    // wrapping fails on this JPEG it's not a usable demo input.
    pivlib::face::incits385::build_facial_record(&portrait_jpeg, None)
        .map_err(|e| format!("portrait_1x1.jpg fails build_facial_record: {e}"))?;
    write(&out_dir, "portrait_1x1.jpg", &portrait_jpeg)?;

    // Also write into the pivlib crate's own fixtures dir so its unit test
    // at face/incits385.rs:209 (`include_bytes!`) can compile and run.
    let crate_fixtures = Path::new("crates/pivlib/tests/fixtures");
    std::fs::create_dir_all(crate_fixtures)?;
    std::fs::write(crate_fixtures.join("portrait_1x1.jpg"), &portrait_jpeg)?;
    eprintln!("  · {} ({} bytes)", crate_fixtures.join("portrait_1x1.jpg").display(), portrait_jpeg.len());

    eprintln!("fixtures written to {} (all verified)", out_dir.display());
    Ok(())
}

fn write_cert(
    dir: &Path,
    name: &str,
    der: &[u8],
    expected_role: Option<PivRole>,
) -> Result<(), Box<dyn std::error::Error>> {
    pivlib::cert::parse::parse_der(der)
        .map_err(|e| format!("{name} fails parse_der: {e}"))?;
    if let Some(want) = expected_role {
        let got = pivlib::cert::piv_role::classify(der)
            .map_err(|e| format!("{name} fails role classification: {e}"))?
            .role;
        if got != want {
            return Err(format!("{name} classified as {got:?}, expected {want:?}").into());
        }
    }
    write(dir, name, der)?;
    Ok(())
}

fn parse_out_dir() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--out-dir" {
            if let Some(p) = args.next() {
                return PathBuf::from(p);
            }
        }
    }
    PathBuf::from("tests/fixtures")
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, bytes)?;
    eprintln!("  · {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn verify(ok: bool, msg: String) -> Result<(), Box<dyn std::error::Error>> {
    if ok {
        Ok(())
    } else {
        Err(msg.into())
    }
}
