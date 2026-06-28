//! pivlib — PIV/PKI inspector CLI.

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "pivlib", version, about = "Inspect and transcode PIV/PKI files")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sniff the encoding (DER / PEM / base64-of-DER / PKCS#7 / PKCS#12 / ...).
    Detect {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Parse and classify an X.509 v3 certificate.
    Cert {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Parse a PKCS#10 CSR.
    Csr {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Parse an X.509 CRL.
    Crl {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Print PKCS#8 private-key metadata (algorithm + parameters; never the key bytes).
    Key {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Enumerate the contents of a PKCS#7 / CMS SignedData envelope.
    Pkcs7 {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Enumerate the structure of a PKCS#12 / PFX bundle (no decryption).
    Pkcs12 {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Decode a PIV CHUID container.
    Chuid {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Decode a PIV CCC container.
    Ccc {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Decode a PIV Security Object (CMS SignedData of LDSSecurityObject).
    SecurityObject {
        input: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "text")]
        format: OutFmt,
    },
    /// Transcode a cert/CSR/CRL between encodings.
    Convert {
        input: Option<PathBuf>,
        #[arg(long, value_enum)]
        to: ConvertTo,
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutFmt {
    Text,
    Json,
}

#[derive(Copy, Clone, ValueEnum)]
enum ConvertTo {
    Der,
    Pem,
    Base64,
    Hex,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Detect { input, format } => run_detect(input, format),
        Cmd::Cert { input, format } => run_cert(input, format),
        Cmd::Csr { input, format } => run_csr(input, format),
        Cmd::Crl { input, format } => run_crl(input, format),
        Cmd::Key { input, format } => run_key(input, format),
        Cmd::Pkcs7 { input, format } => run_pkcs7(input, format),
        Cmd::Pkcs12 { input, format } => run_pkcs12(input, format),
        Cmd::Chuid { input, format } => run_chuid(input, format),
        Cmd::Ccc { input, format } => run_ccc(input, format),
        Cmd::SecurityObject { input, format } => run_secobj(input, format),
        Cmd::Convert { input, to, output } => run_convert(input, to, output),
    }
}

fn read_input(path: Option<PathBuf>) -> Result<Vec<u8>> {
    match path {
        Some(p) => fs::read(&p).with_context(|| format!("reading {}", p.display())),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn normalize(bytes: &[u8]) -> Result<Vec<u8>> {
    let r = pivlib::encoding::detect(bytes).context("encoding detect")?;
    Ok(r.normalized_der)
}

fn emit_text<T: std::fmt::Debug>(v: &T) -> Result<()> {
    println!("{:#?}", v);
    Ok(())
}

fn emit_json<T: serde::Serialize>(v: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(v)?;
    println!("{}", s);
    Ok(())
}

fn run_detect(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let r = pivlib::encoding::detect(&bytes)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_cert(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let summary = pivlib::cert::parse::parse_der(&der)?;
    let classification = pivlib::cert::piv_role::classify(&der)?;
    #[derive(serde::Serialize, Debug)]
    struct Out {
        summary: pivlib::cert::parse::CertSummary,
        classification: pivlib::cert::piv_role::Classification,
    }
    let out = Out { summary, classification };
    match format {
        OutFmt::Text => emit_text(&out),
        OutFmt::Json => emit_json(&out),
    }
}

fn run_csr(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let r = pivlib::csr::parse_der(&der)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_crl(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let r = pivlib::crl::parse_der(&der)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_key(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let r = pivlib::key::parse_metadata(&der)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_pkcs7(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let r = pivlib::pkcs7::enumerate(&der)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_pkcs12(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let r = pivlib::pkcs12::enumerate(&der)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_chuid(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let r = pivlib::chuid::parse(&bytes)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_ccc(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let r = pivlib::ccc::parse(&bytes)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_secobj(input: Option<PathBuf>, format: OutFmt) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let r = pivlib::security_object::parse(&der)?;
    match format {
        OutFmt::Text => emit_text(&r),
        OutFmt::Json => emit_json(&r),
    }
}

fn run_convert(input: Option<PathBuf>, to: ConvertTo, output: Option<PathBuf>) -> Result<()> {
    let bytes = read_input(input)?;
    let der = normalize(&bytes)?;
    let out_bytes: Vec<u8> = match to {
        ConvertTo::Der => der,
        ConvertTo::Pem => pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
            .map(|s| s.into_bytes())
            .map_err(|e| anyhow::anyhow!("pem encode: {e}"))?,
        ConvertTo::Base64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .encode(&der)
                .into_bytes()
        }
        ConvertTo::Hex => hex::encode(&der).into_bytes(),
    };
    match output {
        Some(p) => fs::write(&p, out_bytes).with_context(|| format!("writing {}", p.display()))?,
        None => {
            io::stdout().write_all(&out_bytes)?;
            if !matches!(to, ConvertTo::Der) {
                println!();
            }
        }
    }
    Ok(())
}
