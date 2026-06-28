//! pivlib — PIV-card and PKI toolkit.
//!
//! See [SPEC.md](../../SPEC.md) for the runtime contract and
//! [CLAUDE.md](../../CLAUDE.md) for operational notes.

pub mod error;
pub mod encoding;
pub mod cert;
pub mod csr;
pub mod crl;
pub mod key;
pub mod pkcs7;
pub mod pkcs12;
pub mod chuid;
pub mod ccc;
pub mod security_object;

// Biometric pipeline — moved verbatim from app.pivlib.
pub mod cbeff;
pub mod face;
pub mod finger;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::{Error, Result};
