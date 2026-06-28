use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unknown or unsupported encoding")]
    UnknownEncoding,

    #[error("input was empty")]
    Empty,

    #[error("ASN.1 decode failed: {0}")]
    Asn1(String),

    #[error("PEM decode failed: {0}")]
    Pem(String),

    #[error("base64 decode failed: {0}")]
    Base64(String),

    #[error("hex decode failed: {0}")]
    Hex(String),

    #[error("BER-TLV decode failed at offset {offset}: {message}")]
    Tlv { offset: usize, message: String },

    #[error("not a {expected}: {detail}")]
    WrongType { expected: &'static str, detail: String },

    #[error("biometric encoder failed: {0}")]
    Biometric(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn tlv(offset: usize, msg: impl Into<String>) -> Self {
        Error::Tlv { offset, message: msg.into() }
    }

    pub fn wrong_type(expected: &'static str, detail: impl Into<String>) -> Self {
        Error::WrongType { expected, detail: detail.into() }
    }
}
