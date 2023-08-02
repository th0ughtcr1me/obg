use hex::FromHexError;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    FileSystemError(String),
    EncryptionError(EncryptionError),
    DecryptionError(DecryptionError),
    HexDecodingError(String),
    DeserializationError(String),
    UriParseError(String),
    SerializationError(String),
    InvalidAes256KeySize(String),
    InvalidUtf8(FromUtf8Error),
    InvalidCliArg(String),
    InvalidAesIvSize(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IOError(e) => write!(f, "IOError: {}", e),
            Error::EncryptionError(e) => write!(f, "EncryptionError: {}", e),
            Error::DecryptionError(e) => write!(f, "DecryptionError: {}", e),
            Error::FileSystemError(e) => write!(f, "FileSystemError: {}", e),
            Error::InvalidCliArg(e) => write!(f, "InvalidCliArg: {}", e),
            Error::HexDecodingError(e) => write!(f, "cannot parse hex string: {}", e),
            Error::UriParseError(e) => write!(f, "failed to parse URI {}", e),
            Error::DeserializationError(e) => write!(f, "deserialization error: {}", e),
            Error::SerializationError(e) => write!(f, "serialization error: {}", e),
            Error::InvalidAes256KeySize(s) => write!(f, "InvalidAes256KeySize: {}", s),
            Error::InvalidAesIvSize(s) => write!(f, "InvalidAesIvSize: {}", s),
            Error::InvalidUtf8(s) => write!(f, "InvalidUtf8: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Error::DeserializationError(e.to_string())
    }
}
impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::UriParseError(e.to_string())
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::InvalidUtf8(e)
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        match e {
            FromHexError::OddLength => Error::HexDecodingError(format!("odd length")),
            FromHexError::InvalidHexCharacter { c, index } => {
                Error::HexDecodingError(format!("invalid hex character {} at {}", c, index))
            }
            FromHexError::InvalidStringLength => {
                Error::HexDecodingError(format!("invalid string length"))
            }
        }
    }
}

impl From<EncryptionError> for Error {
    fn from(e: EncryptionError) -> Self {
        Error::EncryptionError(e)
    }
}

impl From<DecryptionError> for Error {
    fn from(e: DecryptionError) -> Self {
        Error::DecryptionError(e)
    }
}

#[derive(Debug)]
pub struct EncryptionError {
    reason: String,
}
impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl EncryptionError {
    pub fn new(reason: String) -> EncryptionError {
        EncryptionError { reason }
    }
}

#[derive(Debug)]
pub struct DecryptionError {
    reason: String,
}
impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl DecryptionError {
    pub fn new(reason: String) -> DecryptionError {
        DecryptionError { reason }
    }
}
