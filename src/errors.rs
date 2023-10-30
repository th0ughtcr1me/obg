use hex::FromHexError;
use std::string::FromUtf8Error;
use std::num::ParseIntError;
use std::backtrace::Backtrace;

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    TemplateError(indicatif::style::TemplateError),
    FileSystemError(String),
    EncryptionError(EncryptionError),
    DecryptionError(DecryptionError),
    HexDecodingError(String),
    DeserializationError(String),
    NumberParsingError(ParseIntError),
    UriParseError(String),
    SerializationError(String),
    KeyError(String),
    NonValidKey(String),
    InvalidAes256KeySize(String),
    InvalidConfig(String),
    InvalidUtf8(FromUtf8Error),
    InvalidCliArg(String),
    InvalidAesIvSize(String),
    YamlFileError(YamlFileError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let bt = Backtrace::capture();

        match self {
            Error::IOError(e) => write!(f, "IOError: {}{}", bt, e),
            Error::TemplateError(e) => write!(f, "IOError: {}{}", bt, e),
            Error::EncryptionError(e) => write!(f, "EncryptionError: {}{}", bt, e),
            Error::DecryptionError(e) => write!(f, "DecryptionError: {}{}", bt, e),
            Error::FileSystemError(e) => write!(f, "FileSystemError: {}{}", bt, e),
            Error::InvalidCliArg(e) => write!(f, "InvalidCliArg: {}{}", bt, e),
            Error::HexDecodingError(e) => write!(f, "cannot parse hex string: {}{}", bt, e),
            Error::NumberParsingError(e) => write!(f, "ParseIntError: {}{}", bt, e),
            Error::UriParseError(e) => write!(f, "failed to parse URI {}{}", bt, e),
            Error::DeserializationError(e) => write!(f, "deserialization error: {}{}", bt, e),
            Error::SerializationError(e) => write!(f, "serialization error: {}{}", bt, e),
            Error::KeyError(s) => write!(f, "KeyError: {}{}", bt, s),
            Error::NonValidKey(s) => write!(f, "InvalidVersion: {}{}", bt, s),
            Error::InvalidAes256KeySize(s) => write!(f, "InvalidAes256KeySize: {}{}", bt, s),
            Error::InvalidAesIvSize(s) => write!(f, "InvalidAesIvSize: {}{}", bt, s),
            Error::InvalidUtf8(s) => write!(f, "InvalidUtf8: {}{}", bt, s),
            Error::InvalidConfig(s) => write!(f, "InvalidConfig: {}{}", bt, s),
            Error::YamlFileError(e) => write!(f, "{}{}", bt, e),
        }
    }
}

impl std::error::Error for Error {}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::NumberParsingError(e)
    }
}
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
impl From<indicatif::style::TemplateError> for Error {
    fn from(e: indicatif::style::TemplateError) -> Self {
        Error::TemplateError(e)
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

impl From<YamlFileError> for Error {
    fn from(e: YamlFileError) -> Self {
        Error::YamlFileError(e)
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
pub struct YamlFileError {
    message: String,
}
impl std::fmt::Display for YamlFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl YamlFileError {
    pub fn with_message(message: String) -> YamlFileError {
        YamlFileError { message }
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
