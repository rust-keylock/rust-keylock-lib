use std::error::Error;
use std::{result, fmt, time};
use crypto::symmetriccipher::SymmetricCipherError;
use std::string::FromUtf8Error;
use std::io;
use base64::DecodeError;
use toml;
use hyper;
use native_tls;
use httpdate;
use std::num::ParseIntError;

pub type Result<T> = result::Result<T, RustKeylockError>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RustKeylockError {
    GeneralError(String),
    ParseError(String),
    DecryptionError(String),
    EncryptionError(String),
    IntegrityError(Vec<u8>),
    SyncError(String),
}

impl fmt::Display for RustKeylockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &RustKeylockError::GeneralError(ref message) => write!(f, "{}", message),
            &RustKeylockError::ParseError(ref message) => write!(f, "Cannot parse: \n{}", message),
            &RustKeylockError::DecryptionError(ref message) => write!(f, "Could not decrypt: {}", message),
            &RustKeylockError::EncryptionError(ref message) => write!(f, "Could not encrypt: {}", message),
            &RustKeylockError::IntegrityError(_) => write!(f, "Integrity check failed"),
            &RustKeylockError::SyncError(ref message) => write!(f, "Could not synchronize the rust-keylock data: {}", message),
        }
    }
}

impl Error for RustKeylockError {
    fn description(&self) -> &str {
        match *self {
            RustKeylockError::GeneralError(_) => ("General error occured"),
            RustKeylockError::ParseError(_) => ("Error during parsing"),
            RustKeylockError::DecryptionError(_) => ("Error during decryption"),
            RustKeylockError::EncryptionError(_) => ("Error during encryption"),
            RustKeylockError::IntegrityError(_) => ("Error during integrity checking"),
            RustKeylockError::SyncError(_) => ("Error while synchronizing"),
        }
    }
}

impl From<SymmetricCipherError> for RustKeylockError {
    fn from(err: SymmetricCipherError) -> RustKeylockError {
        RustKeylockError::DecryptionError(format!("{:?}", err))
    }
}

impl From<FromUtf8Error> for RustKeylockError {
    fn from(err: FromUtf8Error) -> RustKeylockError {
        RustKeylockError::DecryptionError(format!("{:?}", err))
    }
}

impl From<io::Error> for RustKeylockError {
    fn from(err: io::Error) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<DecodeError> for RustKeylockError {
    fn from(err: DecodeError) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}

impl From<toml::de::Error> for RustKeylockError {
    fn from(err: toml::de::Error) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}

impl From<toml::ser::Error> for RustKeylockError {
    fn from(err: toml::ser::Error) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}

impl From<hyper::error::UriError> for RustKeylockError {
    fn from(err: hyper::error::UriError) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<hyper::Error> for RustKeylockError {
    fn from(err: hyper::Error) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<native_tls::Error> for RustKeylockError {
    fn from(err: native_tls::Error) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<httpdate::Error> for RustKeylockError {
    fn from(err: httpdate::Error) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<time::SystemTimeError> for RustKeylockError {
    fn from(err: time::SystemTimeError) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<ParseIntError> for RustKeylockError {
    fn from(err: ParseIntError) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}
