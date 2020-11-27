// Copyright 2017 astonbitecode
// This file is part of rust-keylock password manager.
//
// rust-keylock is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// rust-keylock is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with rust-keylock.  If not, see <http://www.gnu.org/licenses/>.

use base64::DecodeError;
use http;
use hyper;
use native_tls;
use std::{fmt, result, time, sync};
use std::error::Error;
use std::fmt::Debug;
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use std::sync::mpsc::{RecvError, RecvTimeoutError, SendError};
use toml;
use ctr::stream_cipher::LoopError;
use url;
use tokio;
use futures::channel::oneshot::Canceled;
use reqwest;
use serde_json;
use rs_password_utils;

pub type Result<T> = result::Result<T, RustKeylockError>;

// pub fn debug_error_string<T>(error: T) -> String
//     where T: Error + Debug {
//     format!("{:?}", error)
// }

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RustKeylockError {
    GeneralError(String),
    ParseError(String),
    DecryptionError(String),
    EncryptionError(String),
    SyncError(String),
    HttpError(String),
}

impl fmt::Display for RustKeylockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RustKeylockError::GeneralError(ref message) => write!(f, "{}", message),
            RustKeylockError::ParseError(ref message) => write!(f, "Cannot parse: \n{}", message),
            RustKeylockError::DecryptionError(ref message) => write!(f, "Could not decrypt: {}", message),
            RustKeylockError::EncryptionError(ref message) => write!(f, "Could not encrypt: {}", message),
            RustKeylockError::SyncError(ref message) => write!(f, "Could not synchronize the rust-keylock data: {}", message),
            RustKeylockError::HttpError(ref message) => write!(f, "HTTP error: {}", message),
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
            RustKeylockError::SyncError(_) => ("Error while synchronizing"),
            RustKeylockError::HttpError(_) => ("Error while executing HTTP operations"),
        }
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

impl From<http::Error> for RustKeylockError {
    fn from(err: http::Error) -> RustKeylockError {
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

impl<T> From<SendError<T>> for RustKeylockError {
    fn from(err: SendError<T>) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<RecvError> for RustKeylockError {
    fn from(err: RecvError) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<RecvTimeoutError> for RustKeylockError {
    fn from(err: RecvTimeoutError) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<LoopError> for RustKeylockError {
    fn from(err: LoopError) -> RustKeylockError {
        RustKeylockError::EncryptionError(format!("{:?}", err))
    }
}

impl From<url::ParseError> for RustKeylockError {
    fn from(err: url::ParseError) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}

impl From<tokio::sync::mpsc::error::SendTimeoutError<Canceled>> for RustKeylockError {
    fn from(err: tokio::sync::mpsc::error::SendTimeoutError<Canceled>) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<reqwest::Error> for RustKeylockError {
    fn from(err: reqwest::Error) -> RustKeylockError {
        RustKeylockError::HttpError(format!("{:?}", err))
    }
}

impl From<serde_json::error::Error> for RustKeylockError {
    fn from(err: serde_json::error::Error) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}

impl From<std::str::Utf8Error> for RustKeylockError {
    fn from(err: std::str::Utf8Error) -> RustKeylockError {
        RustKeylockError::ParseError(format!("{:?}", err))
    }
}

impl <T> From<sync::PoisonError<T>> for RustKeylockError {
    fn from(err: sync::PoisonError<T>) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}

impl From<rs_password_utils::PasswordUtilsError> for RustKeylockError {
    fn from(err: rs_password_utils::PasswordUtilsError) -> RustKeylockError {
        RustKeylockError::GeneralError(format!("{:?}", err))
    }
}