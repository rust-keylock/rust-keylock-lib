use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RustKeylockError {
    GeneralError(&'static str),
    ParseError(String),
}

impl fmt::Display for RustKeylockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &RustKeylockError::GeneralError(ref message) => write!(f, "{}", message),
            &RustKeylockError::ParseError(ref message) => write!(f, "Cannot parse: \n{}", message),
        }
    }
}

impl Error for RustKeylockError {
    fn description(&self) -> &str {
        match *self {
            RustKeylockError::GeneralError(_) => ("General error occured"),
        	RustKeylockError::ParseError(_) => ("Error during parsing"),
        }
    }
}
