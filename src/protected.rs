#[cfg(not(target_os = "windows"))]
use secstr::SecStr;
use std::borrow::Borrow;

// Struct definition
#[derive(Debug, PartialEq)]
#[cfg(not(target_os = "windows"))]
pub struct RklSecret {
    sec: SecStr,
}

#[derive(Debug, PartialEq)]
#[cfg(target_os = "windows")]
pub struct RklSecret {
	sec: Vec<u8>,
}
// Struct definition end

// Struct implementation
#[cfg(not(target_os = "windows"))]
impl RklSecret {
    pub fn new(data: Vec<u8>) -> RklSecret {
        RklSecret { sec: SecStr::from(data) }
    }

    pub fn borrow(&self) -> &[u8] {
        &self.sec.borrow()
    }
}

#[cfg(target_os = "windows")]
impl RklSecret {
    pub fn new(data: Vec<u8>) -> RklSecret {
        RklSecret { sec: data }
    }

    pub fn borrow(&self) -> &[u8] {
        &self.sec.borrow()
    }
}
// Struct implementation end
