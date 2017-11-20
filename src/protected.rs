use secstr::SecStr;
use std::borrow::Borrow;

#[derive(Debug, PartialEq)]
pub struct RklSecret {
    sec: SecStr,
}

impl RklSecret {
    pub fn new(data: Vec<u8>) -> RklSecret {
        RklSecret { sec: SecStr::from(data) }
    }

    pub fn borrow(&self) -> &[u8] {
        &self.sec.borrow()
    }
}
