// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std;
use std::fmt::{Display, Formatter};
use std::error::Error;
use crate::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crate::cryptoutil::symm_enc_or_dec;

pub trait BlockEncryptor {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockEncryptorX8 {
    fn block_size(&self) -> usize;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptor {
    fn block_size(&self) -> usize;
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> usize;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

#[derive(Debug, Clone, Copy)]
pub enum SymmetricCipherError {
    InvalidLength,
    InvalidPadding
}

impl Display for SymmetricCipherError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        //match *self {
        //    SymmetricCipherError::InvalidLength => "padding output is not a multiple of blocksize",
        //    SymmetricCipherError::InvalidPadding => "stripping the padding wasn't succesfull"
        //}
        Display::fmt(self.description(), f)
    }
}

impl Error for SymmetricCipherError {
    fn description(&self) -> &str {
        match *self {
            SymmetricCipherError::InvalidLength => "padding output is not a multiple of blocksize",
            SymmetricCipherError::InvalidPadding => "stripping the padding wasn't succesfull"
        }
    }
}

pub trait Encryptor {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
        -> Result<BufferResult, SymmetricCipherError>;
}

pub trait Decryptor {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
        -> Result<BufferResult, SymmetricCipherError>;
}

pub trait SynchronousStreamCipher {
    fn process(&mut self, input: &[u8], output: &mut [u8]);
}

// TODO - Its a bit unclear to me why this is necessary
impl SynchronousStreamCipher for Box<SynchronousStreamCipher + 'static> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        let me = &mut **self;
        me.process(input, output);
    }
}

impl Encryptor for Box<SynchronousStreamCipher + 'static> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Box<SynchronousStreamCipher + 'static> {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_symcipher_error() {
        let error1 = SymmetricCipherError::InvalidLength;
        let error2 = SymmetricCipherError::InvalidPadding;
        println!("Testing {} and {}.", error1, error2);
        println!("Some error occured: {}", error1.description());
        println!("Another error occured: {}", error2.description());
    }
}
