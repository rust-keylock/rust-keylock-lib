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

//! Defines the `Cryptor` trait and implements the encryption and decryption for the _rust-keylock_
use std::cmp::PartialEq;
use std::fmt::Debug;
use std::iter::repeat;

use base64;
use crypto::{aes, aessafe, buffer};
use crypto::aes::KeySize;
use crypto::bcrypt::bcrypt;
use crypto::blockmodes::CtrModeX8;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::{Decryptor, Encryptor, SynchronousStreamCipher};
use log::*;
use rand::{Rng, RngCore};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};

use super::errors::RustKeylockError;
use super::protected::RklSecret;

const NUMBER_OF_SALT_KEY_PAIRS: usize = 10;

pub trait Cryptor {
    /// Decrypts a given array of bytes
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError>;
    /// Encrypts a given array of bytes
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError>;
}

/// Encrypts and Decrypts using bcrypt-created password
#[derive(Debug, PartialEq)]
pub struct BcryptAes {
    /// The key to use for decryption. This is created using bcrypt during the initialization.
    ///
    /// This key is retrieved by parsing the passwords file, during the application startup.
    key: RklSecret,
    /// The initialization vector for the AES.
    ///
    /// This iv is retrieved by parsing the passwords file, during the application startup.
    iv: Vec<u8>,
    /// The position of the salt inside the file
    salt_position: usize,
    /// A list of pairs of salt - bcrypt key.
    ///
    /// Each encryption process includes the creation of a new pseudo-random iv and the usage of one of the provided salt-key pairs.
    /// With these, the data is encrypted and the encrypted bytes are returned.
    salt_key_pairs: Vec<(Vec<u8>, RklSecret)>,
    /// A Hasher to be used to guarantee data integrity
    hasher: Sha3Keccak512,
    /// The hash that is retrieved by parsing the passwords file, during the application startup.
    hash: RklSecret,
}

impl BcryptAes {
    /// Creates a new key using the bcrypt algorithm.
    fn create_new_bcrypt_key(password: &str, salt: &[u8], cost: u32, expand: bool) -> Vec<u8> {
        let mut key: Vec<u8> = repeat(0u8).take(24).collect();
        bcrypt(cost, &salt, password.as_bytes(), &mut key);
        if expand {
            let append_to_key: Vec<u8> = repeat(0u8).take(8).collect();
            key.extend(append_to_key.iter());
        }
        key
    }

    /// Creates a new BcryptAes struct, using:
    ///
    /// * The user's password
    /// * Salt for the bcrypt algorithm,
    /// * Cost for the bcrypt algorithm
    /// * iv for AES
    /// * hash for Sha3Keccak512 hashing
    pub fn new(password: String,
               salt: Vec<u8>,
               cost: u32,
               iv: Vec<u8>,
               salt_position: usize,
               hash_bytes: Vec<u8>)
               -> BcryptAes {
        // Create bcrypt password for the current encrypted data
        let key = BcryptAes::create_new_bcrypt_key(&password, &salt, cost, true);

        // Create 10 new salt-key pairs to use them for encryption
        let mut salt_key_pairs = Vec::new();
        for _ in 0..NUMBER_OF_SALT_KEY_PAIRS {
            let s = create_random(16);
            let k = BcryptAes::create_new_bcrypt_key(&password, &s, cost, true);
            salt_key_pairs.push((s, RklSecret::new(k)));
        }

        // Create the SHA3 hasher
        let hasher = Sha3Keccak512::new();

        BcryptAes {
            key: RklSecret::new(key),
            iv: iv,
            salt_position: salt_position,
            salt_key_pairs: salt_key_pairs,
            hasher: hasher,
            hash: RklSecret::new(hash_bytes),
        }
    }

    pub fn ctr(key_size: KeySize, key: &[u8], iv: &[u8]) -> Box<SynchronousStreamCipher + 'static> {
        match key_size {
            KeySize::KeySize128 => {
                let aes_dec = aessafe::AesSafe128EncryptorX8::new(key);
                let dec = Box::new(CtrModeX8::new(aes_dec, iv));
                dec
            }
            KeySize::KeySize192 => {
                let aes_dec = aessafe::AesSafe192EncryptorX8::new(key);
                let dec = Box::new(CtrModeX8::new(aes_dec, iv));
                dec
            }
            KeySize::KeySize256 => {
                let aes_dec = aessafe::AesSafe256EncryptorX8::new(key);
                let dec = Box::new(CtrModeX8::new(aes_dec, iv));
                dec
            }
        }
    }
}

impl Cryptor for BcryptAes {
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
        let extracted_bytes = extract_bytes_to_decrypt(input, self.salt_position);
        let integrity_check_ok = self.hasher.validate_hash(&extracted_bytes, &self.hash.borrow());

        let bytes_to_decrypt = if integrity_check_ok {
            debug!("Integrity check ok!");
            extracted_bytes
        } else {
            warn!("Integrity check failed! Falling back to v0.2.1 handling...");
            extract_bytes_to_decrypt_fallback_for_v_0_3_0_upgrade(input, self.salt_position)
        };

        // Code taken from the rust-crypto example
        let mut final_result = Vec::<u8>::new();
        {
            let mut decryptor = Self::ctr(aes::KeySize::KeySize256, &self.key.borrow(), &self.iv);

            let mut read_buffer = buffer::RefReadBuffer::new(&bytes_to_decrypt);
            let mut buffer = [0; 4096];
            let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

            loop {
                let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
                final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
        }

        // If an error was encountered and integrity checks failed, then return an IntegrityError.
        // The integrity error contains the decrypted data as well and it is left to the caller to do actions because of the failure.
        if !integrity_check_ok {
            debug!("Returning an IntegrityError...");
            Err(RustKeylockError::IntegrityError(final_result))
        } else {
            Ok(final_result)
        }
    }

    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
        // Create a new iv
        let iv = create_random(16);
        // Choose randomly one of the salt-key pairs
        let idx = {
            let mut rng = OsRng::new().ok().unwrap();
            rng.gen_range::<usize>(0, NUMBER_OF_SALT_KEY_PAIRS)
        };
        let ref salt_key_pair = self.salt_key_pairs[idx];

        let bytes_to_save = {
            // Create an encryptor instance of the best performing
            // type available for the platform.
            // Code taken from the rust-crypto example
            let mut encryptor = Self::ctr(aes::KeySize::KeySize256, &salt_key_pair.1.borrow(), &iv);

            let mut encryption_result = Vec::<u8>::new();
            let mut read_buffer = buffer::RefReadBuffer::new(input);

            let mut buffer = [0; 4096];
            let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

            loop {
                let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

                encryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
            // Compose the encrypted bytes with the iv and salt
            compose_bytes_to_save(&encryption_result, self.salt_position, &salt_key_pair.0, &iv, &self.hasher)
        };

        Ok(bytes_to_save)
    }
}

/// Encrypts and decrypts passwords of Entries in order not to be kept in the memory in plain.
#[derive(Debug, PartialEq, Clone)]
pub struct EntryPasswordCryptor {
    /// The encryption/decryption key
    key: RklSecret,
    /// The initialization vector for the AES.
    iv: Vec<u8>,
}

impl EntryPasswordCryptor {
    /// Creates a new EntryPasswordCryptor.
    pub fn new() -> EntryPasswordCryptor {
        // Create a random password
        let password = create_random(32);
        // Create an iv
        let iv = create_random(16);
        // Create a salt
        let salt = create_random(16);
        // Generate a key
        let mut key: Vec<u8> = create_random(24);
        bcrypt(3, &salt, &password, &mut key);
        let append_to_key: Vec<u8> = repeat(0u8).take(8).collect();
        key.extend(append_to_key.iter());
        // Create and return the EntryPasswordCryptor
        EntryPasswordCryptor {
            key: RklSecret::new(key),
            iv: iv,
        }
    }

    /// Gets a String input and returns it encrypted and Base64-encoded
    pub fn encrypt_str(&self, input: &str) -> Result<String, RustKeylockError> {
        let encrypted = self.encrypt(input.as_bytes())?;
        Ok(base64::encode(&encrypted))
    }

    /// Gets a Base64-encoded String input and returns it decrypted
    pub fn decrypt_str(&self, input: &str) -> Result<String, RustKeylockError> {
        let encrypted = base64::decode(&input)?;
        let decrypted_bytes = self.decrypt(&encrypted)?;
        Ok(String::from_utf8(decrypted_bytes)?)
    }
}

impl Cryptor for EntryPasswordCryptor {
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
        // Code taken from the rust-crypto example
        let mut final_result = Vec::<u8>::new();
        {
            let mut decryptor = aes::ctr(aes::KeySize::KeySize256, &self.key.borrow(), &self.iv);

            let mut read_buffer = buffer::RefReadBuffer::new(input);
            let mut buffer = [0; 4096];
            let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

            loop {
                let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
                final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
        }
        Ok(final_result)
    }

    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
        // Create an encryptor instance of the best performing
        // type available for the platform.
        // Code taken from the rust-crypto example
        let mut encryptor = aes::ctr(aes::KeySize::KeySize256, &self.key.borrow(), &self.iv);

        let mut encryption_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(input);

        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

            encryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        Ok(encryption_result)
    }
}

/// No encryption implementation
#[allow(dead_code)]
pub struct NoCryptor;

impl NoCryptor {
    #[allow(dead_code)]
    pub fn new() -> NoCryptor {
        NoCryptor {}
    }
}

impl Cryptor for NoCryptor {
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
        Ok(Vec::from(input))
    }

    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
        Ok(Vec::from(input))
    }
}

pub trait Hasher: Debug + PartialEq {
    /// If the result of the implemented hash algorithm when it is applied on the data provided is equal with the hash provided, the method returns true.
    fn validate_hash(&self, data: &[u8], hash: &[u8]) -> bool;
    /// Calculates the hash value of the given data.
    fn calculate_hash(&self, data: &[u8]) -> Vec<u8>;
}

/// SHA3 hashing with 512 bits output
#[derive(Debug, PartialEq)]
pub struct Sha3Keccak512;

impl Sha3Keccak512 {
    pub fn new() -> Sha3Keccak512 {
        Sha3Keccak512
    }
}

impl Hasher for Sha3Keccak512 {
    fn validate_hash(&self, data: &[u8], hash: &[u8]) -> bool {
        let mut hasher = Sha3_512::default();
        hasher.input(data);
        let data_hash = hasher.result();
        data_hash.as_slice() == hash
    }

    fn calculate_hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_512::default();
        hasher.input(data);
        let data_hash = hasher.result();
        Vec::from(data_hash.as_slice())
    }
}

/// Creates a pseudo-random array of bytes with the given size
pub fn create_random(size: usize) -> Vec<u8> {
    let mut random: Vec<u8> = repeat(0u8).take(size).collect();
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut random);
    random
}

#[allow(unused_assignments)]
fn extract_bytes_to_decrypt(input_bytes: &[u8], salt_position: usize) -> Vec<u8> {
    // If the data bytes are less than 96, fill it with random data. This may happen only in the case of the upgrade to v0.3.0
    let bytes = if input_bytes.len() < 96 {
        let bytes_to_add = create_random(96 - input_bytes.len());
        let mut input_vec = Vec::new();
        let mut vec_to_add = Vec::from(bytes_to_add);
        input_vec = Vec::from(input_bytes);
        input_vec.append(&mut vec_to_add);
        input_vec
    } else {
        Vec::from(input_bytes)
    };
    // Check whether the salt exists between the data.
    // The salt and hash are positioned one right after the other and can generally exist either between the data, or at the end of the data.
    // To calculate this, we need to substract from the overall bytes, 16 bytes which is the iv, 16 bytes which is the salt and 64 bytes which is the hash.
    let salt_between_data = salt_position < (bytes.len() - 96);

    // We need to extract the bytes to be decrypted in order to create correct toml data.
    let bytes_to_decrypt: Vec<u8> = bytes
        .iter()
        // The first 16 bytes are the iv. Skip them.
        .skip(16)
        .enumerate()
        // Filter out the 80 bytes of salt(16) plus hash(64) that are located after the user-selected position
        .filter(|tup| {
            if salt_between_data {
                tup.0 < salt_position || tup.0 >= salt_position + 80
            } else {
                tup.0 < bytes.len() - 96
            }
        })
        // The enumerate function created Tuples. Keep only the second tuple element, which is the actual byte.
        .map(|tup| tup.1.clone())
        .collect();

    bytes_to_decrypt
}

// The hash position is right after the actual salt position
// let hash_position = actual_salt_position + 16;
//
// let integrity_ok = if bytes.len() > 96 && bytes.len() >= hash_position {
// let hash_bytes: Vec<u8> = bytes.clone()
// .into_iter()
// .skip(hash_position)
// .take(64)
// .collect();
// super::datacrypt::validate_data_indegrity(&bytes, &hash_bytes);
// true
// } else {
// true
// };
//
// if !integrity_check_ok {
// let _ = editor.show_message("Data Integrity check failed! This means that that data is corrupted or somehow tampered. If you just upgraded from v0.2.1 to v0.3.0 or higher, there is nothing to worry about. Otherwise, please consider the dangers of the situation...");
// }
//
fn extract_bytes_to_decrypt_fallback_for_v_0_3_0_upgrade(bytes: &[u8], salt_position: usize) -> Vec<u8> {
    // Check whether the salt exists between the data
    // The salt can generally exist either between the data, or at the end of the data
    // To calculate this, we need to substract 16 bytes which is the iv and 16 bytes which is the salt
    let salt_between_data = salt_position < (bytes.len() - 32);

    // We need to extract the bytes to be decrypted in order to create correct toml data.
    let bytes_to_decrypt: Vec<u8> = bytes
        .iter()
        // The first 16 bytes are the iv. Skip them.
        .skip(16)
        .enumerate()
        // Filter out the 16 bytes of salt that are located after the user-selected position
        .filter(|tup| {
            if salt_between_data {
                tup.0 < salt_position || tup.0 >= salt_position + 16
            } else {
                tup.0 < bytes.len() - 32
            }
        })
        // The enumerate function created Tuples. Keep only the second tuple element, which is the actual byte.
        .map(|tup| tup.1.clone())
        .collect();

    bytes_to_decrypt
}

fn compose_bytes_to_save(data: &[u8], salt_position: usize, salt: &[u8], iv: &[u8], hasher: &Sha3Keccak512) -> Vec<u8> {
    let mut bytes_to_save: Vec<u8> = Vec::new();

    // Calculate the hash of the data
    let hash_bytes = hasher.calculate_hash(data);

    // Clone the iv in order to append it in the bytes_to_save
    let mut mut_iv = Vec::from(iv);
    // Calculate the correct salt_position according to the size of the data
    let inferred_salt_position = {
        if salt_position < data.len() {
            salt_position
        } else {
            data.len()
        }
    };
    // Let define the hash position
    let hash_position = inferred_salt_position + 16;
    // Append the iv. This goes always in the beginning of the bytes_to_save
    bytes_to_save.append(&mut mut_iv);
    // Push the data, the salt and the hash
    // The bytes to return contain the iv, the salt, the hash and the actual data.
    // However, since the iv is already appended from above, the length in question is data.len() + salt.len() + hash_bytes.len()
    let length = data.len() + salt.len() + hash_bytes.len();

    for index in 0..length {
        // Push data bytes before the salt position
        if index < inferred_salt_position {
            bytes_to_save.push(data[index]);
        } else if index >= inferred_salt_position && index < inferred_salt_position + 16 {
            // Start pushing the salt bytes after the position indicated by the user
            bytes_to_save.push(salt[index - inferred_salt_position]);
        } else if index >= hash_position && index < hash_position + 64 {
            // Start pushing the hash bytes after the salt
            bytes_to_save.push(hash_bytes[index - hash_position]);
        } else {
            // Push data bytes after the salt + hash position
            bytes_to_save.push(data[index - 80]);
        }
    }

    bytes_to_save
}

#[cfg(test)]
mod test_crypt {
    use super::{Cryptor, Hasher};

    #[test]
    fn create_random() {
        let mut randoms = Vec::new();
        for _ in 0..1000 {
            // bcrypt needs 16 bytes salt
            let random = super::create_random(16);
            assert!(random.len() == 16);
            assert!(!randoms.contains(&random));
            randoms.push(random);
        }
    }

    #[test]
    fn compose_bytes_to_save_salt_position_0() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 0;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(32).take(64).collect();
        let d: Vec<u8> = vec.iter().cloned().skip(96).take(16).collect();
        assert!(i == iv);
        assert!(s == salt);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
        assert!(d == data);
    }

    #[test]
    fn compose_bytes_to_save_salt_position_0_and_no_real_data() {
        let data = Vec::new();
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 0;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(32).take(64).collect();
        let d: Vec<u8> = vec.iter().cloned().skip(96).take(16).collect();
        assert!(i == iv);
        assert!(s == salt);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
        assert!(d == data);
    }

    #[test]
    fn compose_bytes_to_save_salt_position_smaller_than_data_length() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 3;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        // The first part of the data should be from 16 to 19
        let mut d: Vec<u8> = vec.iter().cloned().skip(16).take(3).collect();
        // The second part of the data should be from 99 (19 + 16 + 64) to 112
        let mut d_rest: Vec<u8> = vec.iter().cloned().skip(99).take(13).collect();
        d.append(&mut d_rest);
        // The salt should be located at position 19
        let s: Vec<u8> = vec.iter().cloned().skip(19).take(16).collect();
        // The hash should be located at position 35
        let h: Vec<u8> = vec.iter().cloned().skip(35).take(64).collect();
        assert!(i == iv);
        assert!(s == salt);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
        assert!(d == data);
    }

    #[test]
    fn compose_bytes_to_save_salt_position_smaller_than_data_length_and_no_real_data() {
        let data = Vec::new();
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 3;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(32).take(64).collect();

        assert!(i == iv);
        assert!(s == salt);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
    }

    #[test]
    fn compose_bytes_to_save_salt_position_bigger_than_data_length() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 33;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let d: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let s: Vec<u8> = vec.iter().cloned().skip(32).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(48).take(64).collect();

        assert!(i == iv);
        assert!(s == salt);
        assert!(d == data);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
    }

    #[test]
    fn compose_bytes_to_save_salt_position_bigger_than_data_length_no_real_data() {
        let data = Vec::new();
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 33;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let d: Vec<u8> = Vec::new();
        let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(32).take(64).collect();
        assert!(i == iv);
        assert!(s == salt);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
        assert!(d == data);
    }

    #[test]
    fn compose_bytes_to_save_salt_position_equal_to_data_length() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 16;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let d: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let s: Vec<u8> = vec.iter().cloned().skip(32).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(48).take(64).collect();
        assert!(i == iv);
        assert!(s == salt);
        assert!(d == data);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
    }

    #[test]
    fn compose_bytes_to_save_salt_position_equal_to_data_length_no_real_data() {
        let data = Vec::new();
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let salt_position = 16;

        let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv, &super::Sha3Keccak512::new());

        let i: Vec<u8> = vec.iter().cloned().take(16).collect();
        let d: Vec<u8> = Vec::new();
        let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
        let h: Vec<u8> = vec.iter().cloned().skip(32).take(64).collect();
        assert!(i == iv);
        assert!(s == salt);
        assert!(d == data);
        assert!(h == super::Sha3Keccak512::new().calculate_hash(&data));
    }

    #[test]
    fn extract_bytes_to_decrypt_salt_position_0() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let hash = super::create_random(64);
        // Construct the data
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the salt
        let mut tmp: Vec<u8> = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the hash
        tmp = hash.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the data
        tmp = data.iter().cloned().collect();
        bytes.append(&mut tmp);

        let salt_position = 0;

        let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);

        assert!(vec == data);
    }

    #[test]
    fn extract_bytes_to_decrypt_salt_position_0_no_real_data() {
        let data = Vec::new();
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let hash = super::create_random(64);

        // Construct the data
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the salt
        let mut tmp: Vec<u8> = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the hash
        tmp = hash.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the data
        tmp = data.iter().cloned().collect();
        bytes.append(&mut tmp);

        let salt_position = 0;

        let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);

        assert!(vec == data);
    }

    #[test]
    fn extract_bytes_to_decrypt_salt_position_smaller_than_data_length() {
        // The first 3 bytes of data
        let data1 = vec![0x10u8, 0x11u8, 0x12u8];
        // The next 13 bytes of data
        let data2 = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8];
        // The total bytes of data
        let mut data: Vec<u8> = data1.iter().cloned().collect();
        let mut tmp: Vec<u8> = data2.iter().cloned().collect();
        data.append(&mut tmp);
        // The salt
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        // The iv
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        // The hash
        let hash = super::create_random(64);

        // Construct the data
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the first part of the data
        tmp = data1.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the salt
        tmp = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the hash
        tmp = hash.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the second part of the data
        tmp = data2.iter().cloned().collect();
        bytes.append(&mut tmp);

        let salt_position = 3;

        let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);
        assert!(vec == data);
    }

    #[test]
    fn extract_bytes_to_decrypt_salt_position_bigger_than_data_length() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let hash = super::create_random(64);

        // Construct the data
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the data
        let mut tmp = data.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the salt
        tmp = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the hash
        tmp = hash.iter().cloned().collect();
        bytes.append(&mut tmp);

        let salt_position = 33;

        let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);
        assert!(vec == data);
    }

    #[test]
    fn extract_bytes_to_decrypt_salt_position_bigger_than_data_length_no_real_data() {
        let data = Vec::new();
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let hash = super::create_random(64);

        // Construct the data
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the salt
        let mut tmp = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the hash
        tmp = hash.iter().cloned().collect();
        bytes.append(&mut tmp);

        let salt_position = 33;

        let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);
        assert!(vec == data);
    }

    #[test]
    fn extract_bytes_to_decrypt_salt_position_equal_to_data_length() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];
        let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8,
                        0x04u8, 0x10u8];
        let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8,
                      0x03u8, 0x10u8];
        let hash = super::create_random(64);

        // Construct the data
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the data
        let mut tmp = data.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the salt
        tmp = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add the hash
        tmp = hash.iter().cloned().collect();
        bytes.append(&mut tmp);

        let salt_position = 16;

        let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);
        assert!(vec == data);
    }

    #[test]
    fn password_encryption() {
        let password_cryptor = super::EntryPasswordCryptor::new();
        let password = "hello".as_bytes();
        let encrypted_password = password_cryptor.encrypt(password);
        assert!(encrypted_password.is_ok());
        assert!(encrypted_password.as_ref().unwrap() != &password);
        let decrypted_password = password_cryptor.decrypt(&encrypted_password.unwrap());
        assert!(decrypted_password.is_ok());
        assert!(decrypted_password.unwrap() == password);
    }

    #[test]
    fn password_string_encryption() {
        let password_cryptor = super::EntryPasswordCryptor::new();
        let password = "hello";
        let encrypted_password = password_cryptor.encrypt_str(&password);
        assert!(encrypted_password.is_ok());
        assert!(encrypted_password.as_ref().unwrap() != &password);
        let decrypted_password = password_cryptor.decrypt_str(&encrypted_password.unwrap());
        assert!(decrypted_password.is_ok());
        assert!(decrypted_password.unwrap() == password);
    }

    #[test]
    fn hash() {
        let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8,
                        0x12u8, 0x10u8];

        let hasher = super::Sha3Keccak512::new();
        let hash = hasher.calculate_hash(&data);
        assert!(hash.len() == 64);
        assert!(hasher.validate_hash(&data, &hash));
    }

    #[test]
    fn integrity_failure_on_bcrypt_aes() {
        let iv = super::create_random(16);
        let salt = super::create_random(16);
        let hash = super::create_random(64);
        let data = b"This is the data";
        // Construct the bytes to pass to the decryptor
        // Add the iv
        let mut bytes: Vec<u8> = iv.iter().cloned().collect();
        // Add the salt
        let mut tmp = salt.iter().cloned().collect();
        bytes.append(&mut tmp);
        // Add a different hash than the one created earlier
        tmp = super::create_random(64);
        bytes.append(&mut tmp);
        // Add the data
        tmp = data.iter().cloned().collect();
        bytes.append(&mut tmp);

        // Create the cryptor
        let cryptor = super::BcryptAes::new("password".to_string(), iv, 1, salt, 33, hash);
        let result = cryptor.decrypt(&bytes);
        assert!(result.is_err());
        match result.err() {
            Some(super::super::errors::RustKeylockError::IntegrityError(_)) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn bcrypt_key_size() {
        let key = super::BcryptAes::create_new_bcrypt_key("123", "saltsaltsaltsalt".as_bytes(), 3, false);
        assert!(key.len() == 24);
        let expanded_key = super::BcryptAes::create_new_bcrypt_key("123", "saltsaltsaltsalt".as_bytes(), 3, true);
        assert!(expanded_key.len() == 32);
    }
}
