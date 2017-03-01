//!Defines the `Cryptor` trait and implements the encryption and decryption for the _rust-keylock_
use rand::{ Rng, OsRng };
use std::iter::repeat;
use crypto::bcrypt::bcrypt;
use crypto::{ buffer, aes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::symmetriccipher::{ Encryptor, Decryptor };
use super::errors::RustKeylockError;
use rustc_serialize::base64::{FromBase64, ToBase64, STANDARD};

const NUMBER_OF_SALT_KEY_PAIRS: usize = 10;

pub trait Cryptor {
	///Decrypts a given array of bytes
	fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError>;
	///Encrypts a given array of bytes
	fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError>;
}

///Encrypts and Decrypts using bcrypt-created password
#[derive(Debug, PartialEq)]
pub struct BcryptAes {
	///The key to use for decryption. This is created using bcrypt during the initialization.
	///
	///This key is retrieved by parsing the passwords file, during the application startup.
	key: Vec<u8>,
	///The initialization vector for the AES.
	///
	///This iv is retrieved by parsing the passwords file, during the application startup.
	iv: Vec<u8>,
	///The position of the salt inside the file
	salt_position: usize,
	///A list of pairs of salt - bcrypt key.
	///
	///Each encryption process includes the creation of a new pseudo-random iv and the usage of one of the provided salt-key pairs.
	///With these, the data is encrypted and the encrypted bytes are returned.
	salt_key_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl BcryptAes {
	///Creates a new key using the bcrypt algorithm.
	fn create_new_bcrypt_key(password: &str, salt: &[u8], cost: u32) -> Vec<u8> {
		let mut key: Vec<u8> = repeat(0u8).take(24).collect();
	    bcrypt(cost, &salt, password.as_bytes(), &mut key);
	    key
	}

	///Creates a new BcryptAes struct, using:
	///
	///* The user's password
	///* Salt for the bcrypt algorithm,
	///* Cost for the bcrypt algorithm
	///* iv for AES
	pub fn new(password: String, salt: Vec<u8>, cost: u32, iv: Vec<u8>, salt_position: usize) -> BcryptAes {
		// Create bcrypt password for the current encrypted data
		let key = BcryptAes::create_new_bcrypt_key(&password, &salt, cost);

		// Create 10 new salt-key pairs to use them for encryption
		let mut salt_key_pairs = Vec::new();
		for _ in 0..NUMBER_OF_SALT_KEY_PAIRS {
			let s = create_random(16);
			let k = BcryptAes::create_new_bcrypt_key(&password, &s, cost);
			salt_key_pairs.push((s, k));
		}

		BcryptAes {
			key: key,
			iv: iv,
			salt_position: salt_position,
			salt_key_pairs: salt_key_pairs,
		}
	}
}

impl Cryptor for BcryptAes {
	fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
		let bytes_to_decrypt = extract_bytes_to_decrypt(input, self.salt_position);

	    // Code taken from the rust-crypto example
	    let mut final_result = Vec::<u8>::new();
	    {
		    let mut decryptor = aes::ctr(
	            aes::KeySize::KeySize256,
	            &self.key,
	            &self.iv);

		    let mut read_buffer = buffer::RefReadBuffer::new(&bytes_to_decrypt);
		    let mut buffer = [0; 4096];
		    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
		
		    loop {
		        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
		        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
		        match result {
		            BufferResult::BufferUnderflow => break,
		            BufferResult::BufferOverflow => { }
		        }
		    }
	    }
	    Ok(final_result)
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
			let mut encryptor = aes::ctr(
	            aes::KeySize::KeySize256,
	            &salt_key_pair.1,
	            &iv);

			let mut encryption_result = Vec::<u8>::new();
		    let mut read_buffer = buffer::RefReadBuffer::new(input);

		    let mut buffer = [0; 4096];
		    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

			loop {
		        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

		        encryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

		        match result {
		            BufferResult::BufferUnderflow => break,
		            BufferResult::BufferOverflow => { }
		        }
		    }
			// Compose the encrypted bytes with the iv and salt
			compose_bytes_to_save(&encryption_result, self.salt_position, &salt_key_pair.0, &iv)
		};

	    Ok(bytes_to_save)
	}
}

///Encrypts and decrypts passwords of Entries in order not to be kept in the memory in plain.
pub struct EntryPasswordCryptor {
	///The encryption/decryption key
	key: Vec<u8>,
	///The initialization vector for the AES.
	iv: Vec<u8>,
}

impl EntryPasswordCryptor {
	///Creates a new EntryPasswordCryptor.
	pub fn new() -> EntryPasswordCryptor {
		// Create a random password
		let password = create_random(24);
		// Create an iv
		let iv = create_random(16);
		// Create a salt
		let salt = create_random(16);
		// Generate a key
		let mut key: Vec<u8> = repeat(0u8).take(24).collect();
	    bcrypt(3, &salt, &password, &mut key);
	    // Create and return the EntryPasswordCryptor
	    EntryPasswordCryptor {
	    	key: key,
	    	iv: iv,
	    }
	}

	///Gets a String input and returns it encrypted and Base64-encoded
	pub fn encrypt_str(&self, input: &str) -> Result<String, RustKeylockError> {
		let encrypted = try!(self.encrypt(input.as_bytes()));
		Ok(encrypted.to_base64(STANDARD))
	}

	///Gets a Base64-encoded String input and returns it decrypted
	pub fn decrypt_str(&self, input: &str) -> Result<String, RustKeylockError> {
		let encrypted = try!(input.from_base64());
		let decrypted_bytes = try!(self.decrypt(&encrypted));
		Ok(try!(String::from_utf8(decrypted_bytes)))
	}
}

impl Cryptor for EntryPasswordCryptor {
	fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
	    // Code taken from the rust-crypto example
	    let mut final_result = Vec::<u8>::new();
	    {
		    let mut decryptor = aes::ctr(
	            aes::KeySize::KeySize256,
	            &self.key,
	            &self.iv);

		    let mut read_buffer = buffer::RefReadBuffer::new(input);
		    let mut buffer = [0; 4096];
		    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
		
		    loop {
		        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
		        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());
		        match result {
		            BufferResult::BufferUnderflow => break,
		            BufferResult::BufferOverflow => { }
		        }
		    }
	    }
	    Ok(final_result)
	}

	fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
		// Create an encryptor instance of the best performing
	    // type available for the platform.
	    // Code taken from the rust-crypto example
		let mut encryptor = aes::ctr(
            aes::KeySize::KeySize256,
            &self.key,
            &self.iv);

		let mut encryption_result = Vec::<u8>::new();
	    let mut read_buffer = buffer::RefReadBuffer::new(input);

	    let mut buffer = [0; 4096];
	    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

		loop {
	        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

	        encryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

	        match result {
	            BufferResult::BufferUnderflow => break,
	            BufferResult::BufferOverflow => { }
	        }
	    }

	    Ok(encryption_result)
	}
}

///No encryption implementation
#[allow(dead_code)]
pub struct NoCryptor;

impl NoCryptor {
	#[allow(dead_code)]
	pub fn new() -> NoCryptor {
		NoCryptor{}
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

///Creates a pseudo-random array of bytes with the given size
pub fn create_random(size: usize) -> Vec<u8> {
	let mut random: Vec<u8> = repeat(0u8).take(size).collect();
	let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut random);
	random
}

fn extract_bytes_to_decrypt(bytes: &[u8], salt_position: usize) -> Vec<u8> {
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

fn compose_bytes_to_save(data: &[u8], salt_position: usize, salt: &[u8], iv: &[u8]) -> Vec<u8> {
	let mut bytes_to_save: Vec<u8> = Vec::new();

	// Clone the iv in order to append it in the bytes_to_save
	let mut mut_iv = Vec::from(iv);
	// Calculate the correct salt_position according to the size of the data
	let inferred_salt_position = {
		if salt_position < data.len() {
			salt_position
		}
		else {
			data.len()
		}
	};
	// Append the iv. This goes always in the beginning of the bytes_to_save
	bytes_to_save.append(&mut mut_iv);
	// Push the data and the salt
	// The bytes to return contain the iv, the salt and the actual data.
	// However, since the iv is already appended from above, the length in question is data.len() + salt.len()
	let length = data.len() + salt.len();

	for index in 0..length {
		// Push data bytes before the salt position
		if index < inferred_salt_position {
			bytes_to_save.push(data[index]);
		}
		// Start pushing the salt bytes after the position indicated by the user
		else if index >= inferred_salt_position && index < inferred_salt_position + 16 {
			bytes_to_save.push(salt[index - inferred_salt_position]);
		}
		// Push data bytes after the salt position
		else {
			bytes_to_save.push(data[index - 16]);
		}
	}

	bytes_to_save
}

#[cfg(test)]
mod test_crypt {
	use super::Cryptor;

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
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 0;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
		let d: Vec<u8> = vec.iter().cloned().skip(32).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_0_and_no_real_data() {
		let data = Vec::new();
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 0;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
		let d: Vec<u8> = vec.iter().cloned().skip(32).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_smaller_than_data_length() {
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 3;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		// The first part of the data should be from 16 to 19
		let mut d: Vec<u8> = vec.iter().cloned().skip(16).take(3).collect();
		// The second part of the data should be from 35 (19 + 16) to 48
		let mut d_rest: Vec<u8> = vec.iter().cloned().skip(35).take(13).collect();
		d.append(&mut d_rest);
		// The salt should be located at position 19
		let s: Vec<u8> = vec.iter().cloned().skip(19).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_smaller_than_data_length_and_no_real_data() {
		let data = Vec::new();
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 3;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let d: Vec<u8> = Vec::new();
		let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();

		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_bigger_than_data_length() {
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 33;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let d: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
		let s: Vec<u8> = vec.iter().cloned().skip(32).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_bigger_than_data_length_no_real_data() {
		let data = Vec::new();
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 33;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let d: Vec<u8> = Vec::new();;
		let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_equal_to_data_length() {
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 16;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let d: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
		let s: Vec<u8> = vec.iter().cloned().skip(32).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn compose_bytes_to_save_salt_position_equal_to_data_length_no_real_data() {
		let data = Vec::new();
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];
		let salt_position = 16;

		let vec = super::compose_bytes_to_save(&data, salt_position, &salt, &iv);

		let i: Vec<u8> = vec.iter().cloned().take(16).collect();
		let d: Vec<u8> = Vec::new();
		let s: Vec<u8> = vec.iter().cloned().skip(16).take(16).collect();
		assert!(i == iv);
		assert!(s == salt);
		assert!(d == data);
	}

	#[test]
	fn extract_bytes_to_decrypt_salt_position_0() {
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];

		// Construct the data
		// Add the iv
		let mut bytes: Vec<u8> = iv.iter().cloned().collect();
		// Add the salt
		let mut tmp: Vec<u8> = salt.iter().cloned().collect();
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
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];

		// Construct the data
		// Add the iv
		let mut bytes: Vec<u8> = iv.iter().cloned().collect();
		// Add the salt
		let mut tmp: Vec<u8> = salt.iter().cloned().collect();
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
		let data2 = vec![0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		// The total bytes of data
		let mut data: Vec<u8> = data1.iter().cloned().collect();
		let mut tmp: Vec<u8> = data2.iter().cloned().collect();
		data.append(&mut tmp);
		// The salt
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		// The iv
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];

		// Construct the data
		// Add the iv
		let mut bytes: Vec<u8> = iv.iter().cloned().collect();
		// Add the first part of the data
		tmp = data1.iter().cloned().collect();
		bytes.append(&mut tmp);
		// Add the salt
		tmp = salt.iter().cloned().collect();
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
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];

		// Construct the data
		// Add the iv
		let mut bytes: Vec<u8> = iv.iter().cloned().collect();
		// Add the data
		let mut tmp = data.iter().cloned().collect();
		bytes.append(&mut tmp);
		// Add the salt
		tmp = salt.iter().cloned().collect();
		bytes.append(&mut tmp);

		let salt_position = 33;

		let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);
		assert!(vec == data);
	}

	#[test]
	fn extract_bytes_to_decrypt_salt_position_bigger_than_data_length_no_real_data() {
		let data = Vec::new();
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];

		// Construct the data
		// Add the iv
		let mut bytes: Vec<u8> = iv.iter().cloned().collect();
		// Add the salt
		let mut tmp = salt.iter().cloned().collect();
		bytes.append(&mut tmp);

		let salt_position = 33;

		let vec = super::extract_bytes_to_decrypt(&bytes, salt_position);
		assert!(vec == data);
	}

	#[test]
	fn extract_bytes_to_decrypt_salt_position_equal_to_data_length() {
		let data = vec![0x10u8, 0x11u8, 0x12u8, 0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8,0x10u8, 0x11u8, 0x12u8, 0x10u8];
		let salt = vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8];
		let iv = vec![0x11u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8, 0x43u8, 0x03u8, 0x10u8];

		// Construct the data
		// Add the iv
		let mut bytes: Vec<u8> = iv.iter().cloned().collect();
		// Add the data
		let mut tmp = data.iter().cloned().collect();
		bytes.append(&mut tmp);
		// Add the salt
		tmp = salt.iter().cloned().collect();
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
}