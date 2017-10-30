use super::{Entry, Props};
use super::datacrypt::{Cryptor, BcryptAes};
use super::errors::{self, RustKeylockError};
use std::io::prelude::*;
#[cfg(not(target_os = "android"))]
use std::env;
use std::io;
use std::fs::{self, File};
use std::path::PathBuf;
use toml::value::{Table, Value};
use toml;

pub fn create_bcryptor(filename: &str,
                       password: String,
                       salt_position: usize,
                       reinitialize_randoms: bool,
                       use_default_location: bool)
                       -> Result<BcryptAes, io::Error> {
    debug!("Creating bcryptor");
    let full_path = if use_default_location {
        default_toml_path(filename)
    } else {
        toml_path(filename)
    };
    debug!("Full Path: {:?}", full_path);
    let (iv, salt, hash_bytes) = {
        match File::open(full_path) {
            Ok(mut file) => {
                debug!("Encrypted file found. Extracting salt, iv and hash");
                let mut bytes: Vec<_> = Vec::new();
                file.read_to_end(&mut bytes)?;

                // The iv is always in the start of the file
                // If the bytes are not more than 32 (iv:16 + salt:16) it means that there is no data for entries
                let iv = if bytes.len() > 32 && !reinitialize_randoms {
                    bytes.iter()
                        .take(16)
                        .map(|b| b.clone())
                        .collect()
                } else {
                    super::datacrypt::create_random(16)
                };
                // The actual salt position is the one selected by the user, plus 16 bytes because the first 16 bytes is the iv
                let actual_salt_position = salt_position + 16;
                // If the bytes are not more than 32 (iv:16 + salt:16) it means that there is no data for entries
                let salt = if bytes.len() > 32 && !reinitialize_randoms && bytes.len() >= actual_salt_position {
                    bytes.iter()
                        .skip(actual_salt_position)
                        .take(16)
                        .map(|b| b.clone())
                        .collect()
                } else {
                    super::datacrypt::create_random(16)
                };

                // The hash position is right after the actual salt position
                let hash_position = actual_salt_position + 16;
                // If the bytes are more than 96, use the salt position in order to infer the hash position
                let hash_bytes: Vec<u8> = if bytes.len() > 96 {
                    bytes.iter()
                        .skip(hash_position)
                        .take(64)
                        .map(|b| b.clone())
                        .collect()
                } else if bytes.len() == 96 {
                    // If the bytes are 96, it means that there are no user data.
                    // Thus, the hash is located right after the salt, which is in the position 16.
                    // Skip 16 bytes (iv), 16 bytes (salt) and take 64 bytes (hash)
                    bytes.iter()
                        .skip(32)
                        .take(64)
                        .map(|b| b.clone())
                        .collect()
                } else {
                    Vec::new()
                };
                debug!("Salt, iv and hash extracted");
                (iv, salt, hash_bytes)
            }
            Err(_) => {
                debug!("Encrypted file does not exist. Initializing salt and iv");
                let salt = super::datacrypt::create_random(16);
                let iv = super::datacrypt::create_random(16);
                (iv, salt, Vec::new())
            }
        }
    };
    // TODO: Take the cost from the configuration
    Ok(BcryptAes::new(password, salt, 3, iv, salt_position, hash_bytes))
}

/// Returns true if the passwords file exists in the Filesystem, flase otherwise
pub fn is_first_run(filename: &str) -> bool {
    let full_path = default_toml_path(filename);
    File::open(full_path).is_err()
}

/// Loads a toml file with the specified name
/// If the file does not exist, it is created.
pub fn load(filename: &str, cryptor: &Cryptor, use_default_location: bool) -> Result<Vec<Entry>, RustKeylockError> {
    debug!("Loading {}", filename);
    let full_path = if use_default_location {
        default_toml_path(filename)
    } else {
        toml_path(filename)
    };
    debug!("Full Path to load: {:?}", full_path);
    let toml = try!(load_existing_file(&full_path, Some(cryptor)));
    let value = try!(toml.as_str().parse::<Value>());

    match value.as_table() {
        Some(table) => transform_to_dtos(table, false),
        None => Err(RustKeylockError::ParseError("No Table found in the toml.".to_string())),
    }
}

/// Loads a toml file with the specified name
/// If the file does not exist, it is created.
pub fn load_properties(filename: &str) -> Result<Props, RustKeylockError> {
    debug!("Loading Properties from {}", filename);
    let full_path = default_toml_path(filename);
    debug!("Full Path to load properties from: {:?}", full_path);
    let toml = try!(load_existing_file(&full_path, None));

    if toml.len() == 0 {
        Ok(Props::default())
    } else {
        let value = try!(toml.as_str().parse::<Value>());
        match value.as_table() {
            Some(table) => transform_to_props(table),
            None => Err(RustKeylockError::ParseError("No Table found in the toml while loading properties.".to_string())),
        }
    }
}

/// Attempts to recover a toml file
pub fn recover(filename: &str, cryptor: &Cryptor) -> Result<Vec<Entry>, RustKeylockError> {
    info!("Trying to recover {}", filename);
    let full_path = default_toml_path(filename);
    info!("Full path of file to recover {:?}", full_path);
    let toml = try!(load_existing_file(&full_path, Some(cryptor)));

    let value = try!(toml.as_str().parse::<Value>());

    match value.as_table() {
        Some(table) => transform_to_dtos(table, true),
        None => Err(RustKeylockError::ParseError("No Table found in the toml while trying to recover.".to_string())),
    }
}

/// Returns a PathBuf representing the path of the default location of the toml file.
/// home/$USER/.rust-keylock/rk.toml
fn default_toml_path(filename: &str) -> PathBuf {
    let mut default_rustkeylock_location = default_rustkeylock_location();
    default_rustkeylock_location.push(filename);
    default_rustkeylock_location
}

/// Returns a PathBuf representing the path of a location for the toml file, as this is passed to the argument.
fn toml_path(filename: &str) -> PathBuf {
    PathBuf::from(filename)
}

#[cfg(target_os = "android")]
fn default_rustkeylock_location() -> PathBuf {
    let mut home_dir = PathBuf::from("/data/data/org.astonbitecode.rustkeylock/files");
    home_dir.push(".rust-keylock");
    home_dir
}

#[cfg(not(target_os = "android"))]
fn default_rustkeylock_location() -> PathBuf {
    let mut home_dir = match env::home_dir() {
        Some(pb) => pb,
        None => env::current_dir().unwrap(),
    };
    home_dir.push(".rust-keylock");
    home_dir
}

/// Transforms properties toml to Props dto
fn transform_to_props(table: &Table) -> Result<Props, RustKeylockError> {
    Props::from_table(table)
}

/// Transforms from toml Table which contains a List of Tables (entry) to a Vec<Entry>
/// If recover is true, then only the valid Entries are retrieved (no Error is returned if possible)
fn transform_to_dtos(table: &Table, recover: bool) -> Result<Vec<Entry>, RustKeylockError> {
    match table.get("entry") {
        Some(value) => {
            match value.as_array() {
                Some(array) => {
                    let iter = array.into_iter();
                    let vec: Vec<Option<Entry>> = iter.map(|value| {
                            let conversion_result = match value.as_table() {
                                Some(value_table) => Entry::from_table(value_table),
                                None => Err(RustKeylockError::ParseError("Entry value should be a table".to_string())),
                            };

                            match conversion_result {
                                Ok(entry) => Some(entry),
                                Err(error) => {
                                    if recover {
                                        error!("Error during parsing Entry: {}", error);
                                    }
                                    None
                                }
                            }
                        })
                        .collect();

                    if vec.contains(&None) {
                        if recover {
                            Ok(vec.into_iter().filter(|opt| opt.is_some()).map(|opt| opt.unwrap()).collect())
                        } else {
                            Err(RustKeylockError::GeneralError("Failed because of previous errors (during mapping)".to_string()))
                        }
                    } else {
                        Ok(vec.into_iter().map(|opt| opt.unwrap()).collect())
                    }
                }
                None => Err(RustKeylockError::ParseError("Entry shoud be a List of Tables".to_string())),
            }
        }
        None => Ok(Vec::new()),
    }
}

/// Loads a file that contains a toml String and returns this String
fn load_existing_file<'a>(file_path: &PathBuf, cryptor_opt: Option<&Cryptor>) -> Result<String, RustKeylockError> {
    let bytes = {
        match File::open(file_path) {
            Ok(file) => {
                file.bytes()
                    .map(|b_res| {
                        match b_res {
                            Ok(b) => b.clone(),
                            Err(error) => {
                                error!("Could not read from File while loading {:?}", error);
                                panic!("Could not read from File while loading {:?}", error)
                            }
                        }
                    })
                    .collect()
            }
            Err(_) => {
                debug!("Encrypted file does not exist. Initializing...");
                assert!(fs::create_dir_all(default_rustkeylock_location()).is_ok());
                debug!("Directories created successfully");
                Vec::new()
            }
        }
    };

    match cryptor_opt {
        Some(cryptor) => {
            if bytes.len() > 0 {
                debug!("Decrypting passwords file...");
                match cryptor.decrypt(&bytes) {
                    Ok(dbytes) => Ok(try!(String::from_utf8(dbytes))),
                    Err(errors::RustKeylockError::IntegrityError(dbytes)) => {
                        match String::from_utf8(dbytes) {
                            Ok(toml_string) => {
                                warn!("Temporarily ignoring integrity error in order to be able to upgrade from v0.2.1 to v.0.3.0");
                                Ok(toml_string)
                            }
                            Err(_) => Err(errors::RustKeylockError::IntegrityError(Vec::new())),
                        }
                    }
                    Err(other) => Err(other),
                }
            } else {
                Ok("".to_string())
            }
        }
        None => Ok(try!(String::from_utf8(bytes))),
    }
}

/// Saves the specified entries to a toml file with the specified name
pub fn save(entries: &Vec<Entry>, filename: &str, cryptor: &Cryptor, use_default_location: bool) -> errors::Result<()> {
    info!("Saving Entries in {}", filename);
    let path_buf = if use_default_location {
        default_toml_path(filename)
    } else {
        toml_path(filename)
    };
    let tables_vec = entries.iter()
        .map(|entry| Value::Table(entry.to_table()))
        .collect();
    let mut table = Table::new();
    table.insert("entry".to_string(), Value::Array(tables_vec));
    let toml_string = if entries.len() > 0 {
        try!(toml::ser::to_string(&table))
    } else {
        "".to_string()
    };

    let ebytes = try!(cryptor.encrypt(toml_string.as_bytes()));
    debug!("Encrypted entries");
    let mut file = try!(File::create(path_buf));
    try!(file.write_all(&ebytes));
    info!("Entries saved in {}. Syncing...", filename);
    Ok(try!(file.sync_all()))
}

/// Saves the specified Props to a toml file with the specified name
#[allow(dead_code)]
pub fn save_props(props: &Props, filename: &str) -> errors::Result<()> {
    info!("Saving Properties in {}", filename);
    let path_buf = default_toml_path(filename);
    let mut file = try!(File::create(path_buf));
    let table = props.to_table();
    let toml_string = try!(toml::ser::to_string(&table));
    try!(file.write_all(toml_string.as_bytes()));
    info!("Properties saved in {}. Syncing...", filename);
    Ok(try!(file.sync_all()))
}

#[cfg(test)]
mod test_parser {
    use super::super::{Entry, Props};
    use super::super::datacrypt::{self, NoCryptor, Cryptor};
    use std::io::prelude::*;
    use std::fs;
    use std::fs::File;
    use toml;
    use rand::{Rng, OsRng};
    use std::iter::repeat;
    use crypto::bcrypt::bcrypt;
    use crypto::{buffer, aes, aessafe};
    use crypto::blockmodes::CtrModeX8;
    use crypto::aes::KeySize;
    use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
    use crypto::symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher};
    use super::super::errors::RustKeylockError;
    use super::super::protected::RklSecret;

    #[test]
    fn use_existing_file() {
        let filename = "use_existing_file.toml";
        create_file_with_toml_contents(filename);

        let opt = super::load(filename, &NoCryptor::new(), true);
        assert!(opt.is_ok());
        delete_file(filename);
    }

    #[test]
    fn save_toml_to_file() {
        let filename = "save_toml_to_file.toml";
        create_file_with_toml_contents(filename);

        let opt = super::load(filename, &NoCryptor::new(), true);
        assert!(opt.is_ok());
        let mut vec = opt.unwrap();
        vec.push(Entry::new("name".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string()));
        assert!(super::save(&vec, filename, &NoCryptor::new(), true).is_ok());

        let new_opt = super::load(filename, &NoCryptor::new(), true);
        assert!(new_opt.is_ok());
        let new_vec = new_opt.unwrap();
        assert!(new_vec.contains(&Entry::new("name".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string())));
        delete_file(filename);
    }

    #[test]
    fn create_new_properties_file() {
        let filename = "create_new_properties_file.toml";
        let opt = super::load_properties(filename);
        assert!(opt.is_ok());
        let path_buf = super::default_toml_path(filename);
        let path = path_buf.to_str().unwrap();
        assert!(fs::remove_file(path).is_err());
    }

    #[test]
    fn use_existing_properties_file() {
        let filename = "use_existing_properties_file.toml";
        create_props_file_with_toml_contents(filename);

        let opt = super::load_properties(filename);
        assert!(opt.is_ok());
        delete_file(filename);
    }

    #[test]
    fn save_toml_to_properties_file() {
        let filename = "save_toml_to_properties_file.toml";
        create_props_file_with_toml_contents(filename);

        let opt = super::load_properties(filename);
        assert!(opt.is_ok());
        assert!(super::save_props(&Props::new(60), filename).is_ok());

        let new_opt = super::load_properties(filename);
        assert!(new_opt.is_ok());
        let new_props = new_opt.unwrap();
        assert!(new_props.idle_timeout_seconds == 60);
        delete_file(filename);
    }

    #[test]
    fn transform_to_dtos_success() {
        let toml = r#"
		[[entry]]
			name = "name1"
			user = "user1"
			pass = "123"
			desc = "some description"
		[[entry]]
			name = "name2"
			user = "user2"
			pass = "345"
			desc = "other description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let res = super::transform_to_dtos(table, false);
        assert!(res.is_ok());
        let vec = res.unwrap();
        assert!(vec.len() == 2);
        assert!(vec[0].name == "name1");
        assert!(vec[0].user == "user1");
        assert!(vec[0].pass == "123");
        assert!(vec[0].desc == "some description");
        assert!(vec[1].name == "name2");
        assert!(vec[1].user == "user2");
        assert!(vec[1].pass == "345");
        assert!(vec[1].desc == "other description");
    }

    #[test]
    fn transform_to_dtos_failure() {
        // missing password from entry 1
        let toml = r#"
		[[entry]]
			name = "name1"
			user = "user1"
			desc = "some description"
		[[entry]]
			name = "name2"
			user = "user2"
			pass = "345"
			desc = "other description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let res = super::transform_to_dtos(table, false);
        assert!(res.is_err());
    }

    #[test]
    fn transform_to_dtos_recover_success() {
        let toml = r#"
		[[entry]]
			name = "name1"
			user = "user1"
			desc = "some description"
		[[entry]]
			name = "name2"
			user = "user2"
			pass = "345"
			desc = "other description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let res = super::transform_to_dtos(table, true);
        assert!(res.is_ok());
        let vec = res.unwrap();
        assert!(vec.len() == 1);
        assert!(vec[0].name == "name2");
        assert!(vec[0].user == "user2");
        assert!(vec[0].pass == "345");
        assert!(vec[0].desc == "other description");
    }

    #[test]
    fn create_encrypt_and_then_decrypt() {
        let filename = "create_encrypt_and_then_decrypt.toml";

        let salt_position = 0;
        let password = "123".to_string();

        let mut entries = Vec::new();
        entries.push(Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()));

        let mut cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());
        cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();

        let m = super::load(filename, &cryptor, true);
        assert!(entries == m.unwrap());
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());

        delete_file(filename);
    }

    #[test]
    fn create_encrypt_and_import() {
        // Create the file to import
        let import_filename = "to_import.toml";
        let mut default_rustkeylock_dir_path_buf = super::default_rustkeylock_location();
        default_rustkeylock_dir_path_buf.push(import_filename);
        let filename_import = default_rustkeylock_dir_path_buf.to_str().unwrap();
        create_file_with_contents(filename_import, "");
        let salt_position_import = 0;
        let password_import = "333".to_string();

        let mut entries_import = Vec::new();
        entries_import.push(Entry::new("1_import".to_string(), "1_import".to_string(), "1_import".to_string(), "1_import".to_string()));
        let tmp_cryptor_import = super::create_bcryptor(filename_import, password_import.clone(), salt_position_import, false, false)
            .unwrap();
        assert!(super::save(&entries_import, filename_import, &tmp_cryptor_import, false).is_ok());

        // Create the normal file
        let filename = "create_encrypt_and_import.toml";
        let salt_position = 0;
        let password = "123".to_string();

        let mut entries = Vec::new();
        entries.push(Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()));
        let mut cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());
        cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();
        assert!(super::load(filename, &cryptor, true).is_ok());

        // Import the file by creating a new cryptor
        let cryptor_import = super::create_bcryptor(filename_import, password_import.clone(), salt_position_import, false, false).unwrap();
        assert!(super::load(filename_import, &cryptor_import, false).is_ok());

        delete_file(filename);
        delete_file(import_filename);
    }

    #[test]
    fn create_encrypt_and_then_decrypt_no_data() {
        let filename = "create_encrypt_and_then_decrypt_no_real_data.toml";

        let salt_position = 33;
        let password = "123".to_string();

        let entries = Vec::new();

        let mut cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());

        cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();

        let m = super::load(filename, &cryptor, true);
        assert!(entries == m.unwrap());
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());

        delete_file(filename);
    }

    #[test]
    fn create_v_0_2_1_encrypt_and_then_decrypt_with_v_0_3_0() {
        let filename = "v_0_2_1_encrypt_to_v_0_3_0.toml";

        let salt_position = 33;
        let password = "123".to_string();

        let entries = Vec::new();

        // Create a v0.2.1 cryptor
        let old_cryptor = CryptorV021::new(password.clone(), datacrypt::create_random(16), 3, datacrypt::create_random(16), salt_position);
        assert!(super::save(&entries, filename, &old_cryptor, true).is_ok());
        let new_cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();

        let m = super::load(filename, &new_cryptor, true);
        assert!(entries == m.unwrap());
        assert!(super::save(&entries, filename, &new_cryptor, true).is_ok());

        delete_file(filename);
    }

	#[test]
    fn integrity_error() {
        let filename = "integrity_error.toml";

        let salt_position = 33;
        let password = "123".to_string();

        let entries = vec![Entry::new("name".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string())];

		// Create a bcryptor
        let cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true).unwrap();
        // Saving will change the hash, so reading with the same cryptor should result to an integrity error
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());

        let result = super::load(filename, &cryptor, true);

        assert!(result.is_err());
        match result.err() {
            Some(super::super::errors::RustKeylockError::IntegrityError(_)) => assert!(true),
            _ => assert!(false),
        }

        delete_file(filename);
    }

    #[test]
    fn toml_path() {
        let filename = "/opt/data/my_toml.toml";
        let pb = super::toml_path(filename);
        assert!(pb.to_str().is_some());
        assert!(pb.to_str().unwrap() == filename);
    }

    fn create_file_with_toml_contents(name: &str) {
        // Create the file with some toml contents
        let contents = r#"
        [[entry]]
			name = "name"
			user = "user"
			pass = "123"
			desc = "some description"
        "#;
        create_file_with_contents(name, contents);
    }

    fn create_props_file_with_toml_contents(name: &str) {
        // Create the file with some toml contents
        let contents = r#"idle_timeout_seconds = 33"#;
        create_file_with_contents(name, contents);
    }

    fn create_file_with_contents(filename: &str, contents: &str) {
        let default_rustkeylock_dir_path_buf = super::default_rustkeylock_location();
        let default_rustkeylock_dir = default_rustkeylock_dir_path_buf.to_str().unwrap();
        let creation_result = fs::create_dir_all(default_rustkeylock_dir).map(|_| {
            let path_buf = super::default_toml_path(filename);
            let path = path_buf.to_str().unwrap();
            let mut file = File::create(path).unwrap();
            assert!(file.write_all(contents.as_bytes()).is_ok());
        });
        assert!(creation_result.is_ok());
    }

    fn delete_file(name: &str) {
        let path_buf = super::default_toml_path(name);
        let path = path_buf.to_str().unwrap();
        assert!(fs::remove_file(path).is_ok());
    }

    #[derive(Debug, PartialEq)]
    pub struct CryptorV021 {
        key: RklSecret,
        iv: Vec<u8>,
        salt_position: usize,
        salt_key_pairs: Vec<(Vec<u8>, RklSecret)>,
    }

    impl CryptorV021 {
        fn create_new_bcrypt_key(password: &str, salt: &[u8], cost: u32) -> Vec<u8> {
            let mut key: Vec<u8> = repeat(0u8).take(24).collect();
            bcrypt(cost, &salt, password.as_bytes(), &mut key);
            key
        }

        pub fn new(password: String, salt: Vec<u8>, cost: u32, iv: Vec<u8>, salt_position: usize) -> CryptorV021 {
            // Create bcrypt password for the current encrypted data
            let key = CryptorV021::create_new_bcrypt_key(&password, &salt, cost);

            // Create 10 new salt-key pairs to use them for encryption
            let mut salt_key_pairs = Vec::new();
            for _ in 0..3 {
                let s = datacrypt::create_random(16);
                let k = CryptorV021::create_new_bcrypt_key(&password, &s, cost);
                salt_key_pairs.push((s, RklSecret::new(k)));
            }

            CryptorV021 {
                key: RklSecret::new(key),
                iv: iv,
                salt_position: salt_position,
                salt_key_pairs: salt_key_pairs,
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

    impl Cryptor for CryptorV021 {
        fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, RustKeylockError> {
            let bytes_to_decrypt = extract_bytes_to_decrypt(input, self.salt_position);

            // Code taken from the rust-crypto example
            let mut final_result = Vec::<u8>::new();
            {
                let mut decryptor = Self::ctr(aes::KeySize::KeySize256, &self.key.borrow(), &self.iv);

                let mut read_buffer = buffer::RefReadBuffer::new(&bytes_to_decrypt);
                let mut buffer = [0; 4096];
                let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

                loop {
                    let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
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
            // Create a new iv
            let iv = datacrypt::create_random(16);
            // Choose randomly one of the salt-key pairs
            let idx = {
                let mut rng = OsRng::new().ok().unwrap();
                rng.gen_range::<usize>(0, 3)
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
                    let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

                    encryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

                    match result {
                        BufferResult::BufferUnderflow => break,
                        BufferResult::BufferOverflow => {}
                    }
                }
                // Compose the encrypted bytes with the iv and salt
                compose_bytes_to_save(&encryption_result, self.salt_position, &salt_key_pair.0, &iv)
            };

            Ok(bytes_to_save)
        }
    }

    fn compose_bytes_to_save(data: &[u8], salt_position: usize, salt: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut bytes_to_save: Vec<u8> = Vec::new();

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

}
