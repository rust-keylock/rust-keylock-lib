use super::{ Entry, Props };
use super::datacrypt::{ Cryptor, BcryptAes };
use super::errors::{self, RustKeylockError};
use std::io::prelude::*;
#[cfg(not(target_os = "android"))]
use std::env;
use std::fs::{ self, File };
use std::path::PathBuf;
use toml::{ self, Table, Parser };

pub fn create_bcryptor(filename: &str, password: String, salt_position: usize, reinitialize_randoms: bool, use_default_location: bool) -> BcryptAes {
	debug!("Creating bcryptor");
	let full_path = if use_default_location {
		default_toml_path(filename)
	} else {
		toml_path(filename)
	};
	debug!("Full Path: {:?}", full_path);
    let (iv, salt) = {
    	match File::open(full_path) {
	        Ok(file) => {
	        	debug!("Encrypted file found. Extracting salt and iv");
	        	let bytes: Vec<_> = file.bytes().collect();

	        	// The iv is always in the start of the file
	        	// If the bytes are not more than 32 (iv+salt) it means that there is no data for entries
	        	let iv = if bytes.len() > 32 && !reinitialize_randoms {
	        		bytes.iter().take(16).map(|b_res| {
	        			match b_res {
	        				&Ok(b) => b.clone(),
	        				&Err(ref error) => panic!("Could not read from File {:?}", error),
	        			}
	        		}).collect()
	        	} else {
	        		super::datacrypt::create_random(16)
	        	};
	    		// The actual salt position is the one selected by the user, plus 16 bytes because the first 16 bytes is the iv
	        	let actual_salt_position = salt_position + 16;
	        	// If the bytes are not more than 32 (iv+salt) it means that there is no data for entries
			    let salt = if bytes.len() > 32 && !reinitialize_randoms && bytes.len() >= actual_salt_position {
			    	bytes.iter().skip(actual_salt_position).take(16).map(|b_res| {
	        			match b_res {
	        				&Ok(b) => b.clone(),
	        				&Err(ref error) => panic!("Could not read from File {:?}", error),
	        			}
	        		}).collect()
			    } else {
	        		super::datacrypt::create_random(16)
	        	};
	
				debug!("Salt and iv extracted");
			    (iv, salt)
	        },
	        Err(_) => {
	        	debug!("Encrypted file does not exist. Initializing salt and iv");
	        	let salt = super::datacrypt::create_random(16);
	        	let iv = super::datacrypt::create_random(16);
		       	(iv, salt)
	        },
	    }
    };
	// TODO: Take the cost from the configuration
	BcryptAes::new(password, salt, 3, iv, salt_position)
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

    let mut parser = Parser::new(toml.as_str());
    match parser.parse() {
    	Some(table) => transform_to_dtos(table, false),
    	None => Err(RustKeylockError::ParseError(format!("{:?}", parser.errors)))
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
		Ok(Props::empty())
	} else {
	    let mut parser = Parser::new(toml.as_str());
	    match parser.parse() {
	    	Some(table) => transform_to_props(table),
	    	None => Err(RustKeylockError::ParseError(format!("{:?}", parser.errors)))
	    }
	}
}

/// Attempts to recover a toml file
pub fn recover(filename: &str, cryptor: &Cryptor) -> Result<Vec<Entry>, RustKeylockError> {
	info!("Trying to recover {}", filename);
	let full_path = default_toml_path(filename);
	info!("Full path of file to recover {:?}", full_path);
    let toml = try!(load_existing_file(&full_path, Some(cryptor)));

    let mut parser = Parser::new(toml.as_str());
    match parser.parse() {
    	Some(table) => transform_to_dtos(table, true),
    	None => Err(RustKeylockError::ParseError(format!("{:?}", parser.errors)))
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
	let mut home_dir = match env::home_dir(){
		Some(pb) => pb,
		None => env::current_dir().unwrap(),
	};
    home_dir.push(".rust-keylock");
    home_dir
}

/// Transforms properties toml to Props dto
fn transform_to_props(table: Table) -> Result<Props, RustKeylockError> {
	Props::from_table(&table)
}

/// Transforms from toml Table which contains a List of Tables (entry) to a Vec<Entry>
/// If recover is true, then only the valid Entries are retrieved (no Error is returned if possible)
fn transform_to_dtos(table: Table, recover: bool) -> Result<Vec<Entry>, RustKeylockError> {
    match table.get("entry") {
    	Some(value) => {
    		match value.as_slice() {
    			Some(slice) => {
	    			let iter = slice.into_iter();
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
	    					},
	    				}
	    			}).collect();

	    			if vec.contains(&None) {
	    				if recover {
	    					Ok(vec.into_iter().filter(|opt| opt.is_some()).map(|opt| opt.unwrap()).collect())
	    				} else {
		    				Err(RustKeylockError::GeneralError("Failed because of previous errors (during mapping)".to_string()))
	    				}
	    			}
	    			else {
	    				Ok(vec.into_iter().map(|opt| opt.unwrap()).collect())
	    			}
	    		},
    			None => Err(RustKeylockError::ParseError("Entry shoud be a List of Tables".to_string())),
    		}
    	},
    	None => Ok(Vec::new()),
    }
}

/// Loads a file that contains a toml String and returns this String
fn load_existing_file<'a>(file_path: &PathBuf, cryptor_opt: Option<&Cryptor>) -> Result<String, RustKeylockError> {
	let bytes = {
		match File::open(file_path) {
			Ok(file) => {
				file.bytes().map(|b_res| {
					match b_res {
						Ok(b) => b.clone(),
						Err(error) => {
							error!("Could not read from File while loading {:?}", error);
							panic!("Could not read from File while loading {:?}", error)
						},
					}
				}).collect()
				
			},
	        Err(_) => {
	        	debug!("Encrypted file does not exist. Initializing...");
	        	assert!(fs::create_dir_all(default_rustkeylock_location()).is_ok());
	        	debug!("Directories created successfully");
				Vec::new()
	        },
		}
	};

	match cryptor_opt {
		Some(cryptor) => {
			if bytes.len() > 0 {
				debug!("Decrypting passwords file...");
				let dbytes = try!(cryptor.decrypt(&bytes));
				Ok(try!(String::from_utf8(dbytes)))
			} else {
				Ok("".to_string())
			}
		},
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
	let tables_vec = entries.iter().map(|entry| {
		toml::Value::Table(entry.to_table())
	}).collect();
	let mut table = Table::new();
	table.insert("entry".to_string(), toml::Value::Array(tables_vec));
    let toml_string = if entries.len() > 0 {
    	toml::encode_str(&table)
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
pub fn save_props(props: &Props, filename: &str) -> errors::Result<()> {
	info!("Saving Properties in {}", filename);
	let path_buf = default_toml_path(filename);
	let mut file = try!(File::create(path_buf));
	let table = props.to_table();
    let toml_string = toml::encode_str(&table);
    try!(file.write_all(toml_string.as_bytes()));
    info!("Properties saved in {}. Syncing...", filename);
    Ok(try!(file.sync_all()))
}

#[cfg(test)]
mod test_parser {
	use super::super::{Entry, Props};
	use super::super::datacrypt::NoCryptor;
    use std::io::prelude::*;
    use std::fs;
    use std::fs::File;
    use toml;

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
        assert!(super::save_props(&Props::new("alasalas".to_string()), filename).is_ok());

        let new_opt = super::load_properties(filename);
        assert!(new_opt.is_ok());
        let new_props = new_opt.unwrap();
        assert!(new_props.salt == "alasalas");
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

        let table = toml::Parser::new(toml).parse().unwrap();
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

        let table = toml::Parser::new(toml).parse().unwrap();
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

        let table = toml::Parser::new(toml).parse().unwrap();
        let res = super::transform_to_dtos(table, true);
        assert!(res.is_ok());
        let vec = res.unwrap();
        assert!(vec.len() == 1);
        assert!(vec[0].name == "name2");
        assert!(vec[0].user == "user2");
        assert!(vec[0].pass == "345");
        assert!(vec[0].desc == "other description");
    }

	// TODO: Why it fails when all tests are running, whereas it passes once it runs alone?
	#[test]
	fn create_encrypt_and_then_decrypt() {
		let filename = "create_encrypt_and_then_decrypt.toml";

		let salt_position = 0;
		let password = "123".to_string();

		let mut entries = Vec::new();
	    entries.push(Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()));

		let mut cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true);
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());
        cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true);

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
		let tmp_cryptor_import = super::create_bcryptor(filename_import, password_import.clone(), salt_position_import, false, false);
		assert!(super::save(&entries_import, filename_import, &tmp_cryptor_import, false).is_ok());

		// Create the normal file
		let filename = "create_encrypt_and_import.toml";
		let salt_position = 0;
		let password = "123".to_string();

		let mut entries = Vec::new();
		entries.push(Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()));
		let mut cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true);
		assert!(super::save(&entries, filename, &cryptor, true).is_ok());
        cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true);
        assert!(super::load(filename, &cryptor, true).is_ok());

		// Import the file by creating a new cryptor
		let cryptor_import = super::create_bcryptor(filename_import, password_import.clone(), salt_position_import, false, false);
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

		let cryptor = super::create_bcryptor(filename, password.clone(), salt_position, false, true);
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());

        let m = super::load(filename, &cryptor, true);
        assert!(entries == m.unwrap());
        assert!(super::save(&entries, filename, &cryptor, true).is_ok());

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
        let contents = r#"salt = "alas""#;
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

}
