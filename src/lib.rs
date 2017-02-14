//!# The _rust-keylock_ library
//!
//!Executes the logic of the _rust-keylock_.
//!
//!This library is the executor of the _rust-keylock_ logic. `Editor` references are used to interact with the _rust-keylock_ users.
//!
//!## How it works
//!
//!The library implements the functionality where a User stores password `Entries` in an encrypted toml file.
//!Currently, __AES__ with __CTR__ is used and the encryption key is generated with __Bcrypt__, but more choices can be implemented in the future.
//!
//!The _iv_ that is used for encyption/decryption and the _salt_ for the generation of the encryption key are stored along with the rest of the encrypted data bytes in the same file.
//!
//!The 16-byte _iv_ is always in the start of the file.
//!
//!The 16 bytes of _salt_ are merged along with the encrypted actual data.
//!The position of the _salt_ is actually defined by the user. Upon _rust-keylock_ initialization, the user sets up two things:
//!
//!* A _master password_, which is combined with an initially pseudo-randomly generated 16-bytes array, the _salt_, in order to create the `Bcrypt` key that is used for the data encryption/decryption.
//!* A _number_,  which is the actual location of the salt among the encrypted data.
//!
//!Having the salt inbetween the actual encrypted data gives two obvious benefits:
//!
//!1. Makes the encrypted file portable
//!
//! All the information that is needed for encryption/decryption is in the file itself. Nothing additional is needed. Therefore, the encrypted file can just be copied in some location to be backed-up, or even be synchronized in other devices and be used there as well.
//!
//!1. Increases the security of the encryption
//!
//! The actual data bytes are "interrupted" by the salt and this potentially makes an adversary's job more difficult; more difficult to infer things about the data contents or the encryption key.
//!
//!## A concrete example
//!
//!Let's assume that the user has set his _master password_ and the number __3__ as the _additional number_ to the password.
//!
//!Let's also assume that the actual password `Entries` data gets encrypted as the following byte array:
//!`0x11u8, 0x12u8, 0x13u8, 0x14u8, 0x15u8, 0x16u8, 0x17u8, 0x18u8, 0x19u8, 0x20u8, 0x21u8, 0x22u8, 0x23u8, 0x24u8, 0x25u8, 0x26u8, 0x27u8, 0x28u8, 0x29u8, 0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8, 0x40u8, 0x41u8, 0x42u8`
//!
//!Upon saving to the file, the _rust-keylock_ will generate two pseudo-random byte arrays; one to be the _iv_ and one to be the _salt_.
//!Let the _iv_ be `0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8`.
//!
//!Let the _salt_ be `0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8`.
//!
//!All that makes the actual bytes that are saved in the file to be:
//!
//!1. The _iv_
//!1. Three bytes of real encrypted data
//!1. The _salt_
//!1. The rest of the real encrypted data bytes
//!
//!Thus, the saved data should be looking like following:
//!
//!`0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x01u8, 0x11u8, 0x12u8, 0x13u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x02u8, 0x14u8, 0x15u8, 0x16u8, 0x17u8, 0x18u8, 0x19u8, 0x20u8, 0x21u8, 0x22u8, 0x23u8, 0x24u8, 0x25u8, 0x26u8, 0x27u8, 0x28u8, 0x29u8, 0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8, 0x40u8, 0x41u8, 0x42u8`
//!
//!

#[macro_use]
extern crate log;
extern crate toml;
extern crate crypto;
extern crate rustc_serialize;
extern crate rand;

use toml::Table;
use std::error::Error;

mod file_handler;
mod errors;
pub mod datacrypt;

///Takes a reference of `Editor` implementation as argument and executes the _rust-keylock_ logic.
///The `Editor` is responsible for the interaction with the user. Currently there are `Editor` implementations for __shell__ and for __Android__.
pub fn execute<T: Editor>(editor: &T) {
	info!("Starting rust-keylock...");

	let filename = ".sec";
	let props_filename = ".props";
	let mut user_selection;

	let _ = match file_handler::load_properties(props_filename) {
		Ok(m) => {
			if m.salt.len() == 0 {
				let new_props = Props::new("tmp".to_string());
				assert!(file_handler::save_props(&new_props, props_filename).is_ok());
				new_props
			} else {
				m
			}
		},
		Err(error) => panic!("Could not load properties: {}", error.description()),
	};

	let mut entries;
	let mut contents_changed = false;

	let mut cryptor = {
		let provided_password = if file_handler::is_first_run(filename) {
			editor.show_change_password()
		}
		else {
			editor.show_password_enter()
		};
		match provided_password {
			UserSelection::ProvidedPassword(pwd, salt_pos) => {
				let cr = file_handler::create_bcryptor(filename, pwd, salt_pos, false, true);
				let retrieved_entries = match file_handler::load(filename, &cr, true) {
					Ok(ents) => {
						user_selection = UserSelection::GoTo(Menu::Main);
						ents
					},
					Err(error) => {
						debug!("{}", error.description());
						user_selection = UserSelection::GoTo(Menu::TryFileRecovery);
						Vec::new()
					},
				};
				entries = retrieved_entries;
				debug!("Retrieved entries. Returning {:?} with {} entries ", &user_selection, &entries.len());
				cr
			},
			_ => panic!("Wrong initialization sequence... The editor.show_password_enter must always return a UserSelection::ProvidedPassword. Please, consider opening a bug to the developers."),
		}
	};

	loop {
		editor.sort_entries(&mut entries);
		user_selection = match user_selection {
			UserSelection::GoTo(Menu::Main) => {
				debug!("UserSelection::GoTo(Menu::Main)");
				let m = editor.show_menu(&Menu::Main, &entries);
				debug!("UserSelection::GoTo(Menu::Main) returns {:?}", &m);
				m
			},
			UserSelection::GoTo(Menu::ChangePass) => {
				debug!("UserSelection::GoTo(Menu::ChangePass)");
				contents_changed = true;
				editor.show_change_password()
			},
			UserSelection::ProvidedPassword(pwd, salt_pos) => {
				debug!("UserSelection::GoTo(Menu::ProvidedPassword)");
				cryptor = file_handler::create_bcryptor(filename, pwd, salt_pos, true, true);
				UserSelection::GoTo(Menu::Main)
			},
			UserSelection::GoTo(Menu::EntriesList) => {
				debug!("UserSelection::GoTo(Menu::EntriesList)");
				editor.show_menu(&Menu::EntriesList, &entries)
			},
			UserSelection::GoTo(Menu::NewEntry) => {
				debug!("UserSelection::GoTo(Menu::NewEntry)");
				editor.show_menu(&Menu::NewEntry, &entries)
			},
			UserSelection::GoTo(Menu::ShowEntry(index)) => {
				debug!("UserSelection::GoTo(Menu::ShowEntry(index))");
				editor.show_menu(&Menu::ShowEntry(index), &entries)
			},
			UserSelection::GoTo(Menu::EditEntry(index)) => {
				debug!("UserSelection::GoTo(Menu::EditEntry(index))");
				editor.show_menu(&Menu::EditEntry(index), &entries)
			},
			UserSelection::GoTo(Menu::DeleteEntry(index)) => {
				debug!("UserSelection::GoTo(Menu::DeleteEntry(index))");
				editor.show_menu(&Menu::DeleteEntry(index), &entries)
			},
			UserSelection::GoTo(Menu::Save) => {
				debug!("UserSelection::GoTo(Menu::Save)");
				match file_handler::save(&entries, filename, &cryptor, true) {
					Ok(_) => {
						contents_changed = false;
						let _ = editor.show_message("Encrypted and saved successfully!");
					},
					Err(error) => {
						let _ = editor.show_message("Could not save...");
						error!("Could not save... {:?}", error);
					},
				};
				UserSelection::GoTo(Menu::Main)
			},
			UserSelection::GoTo(Menu::Exit) => {
				debug!("UserSelection::GoTo(Menu::Exit)");
				editor.exit(contents_changed)
			},
			UserSelection::GoTo(Menu::ForceExit) => {
				debug!("UserSelection::GoTo(Menu::ForceExit)");
				break
			},
			UserSelection::NewEntry(entry) => {
				debug!("UserSelection::NewEntry(entry)");
				entries.push(entry);
				contents_changed = true;
				UserSelection::GoTo(Menu::EntriesList)
			},
			UserSelection::ReplaceEntry(index, entry) => {
				debug!("UserSelection::ReplaceEntry(index, entry)");
				entries.push(entry);
				contents_changed = true;
				entries.swap_remove(index);
				UserSelection::GoTo(Menu::EntriesList)
			},
			UserSelection::DeleteEntry(index) => {
				debug!("UserSelection::DeleteEntry(index)");
				entries.remove(index);
				contents_changed = true;
				UserSelection::GoTo(Menu::EntriesList)
			},
			UserSelection::GoTo(Menu::TryFileRecovery) => {
				debug!("UserSelection::GoTo(Menu::TryFileRecovery)");
				let _ = editor.show_message("The password entries are corrupted.\n\nPress Enter to attempt recovery...");
				entries = file_handler::recover(filename, &cryptor).unwrap();
				let message = r#"
Recovery succeeded...

Note the errors that caused the recovery. You may see some useful information about possible values that could not be recovered.
Press Enter to show the Recovered Entries and if you are ok with it, save them.

Warning: Saving will discard all the entries that could not be recovered.
"#;
				let _ = editor.show_message(message);
				contents_changed = true;
				UserSelection::GoTo(Menu::EntriesList)
			},
			UserSelection::GoTo(Menu::ExportEntries) => {
				debug!("UserSelection::GoTo(Menu::ExportEntries)");
				editor.show_menu(&Menu::ExportEntries, &entries)
			}
			UserSelection::ExportTo(path) => {
				debug!("UserSelection::ExportTo(path)");
				match file_handler::save(&entries, &path, &cryptor, false) {
					Ok(_) => {
						let _ = editor.show_message("Export completed successfully!");
					},
					Err(error) => {
						let _ = editor.show_message("Could not export...");
						error!("Could not export... {:?}", error);
					},
				};
				UserSelection::GoTo(Menu::Main)
			}
			UserSelection::GoTo(Menu::ImportEntries) => {
				debug!("UserSelection::GoTo(Menu::ImportEntries)");
				editor.show_menu(&Menu::ImportEntries, &entries)
			}
			UserSelection::ImportFrom(path, pwd, salt_pos) => {
				let cr = file_handler::create_bcryptor(&path, pwd, salt_pos, false, false);
				debug!("UserSelection::ImportFrom(path, pwd, salt_pos)");
				match file_handler::load(&path, &cr, false) {
					Ok(ents) => {
						debug!("Imported {} entries ", &ents.len());
						contents_changed = true;
						merge(&mut entries, ents);
						let _ = editor.show_message("Passwords were successfully imported!");
					},
					Err(error) => {
						let _ = editor.show_message("Could not import...");
						error!("Could not import... {:?}", error);
					},
				};
				UserSelection::GoTo(Menu::Main)
			}
			other => {
				let message = format!("Bug: User Selection '{:?}' should not be handled in the main loop. Please, consider opening a bug to the developers.", &other);
				debug!("{}", message);
				panic!(message)
			},
		}
	}
	info!("Exiting rust-keylock...");
}

/// Merges the main Entries Vector with an incoming one, by appending the incoming elements that are not the same with some existing one in the main
fn merge(main: &mut Vec<Entry>, incoming: Vec<Entry>) {
	let mut to_add = {
		incoming.into_iter().filter(|entry| {
			let mut main_iter = main.clone().into_iter();
			let opt = main_iter.find(|main_entry| {
					main_entry == entry
			});

			opt.is_none()
		}).collect()
	};

	main.append(&mut to_add);
}

/// Struct that defines a password entry.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Entry {
	///The name of the Entry
	///
	///It is used as a label to distinguish among other Entries
    pub name: String,
    ///The username
    pub user: String,
    ///The password
    pub pass: String,
    ///A description of the `Entry`
    pub desc: String,
}

impl Entry {
	///Creates a new `Entry` using the provided name, username, password and description
    pub fn new(name: String, user: String, pass: String, desc: String) -> Entry {
        Entry {
            name: name,
            user: user,
            pass: pass,
            desc: desc,
        }
    }

	///Creates an empty `Entry`
    pub fn empty() -> Entry {
        Entry {
            name: "".to_string(),
            user: "".to_string(),
            pass: "".to_string(),
            desc: "".to_string(),
        }
    }

    fn from_table(table: &Table) -> Result<Entry, errors::RustKeylockError> {
        let name = table.get("name").and_then(|value| {
        		value.as_str().and_then(|str_ref| {
        				Some(str_ref.to_string())
        		})
        });
        let user = table.get("user").and_then(|value| {
        		value.as_str().and_then(|str_ref| {
        				Some(str_ref.to_string())
        		})
        });
        let pass = table.get("pass").and_then(|value| {
        		value.as_str().and_then(|str_ref| {
        				Some(str_ref.to_string())
        		})
        });
        let desc = table.get("desc").and_then(|value| {
        		value.as_str().and_then(|str_ref| {
        				Some(str_ref.to_string())
        		})
        });

        match (name, user, pass, desc) {
            (Some(n), Some(u), Some(p), Some(d)) => {
            	Ok(Self::new(n, u, p, d))
            },
            _ => Err(errors::RustKeylockError::ParseError(toml::encode_str(&table).to_string())),
        }
    }

	fn to_table(&self) -> Table {
		let mut table = Table::new();
		table.insert("name".to_string(), toml::Value::String(self.name.clone()));
		table.insert("user".to_string(), toml::Value::String(self.user.clone()));
		table.insert("pass".to_string(), toml::Value::String(self.pass.clone()));
		table.insert("desc".to_string(), toml::Value::String(self.desc.clone()));

		table
	}
}

///A struct that allows storing general configuration values.
///
///The functionality is not currently used, as it turns out that no additional configuration is needed for the _rust-keylock_.
///However, it may be used in the future.
///
///The configuration values are stored in plaintext.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Props {
    salt: String,
}

impl Props {
    fn new(salt: String) -> Props {
        Props {
            salt: salt,
        }
    }

	fn empty() -> Props {
        Props {
            salt: "".to_string(),
        }
    }

    fn from_table(table: &Table) -> Result<Props, errors::RustKeylockError> {
        let salt = table.get("salt").and_then(|value| {
        		value.as_str().and_then(|str_ref| {
        				Some(str_ref.to_string())
        		})
        });

        match salt {
            Some(s) => {
            	Ok(Self::new(s))
            },
            _ => Err(errors::RustKeylockError::ParseError(toml::encode_str(&table).to_string())),
        }
    }

	fn to_table(&self) -> Table {
		let mut table = Table::new();
		table.insert("salt".to_string(), toml::Value::String(self.salt.clone()));

		table
	}
}

///Enumeration of the several different Menus that an `Editor` implementation should handle.
#[derive(Debug, PartialEq)]
pub enum Menu {
	///The User should provide a password and a number.
	TryPass,
	///The User should provide a new password and a new number.
	ChangePass,
	///The User should be presented with the main menu.
	Main,
	///The User should be presented with a list of all the saved password `Entries`.
	EntriesList,
	///The User should create a new `Entry`
	NewEntry,
	///The User should be presented with a selected `Entry`.
	///
	///The index of the `Entry` inside the `Entries` list is provided.
	ShowEntry(usize),
	///The User should edit a selected `Entry`.
	///
	///The index of the `Entry` inside the `Entries` list is provided.
	EditEntry(usize),
	///The User deletes a selected `Entry`.
	///
	///The index of the `Entry` inside the `Entries` list is provided.
	DeleteEntry(usize),
	///The User encrypts and saves all the existing `Entries` list.
	Save,
	///The User selects to Exit _rust-keylock_
	Exit,
	///The User selects to Exit _rust-keylock_, even if there is unsaved data.
	ForceExit,
	///Parsing the `Entries` _after_ decrypting them may lead to wrong data. This Menu informs the User about the situation and offers an attempt to recover anything that is recoverable.
	TryFileRecovery,
	///The user should be able to import password `Entries`.
	ImportEntries,
	///The user should be able to export password `Entries`.
	ExportEntries,
}

impl Menu {
	///Returns the name of a `Menu`.
	pub fn get_name(&self) -> String {
		match self {
			&Menu::TryPass => format!("{:?}", Menu::TryPass),
			&Menu::ChangePass => format!("{:?}", Menu::ChangePass),
			&Menu::Main => format!("{:?}", Menu::Main),
			&Menu::EntriesList => format!("{:?}", Menu::EntriesList),
			&Menu::NewEntry => format!("{:?}", Menu::NewEntry),
			&Menu::ShowEntry(_) => "ShowEntry".to_string(),
			&Menu::EditEntry(_) => "EditEntry".to_string(),
			&Menu::DeleteEntry(_) => "DeleteEntry".to_string(),
			&Menu::Save => format!("{:?}", Menu::Save),
			&Menu::Exit => format!("{:?}", Menu::Exit),
			&Menu::ForceExit => format!("{:?}", Menu::ForceExit),
			&Menu::TryFileRecovery => format!("{:?}", Menu::TryFileRecovery),
			&Menu::ImportEntries => format!("{:?}", Menu::ImportEntries),
			&Menu::ExportEntries => format!("{:?}", Menu::ExportEntries),
		}
	}

	///Parses a String and creates a `Menu`.
	///
	///Menus that have additional `usize` arguments exist. Thus the existence of the `Option`al argument during parsing.
	pub fn from(name: String, opt: Option<usize>) -> Menu {
		debug!("Creating Menu from name {} and additional argument {:?}", &name, &opt);
		match (name, opt) {
			(ref n, None) if &Menu::TryPass.get_name() == n => Menu::TryPass,
			(ref n, None) if &Menu::ChangePass.get_name() == n => Menu::ChangePass,
			(ref n, None) if &Menu::Main.get_name() == n => Menu::Main,
			(ref n, None) if &Menu::EntriesList.get_name() == n => Menu::EntriesList,
			(ref n, None) if &Menu::NewEntry.get_name() == n => Menu::NewEntry,
			(ref n, Some(arg)) if &Menu::ShowEntry(arg).get_name() == n => Menu::ShowEntry(arg),
			(ref n, Some(arg)) if &Menu::EditEntry(arg).get_name() == n => Menu::EditEntry(arg),
			(ref n, Some(arg)) if &Menu::DeleteEntry(arg).get_name() == n => Menu::DeleteEntry(arg),
			(ref n, None) if &Menu::Save.get_name() == n => Menu::Save,
			(ref n, None) if &Menu::Exit.get_name() == n => Menu::Exit,
			(ref n, None) if &Menu::ForceExit.get_name() == n => Menu::ForceExit,
			(ref n, None) if &Menu::TryFileRecovery.get_name() == n => Menu::TryFileRecovery,
			(ref n, None) if &Menu::ImportEntries.get_name() == n => Menu::ImportEntries,
			(ref n, None) if &Menu::ExportEntries.get_name() == n => Menu::ExportEntries,
			(ref other, opt) => {
				let message = format!("Cannot create Menu from String '{}' and argument '{:?}'. Please, consider opening a bug to the developers.", other, opt);
				error!("{}", message);
				panic!(message);
			},
		}
	}
}

/// Represents a User selection that is returned after showing a `Menu`.
#[derive(Debug)]
pub enum UserSelection {
	///The User selected an `Entry`.
	NewEntry(Entry),
	///The User updated an `Entry`.
	ReplaceEntry(usize, Entry),
	///The User deleted an `Entry`.
	DeleteEntry(usize),
	///The User selected to go to a `Menu`.
	GoTo(Menu),
	///The User provided a password and a number.
	ProvidedPassword(String, usize),
	///The User acknowledges something.
	Ack,
	///The User selected to export the password `Entries` to a path.
	ExportTo(String),
	///The User selected to import the password `Entries` from a path.
	ImportFrom(String, String, usize),
}

///Trait to be implemented by various different `Editor`s (Shell, Web, Android, other...).
///
///It drives the interaction with the Users
pub trait Editor {
	///Shows the interface for entering a Password and a Number.
	fn show_password_enter(&self) -> UserSelection;
	///Shows the interface for changing a Password and/or a Number.
	fn show_change_password(&self) -> UserSelection;
	///Shows the specified `Menu` to the User.
	fn show_menu(&self, menu: &Menu, entries: &[Entry]) -> UserSelection;
	///Shows the Exit `Menu` to the User.
	fn exit(&self, contents_changed: bool) -> UserSelection;
	///Shows a message to the User.
	fn show_message(&self, message: &'static str) -> UserSelection;

	///Sorts the supplied entries.
	fn sort_entries(&self, entries: &mut [Entry]) {
		entries.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
	}
}

#[cfg(test)]
mod unit_tests {
    use toml;
    use super::{Menu, Entry};

    #[test]
    fn entry_from_table_success() {
        let toml = r#"
			name = "name1"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_ok());
        let entry = entry_opt.unwrap();
        assert!(entry.name == "name1");
        assert!(entry.user == "user1");
        assert!(entry.pass == "123");
        assert!(entry.desc == "some description");
    }

    #[test]
    fn entry_from_table_failure_wrong_key() {
        let toml = r#"
			wrong_key = "name1"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_err());
    }

	#[test]
    fn entry_from_table_failure_wrong_value() {
        let toml = r#"
			name = 1
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_err());
    }

	#[test]
    fn entry_to_table() {
        let toml = r#"
			name = "name1"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_ok());
        let entry = entry_opt.unwrap();
        let new_table = entry.to_table();
        assert!(table == new_table);
    }

	#[test]
    fn props_from_table_success() {
        let toml = r#"salt = "alas""#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_ok());
        let props = props_opt.unwrap();
        assert!(props.salt == "alas");
    }

	#[test]
    fn props_from_table_failure_wrong_key() {
        let toml = r#"wrong_key = "alas""#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_err());
    }

	#[test]
    fn props_from_table_failure_wrong_value() {
        let toml = r#"salt = 1"#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_err());
    }

	#[test]
    fn props_to_table() {
        let toml = r#"salt = "alas""#;

        let table = toml::Parser::new(toml).parse().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_ok());
        let props = props_opt.unwrap();
        let new_table = props.to_table();
        assert!(table == new_table);
    }

	#[test]
	fn menu_get_name() {
		let m1 = Menu::TryPass.get_name();
		assert!(m1 == "TryPass");
		let m2 = Menu::EntriesList.get_name();
		assert!(m2 == "EntriesList");
		let m3 = Menu::EditEntry(33).get_name();
		assert!(m3 == "EditEntry");
	}

	#[test]
	fn menu_from_name() {
		let m1 = Menu::from("TryPass".to_string(), None);
		assert!(m1 == Menu::TryPass);
		let m2 = Menu::from("EntriesList".to_string(), None);
		assert!(m2 == Menu::EntriesList);
		let m3 = Menu::from("ShowEntry".to_string(), Some(1));
		assert!(m3 == Menu::ShowEntry(1));
	}

	#[test]
	fn merge_entries() {
		let mut all = vec![
			Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()),
			Entry::new("2".to_string(), "2".to_string(), "2".to_string(), "2".to_string()),
		];

		// This one should be added
		let first = vec![Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string())];
		super::merge(&mut all, first);
		assert!(all.len() == 3);

		// This one should not be added
		let second = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string())];
		super::merge(&mut all, second);
		assert!(all.len() == 3);

		// This one should not be added either (the description is not the same with any of the existing ones
		let third = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "3".to_string())];
		super::merge(&mut all, third);
		assert!(all.len() == 4);
	}
}
