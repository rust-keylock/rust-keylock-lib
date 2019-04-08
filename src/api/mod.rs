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

use std::iter::FromIterator;
use std::time::{SystemTime, UNIX_EPOCH};

use log::*;
use toml;
use toml::value::Table;

use super::{asynch, datacrypt, errors, nextcloud};

use self::safe::Safe;

pub mod safe;

/// Struct to use for retrieving and saving data from/to the file
pub struct RklContent {
    pub entries: Vec<Entry>,
    pub nextcloud_conf: asynch::nextcloud::NextcloudConfiguration,
    pub system_conf: SystemConfiguration,
}

impl RklContent {
    pub fn new(entries: Vec<Entry>,
               nextcloud_conf: asynch::nextcloud::NextcloudConfiguration,
               system_conf: SystemConfiguration)
               -> RklContent {
        RklContent {
            entries,
            nextcloud_conf,
            system_conf,
        }
    }

    pub fn from(tup: (&Safe, &asynch::nextcloud::NextcloudConfiguration, &SystemConfiguration)) -> errors::Result<RklContent> {
        let entries = tup.0.get_entries_decrypted();
        let nextcloud_conf = asynch::nextcloud::NextcloudConfiguration::new(tup.1.server_url.clone(),
                                                                            tup.1.username.clone(),
                                                                            tup.1.decrypted_password()?,
                                                                            tup.1.use_self_signed_certificate);
        let system_conf = SystemConfiguration::new(tup.2.saved_at, tup.2.version, tup.2.last_sync_version);

        Ok(RklContent::new(entries, nextcloud_conf?, system_conf))
    }
}

/// Keeps the Configuration
#[derive(Debug, PartialEq, Clone)]
pub struct RklConfiguration {
    pub system: SystemConfiguration,
    pub nextcloud: asynch::nextcloud::NextcloudConfiguration,
}

impl RklConfiguration {
    pub fn update_system_for_save(&mut self, update_last_sync_version: bool) -> errors::Result<()> {
        if update_last_sync_version {
            self.update_system_last_sync();
        } else {
            self.system.version = Some((self.system.version.unwrap_or(0)) + 1);
        }
        let local_time_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.system.saved_at = Some(local_time_seconds as i64);
        Ok(())
    }

    pub fn update_system_last_sync(&mut self) {
        self.system.last_sync_version = self.system.version;
    }
}

impl From<(asynch::nextcloud::NextcloudConfiguration, SystemConfiguration)> for RklConfiguration {
    fn from(confs: (asynch::nextcloud::NextcloudConfiguration, SystemConfiguration)) -> Self {
        RklConfiguration {
            system: confs.1,
            nextcloud: confs.0,
        }
    }
}

/// System - internal configuration
#[derive(Debug, PartialEq, Clone)]
pub struct SystemConfiguration {
    /// When the passwords were saved
    pub saved_at: Option<i64>,
    /// A number that gets incremented with each persisted change
    pub version: Option<i64>,
    /// The version that was set upon the last sync. This is the same with the version once the data is uploaded to the server
    pub last_sync_version: Option<i64>,
}

impl SystemConfiguration {
    pub fn new(saved_at: Option<i64>, version: Option<i64>, last_sync_version: Option<i64>) -> SystemConfiguration {
        SystemConfiguration {
            saved_at,
            version,
            last_sync_version,
        }
    }

    pub fn from_table(table: &Table) -> Result<SystemConfiguration, errors::RustKeylockError> {
        let saved_at = table.get("saved_at").and_then(|value| value.as_integer().and_then(Some));
        let version = table.get("version").and_then(|value| value.as_integer().and_then(Some));
        let last_sync_version = table.get("last_sync_version").and_then(|value| value.as_integer().and_then(Some));
        Ok(SystemConfiguration::new(saved_at, version, last_sync_version))
    }

    pub fn to_table(&self) -> errors::Result<Table> {
        let mut table = Table::new();
        if self.saved_at.is_some() {
            table.insert("saved_at".to_string(), toml::Value::Integer(self.saved_at.unwrap()));
        }
        if self.version.is_some() {
            table.insert("version".to_string(), toml::Value::Integer(self.version.unwrap()));
        }
        if self.last_sync_version.is_some() {
            table.insert("last_sync_version".to_string(), toml::Value::Integer(self.last_sync_version.unwrap()));
        }

        Ok(table)
    }
}

impl Default for SystemConfiguration {
    fn default() -> SystemConfiguration {
        SystemConfiguration {
            saved_at: None,
            version: None,
            last_sync_version: None,
        }
    }
}

/// Struct that defines a password entry.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Entry {
    /// The name of the Entry
    ///
    /// It is used as a label to distinguish among other Entries
    pub name: String,
    /// A URL (optional)
    pub url: String,
    /// The username
    pub user: String,
    /// The password
    pub pass: String,
    /// A description of the `Entry` (Optional)
    pub desc: String,
    /// Whether the Entry has encrypted elements (like password)
    pub encrypted: bool,
}

impl Entry {
    /// Creates a new `Entry` using the provided name, url, username, password and description
    pub fn new(name: String, url: String, user: String, pass: String, desc: String) -> Entry {
        Entry {
            name,
            url,
            user,
            pass,
            desc,
            encrypted: false,
        }
    }

    /// Creates an empty `Entry`
    pub fn empty() -> Entry {
        Entry {
            name: "".to_string(),
            url: "".to_string(),
            user: "".to_string(),
            pass: "".to_string(),
            desc: "".to_string(),
            encrypted: false,
        }
    }

    pub fn from_table(table: &Table) -> Result<Entry, errors::RustKeylockError> {
        let name = table.get("name").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let url = table.get("url").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let user = table.get("user").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let pass = table.get("pass").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let desc = table.get("desc").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        match (name, url, user, pass, desc) {
            (Some(n), Some(ul), Some(u), Some(p), Some(d)) => Ok(Self::new(n, ul, u, p, d)),
            _ => Err(errors::RustKeylockError::ParseError(toml::ser::to_string(&table).unwrap_or_else(|_| "Cannot serialize toml".to_string()))),
        }
    }

    pub fn to_table(&self) -> Table {
        let mut table = Table::new();
        table.insert("name".to_string(), toml::Value::String(self.name.clone()));
        table.insert("url".to_string(), toml::Value::String(self.url.clone()));
        table.insert("user".to_string(), toml::Value::String(self.user.clone()));
        table.insert("pass".to_string(), toml::Value::String(self.pass.clone()));
        table.insert("desc".to_string(), toml::Value::String(self.desc.clone()));

        table
    }

    pub fn encrypted(&self, cryptor: &datacrypt::EntryPasswordCryptor) -> Entry {
        let (encrypted_password, encryption_succeeded) = match cryptor.encrypt_str(&self.pass) {
            Ok(encrypted) => (encrypted, true),
            Err(_) => {
                error!("Could not encrypt password for {}. Defaulting in keeping it in plain...", &self.name);
                (self.pass.clone(), false)
            }
        };
        Entry {
            name: self.name.clone(),
            url: self.url.clone(),
            user: self.user.clone(),
            pass: encrypted_password,
            desc: self.desc.clone(),
            encrypted: encryption_succeeded,
        }
    }

    pub fn decrypted(&self, cryptor: &datacrypt::EntryPasswordCryptor) -> Entry {
        let decrypted_password = if self.encrypted {
            match cryptor.decrypt_str(&self.pass) {
                Ok(decrypted) => decrypted,
                Err(_) => self.pass.clone(),
            }
        } else {
            self.pass.clone()
        };
        Entry::new(self.name.clone(), self.url.clone(), self.user.clone(), decrypted_password, self.desc.clone())
    }
}

/// A struct that allows storing general configuration values.
/// The configuration values are stored in plaintext.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Props {
    /// Inactivity timeout seconds
    idle_timeout_seconds: i64,
    /// Fallback to pre v0.8.0 handling
    legacy_handling: bool,
}

impl Default for Props {
    fn default() -> Self {
        Props {
            idle_timeout_seconds: 1800,
            legacy_handling: false,
        }
    }
}

impl Props {
    pub(crate) fn new(idle_timeout_seconds: i64, legacy_handling: bool) -> Props {
        Props {
            idle_timeout_seconds,
            legacy_handling,
        }
    }

    pub fn from_table(table: &Table) -> Result<Props, errors::RustKeylockError> {
        let idle_timeout_seconds = table.get("idle_timeout_seconds").and_then(|value| value.as_integer().and_then(Some));
        let legacy_handling = table.get("legacy_handling").and_then(|value| value.as_bool().and_then(Some));

        match (idle_timeout_seconds, legacy_handling) {
            (Some(s), Some(l)) => Ok(Self::new(s, l)),
            (Some(s), None) => Ok(Self::new(s, true)),
            (_, _) => Err(errors::RustKeylockError::ParseError(toml::ser::to_string(&table).unwrap_or_else(|_| "Cannot serialize toml".to_string()))),
        }
    }

    #[allow(dead_code)]
    pub fn to_table(&self) -> Table {
        let mut table = Table::new();
        table.insert("idle_timeout_seconds".to_string(), toml::Value::Integer(self.idle_timeout_seconds));
        table.insert("legacy_handling".to_string(), toml::Value::Boolean(self.legacy_handling));

        table
    }

    pub fn idle_timeout_seconds(&self) -> i64 {
        self.idle_timeout_seconds
    }

    pub fn legacy_handling(&self) -> bool {
        self.legacy_handling
    }

    pub fn set_legacy_handling(&mut self, lh: bool) {
        self.legacy_handling = lh
    }
}

/// Enumeration of the several different Menus that an `Editor` implementation should handle.
#[derive(Debug, PartialEq, Clone)]
pub enum Menu {
    /// The User should provide a password and a number.
    /// If bool is true, the last_sync_version will be updated to be the same with the local_version.
    /// If false, nothing will be updated.
    TryPass(bool),
    /// The User should provide a new password and a new number.
    ChangePass,
    /// The User should be presented with the main menu.
    Main,
    /// The User should be presented with a list of all the saved password `Entries`, filtered by the string provided as argument
    EntriesList(String),
    /// The User should create a new `Entry`
    NewEntry,
    /// The User should be presented with a selected `Entry`.
    ///
    /// The index of the `Entry` inside the `Entries` list is provided.
    ShowEntry(usize),
    /// The User should edit a selected `Entry`.
    ///
    /// The index of the `Entry` inside the `Entries` list is provided.
    EditEntry(usize),
    /// The User deletes a selected `Entry`.
    ///
    /// The index of the `Entry` inside the `Entries` list is provided.
    DeleteEntry(usize),
    /// The User encrypts and saves all the existing `Entries` list.
    /// If bool is true, the last_sync_version will be updated to be the same with the local_version.
    /// If false, only the local_version will be updated.
    Save(bool),
    /// The User selects to Exit _rust-keylock_
    Exit,
    /// The User selects to Exit _rust-keylock_, even if there is unsaved data.
    ForceExit,
    /// Parsing the `Entries` _after_ decrypting them may lead to wrong data. This Menu informs the User about the situation and offers an attempt to recover anything that is recoverable.
    TryFileRecovery,
    /// The user should be able to import password `Entries`.
    ImportEntries,
    /// The user should be able to export password `Entries`.
    ExportEntries,
    /// The user should be presented with the configuration menu
    ShowConfiguration,
    /// Stay in the current menu
    Current,
}

impl Menu {
    /// Returns the name of a `Menu`.
    pub fn get_name(&self) -> String {
        match *self {
            Menu::TryPass(b) => format!("{:?}", Menu::TryPass(b)),
            Menu::ChangePass => format!("{:?}", Menu::ChangePass),
            Menu::Main => format!("{:?}", Menu::Main),
            Menu::EntriesList(_) => "EntriesList".to_string(),
            Menu::NewEntry => format!("{:?}", Menu::NewEntry),
            Menu::ShowEntry(_) => "ShowEntry".to_string(),
            Menu::EditEntry(_) => "EditEntry".to_string(),
            Menu::DeleteEntry(_) => "DeleteEntry".to_string(),
            Menu::Save(b) => format!("{:?}", Menu::Save(b)),
            Menu::Exit => format!("{:?}", Menu::Exit),
            Menu::ForceExit => format!("{:?}", Menu::ForceExit),
            Menu::TryFileRecovery => format!("{:?}", Menu::TryFileRecovery),
            Menu::ImportEntries => format!("{:?}", Menu::ImportEntries),
            Menu::ExportEntries => format!("{:?}", Menu::ExportEntries),
            Menu::ShowConfiguration => format!("{:?}", Menu::ShowConfiguration),
            Menu::Current => format!("{:?}", Menu::Current),
        }
    }

    /// Parses a String and creates a `Menu`.
    ///
    /// Menus that have additional `usize` and `String` arguments exist. Thus the existence of the `Option`al arguments during parsing.
    pub fn from(name: String, opt_num: Option<usize>, opt_string: Option<String>) -> Menu {
        debug!("Creating Menu from name {} and additional arguments usize: {:?}, String: {:?}", &name, &opt_num, &opt_string);
        match (name, opt_num, opt_string.clone()) {
            (ref n, None, None) if &Menu::TryPass(false).get_name() == n => Menu::TryPass(false),
            (ref n, None, None) if &Menu::TryPass(true).get_name() == n => Menu::TryPass(true),
            (ref n, None, None) if "TryPass" == n => Menu::TryPass(false),
            (ref n, None, None) if &Menu::ChangePass.get_name() == n => Menu::ChangePass,
            (ref n, None, None) if &Menu::Main.get_name() == n => Menu::Main,
            (ref n, None, Some(ref arg)) if &Menu::EntriesList(arg.clone()).get_name() == n => Menu::EntriesList(arg.clone()),
            (ref n, None, None) if &Menu::NewEntry.get_name() == n => Menu::NewEntry,
            (ref n, Some(arg), None) if &Menu::ShowEntry(arg).get_name() == n => Menu::ShowEntry(arg),
            (ref n, Some(arg), None) if &Menu::EditEntry(arg).get_name() == n => Menu::EditEntry(arg),
            (ref n, Some(arg), None) if &Menu::DeleteEntry(arg).get_name() == n => Menu::DeleteEntry(arg),
            (ref n, None, None) if &Menu::Save(false).get_name() == n => Menu::Save(false),
            (ref n, None, None) if &Menu::Save(true).get_name() == n => Menu::Save(true),
            (ref n, None, None) if "Save" == n => Menu::Save(false),
            (ref n, None, None) if &Menu::Exit.get_name() == n => Menu::Exit,
            (ref n, None, None) if &Menu::ForceExit.get_name() == n => Menu::ForceExit,
            (ref n, None, None) if &Menu::TryFileRecovery.get_name() == n => Menu::TryFileRecovery,
            (ref n, None, None) if &Menu::ImportEntries.get_name() == n => Menu::ImportEntries,
            (ref n, None, None) if &Menu::ExportEntries.get_name() == n => Menu::ExportEntries,
            (ref n, None, None) if &Menu::ShowConfiguration.get_name() == n => Menu::ShowConfiguration,
            (ref n, None, None) if &Menu::Current.get_name() == n => Menu::Current,
            (ref other, _, _) => {
                let message = format!("Cannot create Menu from String '{}' and arguments usize: '{:?}', String: '{:?}'. Please, consider \
                                       opening a bug to the developers.",
                                      other,
                                      opt_num,
                                      opt_string);
                error!("{}", message);
                panic!(message);
            }
        }
    }
}

/// Represents a User selection that is returned after showing a `Menu`.
#[derive(Debug, PartialEq, Clone)]
pub enum UserSelection {
    /// The User selected an `Entry`.
    NewEntry(Entry),
    /// The User updated an `Entry`.
    ReplaceEntry(usize, Entry),
    /// The User deleted an `Entry`.
    DeleteEntry(usize),
    /// The User selected to go to a `Menu`.
    GoTo(Menu),
    /// The User provided a password and a number.
    ProvidedPassword(String, usize),
    /// The User acknowledges something.
    Ack,
    /// The User selected to export the password `Entries` to a path.
    ExportTo(String),
    /// The User selected to import the password `Entries` from a path.
    ImportFrom(String, String, usize),
    /// The User selected to import the password `Entries` from a file in the default location.
    ImportFromDefaultLocation(String, String, usize),
    /// The User may be offered to select one of the Options.
    UserOption(UserOption),
    /// The User updates the configuration.
    UpdateConfiguration(nextcloud::NextcloudConfiguration),
    /// The user copies content to the clipboard.
    AddToClipboard(String),
}

impl UserSelection {
    pub fn is_same_variant_with(&self, other: &UserSelection) -> bool {
        self.ordinal() == other.ordinal()
    }

    fn ordinal(&self) -> i8 {
        match self {
            UserSelection::NewEntry(_) => 1,
            UserSelection::ReplaceEntry(_, _) => 2,
            UserSelection::DeleteEntry(_) => 3,
            UserSelection::GoTo(_) => 4,
            UserSelection::ProvidedPassword(_, _) => 5,
            UserSelection::Ack => 6,
            UserSelection::ExportTo(_) => 7,
            UserSelection::ImportFrom(_, _, _) => 8,
            UserSelection::ImportFromDefaultLocation(_, _, _) => 9,
            UserSelection::UserOption(_) => 10,
            UserSelection::UpdateConfiguration(_) => 11,
            UserSelection::AddToClipboard(_) => 12,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct UserOption {
    pub label: String,
    pub value: UserOptionType,
    pub short_label: String,
}

impl<'a> From<&'a UserOption> for UserOption {
    fn from(uo: &UserOption) -> Self {
        UserOption {
            label: uo.label.clone(),
            value: uo.value.clone(),
            short_label: uo.short_label.clone(),
        }
    }
}

impl From<(String, String, String)> for UserOption {
    fn from(f: (String, String, String)) -> Self {
        UserOption {
            label: f.0,
            value: UserOptionType::from(f.1.as_ref()),
            short_label: f.2,
        }
    }
}

impl UserOption {
    pub fn new(label: &str, option_type: UserOptionType, short_label: &str) -> UserOption {
        UserOption {
            label: label.to_string(),
            value: option_type,
            short_label: short_label.to_string(),
        }
    }

    pub fn empty() -> UserOption {
        UserOption {
            label: "".to_string(),
            value: UserOptionType::None,
            short_label: "".to_string(),
        }
    }

    pub fn ok() -> UserOption {
        UserOption {
            label: "Ok".to_string(),
            value: UserOptionType::String("Ok".to_string()),
            short_label: "o".to_string(),
        }
    }

    pub fn cancel() -> UserOption {
        UserOption {
            label: "Cancel".to_string(),
            value: UserOptionType::String("Cancel".to_string()),
            short_label: "c".to_string(),
        }
    }

    pub fn yes() -> UserOption {
        UserOption {
            label: "Yes".to_string(),
            value: UserOptionType::String("Yes".to_string()),
            short_label: "y".to_string(),
        }
    }

    pub fn no() -> UserOption {
        UserOption {
            label: "No".to_string(),
            value: UserOptionType::String("No".to_string()),
            short_label: "n".to_string(),
        }
    }
}

/// Represents a type for a `UserOption`
#[derive(Debug, PartialEq, Clone)]
pub enum UserOptionType {
    Number(isize),
    String(String),
    None,
}

impl UserOptionType {
    fn extract_value_from_string(s: &str) -> errors::Result<String> {
        let start = s.find('(');
        if s.ends_with(')') {
            match start {
                Some(st) => {
                    let i = s.chars().skip(st + 1).take(s.len() - st - 2);
                    let s = String::from_iter(i);
                    Ok(s)
                }
                _ => {
                    Err(errors::RustKeylockError::ParseError(format!("Could not extract UserOptionType value from {}. The \
                                                                      UserOptionType can be extracted from strings like String(value)",
                                                                     s)))
                }
            }
        } else {
            Err(errors::RustKeylockError::ParseError(format!("Could not extract UserOptionType value from {}. The UserOptionType can be \
                                                              extracted from strings like String(value)",
                                                             s)))
        }
    }
}

impl ToString for UserOptionType {
    fn to_string(&self) -> String {
        match *self {
            UserOptionType::String(ref s) => format!("String({})", s),
            _ => format!("{:?}", &self),
        }
    }
}

impl<'a> From<&'a str> for UserOptionType {
    fn from(string: &str) -> Self {
        match string {
            ref s if s.starts_with("String") => {
                match Self::extract_value_from_string(s) {
                    Ok(value) => UserOptionType::String(value),
                    Err(error) => {
                        error!("Could not create UserOptionType from {}: {:?}. Please consider opening a bug to the developers.", s, error);
                        UserOptionType::None
                    }
                }
            }
            ref s if s.starts_with("Number") => {
                let m = Self::extract_value_from_string(s).and_then(|value| {
                    value.parse::<i64>().map_err(|_| errors::RustKeylockError::ParseError(format!("Could not parse {} to i64", value)))
                });
                match m {
                    Ok(num) => UserOptionType::Number(num as isize),
                    Err(error) => {
                        error!("Could not create UserOptionType from {}: {:?}. Please consider opening a bug to the developers.", s, error);
                        UserOptionType::None
                    }
                }
            }
            other => {
                error!("Could not create UserOptionType from {}. Please consider opening a bug to the developers.", other);
                UserOptionType::None
            }
        }
    }
}

/// Severity for the messages presented to the Users
#[derive(Debug, PartialEq)]
pub enum MessageSeverity {
    Info,
    Warn,
    Error,
}

impl Default for MessageSeverity {
    fn default() -> Self {
        MessageSeverity::Info
    }
}

impl ToString for MessageSeverity {
    fn to_string(&self) -> String {
        format!("{:?}", &self)
    }
}

// Not need for boxing... The largest variant is the most frequent one.
#[allow(clippy::large_enum_variant)]
pub(crate) enum UiCommand {
    ShowPasswordEnter,
    ShowChangePassword,
    ShowMenu(Menu, Safe, RklConfiguration),
    Exit(bool),
    ShowMessage(String, Vec<UserOption>, MessageSeverity),
}

#[cfg(test)]
mod api_unit_tests {
    use toml;

    use crate::datacrypt::EntryPasswordCryptor;

    use super::{Entry, Menu, UserOption, UserSelection};

    #[test]
    fn entry_from_table_success() {
        let toml = r#"
			name = "name1"
			url = "url1"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let entry_opt = Entry::from_table(&table);
        assert!(entry_opt.is_ok());
        let entry = entry_opt.unwrap();
        assert!(entry.name == "name1");
        assert!(entry.url == "url1");
        assert!(entry.user == "user1");
        assert!(entry.pass == "123");
        assert!(entry.desc == "some description");
    }

    #[test]
    fn entry_from_table_failure_wrong_key() {
        let toml = r#"
			wrong_key = "name1"
			url = "url"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_err());
    }

    #[test]
    fn entry_from_table_failure_wrong_value() {
        let toml = r#"
			name = 1
			url = "url"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_err());
    }

    #[test]
    fn entry_to_table() {
        let toml = r#"
			name = "name1"
			url = "url1"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let entry_opt = super::Entry::from_table(&table);
        assert!(entry_opt.is_ok());
        let entry = entry_opt.unwrap();
        let new_table = entry.to_table();
        assert!(table == &new_table);
    }

    #[test]
    fn entry_to_encrypted() {
        let cryptor = EntryPasswordCryptor::new();
        let entry = super::Entry::new("name".to_string(), "url".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string());
        let enc_entry = entry.encrypted(&cryptor);
        assert!(enc_entry.name == entry.name);
        assert!(enc_entry.url == entry.url);
        assert!(enc_entry.user == entry.user);
        assert!(enc_entry.pass != entry.pass);
        assert!(enc_entry.desc == entry.desc);
        let dec_entry = enc_entry.decrypted(&cryptor);
        assert!(dec_entry.pass == entry.pass);
    }

    #[test]
    fn entry_to_encrypted_encryption_may_fail() {
        let cryptor = EntryPasswordCryptor::new();
        let entry = super::Entry::new("name".to_string(), "url".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string());
        let dec_entry = entry.decrypted(&cryptor);
        assert!(dec_entry.pass == entry.pass);
    }

    #[test]
    fn props_from_table_success() {
        let toml = r#"
        idle_timeout_seconds = 33
        legacy_handling = false
        "#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_ok());
        let props = props_opt.unwrap();
        assert!(props.idle_timeout_seconds() == 33);
        assert!(!props.legacy_handling());
    }

    #[test]
    fn props_from_table_success_no_legacy_handling_exists() {
        let toml = r#"
        idle_timeout_seconds = 33
        "#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_ok());
        let props = props_opt.unwrap();
        assert!(props.idle_timeout_seconds() == 33);
        assert!(props.legacy_handling());
    }

    #[test]
    fn props_from_table_failure_wrong_key() {
        let toml = r#"wrong_key = "alas""#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_err());
    }

    #[test]
    fn props_from_table_failure_wrong_value() {
        let toml = r#"salt = 1"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_err());
    }

    #[test]
    fn props_to_table() {
        let toml = r#"
        idle_timeout_seconds = 33
        legacy_handling = false"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_ok());
        let props = props_opt.unwrap();
        let new_table = props.to_table();
        assert!(table == &new_table);
    }

    #[test]
    fn menu_get_name() {
        let m1 = Menu::TryPass(false).get_name();
        assert!(m1 == "TryPass(false)");
        let m2 = Menu::EntriesList("".to_string()).get_name();
        assert!(m2 == "EntriesList");
        let m3 = Menu::EditEntry(33).get_name();
        assert!(m3 == "EditEntry");
        let m4 = Menu::DeleteEntry(1).get_name();
        assert!(m4 == "DeleteEntry");
        let m5 = Menu::NewEntry.get_name();
        assert!(m5 == "NewEntry");
        let m6 = Menu::ForceExit.get_name();
        assert!(m6 == "ForceExit");
        let m7 = Menu::ChangePass.get_name();
        assert!(m7 == "ChangePass");
        let m8 = Menu::Save(false).get_name();
        assert!(m8 == "Save(false)");
        let m9 = Menu::Exit.get_name();
        assert!(m9 == "Exit");
        let m10 = Menu::Main.get_name();
        assert!(m10 == "Main");
        let m11 = Menu::Current.get_name();
        assert!(m11 == "Current");
        let m12 = Menu::EditEntry(1).get_name();
        assert!(m12 == "EditEntry");
        let m13 = Menu::EntriesList("".to_owned()).get_name();
        assert!(m13 == "EntriesList");
        let m14 = Menu::ExportEntries.get_name();
        assert!(m14 == "ExportEntries");
        let m15 = Menu::ImportEntries.get_name();
        assert!(m15 == "ImportEntries");
        let m16 = Menu::ShowConfiguration.get_name();
        assert!(m16 == "ShowConfiguration");
        let m17 = Menu::ShowEntry(1).get_name();
        assert!(m17 == "ShowEntry");
        let m18 = Menu::TryFileRecovery.get_name();
        assert!(m18 == "TryFileRecovery");
    }

    #[test]
    fn menu_from_name() {
        let m1 = Menu::from("TryPass(false)".to_string(), None, None);
        assert!(m1 == Menu::TryPass(false));
        let m2 = Menu::from("EntriesList".to_string(), None, Some("".to_string()));
        assert!(m2 == Menu::EntriesList("".to_string()));
        let m3 = Menu::from("ShowEntry".to_string(), Some(1), None);
        assert!(m3 == Menu::ShowEntry(1));
    }

    #[test]
    fn user_option_constructors() {
        let opt1 = super::UserOption::cancel();
        assert!(&opt1.label == "Cancel");
        assert!(opt1.value == super::UserOptionType::String("Cancel".to_string()));
        assert!(&opt1.short_label == "c");

        let opt2 = super::UserOption::empty();
        assert!(&opt2.label == "");
        assert!(opt2.value == super::UserOptionType::None);
        assert!(&opt2.short_label == "");

        let opt3 = super::UserOption::ok();
        assert!(&opt3.label == "Ok");
        assert!(opt3.value == super::UserOptionType::String("Ok".to_string()));
        assert!(&opt3.short_label == "o");
    }

    #[test]
    fn user_option_type_extract_value_from_string() {
        let s1 = "String(my string)";
        let sr1 = super::UserOptionType::extract_value_from_string(&s1).unwrap();
        assert!(sr1 == "my string");

        let s2 = "String(wrong";
        assert!(super::UserOptionType::extract_value_from_string(&s2).is_err());

        let s3 = "String wrong)";
        assert!(super::UserOptionType::extract_value_from_string(&s3).is_err());

        let s4 = "String((my string))";
        let sr4 = super::UserOptionType::extract_value_from_string(&s4).unwrap();
        assert!(sr4 == "(my string)");
    }

    #[test]
    fn user_option_type_from_string() {
        assert!(super::UserOptionType::from("String(my string)") == super::UserOptionType::String("my string".to_string()));
        assert!(super::UserOptionType::from("Number(33)") == super::UserOptionType::Number(33));
        assert!(super::UserOptionType::from("Other(33)") == super::UserOptionType::None);
    }

    #[test]
    fn user_option_type_to_string_from_string() {
        let user_option_type = super::UserOptionType::String("my string".to_string());
        let string = user_option_type.to_string();
        assert!(string == "String(my string)");
        let s: &str = &string;
        assert!(super::UserOptionType::from(s) == super::UserOptionType::String("my string".to_string()));
    }

    #[test]
    fn system_configuration_to_table() {
        let toml = r#"
			saved_at = 123
			version = 1
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let res = super::SystemConfiguration::from_table(&table);
        assert!(res.is_ok());
        let conf = res.unwrap();
        let new_table = conf.to_table().unwrap();
        assert!(table == &new_table);
    }

    #[test]
    fn system_configuration_from_table_success() {
        let toml = r#"
			saved_at = 123
			version = 1
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let res = super::SystemConfiguration::from_table(&table);
        assert!(res.is_ok());
        let conf = res.unwrap();
        assert!(conf.saved_at == Some(123));
        assert!(conf.version == Some(1));
    }

    #[test]
    fn user_selection_ordinal() {
        assert!(UserSelection::NewEntry(Entry::empty()).ordinal() == 1);
        assert!(UserSelection::ReplaceEntry(1, Entry::empty()).ordinal() == 2);
        assert!(UserSelection::DeleteEntry(1).ordinal() == 3);
        assert!(UserSelection::GoTo(Menu::TryPass(false)).ordinal() == 4);
        assert!(UserSelection::ProvidedPassword("".to_owned(), 33).ordinal() == 5);
        assert!(UserSelection::Ack.ordinal() == 6);
        assert!(UserSelection::ExportTo("".to_owned()).ordinal() == 7);
        assert!(UserSelection::ImportFrom("".to_owned(), "".to_owned(), 1).ordinal() == 8);
        assert!(UserSelection::ImportFromDefaultLocation("".to_owned(), "".to_owned(), 1).ordinal() == 9);
        assert!(UserSelection::UserOption(UserOption::empty()).ordinal() == 10);
        assert!(UserSelection::UpdateConfiguration(super::nextcloud::NextcloudConfiguration::default()).ordinal() == 11);
        assert!(UserSelection::AddToClipboard("".to_owned()).ordinal() == 12);
    }

    #[test]
    fn is_same_variant_with() {
        assert!(UserSelection::ProvidedPassword("".to_owned(), 33).is_same_variant_with(&UserSelection::ProvidedPassword("other".to_owned(), 11)));
    }
}