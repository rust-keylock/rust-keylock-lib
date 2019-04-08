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

use crate::{datacrypt, errors};
use std::collections::HashMap;
use super::Entry;

/// Holds the data that should be safe and secret.
///
/// This includes the password entries and a Cryptor that is used to encrypt the passwords of the entries when they are stored in memory
/// and decrypt them when needed (to be presented to the User)
#[derive(Clone)]
pub struct Safe {
    pub(crate) entries: Vec<Entry>,
    filtered_entries: Vec<Entry>,
    /// Maps the filtered Entries to the Vec that contains all the entries.
    map_filtered_to_unfiltered: HashMap<usize, usize>,
    password_cryptor: datacrypt::EntryPasswordCryptor,
    filter: String,
}

impl Default for Safe {
    fn default() -> Self {
        Safe {
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            map_filtered_to_unfiltered: HashMap::new(),
            password_cryptor: datacrypt::EntryPasswordCryptor::new(),
            filter: "".to_string(),
        }
    }
}

impl Safe {
    pub(crate) fn new() -> Safe {
        Safe {
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            map_filtered_to_unfiltered: HashMap::new(),
            password_cryptor: datacrypt::EntryPasswordCryptor::new(),
            filter: "".to_string(),
        }
    }

    /// Adds an Entry to the Safe, with the Entry password encrypted
    pub(crate) fn add_entry(&mut self, new_entry: Entry) {
        self.entries.push(new_entry.encrypted(&self.password_cryptor));
        self.apply_filter();
    }

    /// Replaces an Entry in the Safe, with a new Entry that has the password encrypted
    pub(crate) fn replace_entry(&mut self, index: usize, entry: Entry) -> errors::Result<()> {
        // Push the Entry
        self.entries.push(entry.encrypted(&self.password_cryptor));
        // Find the correct index of the edited entry in the main Entries Vec
        let res = match self.map_filtered_to_unfiltered.get(&index) {
            Some(index_in_main_vec) => {
                // Replace
                self.entries.swap_remove(*index_in_main_vec);
                Ok(())
            }
            None => {
                Err(errors::RustKeylockError::GeneralError("The entry being replaced was not found in the Entries... If the entries \
                                                            changed meanwhile, this is normal. If not, please consider opening a bug to \
                                                            the developers."
                    .to_string()))
            }
        };
        // Apply the filter once again
        self.apply_filter();
        res
    }

    /// Removes an Entry from the Safe
    pub(crate) fn remove_entry(&mut self, index: usize) -> errors::Result<()> {
        let res = match self.map_filtered_to_unfiltered.get(&index) {
            Some(index_in_main_vec) => {
                // Remove
                self.entries.remove(*index_in_main_vec);
                Ok(())
            }
            None => {
                Err(errors::RustKeylockError::GeneralError("The entry being replaced was not found in the Entries... If the entries \
                                                            changed meanwhile, this is normal. If not, please consider opening a bug to \
                                                            the developers."
                    .to_string()))
            }
        };
        // Apply the filter once again
        self.apply_filter();
        res
    }

    /// Merges the Entries, by appending the incoming elements that are not the same with some existing one in Safe
    pub(crate) fn merge(&mut self, incoming: Vec<Entry>) {
        let mut to_add = {
            incoming.into_iter()
                .filter(|entry| {
                    let mut main_iter = self.entries.iter();
                    let opt = main_iter.find(|main_entry| {
                        let enrypted_entry = entry.encrypted(&self.password_cryptor);
                        main_entry.name == enrypted_entry.name && main_entry.url == enrypted_entry.url &&
                            main_entry.user == enrypted_entry.user && main_entry.pass == enrypted_entry.pass && main_entry.desc == enrypted_entry.desc
                    });
                    opt.is_none()
                })
                .map(|entry| entry.encrypted(&self.password_cryptor))
                .collect()
        };

        self.entries.append(&mut to_add);
        self.apply_filter();
    }

    /// Adds the Entries in the Safe
    pub(crate) fn add_all(&mut self, incoming: Vec<Entry>) {
        let mut to_add = {
            incoming.into_iter()
                .map(|entry| entry.encrypted(&self.password_cryptor))
                .collect()
        };

        self.entries.append(&mut to_add);
        self.apply_filter();
    }

    /// Retrieves an Entry at a given index, after applying the filter to the Vector
    pub fn get_entry(&self, index: usize) -> &Entry {
        &self.get_entries()[index]
    }

    /// Retrieves an Entry at a given index with the password decrypted
    pub fn get_entry_decrypted(&self, index: usize) -> Entry {
        self.get_entry(index).decrypted(&self.password_cryptor)
    }

    /// Retrieves the existing entries, after applying the filter to the Vector
    pub fn get_entries(&self) -> &[Entry] {
        &self.filtered_entries
    }

    /// Retrieves __all__ the Entries with the passwords decrypted
    pub(crate) fn get_entries_decrypted(&self) -> Vec<Entry> {
        self.get_entries()
            .iter()
            .map(|entry| entry.decrypted(&self.password_cryptor))
            .collect()
    }

    /// Sets a filter to be applied when retrieving the entries
    pub(crate) fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.apply_filter();
    }

    /// Gets the filter of the Safe
    pub fn get_filter(&self) -> String {
        self.filter.clone()
    }

    fn apply_filter(&mut self) {
        let m: Vec<Entry> = if !self.filter.is_empty() {
            let lower_filter = self.filter.to_lowercase();
            let mut indexes_vec = Vec::new();
            let mut vec = Vec::new();

            {
                let iter = self.entries
                    .iter()
                    .enumerate()
                    .filter(|&(_, entry)| {
                        entry.name.to_lowercase().contains(&lower_filter) || entry.url.to_lowercase().contains(&lower_filter) ||
                            entry.user.to_lowercase().contains(&lower_filter) || entry.desc.to_lowercase().contains(&lower_filter)
                    });
                for tup in iter {
                    // Push the entry in the vec
                    vec.push(tup.1.clone());
                    // Push the index in the indexes vec
                    indexes_vec.push(tup.0);
                }
            }

            // Put the indexes mapping in the map_filtered_to_unfiltered
            self.map_filtered_to_unfiltered.clear();
            indexes_vec.iter().enumerate().for_each(|(index_in_filtered_vec, index_in_main_vec)| {
                self.map_filtered_to_unfiltered.insert(index_in_filtered_vec, *index_in_main_vec);
            });

            vec
        } else {
            // Put the indexes mapping in the map_filtered_to_unfiltered.
            // The mapping here is one-to-one
            self.map_filtered_to_unfiltered.clear();
            for index in 0..self.entries.len() {
                self.map_filtered_to_unfiltered.insert(index, index);
            }
            self.entries.clone()
        };

        self.filtered_entries = m;
    }

    pub(crate) fn clear(&mut self) {
        self.filtered_entries = Vec::new();
        self.entries = Vec::new();
        self.map_filtered_to_unfiltered.clear();
        self.filter = "".to_string();
    }
}

#[cfg(test)]
mod safe_unit_tests {
    use crate::api::Entry;

    #[test]
    fn merge_entries() {
        let mut safe = super::Safe::new();
        assert!(safe.entries.len() == 0);

        // Add some initial Entries
        let all = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()),
                       Entry::new("2".to_string(), "2".to_string(), "2".to_string(), "2".to_string(), "2".to_string())];
        safe.add_all(all);

        // This one should be added
        let first = vec![Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string())];
        safe.merge(first);
        assert!(safe.entries.len() == 3);

        // This one should not be added
        let second = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string(), "1".to_string())];
        safe.merge(second);
        assert!(safe.entries.len() == 3);

        // This one should not be added either (the description is not the same with any of the existing ones
        let third = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string(), "3".to_string())];
        safe.merge(third);
        assert!(safe.entries.len() == 4);
    }

    #[test]
    fn add_entry() {
        let mut safe = super::Safe::new();
        let entry = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry.clone());
        assert!(safe.entries.len() == 1);
        assert!(safe.entries[0].name == entry.name);
        assert!(safe.entries[0].url == entry.url);
        assert!(safe.entries[0].user == entry.user);
        assert!(safe.entries[0].pass != entry.pass);
        assert!(safe.entries[0].desc == entry.desc);
    }

    #[test]
    fn replace_entry() {
        let mut safe = super::Safe::new();
        let entry = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry.clone());
        let new_entry = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let _ = safe.replace_entry(0, new_entry.clone());

        assert!(safe.entries.len() == 1);
        let replaced_entry = safe.get_entry_decrypted(0);
        assert!(replaced_entry.name == new_entry.name);
        assert!(replaced_entry.url == new_entry.url);
        assert!(replaced_entry.user == new_entry.user);
        assert!(replaced_entry.pass == new_entry.pass);
        assert!(replaced_entry.desc == new_entry.desc);
    }

    #[test]
    fn replace_entry_after_filter() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string(), "1".to_string());
        let entry2 = Entry::new("2".to_string(), "2".to_string(), "2".to_string(), "2".to_string(), "2".to_string());
        let entry3 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry1.clone());
        safe.add_entry(entry2.clone());
        safe.add_entry(entry3.clone());
        let new_entry = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());

        safe.set_filter("3".to_string());
        let _ = safe.replace_entry(0, new_entry.clone());
        safe.set_filter("".to_string());

        assert!(safe.entries.len() == 3);
        let replaced_entry = safe.get_entry_decrypted(2);
        assert!(replaced_entry.name == new_entry.name);
        assert!(replaced_entry.url == new_entry.url);
        assert!(replaced_entry.user == new_entry.user);
        assert!(replaced_entry.pass == new_entry.pass);
        assert!(replaced_entry.desc == new_entry.desc);
    }

    #[test]
    fn remove_entry() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        safe.add_entry(entry1.clone());
        safe.add_entry(entry2.clone());

        let _ = safe.remove_entry(1);

        assert!(safe.entries.len() == 1);
        assert!(safe.entries[0].name == entry1.name);
        assert!(safe.entries[0].url == entry1.url);
        assert!(safe.entries[0].user == entry1.user);
        assert!(safe.entries[0].pass != entry1.pass);
        assert!(safe.entries[0].desc == entry1.desc);
    }

    #[test]
    fn remove_entry_after_filter() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        safe.add_entry(entry1.clone());
        safe.add_entry(entry2.clone());

        safe.set_filter("33".to_string());
        let _ = safe.remove_entry(0);
        safe.set_filter("".to_string());

        assert!(safe.entries.len() == 1);
        let decrypted_entry = safe.get_entry_decrypted(0);
        assert!(decrypted_entry.name == entry1.name);
        assert!(decrypted_entry.url == entry1.url);
        assert!(decrypted_entry.user == entry1.user);
        assert!(decrypted_entry.pass == entry1.pass);
        assert!(decrypted_entry.desc == entry1.desc);
    }

    #[test]
    fn add_all() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];

        safe.add_all(entries);

        assert!(safe.entries.len() == 2);
        assert!(safe.entries[0].pass != entry1.pass && safe.entries[0].pass != entry2.pass);
        assert!(safe.entries[1].pass != entry1.pass && safe.entries[0].pass != entry2.pass);
    }

    #[test]
    fn get_entry() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entry = safe.get_entry(1);
        assert!(got_entry.name == entry2.name);
        assert!(got_entry.url == entry2.url);
        assert!(got_entry.user == entry2.user);
        assert!(got_entry.pass != entry2.pass);
        assert!(got_entry.desc == entry2.desc);
    }

    #[test]
    fn get_entry_decrypted() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entry = safe.get_entry_decrypted(1);
        assert!(got_entry.name == entry2.name);
        assert!(got_entry.url == entry2.url);
        assert!(got_entry.user == entry2.user);
        assert!(got_entry.pass == entry2.pass);
        assert!(got_entry.desc == entry2.desc);
    }

    #[test]
    fn get_entries() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entries = safe.get_entries();
        assert!(got_entries.len() == 2);
    }

    #[test]
    fn get_entries_decrypted() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entries = safe.get_entries_decrypted();
        assert!(got_entries.len() == 2);
        assert!(got_entries[0].pass == entry1.pass);
        assert!(got_entries[1].pass == entry2.pass);
    }

    #[test]
    fn set_filter() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("1".to_string(), "2".to_string(), "3".to_string(), "5".to_string(), "4".to_string());
        let entry2 = Entry::new("11".to_string(), "12".to_string(), "13".to_string(), "15".to_string(), "14".to_string());
        let entries = vec![entry1, entry2];
        safe.add_all(entries);

        // Assert that the filter can be applied on name, url, user and desc fields of Entries
        safe.set_filter("1".to_string());
        assert!(safe.get_entries().len() == 2);
        safe.set_filter("11".to_string());
        assert!(safe.get_entries().len() == 1);

        safe.set_filter("2".to_string());
        assert!(safe.get_entries().len() == 2);
        safe.set_filter("12".to_string());
        assert!(safe.get_entries().len() == 1);

        safe.set_filter("3".to_string());
        assert!(safe.get_entries().len() == 2);
        safe.set_filter("13".to_string());
        assert!(safe.get_entries().len() == 1);

        safe.set_filter("4".to_string());
        assert!(safe.get_entries().len() == 2);
        safe.set_filter("14".to_string());
        assert!(safe.get_entries().len() == 1);

        // The filter cannot be applied on password
        safe.set_filter("5".to_string());
        assert!(safe.get_entries().len() == 0);

        // The filter should by applied ignoring the case
        let entry3 = Entry::new("NAME".to_string(), "Url".to_string(), "User".to_string(), "pass".to_string(), "Desc".to_string());
        safe.add_entry(entry3);
        safe.set_filter("name".to_string());
        assert!(safe.get_entries().len() == 1);
    }

    #[test]
    fn get_filter() {
        let mut safe = super::Safe::new();
        safe.set_filter("33".to_string());
        assert!(safe.get_filter() == "33".to_string());
    }

    #[test]
    fn clear() {
        let mut safe = super::Safe::new();
        let entry = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry.clone());
        safe.set_filter("a_filter".to_string());

        safe.clear();

        assert!(safe.entries.len() == 0);
        assert!(safe.filtered_entries.len() == 0);
        assert!(safe.filter.len() == 0);
    }
}