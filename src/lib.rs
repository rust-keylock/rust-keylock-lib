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

//! # The _rust-keylock_ library
//!
//! Executes the logic of the _rust-keylock_.
//!
//! This library is the executor of the _rust-keylock_ logic. `Editor` references are used to interact with the _rust-keylock_ users.

extern crate async_trait;
extern crate base64;
extern crate dirs;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate hyper_tls;
extern crate log;
extern crate native_tls;
extern crate openssl_probe;
extern crate rand;
extern crate rs_password_utils;
extern crate secstr;
extern crate sha3;
extern crate terminal_clipboard;
extern crate toml;
extern crate xml;

use std::path::PathBuf;
use std::time::Duration;

pub use api::GeneralConfiguration;
use async_trait::async_trait;
use asynch::{AsyncTask, SyncStatus};
use futures::{future, select, FutureExt};
use log::*;

pub use file_handler::default_rustkeylock_location;
use rest_server::RestService;
use tokio::time::sleep;

use crate::api::{EditorShowMessageWrapper, PasswordChecker, RklPasswordChecker};
use crate::asynch::dropbox::DropboxConfiguration;
use crate::asynch::nextcloud::NextcloudConfiguration;
use crate::datacrypt::BcryptAes;

use self::api::safe::Safe;

// Read the code version
include!(concat!(env!("OUT_DIR"), "/rkl_version.rs"));

pub use self::api::{
    AllConfigurations, Entry, EntryMeta, EntryPresentationType, Menu, MessageSeverity, UserOption,
    UserSelection,
};
use self::api::{Props, RklConfiguration, RklContent, SystemConfiguration};
pub use self::asynch::dropbox;
pub use self::asynch::nextcloud;

mod api;
mod asynch;
mod datacrypt;
mod errors;
mod file_handler;
mod protected;
mod rest_server;
mod utils;

const FILENAME: &str = ".sec";
const PROPS_FILENAME: &str = ".props";
const BCRYPT_COST: u32 = 12;
const BCRYPT_COST_PRE_0_17_0: u32 = 7;

/// Takes a reference of `Editor` implementation as argument and executes the _rust-keylock_ logic.
/// The `Editor` is responsible for the interaction with the user. Currently there are `Editor` implementations for __shell__ and for __Android__.
pub async fn execute_async(editor: Box<dyn AsyncEditor>) {

    let mut rest_server = RestService::new(editor.start_rest_server())
        .await
        .expect("Could not start the rest server");
    let rest_server_clone = rest_server.clone();

    if editor.start_rest_server() {
        tokio::task::spawn(async move {
            loop {
                if let Err(e) = rest_server.serve().await {
                    error!("Could not serve HTTP Rest servers: {e}");
                }
            }
        });
    }

    unsafe {
        openssl_probe::init_openssl_env_vars();
    }
    info!("Starting rust-keylock...");
    let props = match file_handler::load_properties(PROPS_FILENAME) {
        Ok(m) => m,
        Err(error) => {
            error!(
                "Could not load properties. Using defaults. The error was: {}",
                error
            );
            Props::default()
        }
    };

    let mut executor = CoreLogicHandler::new(editor, props).await;

    loop {
        if let Err(e) = rest_server_clone.update_safe(executor.get_safe()) {
            error!("Could not update the safe for the HTTP server: {e}");
        }
        let token = executor
            .get_configuration()
            .general
            .browser_extension_token
            .unwrap_or_default();
        if let Err(e) = rest_server_clone.update_token(token.to_string()) {
            error!("Could not update the safe for the HTTP server: {e}");
        }
        let (new_executor, stop) = executor.handle().await.unwrap();
        executor = new_executor;
        if stop {
            break;
        }
    }

    info!("Exiting rust-keylock...");
}

struct CoreLogicHandler {
    props: Props,
    // Holds the UserSelections
    user_selection: UserSelection,
    // Keeps the sensitive data
    safe: Safe,
    configuration: RklConfiguration,
    dbx_synchronizer: dropbox::Synchronizer,
    nc_synchronizer: nextcloud::Synchronizer,
    // Signals changes that are not saved
    contents_changed: bool,
    cryptor: datacrypt::BcryptAes,
    editor: Box<dyn AsyncEditor>
}

impl CoreLogicHandler {
    async fn new(editor: Box<dyn AsyncEditor>, props: Props) -> CoreLogicHandler {
        let mut props = props;
        let editor = editor;
        // Holds the UserSelections
        let user_selection;

        // Keeps the sensitive data
        let mut safe = Safe::new();
        // Keeps the configuration data
        let mut configuration = RklConfiguration::from((
            nextcloud::NextcloudConfiguration::default(),
            dropbox::DropboxConfiguration::default(),
            SystemConfiguration::default(),
            GeneralConfiguration::default(),
        ));
        // Signals changes that are not saved
        let contents_changed = false;
        // Create a Cryptor
        let cryptor: BcryptAes;
        loop {
            // First time run?
            let provided_password = if file_handler::is_first_run(FILENAME) {
                editor.show_change_password().await
            } else {
                editor.show_password_enter().await
            };

            // Take the provided password and do the initialization
            let (us, cr) = handle_provided_password_for_init(
                provided_password,
                FILENAME,
                &mut safe,
                &mut configuration,
                &editor,
            ).await;
            // If the password was correct
            if us != UserSelection::GoTo(Menu::TryPass(false)) {
                // Save the version
                props.set_version(rkl_version());
                let _ = file_handler::save_props(&props, PROPS_FILENAME);
                // Set the UserSelection
                user_selection = us;
                cryptor = cr;
                break;
            }
        };

        // Initialize the synchronizers
        let mut nc_synchronizer = nextcloud::Synchronizer::new(
            &configuration.nextcloud, 
            &configuration.system,
                FILENAME
            ).unwrap();
            let _ = nc_synchronizer.init().await;

        let mut dbx_synchronizer = dropbox::Synchronizer::new(
            &configuration.dropbox, 
            &configuration.system,
                FILENAME
            ).unwrap();
        let _ = dbx_synchronizer.init().await;
        
        CoreLogicHandler {
            editor,
            props: props,
            user_selection,
            safe,
            configuration,
            dbx_synchronizer,
            nc_synchronizer,
            contents_changed,
            cryptor,
        }
    }

    pub(crate) fn get_safe(&self) -> Safe {
        self.safe.clone()
    }

    pub(crate) fn get_configuration(&self) -> RklConfiguration {
        self.configuration.clone()
    }

    // This is the main function that handles all the user selections. Its complexity is expected to be big.
    // This may change in the future during a refactoring but is accepted for now.
    #[allow(clippy::cyclomatic_complexity)]
    async fn handle(self) -> errors::Result<(CoreLogicHandler, bool)> {
        let mut stop = false;
        let mut s = self;

        s.editor.sort_entries(&mut s.safe.entries);
        // Handle
        let user_selection_future = match s.user_selection {
            UserSelection::GoTo(Menu::TryPass(update_last_sync_version)) => {
                let (user_selection, cr) = handle_provided_password_for_init(
                    s.editor.show_password_enter().await,
                    FILENAME,
                    &mut s.safe,
                    &mut s.configuration,
                    &s.editor,
                ).await;
                if update_last_sync_version {
                    s.configuration.update_system_last_sync();
                    let rkl_content = RklContent::from((
                        &s.safe,
                        &s.configuration.nextcloud,
                        &s.configuration.dropbox,
                        &s.configuration.system,
                        &s.configuration.general,
                    ));
                    let _ =
                        rkl_content.and_then(|c| file_handler::save(c, FILENAME, &s.cryptor, true));
                }
                s.cryptor = cr;
                Box::pin(future::ready(user_selection))
            }
            UserSelection::GoTo(Menu::Main) => {
                debug!("UserSelection::GoTo(Menu::Main)");
                s.editor.show_menu(Menu::Main)
            }
            UserSelection::GoTo(Menu::ChangePass) => {
                debug!("UserSelection::GoTo(Menu::ChangePass)");
                s.contents_changed = true;
                s.editor.show_change_password()
            }
            UserSelection::ProvidedPassword(pwd, salt_pos) => {
                debug!("UserSelection::GoTo(Menu::ProvidedPassword)");
                s.cryptor =
                    file_handler::create_bcryptor(FILENAME, pwd.to_string(), bcrypt_cost_from_file(), *salt_pos, true, true)
                        .unwrap();
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Main)))
            }
            UserSelection::GoTo(Menu::EntriesList(filter_opt)) => {
                match filter_opt {
                    Some(filter) => {
                        debug!(
                            "UserSelection::GoTo(Menu::EntriesList) with filter '{}'",
                            &filter
                        );
                        s.safe.set_filter(filter.clone());
                    },
                    None => {
                        debug!(
                            "UserSelection::GoTo(Menu::EntriesList) with existing filter '{}'",
                            &s.safe.get_filter()
                        );
                    }
                }
                s.editor.show_entries(s.safe.get_entries().to_vec(), s.safe.get_filter())
            }
            UserSelection::GoTo(Menu::NewEntry(opt)) => {
                debug!("UserSelection::GoTo(Menu::NewEntry)");
                s.editor.show_menu(Menu::NewEntry(opt))
            }
            UserSelection::GoTo(Menu::ShowEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::ShowEntry(index))");
                s.editor.show_entry(
                    s.safe.get_entry_decrypted(index),
                    index,
                    EntryPresentationType::View,
                )
            }
            UserSelection::GoTo(Menu::EditEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::EditEntry(index))");
                s.editor.show_entry(
                    s.safe.get_entry_decrypted(index),
                    index,
                    EntryPresentationType::Edit,
                )
            }
            UserSelection::GoTo(Menu::DeleteEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::DeleteEntry(index))");
                s.editor.show_entry(
                    s.safe.get_entry_decrypted(index),
                    index,
                    EntryPresentationType::Delete,
                )
            }
            UserSelection::GoTo(Menu::Save(update_last_sync_version)) => {
                debug!("UserSelection::GoTo(Menu::Save({}))",update_last_sync_version);
                if s.configuration.nextcloud.is_filled() && s.configuration.dropbox.is_filled() {
                    error!("Cannot save because both Nextcloud and Dropbox are configured");
                    s.editor.show_message("Having both Nextcloud and Dropbox configured may lead to unexpected state and currently is not allowed.\
                    Please configure only one of them.", vec![UserOption::ok()], MessageSeverity::Error).await;
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
                } else {
                    let _ = s
                        .configuration
                        .update_system_for_save(update_last_sync_version)
                        .map_err(|error| error!("Cannot update system for save: {:?}", error));
                    // Reset the filter
                    s.safe.set_filter("".to_string());
                    // Initialize the synchronizers
                    let mut nc_synchronizer = nextcloud::Synchronizer::new(
                       &s.configuration.nextcloud, 
                       &s.configuration.system,
                           FILENAME
                       ).unwrap();
                    let started = nc_synchronizer.init().await;
                    if started.is_err() {
                        let _ = s.editor.show_message(
                            "Could not start the Nextcloud synchronizer",
                            vec![UserOption::ok()],
                            MessageSeverity::Error,
                        ).await;
                    }
                    s.nc_synchronizer = nc_synchronizer;

                    let mut dbx_synchronizer = dropbox::Synchronizer::new(
                        &s.configuration.dropbox, 
                        &s.configuration.system,
                            FILENAME
                        ).unwrap();
                    let started = dbx_synchronizer.init().await;
                    if started.is_err() {
                        let _ = s.editor.show_message(
                            "Could not start the Dropbox synchronizer",
                            vec![UserOption::ok()],
                            MessageSeverity::Error,
                        ).await;
                    }
                    s.dbx_synchronizer = dbx_synchronizer;

                    let rkl_content = RklContent::from((
                        &s.safe,
                        &s.configuration.nextcloud,
                        &s.configuration.dropbox,
                        &s.configuration.system,
                        &s.configuration.general,
                    ));
                    let res =
                        rkl_content.and_then(|c| file_handler::save(c, FILENAME, &s.cryptor, true));
                    match res {
                        Ok(_) => {
                            // Clean the flag for unsaved data
                            s.contents_changed = false;
                            if !update_last_sync_version {
                                let _ = s.editor.show_message(
                                    "Encrypted and saved successfully!",
                                    vec![UserOption::ok()],
                                    MessageSeverity::default(),
                                ).await;
                            }
                        }
                        Err(error) => {
                            let _ = s.editor.show_message(
                                "Could not save...",
                                vec![UserOption::ok()],
                                MessageSeverity::Error,
                            ).await;
                            error!("Could not save... {:?}", error);
                        }
                    };
                    if update_last_sync_version {
                        Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
                    } else {
                        Box::pin(future::ready(UserSelection::GoTo(Menu::Main)))
                    }
                }
            }
            UserSelection::GoTo(Menu::Exit) => {
                debug!("UserSelection::GoTo(Menu::Exit)");
                s.editor.exit(s.contents_changed)
            }
            UserSelection::GoTo(Menu::ForceExit) => {
                debug!("UserSelection::GoTo(Menu::ForceExit)");
                stop = true;
                Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
            }
            UserSelection::NewEntry(mut entry) => {
                debug!("UserSelection::NewEntry(entry)");

                let entry_to_replace_opt = match RklPasswordChecker::default()
                    .is_unsafe(&entry.pass)
                    .await
                {
                    Ok(true) => {
                        warn!("The password for entry {} has leaked!", entry.name);
                        let sel = s.editor.show_message(
                            "The password you provided has been leaked and is not safe. Are you sure you want to use it?",
                            vec![UserOption::yes(), UserOption::no()],
                            MessageSeverity::Warn).await;

                        if sel == UserSelection::UserOption(UserOption::yes()) {
                            warn!(
                                "The user accepted that entry {} will have leaked password.",
                                entry.name
                            );
                            entry.meta.leaked_password = true;
                            Some(entry)
                        } else {
                            None
                        }
                    }
                    Ok(false) => {
                        debug!("The password for entry {} is not leaked!", entry.name);
                        entry.meta.leaked_password = false;
                        Some(entry)
                    }
                    Err(error) => {
                        debug!(
                            "No information about password leakage for entry {}. Reason: {}",
                            entry.name, error
                        );
                        Some(entry)
                    }
                };

                if let Some(entry) = entry_to_replace_opt {
                    s.safe.add_entry(entry);
                    s.contents_changed = true;
                    Box::pin(future::ready(UserSelection::GoTo(Menu::EntriesList(Some("".to_string())))))
                } else {
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
                }
            }
            UserSelection::ReplaceEntry(index, mut entry) => {
                debug!("UserSelection::ReplaceEntry(index, entry)");

                let entry_to_replace_opt = match RklPasswordChecker::default()
                    .is_unsafe(&entry.pass)
                    .await
                {
                    Ok(true) => {
                        warn!("The password for entry {} has leaked!", entry.name);
                        let sel = s.editor.show_message(
                            "The password you provided has been leaked and is not safe. Are you sure you want to use it?",
                            vec![UserOption::yes(), UserOption::no()],
                            MessageSeverity::Warn).await;

                        if sel == UserSelection::UserOption(UserOption::yes()) {
                            warn!(
                                "The user accepted that entry {} will have leaked password.",
                                entry.name
                            );
                            entry.meta.leaked_password = true;
                            Some(entry)
                        } else {
                            None
                        }
                    }
                    Ok(false) => {
                        debug!("The password for entry {} is not leaked!", entry.name);
                        entry.meta.leaked_password = false;
                        Some(entry)
                    }
                    Err(error) => {
                        debug!(
                            "No information about password leakage for entry {}. Reason: {}",
                            entry.name, error
                        );
                        Some(entry)
                    }
                };

                if let Some(entry) = entry_to_replace_opt {
                    s.contents_changed = true;
                    match s.safe.replace_entry(index, entry) {
                        Ok(_) => { /**/ }
                        Err(error) => {
                            error!("Could not replace entry: {:?}", error);
                            let _ = s.editor.show_message("Could not replace the password entry. Please see the logs for more details.", vec![UserOption::ok()], MessageSeverity::Error).await;
                        }
                    }
                    Box::pin(future::ready(UserSelection::GoTo(Menu::EntriesList(None))))
                } else {
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
                }
            }
            UserSelection::DeleteEntry(index) => {
                debug!("UserSelection::DeleteEntry(index)");
                let _ = s.safe.remove_entry(index).map_err(|err| {
                    error!("Could not delete entry {:?}", err);
                    let _ = s.editor.show_message(
                        "Could not delete entry. Please see the logs for more details.",
                        vec![UserOption::ok()],
                        MessageSeverity::Error,
                    );
                });
                s.contents_changed = true;
                Box::pin(future::ready(UserSelection::GoTo(Menu::EntriesList(None))))
            }
            UserSelection::GoTo(Menu::TryFileRecovery) => {
                debug!("UserSelection::GoTo(Menu::TryFileRecovery)");
                let _ = s.editor.show_message(
                    "The password entries are corrupted.\n\nPress Enter to attempt recovery...",
                    vec![UserOption::ok()],
                    MessageSeverity::Error,
                ).await;
                let mut rec_entries = match file_handler::recover(FILENAME, &s.cryptor) {
                    Ok(recovered_entries) => {
                        let message = r#"
Recovery succeeded...

Note the errors that caused the recovery. You may see some useful information about possible values that could not be recovered.
Press Enter to show the Recovered Entries and if you are ok with it, save them.

Warning: Saving will discard all the entries that could not be recovered.
"#;
                        let _ = s.editor.show_message(
                            message,
                            vec![UserOption::ok()],
                            MessageSeverity::default(),
                        ).await;
                        s.contents_changed = true;
                        s.safe.entries.clear();
                        recovered_entries
                    }
                    Err(error) => {
                        let message = format!("Recovery failed... Reason {:?}", error);
                        error!("{}", &message);
                        let _ = s.editor.show_message(
                            "Recovery failed...",
                            vec![UserOption::ok()],
                            MessageSeverity::Error,
                        ).await;
                        s.safe.entries.clone()
                    }
                };
                s.safe.entries.append(&mut rec_entries);

                Box::pin(future::ready(UserSelection::GoTo(Menu::EntriesList(Some("".to_string())))))
            }
            UserSelection::GoTo(Menu::ExportEntries) => {
                debug!("UserSelection::GoTo(Menu::ExportEntries)");
                s.editor.show_menu(Menu::ExportEntries)
            }
            UserSelection::ExportTo(path) => {
                debug!("UserSelection::ExportTo(path)");
                let do_export = if file_handler::file_exists(&PathBuf::from(&path)) {
                    let selection = s.editor.show_message(
                        "This will overwrite an existing file. Do you want to proceed?",
                        vec![UserOption::yes(), UserOption::no()],
                        MessageSeverity::Warn,
                    ).await;

                    debug!(
                        "The user selected {:?} as an answer for overwriting the file {}",
                        selection, path
                    );
                    selection == UserSelection::UserOption(UserOption::yes())
                } else {
                    true
                };

                if do_export {
                    match RklContent::from((
                        &s.safe,
                        &s.configuration.nextcloud,
                        &s.configuration.dropbox,
                        &s.configuration.system,
                        &s.configuration.general,
                    )) {
                        Ok(c) => match file_handler::save(c, &path, &s.cryptor, false) {
                            Ok(_) => {
                                let _ = s.editor.show_message(
                                    "Export completed successfully!",
                                    vec![UserOption::ok()],
                                    MessageSeverity::default(),
                                ).await;
                            }
                            Err(error) => {
                                error!("Could not export... {:?}", error);
                                let _ = s.editor.show_message(
                                    "Could not export...",
                                    vec![UserOption::ok()],
                                    MessageSeverity::Error,
                                ).await;
                            }
                        },
                        Err(error) => {
                            error!("Could not export... {:?}", error);
                            let _ = s.editor.show_message(
                                "Could not export...",
                                vec![UserOption::ok()],
                                MessageSeverity::Error,
                            ).await;
                        }
                    };
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Main)))
                } else {
                    Box::pin(future::ready(UserSelection::GoTo(Menu::ExportEntries)))
                }
            }
            UserSelection::GoTo(Menu::ImportEntries) => {
                debug!("UserSelection::GoTo(Menu::ImportEntries)");
                s.editor.show_menu(Menu::ImportEntries)
            }
            us @ UserSelection::ImportFrom(_, _, _)
            | us @ UserSelection::ImportFromDefaultLocation(_, _, _) => {
                let import_from_default_location = match us {
                    UserSelection::ImportFrom(_, _, _) => false,
                    UserSelection::ImportFromDefaultLocation(_, _, _) => true,
                    _ => false,
                };
                match us {
                    UserSelection::ImportFrom(path, pwd, salt_pos)
                    | UserSelection::ImportFromDefaultLocation(path, pwd, salt_pos) => {
                        let cr = file_handler::create_bcryptor(
                            &path,
                            pwd.to_string(),
                            bcrypt_cost_from_file(),
                            *salt_pos,
                            false,
                            import_from_default_location,
                        )
                        .unwrap();
                        debug!("UserSelection::ImportFrom(path, pwd, salt_pos)");

                        match file_handler::load(&path, &cr, import_from_default_location) {
                            Err(error) => {
                                error!("Could not import... {:?}", error);
                                let _ = s.editor.show_message(
                                    "Could not import...",
                                    vec![UserOption::ok()],
                                    MessageSeverity::Error,
                                ).await;
                            }
                            Ok(rkl_content) => {
                                let message =
                                    format!("Imported {} entries!", &rkl_content.entries.len());
                                debug!("{}", message);
                                // Mark contents changed
                                s.contents_changed = true;
                                // Do the merge
                                s.safe.merge(rkl_content.entries);
                                // Replace the configuration
                                s.configuration.system = rkl_content.system_conf;
                                // Make the last_sync_version equal to the local one.
                                s.configuration.update_system_last_sync();

                                let _ = s.editor.show_message(
                                    &message,
                                    vec![UserOption::ok()],
                                    MessageSeverity::default(),
                                ).await;
                            }
                        };
                    }
                    _ => {}
                };

                Box::pin(future::ready(UserSelection::GoTo(Menu::Main)))
            }
            UserSelection::GoTo(Menu::ShowConfiguration) => {
                debug!("UserSelection::GoTo(Menu::ShowConfiguration)");
                s.editor.show_configuration(
                    s.configuration.nextcloud.clone(),
                    s.configuration.dropbox.clone(),
                    s.configuration.general.clone(),
                )
            }
            UserSelection::GenerateBrowserExtensionToken => {
                debug!("UserSelection::GenerateBrowserExtensionToken");
                let new_token = rs_password_utils::dice::generate_with_separator(
                    s.props.generated_passphrases_words_count() as usize,
                    "_",
                );
                let mut updated_gen_conf = s.configuration.general.clone();
                updated_gen_conf.browser_extension_token = Some(new_token);
                s.editor.show_configuration(
                    s.configuration.nextcloud.clone(),
                    s.configuration.dropbox.clone(),
                    updated_gen_conf,
                )
            }
            UserSelection::UpdateConfiguration(new_conf) => {
                debug!("UserSelection::UpdateConfiguration");
                if new_conf.nextcloud.is_filled() && new_conf.dropbox.is_filled() {
                    error!("Cannot update the configuration because both Nextcloud and Dropbox are configured");
                    s.editor.show_message("Having both Nextcloud and Dropbox configured may lead to unexpected state and currently is not allowed.\
                    Please configure only one of them.", vec![UserOption::ok()], MessageSeverity::Error).await;
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
                } else {
                    s.configuration.nextcloud = new_conf.nextcloud;
                    s.configuration.dropbox = new_conf.dropbox;
                    if s.configuration.general != new_conf.general {
                        debug!("General configuration changed");
                        s.contents_changed = true;
                        s.configuration.general = new_conf.general;
                    }
                    if s.configuration.nextcloud.is_filled() {
                        debug!("A valid configuration for Nextcloud synchronization was found after being updated by the User. Spawning \
                            nextcloud sync task");
                        s.contents_changed = true;
                        // Stop the synchronizer if running
                        let stopped = s.nc_synchronizer.stop();
                        if stopped.is_err() {
                            s.editor.show_message("Could not stop the nextcloud synchronizer.", vec![UserOption::ok()], MessageSeverity::Error).await;
                        }
                    }
                    if s.configuration.dropbox.is_filled() {
                        debug!("A valid configuration for dropbox synchronization was found after being updated by the User. Spawning \
                            dropbox sync task");
                        s.contents_changed = true;
                        // Stop the synchronizer if running
                        let stopped = s.dbx_synchronizer.stop();
                        if stopped.is_err() {
                            s.editor.show_message("Could not stop the Dropbox synchronizer.", vec![UserOption::ok()], MessageSeverity::Error).await;
                        }
                    }
                    Box::pin(future::ready(UserSelection::GoTo(Menu::Main)))
                }
            }
            UserSelection::AddToClipboard(content) => {
                debug!("UserSelection::AddToClipboard");
                let res = terminal_clipboard::set_string(content).map_err(|error| {
                    errors::RustKeylockError::GeneralError(error.to_string())
                });
                match res {
                    Ok(_) => {
                        let _ = s.editor.show_message("Copied! ", vec![UserOption::ok()], MessageSeverity::default()).await;
                    }
                    Err(error) => {
                        error!("Could not copy: {:?}", error);
                        let error_message = format!("Could not copy... Reason: {}", error);
                        let _ = s.editor.show_message(&error_message, vec![UserOption::ok()], MessageSeverity::Error).await;
                    }
                };
            
                // Do not change Menu
                Box::pin(future::ready(UserSelection::GoTo(Menu::Current)))
            }
            UserSelection::GoTo(Menu::WaitForDbxTokenCallback(url)) => {
                debug!("UserSelection::GoTo(Menu::WaitForDbxTokenCallback)");
                match dropbox::retrieve_token(url).await {
                    Ok(token) => {
                        if token.is_empty() {
                            let _ = s.editor.show_message(
                                "Empty Dropbox Authentication token was retrieved.",
                                vec![UserOption::ok()],
                                MessageSeverity::Error,
                            );
                            Box::pin(future::ready(UserSelection::GoTo(Menu::ShowConfiguration)))
                        } else {
                            Box::pin(future::ready(UserSelection::GoTo(Menu::SetDbxToken(token))))
                        }
                    }
                    Err(error) => {
                        error!(
                            "Error while retrieving Dropbox Authentication token: {} ({:?})",
                            error, error
                        );
                        let _ = s.editor.show_message(
                            &format!(
                                "Error while retrieving Dropbox Authentication token: {}",
                                error
                            ),
                            vec![UserOption::ok()],
                            MessageSeverity::Error,
                        ).await;
                        Box::pin(future::ready(UserSelection::GoTo(Menu::ShowConfiguration)))
                    }
                }
            }
            UserSelection::GoTo(Menu::SetDbxToken(token)) => {
                debug!("UserSelection::GoTo(Menu::SetDbxToken)");
                let tok_res = dropbox::DropboxConfiguration::new(token);
                match tok_res {
                    Ok(dbx_conf) => {
                        s.contents_changed = true;
                        s.configuration.dropbox = dbx_conf;
                        Box::pin(future::ready(UserSelection::GoTo(Menu::ShowConfiguration)))
                    }
                    Err(error) => {
                        error!("Could not set the Dropbox token: {:?}", error);
                        let _ = s.editor.show_message("Could not obtain the Dropbox token. Please see the logs for more details.", vec![UserOption::ok()], MessageSeverity::Error);
                        Box::pin(future::ready(UserSelection::GoTo(Menu::ShowConfiguration)))
                    }
                }
            }
            UserSelection::GeneratePassphrase(index_opt, mut entry) => {
                debug!("UserSelection::GoTo(Menu::GeneratePassphrase)");
                entry.pass = rs_password_utils::dice::generate_with_separator(
                    s.props.generated_passphrases_words_count() as usize,
                    "_"
                );
                match index_opt {
                    Some(index) => s
                        .editor
                        .show_entry(entry, index, EntryPresentationType::Edit),
                    None => {
                        s.editor.show_menu(Menu::NewEntry(Some(entry)))
                    },
                }
            }
            UserSelection::CheckPasswords => {
                debug!("UserSelection::CheckPasswords");
                match handle_check_passwords(&mut s.safe, &RklPasswordChecker::default()).await {
                    Ok(mr) => {
                        let _ = s
                            .editor
                            .show_message(&mr.message, mr.user_options, mr.severity).await;
                        Box::pin(future::ready(UserSelection::GoTo(Menu::EntriesList(Some("".to_string())))))
                    }
                    Err(error) => {
                        let _ = s.editor.show_message(
                            error.to_string().as_str(),
                            vec![UserOption::ok()],
                            MessageSeverity::Error,
                        ).await;
                        Box::pin(future::ready(UserSelection::GoTo(Menu::EntriesList(Some("".to_string())))))
                    }
                }
            }
            UserSelection::GoTo(Menu::Current) => {
                debug!("UserSelection::GoTo(Menu::Current)");
                s.editor.show_menu(Menu::Current)
            }
            other => {
                let message = format!("Bug: User Selection '{:?}' should not be handled in the main loop. Please, consider opening a bug \
                                       to the developers.",
                                      &other);
                error!("{}", message);
                panic!("{}", message)
            }
        };
        
        // Prepare all the possible futures from which we expect possible user_selection
        let nc_synchronizer_clonne = s.nc_synchronizer.clone();
        let dbx_synchronizer_clone = s.dbx_synchronizer.clone();
        let mut nc_future = nc_synchronizer_clonne.execute().fuse();
        let mut dbx_future = dbx_synchronizer_clone.execute().fuse();
        let mut fused_user_selection_future = user_selection_future.fuse();
        let mut inactivity_timeout_future = Box::pin(sleep(Duration::from_secs(s.props.idle_timeout_seconds() as u64))).fuse();

        let mut loop_result;
        loop {
            // Get the first future that completes
            loop_result = select! {
                selection_from_future = fused_user_selection_future => {
                    LoopResult::LoopUserSelection(selection_from_future)
                },
                sync_status_res = nc_future => {
                    if sync_status_res == Ok(SyncStatus::None) {
                        LoopResult::Ignore("nextcloud")
                    } else {
                        LoopResult::LoopSyncStatus(sync_status_res, "nextcloud")
                    }
                },
                sync_status_res = dbx_future => {
                    if sync_status_res == Ok(SyncStatus::None) {
                        LoopResult::Ignore("dropbox")
                    } else {
                        LoopResult::LoopSyncStatus(sync_status_res, "dropbox")
                    }
                },
                _ = inactivity_timeout_future => {
                    LoopResult::Timeout
                },
            };
            match loop_result {
                LoopResult::Ignore(_) => {/* Ignore this. Continue the loop */},
                _ => break,
            }
        }

        std::mem::drop(fused_user_selection_future);

        match loop_result {
            LoopResult::LoopUserSelection(selection) => {
                s.user_selection = selection;
            },
            LoopResult::LoopSyncStatus(sync_status_res, synchronizer_name) => {
                let (selection, stop_synchronizers) = handle_sync_status(&s.editor, sync_status_res, FILENAME, synchronizer_name).await;
                s.user_selection = selection;
                if stop_synchronizers {
                    let _ = s.nc_synchronizer.stop();
                    let _ = s.dbx_synchronizer.stop();
                }
            },
            LoopResult::Timeout => {
                warn!("Idle time of {} seconds elapsed! Locking...", s.props.idle_timeout_seconds());
                let message = format!("Idle time of {} seconds elapsed! Locking...", s.props.idle_timeout_seconds());
                let _ = s.editor.show_message(&message, vec![UserOption::ok()], MessageSeverity::default()).await;
                s.user_selection = UserSelection::GoTo(Menu::TryPass(false))
            }
            LoopResult::Ignore(synchronizer_name) => {
                let (selection, stop_synchronizers) = handle_sync_status(&s.editor, Ok(SyncStatus::None), FILENAME, synchronizer_name).await;
                s.user_selection = selection;
                if stop_synchronizers {
                    let _ = s.nc_synchronizer.stop();
                    let _ = s.dbx_synchronizer.stop();
                }
            },
        }

        Ok((s, stop))
    }
}

#[derive(Debug, PartialEq)]
enum LoopResult {
    LoopUserSelection(UserSelection),
    LoopSyncStatus(errors::Result<SyncStatus>, &'static str),
    Timeout,
    Ignore(&'static str),
}

async fn handle_sync_status(editor: &Box<dyn AsyncEditor>, sync_status_res: errors::Result<SyncStatus>, filename: &str, synchronizer_name: &str) -> (UserSelection, bool) {
    if sync_status_res.is_err() {
        error!("Error during {synchronizer_name} sync: {:?}", sync_status_res);
        let _ = editor.show_message(&format!("Synchronization error occured. Please see the logs for more details."), vec![UserOption::ok()], MessageSeverity::Error).await;
        (UserSelection::GoTo(Menu::Current), true)
    } else {
        match sync_status_res.unwrap() {
            SyncStatus::UploadSuccess(who) => {
                debug!("The {} server was updated with the local data", who);
                let _ = editor.show_message(&format!("The {} server was updated with the local data", who), vec![UserOption::ok()], MessageSeverity::Info).await;
                (UserSelection::GoTo(Menu::Save(true)), false)
            }
            SyncStatus::NewAvailable(who, downloaded_filename) => {
                debug!("Downloaded new data from the {} server.", who);
                let selection = editor.show_message(&format!("Downloaded new data from the {} server. Do you want to apply them locally now?", who),
                                                vec![UserOption::yes(), UserOption::no()],
                                                MessageSeverity::Info).await;

                debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
                if selection == UserSelection::UserOption(UserOption::yes()) {
                    debug!("Replacing the local file with the one downloaded from the server");
                    let _ = file_handler::replace(&downloaded_filename, filename);
                    (UserSelection::GoTo(Menu::TryPass(true)), true)
                } else {
                    (UserSelection::GoTo(Menu::Current), true)
                }
            }
            SyncStatus::NewToMerge(who, downloaded_filename) => {
                debug!("Downloaded data from the {} server, but conflicts were identified. The contents will be merged.", who);
                let selection =
                    editor.show_message(&format!("Downloaded data from the {} server, but conflicts were identified. The contents will be merged \
                                but nothing will be saved. You will need to explicitly save after reviewing the merged data. Do you \
                                want to do the merge now?", who),
                                    vec![UserOption::yes(), UserOption::no()],
                                    MessageSeverity::Info).await;

                if selection == UserSelection::UserOption(UserOption::yes()) {
                    debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
                    debug!("Merging the local data with the downloaded from the server");

                    match editor.show_password_enter().await {
                        UserSelection::ProvidedPassword(pwd, salt_pos) => {
                            (UserSelection::ImportFromDefaultLocation(downloaded_filename, pwd, salt_pos), true)
                        }
                        other => {
                            let message = format!("Expected a ProvidedPassword but received '{:?}'. Please, consider opening a bug to the \
                                            developers.",
                                                &other);
                            error!("{}", message);
                            let _ =
                                editor.show_message("Unexpected result when waiting for password. See the logs for more details. Please \
                                                consider opening a bug to the developers.",
                                                vec![UserOption::ok()],
                                                MessageSeverity::Error).await;
                            (UserSelection::GoTo(Menu::TryPass(false)), true)
                        }
                    }
                } else {
                    (UserSelection::GoTo(Menu::Current), true)
                }
            }
            SyncStatus::None => {
                let _ = editor.show_message(&format!("{synchronizer_name} synchronization got into unexpected Status. This should never happen theoretically. Please consider opening a bug to the developers."), vec![UserOption::ok()], MessageSeverity::Error).await;
                (UserSelection::GoTo(Menu::Current), true)
            }
        }
    }
}

async fn handle_check_passwords<T>(
    safe: &mut Safe,
    password_checker: &T,
) -> errors::Result<EditorShowMessageWrapper>
where
    T: PasswordChecker,
{
    let mut pwned_passwords_found: Option<Vec<String>> = None;
    for index in 0..safe.get_entries().len() {
        let mut entry = safe.get_entry_decrypted(index);
        let pwned_res = password_checker.is_unsafe(&entry.pass).await;
        if pwned_res.is_ok() {
            let is_pwned = pwned_res.unwrap();
            if pwned_passwords_found.is_none() {
                pwned_passwords_found = Some(Vec::new());
            }
            if is_pwned {
                pwned_passwords_found
                    .as_mut()
                    .unwrap()
                    .push(entry.name.clone());
            }
            if is_pwned != entry.meta.leaked_password {
                entry.meta.leaked_password = is_pwned;
                safe.replace_entry(index, entry)?;
            }
        } else {
            error!("Error while checking passwords: {}", pwned_res.unwrap_err());
            pwned_passwords_found = None;
            break;
        }
    }
    if pwned_passwords_found.is_none() {
        if !safe.get_entries().is_empty() {
            Ok(EditorShowMessageWrapper::new(
                "Error while checking passwords health. Please see the logs for more details.",
                vec![UserOption::ok()],
                MessageSeverity::Error,
            ))
        } else {
            Ok(EditorShowMessageWrapper::new(
                "No entries to check",
                vec![UserOption::ok()],
                MessageSeverity::Info,
            ))
        }
    } else {
        if !pwned_passwords_found.as_ref().unwrap().is_empty() {
            let message = format!(
                "The following entries have leaked passwords: {}! Please change them immediately!",
                pwned_passwords_found.unwrap().join(",")
            );
            info!("{}", message);
            Ok(EditorShowMessageWrapper::new(
                &message,
                vec![UserOption::ok()],
                MessageSeverity::Warn,
            ))
        } else {
            let message = format!("The passwords of the entries look ok!");
            debug!("{}", message);
            Ok(EditorShowMessageWrapper::new(
                &message,
                vec![UserOption::ok()],
                MessageSeverity::Info,
            ))
        }
    }
}

fn bcrypt_cost_from_file() -> u32 {
    let props = file_handler::load_properties(PROPS_FILENAME).unwrap_or_default();

    // The bcrypt cost changed in 0.17.0 from 7 to 12
    if rkl_version() == props.version() || file_handler::is_first_run(FILENAME) {
        BCRYPT_COST
    } else {
        BCRYPT_COST_PRE_0_17_0
    }
}

async fn handle_provided_password_for_init(
    provided_password: UserSelection,
    filename: &str,
    safe: &mut Safe,
    configuration: &mut RklConfiguration,
    editor: &Box<dyn AsyncEditor>,
) -> (UserSelection, datacrypt::BcryptAes) {
    let user_selection: UserSelection;
    match provided_password {
        UserSelection::ProvidedPassword(pwd, salt_pos) => {
            let bcrypt_cost = bcrypt_cost_from_file();
            info!("Using bcrypt with cost {bcrypt_cost}");
            // Create cryptor for decryption
            let cr: BcryptAes =
                file_handler::create_bcryptor(filename, pwd.to_string(), bcrypt_cost, *salt_pos, false, true)
                    .unwrap();
            // Try to decrypt and load the Entries
            let retrieved_entries = match file_handler::load(filename, &cr, true) {
                // Success, go to the List of entries
                Ok(rkl_content) => {
                    user_selection = UserSelection::GoTo(Menu::EntriesList(Some("".to_string())));
                    // Set the retrieved configuration
                    let new_rkl_conf = RklConfiguration::from((
                        rkl_content.nextcloud_conf,
                        rkl_content.dropbox_conf,
                        rkl_content.system_conf,
                        rkl_content.general_conf,
                    ));
                    *configuration = new_rkl_conf;
                    rkl_content.entries
                }
                // Failure cases
                Err(error) => {
                    match error {
                        // If Parse error, try recovery
                        errors::RustKeylockError::ParseError(desc) => {
                            warn!("{}", desc);
                            user_selection = UserSelection::GoTo(Menu::TryFileRecovery);
                            Vec::new()
                        }
                        // In all the other cases, notify the User and retry
                        _ => {
                            error!("{}", error);
                            let s =
                                editor.show_message("Wrong password or number! Please make sure that both the password and number that you \
                                                   provide are correct.",
                                                    vec![UserOption::ok()],
                                                    MessageSeverity::Error)
                                                    .await;
                            match s {
                                _ => {
                                    user_selection = UserSelection::GoTo(Menu::TryPass(false));
                                    Vec::new()
                                }
                            }
                        }
                    }
                }
            };

            safe.clear();
            safe.add_all(retrieved_entries);
            debug!(
                "Retrieved entries. Returning {:?} with {} entries ",
                &user_selection,
                safe.entries.len()
            );
            // Return cryptor with the correct current bcrypt cost
            let cr = if bcrypt_cost != BCRYPT_COST {
                file_handler::create_bcryptor(filename, pwd.to_string(), BCRYPT_COST, *salt_pos, false, true)
                    .unwrap()
            } else {
                cr
            };
            (user_selection, cr)
        }
        UserSelection::GoTo(Menu::Exit) => {
            debug!("UserSelection::GoTo(Menu::Exit) was called before providing credentials");
            let cr = file_handler::create_bcryptor(filename, "dummy".to_string(), 1, 33, false, true)
                .unwrap();
            let exit_selection = UserSelection::GoTo(Menu::ForceExit);
            (exit_selection, cr)
        }
        other => {
            panic!("Wrong initialization sequence... The editor.show_password_enter must always return a UserSelection::ProvidedPassword. \
                    Please, consider opening a bug to the developers.: {:?}", other)
        }
    }
}

/// Trait to be implemented by various different `Editor`s (Shell, Web, Android, other...).
///
/// It drives the interaction with the Users
pub trait Editor {
    /// Shows the interface for entering a Password and a Number.
    fn show_password_enter(&self) -> UserSelection;
    /// Shows the interface for changing a Password and/or a Number.
    fn show_change_password(&self) -> UserSelection;
    /// Shows the specified `Menu` to the User.
    fn show_menu(&self, menu: &Menu) -> UserSelection;
    /// Shows the provided entries to the User. The provided entries are already filtered with the filter argument.
    fn show_entries(&self, entries: Vec<Entry>, filter: String) -> UserSelection;
    /// Shows the provided entry details to the User following a PresentationType.
    fn show_entry(
        &self,
        entry: Entry,
        index: usize,
        presentation_type: EntryPresentationType,
    ) -> UserSelection;
    /// Shows the Exit `Menu` to the User.
    fn exit(&self, contents_changed: bool) -> UserSelection;
    /// Shows the configuration screen.
    fn show_configuration(
        &self,
        nextcloud: NextcloudConfiguration,
        dropbox: DropboxConfiguration,
        general: GeneralConfiguration,
    ) -> UserSelection;
    /// Shows a message to the User.
    /// Along with the message, the user should select one of the offered `UserOption`s.
    fn show_message(
        &self,
        message: &str,
        options: Vec<UserOption>,
        severity: MessageSeverity,
    ) -> UserSelection;

    /// Sorts the supplied entries.
    fn sort_entries(&self, entries: &mut [Entry]) {
        entries.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
    }
}

/// Trait to be implemented by various different `Editor`s (Shell, Web, Android, other...).
///
/// It drives the interaction with the Users
#[async_trait]
pub trait AsyncEditor {
    /// Shows the interface for entering a Password and a Number.
    async fn show_password_enter(&self) -> UserSelection;
    /// Shows the interface for changing a Password and/or a Number.
    async fn show_change_password(&self) -> UserSelection;
    /// Shows the specified `Menu` to the User.
    async fn show_menu(&self, menu: Menu) -> UserSelection;
    /// Shows the provided entries to the User. The provided entries are already filtered with the filter argument.
    async fn show_entries(&self, entries: Vec<Entry>, filter: String) -> UserSelection;
    /// Shows the provided entry details to the User following a presentation type.
    async fn show_entry(
        &self,
        entry: Entry,
        index: usize,
        presentation_type: EntryPresentationType,
    ) -> UserSelection;
    /// Shows the Exit `Menu` to the User.
    async fn exit(&self, contents_changed: bool) -> UserSelection;
    /// Shows the configuration screen.
    async fn show_configuration(
        &self,
        nextcloud: NextcloudConfiguration,
        dropbox: DropboxConfiguration,
        general: GeneralConfiguration,
    ) -> UserSelection;
    /// Shows a message to the User.
    /// Along with the message, the user should select one of the offered `UserOption`s.
    async fn show_message(
        &self,
        message: &str,
        options: Vec<UserOption>,
        severity: MessageSeverity,
    ) -> UserSelection;

    /// Sorts the supplied entries.
    fn sort_entries(&self, entries: &mut [Entry]) {
        entries.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
    }

    /// Denotes if the rest_server should be start or nor
    fn start_rest_server(&self) -> bool;
}

#[cfg(test)]
mod unit_tests {
    use async_trait::async_trait;

    use crate::api::safe::Safe;
    use crate::api::EntryMeta;

    use super::api::Entry;
    use super::*;

    struct AlwaysOkTruePasswordChecker {}

    #[async_trait]
    impl PasswordChecker for AlwaysOkTruePasswordChecker {
        async fn is_unsafe(&self, _: &str) -> errors::Result<bool> {
            Ok(true)
        }
    }

    struct AlwaysOkFalsePasswordChecker {}

    #[async_trait]
    impl PasswordChecker for AlwaysOkFalsePasswordChecker {
        async fn is_unsafe(&self, _: &str) -> errors::Result<bool> {
            Ok(false)
        }
    }

    struct AlwaysErrorPasswordChecker {}

    #[async_trait]
    impl PasswordChecker for AlwaysErrorPasswordChecker {
        async fn is_unsafe(&self, _: &str) -> errors::Result<bool> {
            Err(errors::RustKeylockError::GeneralError("".to_string()))
        }
    }

    #[tokio::test]
    async fn test_handle_check_passwords() {
        let mut safe = Safe::default();

        // No entries to check
        let smw = handle_check_passwords(&mut safe, &AlwaysOkTruePasswordChecker {})
            .await
            .unwrap();
        assert!(&smw.message == "No entries to check");

        // Entries Ok and healthy
        safe.add_entry(Entry::new(
            "name".to_string(),
            "url".to_string(),
            "user".to_string(),
            "pass".to_string(),
            "desc".to_string(),
            EntryMeta::default(),
        ));
        let smw = handle_check_passwords(&mut safe, &AlwaysOkFalsePasswordChecker {})
            .await
            .unwrap();
        assert!(&smw.message == "The passwords of the entries look ok!");

        // Entries Ok but not healthy
        let smw = handle_check_passwords(&mut safe, &AlwaysOkTruePasswordChecker {})
            .await
            .unwrap();
        assert!(&smw.message == "The following entries have leaked passwords: name! Please change them immediately!");

        // Entries Error
        let smw = handle_check_passwords(&mut safe, &AlwaysErrorPasswordChecker {})
            .await
            .unwrap();
        assert!(
            &smw.message
                == "Error while checking passwords health. Please see the logs for more details."
        );
    }
}
