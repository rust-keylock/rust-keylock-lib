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

extern crate base64;
extern crate clipboard;
extern crate crypto;
extern crate dirs;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate hyper_tls;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate openssl_probe;
extern crate rand;
extern crate secstr;
extern crate sha3;
extern crate toml;
extern crate xml;

use self::api::{
    Props,
    RklContent,
    SystemConfiguration,
};
pub use self::api::{
    Entry as Entry,
    Menu as Menu,
    MessageSeverity as MessageSeverity,
    RklConfiguration as RklConfiguration,
    UserOption as UserOption,
    UserSelection as UserSelection,
};
pub use self::api::safe::Safe as Safe;
use self::api::UiCommand;
use self::asynch::{AsyncEditorFacade, AsyncTask};
pub use self::asynch::nextcloud;
use std::error::Error;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time;

mod file_handler;
mod errors;
mod protected;
pub mod datacrypt;
mod asynch;
mod api;
mod selection_handling;

const FILENAME: &'static str = ".sec";
const PROPS_FILENAME: &'static str = ".props";

/// Takes a reference of `Editor` implementation as argument and executes the _rust-keylock_ logic.
/// The `Editor` is responsible for the interaction with the user. Currently there are `Editor` implementations for __shell__ and for __Android__.
pub fn execute_async<T: AsyncEditor>(editor: &T) {
    openssl_probe::init_ssl_cert_env_vars();
    info!("Starting rust-keylock...");
    let props = match file_handler::load_properties(PROPS_FILENAME) {
        Ok(m) => m,
        Err(error) => {
            error!("Could not load properties. Using defaults. The error was: {}", error.description());
            Props::default()
        }
    };

    let (command_tx, command_rx) = mpsc::channel();
    let (ui_tx, ui_rx) = mpsc::channel();
    let mut ui_rx_vec = Vec::new();

    let mut editor_facade = asynch::AsyncEditorFacade::new(ui_rx, command_tx, props);

    let _ = thread::spawn(move || {
        debug!("Spawned async task");
        do_execute(&mut editor_facade);
    });

    // The select macro is a nightly feature and is going to be deprecated. Use polling until a better solution is found.
    // https://github.com/rust-lang/rust/issues/27800
    loop {
        thread::park_timeout(asynch::ASYNC_EDITOR_PARK_TIMEOUT);
        match command_rx.try_recv() {
            Ok(command) => {
                match command {
                    UiCommand::ShowPasswordEnter => {
                        ui_rx_vec.push(editor.show_password_enter());
                    }
                    UiCommand::ShowChangePassword => {
                        ui_rx_vec.push(editor.show_change_password());
                    }
                    UiCommand::ShowMenu(menu, safe, rkl_configuration) => {
                        ui_rx_vec.push(editor.show_menu(&menu, &safe, &rkl_configuration));
                    }
                    UiCommand::ShowMessage(message, options, severity) => {
                        ui_rx_vec.push(editor.show_message(&message, options, severity));
                    }
                    UiCommand::Exit(contents_changed) => {
                        ui_rx_vec.push(editor.exit(contents_changed));
                    }
                }
            }
            Err(TryRecvError::Disconnected) => {
                break;
            }
            Err(TryRecvError::Empty) => { /* ignore */ }
        }

        match try_recv_from_vec(&mut ui_rx_vec) {
            Some(sel) => {
                let should_break = sel == UserSelection::GoTo(Menu::ForceExit);
                send(&ui_tx, sel);
                if should_break {
                    break;
                }
            }
            None => {}
        }
    }
    info!("Exiting rust-keylock...");
}

fn try_recv_from_vec(rxs: &mut Vec<Receiver<UserSelection>>) -> Option<UserSelection> {
    let mut res_opt: Option<UserSelection> = None;
    let mut i = 0;
    let mut remove_element = false;

    for rx in rxs.iter() {
        match rx.try_recv() {
            Ok(res) => {
                res_opt = Some(res);
                remove_element = true;
                break;
            }
            Err(TryRecvError::Disconnected) => {
                remove_element = true;
                break;
            }
            Err(TryRecvError::Empty) => { /* ignore */ }
        }

        i = i + 1;
    }

    if remove_element {
        rxs.remove(i);
    }
    res_opt
}

pub fn execute<T: Editor>(editor: &T) {
    openssl_probe::init_ssl_cert_env_vars();
    info!("Starting rust-keylock...");
    let props = match file_handler::load_properties(PROPS_FILENAME) {
        Ok(m) => m,
        Err(error) => {
            error!("Could not load properties. Using defaults. The error was: {}", error.description());
            Props::default()
        }
    };

    let (command_tx, command_rx) = mpsc::channel();
    let (ui_tx, ui_rx) = mpsc::channel();

    let mut async_editor = asynch::AsyncEditorFacade::new(ui_rx, command_tx, props);

    let _ = thread::spawn(move || {
        debug!("Spawned async task");
        do_execute(&mut async_editor);
    });

    loop {
        match command_rx.recv() {
            Ok(command) => {
                match command {
                    UiCommand::ShowPasswordEnter => {
                        println!("Showing password");
                        send(&ui_tx, editor.show_password_enter())
                    }
                    UiCommand::ShowChangePassword => {
                        println!("Showing change password");
                        send(&ui_tx, editor.show_change_password())
                    }
                    UiCommand::ShowMenu(menu, safe, rkl_configuration) => {
                        println!("Showing menu {:?}", menu);
                        let sel = editor.show_menu(&menu, &safe, &rkl_configuration);
                        let should_break = sel == UserSelection::GoTo(Menu::ForceExit);
                        send(&ui_tx, sel);
                        if should_break {
                            break;
                        }
                    }
                    UiCommand::ShowMessage(message, options, severity) => {
                        println!("Showing message");
                        send(&ui_tx, editor.show_message(&message, options, severity))
                    }
                    UiCommand::Exit(contents_changed) => {
                        println!("Exiting");
                        let sel = editor.exit(contents_changed);
                        let should_break = sel == UserSelection::GoTo(Menu::ForceExit);
                        send(&ui_tx, sel);
                        if should_break {
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                error!("Error while receiving command from spawned execution: {:?}", error);
            }
        }
    }
    info!("Exiting rust-keylock...");
}

fn send(tx: &Sender<UserSelection>, user_selection: UserSelection) {
    match tx.send(user_selection) {
        Ok(_) => { /* ignore*/ }
        Err(error) => error!("Could not send User Selection to the core lib: {:?}", error),
    }
}

fn do_execute(editor: &mut AsyncEditorFacade) {
    // Holds the UserSelections
    let mut user_selection;

    // Keeps the sensitive data
    let mut safe = Safe::new();
    // Keeps the configuration data
    let mut configuration = RklConfiguration::from((asynch::nextcloud::NextcloudConfiguration::default(), SystemConfiguration::default()));
    // Signals changes that are not saved
    let mut contents_changed = false;
    let mut async_task_handle: Option<asynch::AsyncTaskHandle> = None;

    // Create a Cryptor
    let mut cryptor = {
        // First time run?
        let provided_password = if file_handler::is_first_run(FILENAME) {
            editor.show_change_password()
        } else {
            editor.show_password_enter()
        };

        // Take the provided password and do the initialization
        let (us, cr) = handle_provided_password_for_init(provided_password, FILENAME, &mut safe, &mut configuration, editor);
        // If a valid nextcloud configuration is in place, spawn the background async execution
        if configuration.nextcloud.is_filled() {
            let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &configuration, &async_task_handle);
            async_task_handle = Some(handle);
            editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
        }
        // Set the UserSelection
        user_selection = us;
        cr
    };

    loop {
        editor.sort_entries(&mut safe.entries);
        // Handle
        user_selection = match user_selection {
            UserSelection::GoTo(Menu::TryPass) => {
                // Cancel any pending background tasks
                let _ = async_task_handle.as_ref().map(|handle| handle.stop());
                let (user_selection, cr) =
                    handle_provided_password_for_init(editor.show_password_enter(), FILENAME, &mut safe, &mut configuration, editor);
                // If a valid nextcloud configuration is in place, spawn the background async execution
                if configuration.nextcloud.is_filled() {
                    debug!("A valid configuration for Nextcloud synchronization was found. Spawning async tasks");
                    let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &configuration, &async_task_handle);
                    async_task_handle = Some(handle);
                    editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
                }
                cryptor = cr;
                user_selection
            }
            UserSelection::GoTo(Menu::Main) => {
                debug!("UserSelection::GoTo(Menu::Main)");
                let m = editor.show_menu(&Menu::Main, &safe, &configuration);
                debug!("UserSelection::GoTo(Menu::Main) returns {:?}", &m);
                m
            }
            UserSelection::GoTo(Menu::ChangePass) => {
                debug!("UserSelection::GoTo(Menu::ChangePass)");
                contents_changed = true;
                editor.show_change_password()
            }
            UserSelection::ProvidedPassword(pwd, salt_pos) => {
                debug!("UserSelection::GoTo(Menu::ProvidedPassword)");
                cryptor = file_handler::create_bcryptor(FILENAME, pwd, salt_pos, true, true).unwrap();
                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::EntriesList(filter)) => {
                debug!("UserSelection::GoTo(Menu::EntriesList) with filter '{}'", &filter);
                safe.set_filter(filter.clone());
                editor.show_menu(&Menu::EntriesList(filter), &safe, &configuration)
            }
            UserSelection::GoTo(Menu::NewEntry) => {
                debug!("UserSelection::GoTo(Menu::NewEntry)");
                editor.show_menu(&Menu::NewEntry, &safe, &configuration)
            }
            UserSelection::GoTo(Menu::ShowEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::ShowEntry(index))");
                editor.show_menu(&Menu::ShowEntry(index), &safe, &configuration)
            }
            UserSelection::GoTo(Menu::EditEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::EditEntry(index))");
                editor.show_menu(&Menu::EditEntry(index), &safe, &configuration)
            }
            UserSelection::GoTo(Menu::DeleteEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::DeleteEntry(index))");
                editor.show_menu(&Menu::DeleteEntry(index), &safe, &configuration)
            }
            UserSelection::GoTo(Menu::Save) => {
                debug!("UserSelection::GoTo(Menu::Save)");
                let _ = configuration.update_system_for_save().map_err(|error| error!("Cannot update system for save: {:?}", error));
                // Reset the filter
                safe.set_filter("".to_string());
                let rkl_content = RklContent::from((&safe, &configuration.nextcloud, &configuration.system));
                let res = rkl_content.and_then(|c| file_handler::save(c, FILENAME, &cryptor, true));
                match res {
                    Ok(_) => {
                        // Cancel any pending background tasks
                        let _ = async_task_handle.as_ref().map(|handle| handle.stop());
                        // Clean the flag for unsaved data
                        contents_changed = false;
                        // Start a new background async task
                        let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &configuration, &async_task_handle);
                        async_task_handle = Some(handle);
                        editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
                        let _ = editor.show_message("Encrypted and saved successfully!", vec![UserOption::ok()], MessageSeverity::default());
                    }
                    Err(error) => {
                        let _ = editor.show_message("Could not save...", vec![UserOption::ok()], MessageSeverity::Error);
                        error!("Could not save... {:?}", error);
                    }
                };
                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::Exit) => {
                debug!("UserSelection::GoTo(Menu::Exit)");
                editor.exit(contents_changed)
            }
            UserSelection::GoTo(Menu::ForceExit) => {
                debug!("UserSelection::GoTo(Menu::ForceExit)");
                break;
            }
            UserSelection::NewEntry(entry) => {
                debug!("UserSelection::NewEntry(entry)");
                safe.add_entry(entry);
                contents_changed = true;
                UserSelection::GoTo(Menu::EntriesList("".to_string()))
            }
            UserSelection::ReplaceEntry(index, entry) => {
                debug!("UserSelection::ReplaceEntry(index, entry)");
                contents_changed = true;
                let _ = safe.replace_entry(index, entry).map_err(|err| {
                    let _ = editor.show_message(&format!("{:?}", err), vec![UserOption::ok()], MessageSeverity::Error);
                });
                UserSelection::GoTo(Menu::EntriesList(safe.get_filter()))
            }
            UserSelection::DeleteEntry(index) => {
                debug!("UserSelection::DeleteEntry(index)");
                let _ = safe.remove_entry(index).map_err(|err| {
                    let _ = editor.show_message(&format!("{:?}", err), vec![UserOption::ok()], MessageSeverity::Error);
                });
                contents_changed = true;
                UserSelection::GoTo(Menu::EntriesList("".to_string()))
            }
            UserSelection::GoTo(Menu::TryFileRecovery) => {
                debug!("UserSelection::GoTo(Menu::TryFileRecovery)");
                let _ = editor.show_message("The password entries are corrupted.\n\nPress Enter to attempt recovery...",
                                            vec![UserOption::ok()],
                                            MessageSeverity::Error);
                let mut rec_entries = match file_handler::recover(FILENAME, &cryptor) {
                    Ok(recovered_entries) => {
                        let message = r#"
Recovery succeeded...

Note the errors that caused the recovery. You may see some useful information about possible values that could not be recovered.
Press Enter to show the Recovered Entries and if you are ok with it, save them.

Warning: Saving will discard all the entries that could not be recovered.
"#;
                        let _ = editor.show_message(message, vec![UserOption::ok()], MessageSeverity::default());
                        contents_changed = true;
                        safe.entries.clear();
                        recovered_entries
                    }
                    Err(error) => {
                        let message = format!("Recovery failed... Reason {:?}", error);
                        error!("{}", &message);
                        let _ = editor.show_message("Recovery failed...", vec![UserOption::ok()], MessageSeverity::Error);
                        safe.entries.clone()
                    }
                };
                safe.entries.append(&mut rec_entries);

                UserSelection::GoTo(Menu::EntriesList("".to_string()))
            }
            UserSelection::GoTo(Menu::ExportEntries) => {
                debug!("UserSelection::GoTo(Menu::ExportEntries)");
                editor.show_menu(&Menu::ExportEntries, &safe, &configuration)
            }
            UserSelection::ExportTo(path) => {
                debug!("UserSelection::ExportTo(path)");
                let do_export = if file_handler::file_exists(&PathBuf::from(&path)) {
                    let selection = editor.show_message("This will overwrite an existing file. Do you want to proceed?",
                                                        vec![UserOption::yes(), UserOption::no()],
                                                        MessageSeverity::Warn);

                    debug!("The user selected {:?} as an answer for overwritine the file {}", selection, path);
                    if selection == UserSelection::UserOption(UserOption::yes()) {
                        true
                    } else {
                        false
                    }
                } else {
                    true
                };

                if do_export {
                    let rkl_content = RklContent::from((&safe, &configuration.nextcloud, &configuration.system));
                    let res = rkl_content.and_then(|c| file_handler::save(c, &path, &cryptor, false));
                    match res {
                        Ok(_) => {
                            let _ = editor.show_message("Export completed successfully!", vec![UserOption::ok()], MessageSeverity::default());
                        }
                        Err(error) => {
                            let _ = editor.show_message("Could not export...", vec![UserOption::ok()], MessageSeverity::Error);
                            error!("Could not export... {:?}", error);
                        }
                    };
                    UserSelection::GoTo(Menu::Main)
                } else {
                    UserSelection::GoTo(Menu::ExportEntries)
                }
            }
            UserSelection::GoTo(Menu::ImportEntries) => {
                debug!("UserSelection::GoTo(Menu::ImportEntries)");
                editor.show_menu(&Menu::ImportEntries, &safe, &configuration)
            }
            us @ UserSelection::ImportFrom(_, _, _) |
            us @ UserSelection::ImportFromDefaultLocation(_, _, _) => {
                let import_from_default_location = match us {
                    UserSelection::ImportFrom(_, _, _) => false,
                    UserSelection::ImportFromDefaultLocation(_, _, _) => true,
                    _ => false,
                };
                match us {
                    UserSelection::ImportFrom(path, pwd, salt_pos) |
                    UserSelection::ImportFromDefaultLocation(path, pwd, salt_pos) => {
                        let cr = file_handler::create_bcryptor(&path, pwd, salt_pos, false, import_from_default_location).unwrap();
                        debug!("UserSelection::ImportFrom(path, pwd, salt_pos)");

                        match file_handler::load(&path, &cr, import_from_default_location) {
                            Ok(rkl_content) => {
                                let message = format!("Imported {} entries!", &rkl_content.entries.len());
                                debug!("{}", message);
                                contents_changed = true;
                                safe.merge(rkl_content.entries);
                                let _ = editor.show_message(&message, vec![UserOption::ok()], MessageSeverity::default());
                            }
                            Err(error) => {
                                let _ = editor.show_message("Could not import...", vec![UserOption::ok()], MessageSeverity::Error);
                                error!("Could not import... {:?}", error);
                            }
                        };
                    }
                    _ => {}
                };

                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::ShowConfiguration) => {
                debug!("UserSelection::GoTo(Menu::ShowConfiguration)");
                editor.show_menu(&Menu::ShowConfiguration, &safe, &configuration)
            }
            UserSelection::UpdateConfiguration(new_conf) => {
                debug!("UserSelection::UpdateConfiguration");
                configuration.nextcloud = new_conf;
                if configuration.nextcloud.is_filled() {
                    debug!("A valid configuration for Nextcloud synchronization was found after being updated by the User. Spawning \
                            async tasks");
                    let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &configuration, &async_task_handle);
                    async_task_handle = Some(handle);
                    editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
                    contents_changed = true;
                }
                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::Synchronize) => {
                debug!("UserSelection::GoTo(Menu::Synchronize)");
                let (tx, rx) = mpsc::channel();
                let synchronizer = asynch::nextcloud::Synchronizer::new(&configuration.nextcloud, &configuration.system, tx, FILENAME).unwrap();
                synchronizer.execute();
                let to_ret = match rx.recv() {
                    Ok(res) => {
                        match res {
                            Ok(sync_status) => {
                                let mut tmp_user_selection = UserSelection::GoTo(Menu::Main);
                                handle_sync_status_success(sync_status, editor, FILENAME, &mut tmp_user_selection, false);
                                tmp_user_selection
                            }
                            Err(error) => {
                                let error_message = format!("Could not synchronize... Error detail: {:?}", error);
                                let _ = editor.show_message(&error_message, vec![UserOption::ok()], MessageSeverity::Error);
                                UserSelection::GoTo(Menu::ShowConfiguration)
                            }
                        }
                    }
                    Err(error) => {
                        let error_message = format!("Could not synchronize... Error detail: {:?}", error);
                        let _ = editor.show_message(&error_message, vec![UserOption::ok()], MessageSeverity::Error);
                        UserSelection::GoTo(Menu::ShowConfiguration)
                    }
                };

                to_ret
            }
            UserSelection::AddToClipboard(content) => {
                debug!("UserSelection::AddToClipboard");
                selection_handling::add_to_clipboard(content, editor)
            }
            UserSelection::GoTo(Menu::Current) => {
                debug!("UserSelection::GoTo(Menu::Current)");
                editor.show_menu(&Menu::Current, &safe, &configuration)
            }
            other => {
                let message = format!("Bug: User Selection '{:?}' should not be handled in the main loop. Please, consider opening a bug \
                                       to the developers.",
                                      &other);
                error!("{}", message);
                panic!(message)
            }
        }
    }
}

fn handle_sync_status_success(sync_status: asynch::nextcloud::SyncStatus,
                              editor: &Editor,
                              filename: &str,
                              user_selection: &mut UserSelection,
                              ignore_contents_identical_message: bool) {
    match sync_status {
        asynch::nextcloud::SyncStatus::UploadSuccess => {
            let _ =
                editor.show_message("The nextcloud server was updated with the local data", vec![UserOption::ok()], MessageSeverity::Info);
        }
        asynch::nextcloud::SyncStatus::NewAvailable(downloaded_filename) => {
            let selection = editor.show_message("Downloaded new data from the nextcloud server. Do you want to apply them locally now?",
                                                vec![UserOption::yes(), UserOption::no()],
                                                MessageSeverity::Info);

            debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
            if selection == UserSelection::UserOption(UserOption::yes()) {
                debug!("Replacing the local file with the one downloaded from the server");
                let _ = file_handler::replace(&downloaded_filename, filename);
                *user_selection = UserSelection::GoTo(Menu::TryPass);
            }
        }
        asynch::nextcloud::SyncStatus::NewToMerge(downloaded_filename) => {
            let selection =
                editor.show_message("Downloaded data from the nextcloud server, but conflicts were identified. The contents will be merged \
                                   but nothing will be saved. You will need to explicitly save after reviewing the merged data. Do you \
                                   want to do the merge now?",
                                    vec![UserOption::yes(), UserOption::no()],
                                    MessageSeverity::Info);

            debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
            if selection == UserSelection::UserOption(UserOption::yes()) {
                debug!("Merging the local data with the downloaded from the server");

                match editor.show_password_enter() {
                    UserSelection::ProvidedPassword(pwd, salt_pos) => {
                        *user_selection = UserSelection::ImportFromDefaultLocation(downloaded_filename, pwd, salt_pos);
                    }
                    other => {
                        let message = format!("Expected a ProvidedPassword but received '{:?}'. Please, consider opening a bug to the \
                                               developers.",
                                              &other);
                        error!("{}", message);
                        let _ =
                            editor.show_message("Unexpected result when waiting for password. See the logs for more details. Please \
                                                 consider opening a but to the developers.",
                                                vec![UserOption::ok()],
                                                MessageSeverity::Error);
                        *user_selection = UserSelection::GoTo(Menu::TryPass);
                    }
                }
            }
        }
        asynch::nextcloud::SyncStatus::None if !ignore_contents_identical_message => {
            let _ = editor.show_message("No need to sync. The contents are identical", vec![UserOption::ok()], MessageSeverity::Info);
        }
        _ => {
            // ignore
        }
    }
}

fn handle_provided_password_for_init(provided_password: UserSelection,
                                     filename: &str,
                                     safe: &mut Safe,
                                     configuration: &mut RklConfiguration,
                                     editor: &Editor)
                                     -> (UserSelection, datacrypt::BcryptAes) {
    let user_selection: UserSelection;
    match provided_password {
        UserSelection::ProvidedPassword(pwd, salt_pos) => {
            // New Cryptor here
            let cr = file_handler::create_bcryptor(filename, pwd.clone(), salt_pos, false, true).unwrap();
            // Try to decrypt and load the Entries
            let retrieved_entries = match file_handler::load(filename, &cr, true) {
                // Success, go to the Main menu
                Ok(rkl_content) => {
                    user_selection = UserSelection::GoTo(Menu::Main);
                    // Set the retrieved configuration
                    let new_rkl_conf = RklConfiguration::from((rkl_content.nextcloud_conf, rkl_content.system_conf));
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
                            error!("{}", error.description());
                            let s =
                                editor.show_message("Wrong password or number! Please make sure that both the password and number that you \
                                                   provide are correct. If this is the case, the rust-keylock data is corrupted and \
                                                   nothing can be done about it.",
                                                    vec![UserOption::ok()],
                                                    MessageSeverity::Error);
                            match s {
                                _ => {
                                    user_selection = UserSelection::GoTo(Menu::TryPass);
                                    Vec::new()
                                }
                            }
                        }
                    }
                }
            };

            safe.clear();
            safe.add_all(retrieved_entries);
            debug!("Retrieved entries. Returning {:?} with {} entries ", &user_selection, safe.entries.len());
            (user_selection, cr)
        }
        UserSelection::GoTo(Menu::Exit) => {
            debug!("UserSelection::GoTo(Menu::Exit) was called before providing credentials");
            let cr = file_handler::create_bcryptor(filename, "dummy".to_string(), 33, false, true).unwrap();
            let exit_selection = UserSelection::GoTo(Menu::ForceExit);
            (exit_selection, cr)
        }
        other => {
            panic!("Wrong initialization sequence... The editor.show_password_enter must always return a UserSelection::ProvidedPassword. \
                    Please, consider opening a bug to the developers.: {:?}", other)
        }
    }
}

fn spawn_nextcloud_async_task(filename: &str,
                              configuration: &RklConfiguration,
                              async_task_handle_opt: &Option<asynch::AsyncTaskHandle>)
                              -> (asynch::AsyncTaskHandle, Receiver<errors::Result<asynch::nextcloud::SyncStatus>>) {
    if let Some(ref async_task) = async_task_handle_opt.as_ref() {
        debug!("Stopping a previously spawned nextcloud async task");
        let _ = async_task.stop();
    }

    debug!("Spawning nextcloud async task");
    // Create a new channel
    let (tx, rx) = mpsc::channel();
    let every = time::Duration::from_millis(10000);
    let nc = asynch::nextcloud::Synchronizer::new(&configuration.nextcloud, &configuration.system, tx, filename).unwrap();
    (asynch::execute_task(Box::new(nc), every), rx)
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
    fn show_menu(&self, menu: &Menu, safe: &Safe, configuration: &RklConfiguration) -> UserSelection;
    /// Shows the Exit `Menu` to the User.
    fn exit(&self, contents_changed: bool) -> UserSelection;
    /// Shows a message to the User.
    /// Along with the message, the user should select one of the offered `UserOption`s.
    fn show_message(&self, message: &str, options: Vec<UserOption>, severity: MessageSeverity) -> UserSelection;

    /// Sorts the supplied entries.
    fn sort_entries(&self, entries: &mut [Entry]) {
        entries.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
    }
}


/// Trait to be implemented by various different `Editor`s (Shell, Web, Android, other...).
///
/// It drives the interaction with the Users
pub trait AsyncEditor {
    /// Shows the interface for entering a Password and a Number.
    fn show_password_enter(&self) -> Receiver<UserSelection>;
    /// Shows the interface for changing a Password and/or a Number.
    fn show_change_password(&self) -> Receiver<UserSelection>;
    /// Shows the specified `Menu` to the User.
    fn show_menu(&self, menu: &Menu, safe: &Safe, configuration: &RklConfiguration) -> Receiver<UserSelection>;
    /// Shows the Exit `Menu` to the User.
    fn exit(&self, contents_changed: bool) -> Receiver<UserSelection>;
    /// Shows a message to the User.
    /// Along with the message, the user should select one of the offered `UserOption`s.
    fn show_message(&self, message: &str, options: Vec<UserOption>, severity: MessageSeverity) -> Receiver<UserSelection>;

    /// Sorts the supplied entries.
    fn sort_entries(&self, entries: &mut [Entry]) {
        entries.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
    }
}

#[cfg(test)]
mod unit_tests {
    use std::mem;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use super::api::{Entry, Menu, UserOption, UserSelection};

    #[test]
    fn try_recv_from_vec() {
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        let (tx4, rx4) = mpsc::channel();
        let mut v = Vec::new();
        v.push(rx1);
        v.push(rx2);
        v.push(rx3);
        v.push(rx4);

        // No messages arrive yet
        assert!(super::try_recv_from_vec(&mut v).is_none());
        assert!(v.len() == 4);

        // Send a message
        assert!(tx1.send(UserSelection::Ack).is_ok());
        let m1 = super::try_recv_from_vec(&mut v);
        // A result is picked
        assert!(m1.is_some());
        assert!(m1.unwrap() == UserSelection::Ack);
        // rx1 is removed from the vec
        assert!(v.len() == 3);
        assert!(tx1.send(UserSelection::Ack).is_err());
        // No more messages exist
        assert!(super::try_recv_from_vec(&mut v).is_none());

        // Send two messages
        assert!(tx2.send(UserSelection::GoTo(Menu::Current)).is_ok());
        assert!(tx3.send(UserSelection::GoTo(Menu::Exit)).is_ok());
        // Pick the two results
        let m2_opt = super::try_recv_from_vec(&mut v);
        let m3_opt = super::try_recv_from_vec(&mut v);
        assert!(m2_opt.is_some() && m3_opt.is_some());
        let m2 = m2_opt.unwrap();
        let m3 = m3_opt.unwrap();
        assert!(m2 == UserSelection::GoTo(Menu::Current) || m2 == UserSelection::GoTo(Menu::Exit));
        assert!(m3 == UserSelection::GoTo(Menu::Current) || m3 == UserSelection::GoTo(Menu::Exit));
        // rx2 and rx3 are removed from the vec
        assert!(v.len() == 1);
        assert!(tx2.send(UserSelection::Ack).is_err());
        assert!(tx3.send(UserSelection::Ack).is_err());
        // No more messages exist
        assert!(super::try_recv_from_vec(&mut v).is_none());

        // Drop tx4 to close the channel
        mem::drop(tx4);
        assert!(super::try_recv_from_vec(&mut v).is_none());
        // rx4 is removed from the vec
        assert!(v.is_empty());
        // No more messages exist
        assert!(super::try_recv_from_vec(&mut v).is_none());
    }

    #[test]
    fn execution_cases() {
        execute_try_pass();
        execute_add_entry();
        execute_delete_entry();
        execute_change_pass();
    }

    fn execute_try_pass() {
        println!("===========execute_try_pass");
        let editor = TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Save
            UserSelection::GoTo(Menu::Save),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)]);

        super::execute(&editor);
        assert!(editor.all_selections_executed());
    }

    fn execute_add_entry() {
        println!("===========execute_add_entry");
        let editor = TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Add an entry
            UserSelection::NewEntry(Entry::new("n".to_owned(), "url".to_owned(), "u".to_owned(), "p".to_owned(), "s".to_owned())),
            // Save
            UserSelection::GoTo(Menu::Save),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)]);

        super::execute(&editor);
        assert!(editor.all_selections_executed());
    }

    fn execute_delete_entry() {
        println!("===========execute_delete_entry");
        let editor = TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Add an entry
            UserSelection::NewEntry(Entry::new("11nn".to_owned(), "11url".to_owned(), "11un".to_owned(), "11pn".to_owned(), "11sn".to_owned())),
            // Delete the first entry
            UserSelection::DeleteEntry(0),
            // Save
            UserSelection::GoTo(Menu::Save),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)]);

        super::execute(&editor);
        assert!(editor.all_selections_executed());
    }

    fn execute_change_pass() {
        println!("===========execute_change_pass");
        let editor1 = TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Go to change pass
            UserSelection::GoTo(Menu::ChangePass),
            // Return the new password
            UserSelection::ProvidedPassword("321".to_string(), 1),
            // Save
            UserSelection::GoTo(Menu::Save),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)]);

        super::execute(&editor1);
        assert!(editor1.all_selections_executed());

        // Assert the password is changed
        let editor2 = TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("321".to_string(), 1),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)]);

        super::execute(&editor2);
        assert!(editor2.all_selections_executed());

        // Change the password back to the previous one
        let editor3 = TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("321".to_string(), 1),
            // Go to change pass
            UserSelection::GoTo(Menu::ChangePass),
            // Return the new password
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Save
            UserSelection::GoTo(Menu::Save),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)]);

        super::execute(&editor3);
        assert!(editor3.all_selections_executed());
    }

    struct TestEditor {
        selections_to_execute: Mutex<Vec<UserSelection>>,
    }

    impl TestEditor {
        pub fn new(selections_to_execute: Vec<UserSelection>) -> TestEditor {
            let mut selections_to_execute_mut = selections_to_execute;
            selections_to_execute_mut.reverse();
            TestEditor { selections_to_execute: Mutex::new(selections_to_execute_mut) }
        }

        fn return_first_selection(&self) -> UserSelection {
            let mut available_selections_mut = self.selections_to_execute.lock().unwrap();
            let to_ret = match available_selections_mut.pop() {
                Some(sel) => sel,
                None => panic!("Don't have more user selections to execute"),
            };

            to_ret
        }

        pub fn all_selections_executed(&self) -> bool {
            let available_selections_mut = self.selections_to_execute.lock().unwrap();
            available_selections_mut.len() == 0
        }
    }

    impl super::Editor for TestEditor {
        fn show_password_enter(&self) -> UserSelection {
            println!("TestEditor::show_password_enter");
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }

        fn show_change_password(&self) -> UserSelection {
            println!("TestEditor::show_change_password");
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }

        fn show_menu(&self, m: &Menu, s: &super::Safe, _: &super::RklConfiguration) -> UserSelection {
            println!("TestEditor::show_menu {:?} with entries: {:?}", m, s.get_entries());
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }

        fn exit(&self, force: bool) -> UserSelection {
            println!("TestEditor::exit {}", force);
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }

        fn show_message(&self, m: &str, _: Vec<super::UserOption>, _: super::MessageSeverity) -> UserSelection {
            println!("TestEditor::show_message {}", m);
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }
    }
}