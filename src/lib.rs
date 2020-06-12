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
extern crate dirs;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate hyper_tls;
#[cfg(test)]
extern crate lazy_static;
extern crate log;
extern crate native_tls;
extern crate openssl_probe;
extern crate rand;
extern crate rs_password_utils;
extern crate secstr;
extern crate sha3;
extern crate toml;
extern crate xml;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time;

use log::*;
use tokio::prelude::*;
use tokio::prelude::future::{FutureResult, lazy, Loop, loop_fn, ok};

pub use file_handler::default_rustkeylock_location;

use crate::asynch::dropbox::DropboxConfiguration;
use crate::asynch::nextcloud::NextcloudConfiguration;
use crate::asynch::ReqwestClientFactory;

use self::api::{
    Props,
    RklConfiguration,
    RklContent,
    SystemConfiguration,
};
pub use self::api::{
    AllConfigurations,
    Entry,
    EntryPresentationType,
    Menu,
    MessageSeverity,
    UserOption,
    UserSelection,
};
use self::api::safe::Safe;
use self::api::UiCommand;
use self::asynch::AsyncEditorFacade;
pub use self::asynch::dropbox;
pub use self::asynch::nextcloud;

mod file_handler;
mod errors;
mod protected;
mod datacrypt;
mod asynch;
mod api;
mod selection_handling;
mod utils;

const FILENAME: &str = ".sec";
const PROPS_FILENAME: &str = ".props";

/// Takes a reference of `Editor` implementation as argument and executes the _rust-keylock_ logic.
/// The `Editor` is responsible for the interaction with the user. Currently there are `Editor` implementations for __shell__ and for __Android__.
pub fn execute_async(editor: Box<dyn AsyncEditor>) {
    let (command_tx, command_rx) = mpsc::channel();
    let (ui_tx, ui_rx) = mpsc::channel();
    let mut ui_rx_vec = Vec::new();

    thread::spawn(move || {
        tokio::run(lazy(|| {
            openssl_probe::init_ssl_cert_env_vars();
            info!("Starting rust-keylock...");
            let props = match file_handler::load_properties(PROPS_FILENAME) {
                Ok(m) => m,
                Err(error) => {
                    error!("Could not load properties. Using defaults. The error was: {}", error);
                    Props::default()
                }
            };

            let editor_facade = asynch::AsyncEditorFacade::new(ui_rx, command_tx, props.clone());

            let main_loop = loop_fn(CoreLogicHandler::new(editor_facade, props), |executor| {
                executor.handle()
                    .map_err(|_| ())
                    .and_then(|(executor, stop)| {
                        if stop {
                            ok(Loop::Break(()))
                        } else {
                            ok(Loop::Continue(executor))
                        }
                    })
            });

            tokio::spawn(main_loop);

            Ok(())
        }));
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
                    UiCommand::ShowMenu(menu) => {
                        ui_rx_vec.push(editor.show_menu(&menu));
                    }
                    UiCommand::ShowEntries(entries, filter) => {
                        ui_rx_vec.push(editor.show_entries(entries, filter));
                    }
                    UiCommand::ShowEntry(entry, index, presentation_type) => {
                        ui_rx_vec.push(editor.show_entry(entry, index, presentation_type));
                    }
                    UiCommand::ShowConfiguration(nextcloud, dropbox) => {
                        ui_rx_vec.push(editor.show_configuration(nextcloud, dropbox));
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

        if let Some(sel) = try_recv_from_vec(&mut ui_rx_vec) {
            let should_break = sel == UserSelection::GoTo(Menu::ForceExit);
            send(&ui_tx, sel);
            if should_break {
                break;
            }
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

        i += 1;
    }

    if remove_element {
        rxs.remove(i);
    }
    res_opt
}

pub fn execute(editor: Box<dyn Editor>) {
    openssl_probe::init_ssl_cert_env_vars();
    info!("Starting rust-keylock...");
    let (command_tx, command_rx) = mpsc::channel();
    let (ui_tx, ui_rx) = mpsc::channel();

    thread::spawn(move || {
        tokio::run(lazy(|| {
            let props = match file_handler::load_properties(PROPS_FILENAME) {
                Ok(m) => m,
                Err(error) => {
                    error!("Could not load properties. Using defaults. The error was: {}", error);
                    Props::default()
                }
            };

            let editor_facade = asynch::AsyncEditorFacade::new(ui_rx, command_tx, props.clone());

            let main_loop = loop_fn(CoreLogicHandler::new(editor_facade, props), |executor| {
                executor.handle()
                    .map_err(|_| ())
                    .and_then(|(executor, stop)| {
                        if stop {
                            ok(Loop::Break(()))
                        } else {
                            ok(Loop::Continue(executor))
                        }
                    })
            });

            tokio::spawn(main_loop);

            ok(())
        }));
    });

    loop {
        match command_rx.recv() {
            Ok(command) => {
                match command {
                    UiCommand::ShowPasswordEnter => {
                        debug!("Showing password");
                        send(&ui_tx, editor.show_password_enter())
                    }
                    UiCommand::ShowChangePassword => {
                        debug!("Showing change password");
                        send(&ui_tx, editor.show_change_password())
                    }
                    UiCommand::ShowMenu(menu) => {
                        debug!("Showing menu {:?}", menu);
                        let sel = editor.show_menu(&menu);
                        let should_break = sel == UserSelection::GoTo(Menu::ForceExit);
                        send(&ui_tx, sel);
                        if should_break {
                            break;
                        }
                    }
                    UiCommand::ShowEntries(entries, filter) => {
                        debug!("Showing entries");
                        send(&ui_tx, editor.show_entries(entries, filter))
                    }
                    UiCommand::ShowEntry(entry, index, presentation_type) => {
                        debug!("Showing entry");
                        send(&ui_tx, editor.show_entry(entry, index, presentation_type))
                    }
                    UiCommand::ShowConfiguration(nextcloud, dropbox) => {
                        debug!("Showing configuration");
                        send(&ui_tx, editor.show_configuration(nextcloud, dropbox))
                    }
                    UiCommand::ShowMessage(message, options, severity) => {
                        debug!("Showing message");
                        send(&ui_tx, editor.show_message(&message, options, severity))
                    }
                    UiCommand::Exit(contents_changed) => {
                        debug!("Exiting");
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
                break;
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

struct CoreLogicHandler {
    editor: AsyncEditorFacade,
    props: Props,
    // Holds the UserSelections
    user_selection: UserSelection,
    // Keeps the sensitive data
    safe: Safe,
    configuration: RklConfiguration,
    // Signals changes that are not saved
    contents_changed: bool,
    async_task_handles: HashMap<&'static str, asynch::AsyncTaskHandle>,
    cryptor: datacrypt::BcryptAes,
}

impl CoreLogicHandler {
    fn new(editor: AsyncEditorFacade, props: Props) -> CoreLogicHandler {
        let mut editor = editor;
        // Holds the UserSelections
        let user_selection;

        // Keeps the sensitive data
        let mut safe = Safe::new();
        // Keeps the configuration data
        let mut configuration = RklConfiguration::from((
            nextcloud::NextcloudConfiguration::default(),
            dropbox::DropboxConfiguration::default(),
            SystemConfiguration::default()));
        // Signals changes that are not saved
        let contents_changed = false;
        let mut async_task_handles = HashMap::new();
        // Create a Cryptor
        let cryptor = {
            // First time run?
            let provided_password = if file_handler::is_first_run(FILENAME) {
                editor.show_change_password()
            } else {
                editor.show_password_enter()
            };

            // Take the provided password and do the initialization
            let (us, cr) = handle_provided_password_for_init(provided_password, FILENAME, &mut safe, &mut configuration, &editor);
            // If a valid nextcloud configuration is in place, spawn the background async execution
            if configuration.nextcloud.is_filled() {
                let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &configuration, &async_task_handles);
                async_task_handles.insert("nextcloud", handle);
                editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
            }
            // If a valid dropbox configuration is in place, spawn the background async execution
            if configuration.dropbox.is_filled() {
                let (handle, dropbox_sync_status_rx) = spawn_dropbox_async_task(FILENAME, &configuration, &async_task_handles);
                async_task_handles.insert("dropbox", handle);
                editor.update_dropbox_rx(Some(dropbox_sync_status_rx));
            }
            // Set the UserSelection
            user_selection = us;
            cr
        };

        CoreLogicHandler {
            editor,
            props: props,
            user_selection,
            safe,
            configuration,
            contents_changed,
            async_task_handles,
            cryptor,
        }
    }

    // This is the main function that handles all the user selections. Its complexity is expected to be big.
    // This may change in the future during a refactoring but is accepted for now.
    #[allow(clippy::cyclomatic_complexity)]
    fn handle(self) -> FutureResult<(CoreLogicHandler, bool), ()> {
        let mut stop = false;
        let mut s = self;

        s.editor.sort_entries(&mut s.safe.entries);
        // Handle
        s.user_selection = match s.user_selection {
            UserSelection::GoTo(Menu::TryPass(update_last_sync_version)) => {
                // Cancel any pending background tasks
                for handle in s.async_task_handles.values() {
                    let _ = handle.stop();
                }
                let (user_selection, cr) = handle_provided_password_for_init(
                    s.editor.show_password_enter(),
                    FILENAME,
                    &mut s.safe,
                    &mut s.configuration,
                    &s.editor);
                if update_last_sync_version {
                    s.configuration.update_system_last_sync();
                    let rkl_content = RklContent::from((&s.safe, &s.configuration.nextcloud, &s.configuration.dropbox, &s.configuration.system));
                    let _ = rkl_content.and_then(|c| file_handler::save(c, FILENAME, &s.cryptor, true));
                }
                // If a valid nextcloud configuration is in place, spawn the background async execution
                if s.configuration.nextcloud.is_filled() {
                    debug!("A valid configuration for Nextcloud synchronization was found. Spawning async tasks");
                    let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &s.configuration, &s.async_task_handles);
                    s.async_task_handles.insert("nextcloud", handle);
                    s.editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
                }
                // If a valid dropbox configuration is in place, spawn the background async execution
                if s.configuration.dropbox.is_filled() {
                    debug!("A valid configuration for dropbox synchronization was found. Spawning async tasks");
                    let (handle, dropbox_sync_status_rx) = spawn_dropbox_async_task(FILENAME, &s.configuration, &s.async_task_handles);
                    s.async_task_handles.insert("dropbox", handle);
                    s.editor.update_nextcloud_rx(Some(dropbox_sync_status_rx));
                }
                s.cryptor = cr;
                user_selection
            }
            UserSelection::GoTo(Menu::Main) => {
                debug!("UserSelection::GoTo(Menu::Main)");
                let m = s.editor.show_menu(&Menu::Main);
                debug!("UserSelection::GoTo(Menu::Main) returns {:?}", &m);
                m
            }
            UserSelection::GoTo(Menu::ChangePass) => {
                debug!("UserSelection::GoTo(Menu::ChangePass)");
                s.contents_changed = true;
                s.editor.show_change_password()
            }
            UserSelection::ProvidedPassword(pwd, salt_pos) => {
                debug!("UserSelection::GoTo(Menu::ProvidedPassword)");
                s.cryptor = file_handler::create_bcryptor(FILENAME, pwd, salt_pos, true, true).unwrap();
                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::EntriesList(filter)) => {
                debug!("UserSelection::GoTo(Menu::EntriesList) with filter '{}'", &filter);
                s.safe.set_filter(filter.clone());
                s.editor.show_entries(s.safe.get_entries().to_vec(), s.safe.get_filter())
            }
            UserSelection::GoTo(Menu::NewEntry(opt)) => {
                debug!("UserSelection::GoTo(Menu::NewEntry)");
                s.editor.show_menu(&Menu::NewEntry(opt))
            }
            UserSelection::GoTo(Menu::ShowEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::ShowEntry(index))");
                s.editor.show_entry(s.safe.get_entry_decrypted(index), index, EntryPresentationType::View)
            }
            UserSelection::GoTo(Menu::EditEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::EditEntry(index))");
                s.editor.show_entry(s.safe.get_entry_decrypted(index), index, EntryPresentationType::Edit)
            }
            UserSelection::GoTo(Menu::DeleteEntry(index)) => {
                debug!("UserSelection::GoTo(Menu::DeleteEntry(index))");
                s.editor.show_entry(s.safe.get_entry_decrypted(index), index, EntryPresentationType::Delete)
            }
            UserSelection::GoTo(Menu::Save(update_last_sync_version)) => {
                debug!("UserSelection::GoTo(Menu::Save({}))", update_last_sync_version);
                if s.configuration.nextcloud.is_filled() &&
                    s.configuration.dropbox.is_filled() {
                    error!("Cannot save because both Nextcloud and Dropbox are configured");
                    s.editor.show_message("Having both Nextcloud and Dropbox configured may lead to unexpected state and currently is not allowed.\
                    Please configure only one of them.", vec![UserOption::ok()], MessageSeverity::Error);
                    UserSelection::GoTo(Menu::Current)
                } else {
                    let _ = s.configuration.update_system_for_save(update_last_sync_version).map_err(|error| error!("Cannot update system for save: {:?}", error));
                    // Reset the filter
                    s.safe.set_filter("".to_string());
                    let rkl_content = RklContent::from((&s.safe, &s.configuration.nextcloud, &s.configuration.dropbox, &s.configuration.system));
                    let res = rkl_content.and_then(|c| file_handler::save(c, FILENAME, &s.cryptor, true));
                    match res {
                        Ok(_) => {
                            // Cancel any pending background tasks
                            for handle in s.async_task_handles.values() {
                                let _ = handle.stop();
                            }
                            // Clean the flag for unsaved data
                            s.contents_changed = false;
                            if s.configuration.nextcloud.is_filled() {
                                // Start a new background async task
                                let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &s.configuration, &s.async_task_handles);
                                s.async_task_handles.insert("nextcloud", handle);
                                s.editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
                            }
                            if s.configuration.dropbox.is_filled() {
                                // Start a new background async task
                                let (handle, dropbox_sync_status_rx) = spawn_dropbox_async_task(FILENAME, &s.configuration, &s.async_task_handles);
                                s.async_task_handles.insert("dropbox", handle);
                                s.editor.update_dropbox_rx(Some(dropbox_sync_status_rx));
                            }
                            if !update_last_sync_version {
                                let _ = s.editor.show_message("Encrypted and saved successfully!", vec![UserOption::ok()], MessageSeverity::default());
                            }
                        }
                        Err(error) => {
                            let _ = s.editor.show_message("Could not save...", vec![UserOption::ok()], MessageSeverity::Error);
                            error!("Could not save... {:?}", error);
                        }
                    };
                    if update_last_sync_version {
                        UserSelection::GoTo(Menu::Current)
                    } else {
                        UserSelection::GoTo(Menu::Main)
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
                UserSelection::GoTo(Menu::Current)
            }
            UserSelection::NewEntry(entry) => {
                debug!("UserSelection::NewEntry(entry)");
                s.safe.add_entry(entry);
                s.contents_changed = true;
                UserSelection::GoTo(Menu::EntriesList("".to_string()))
            }
            UserSelection::ReplaceEntry(index, entry) => {
                debug!("UserSelection::ReplaceEntry(index, entry)");
                s.contents_changed = true;
                match s.safe.replace_entry(index, entry) {
                    Ok(_) => { /**/ }
                    Err(error) => {
                        error!("Could not replace entry: {:?}", error);
                        let _ = s.editor.show_message("Could not replace the password entry. Please see the logs for more details.", vec![UserOption::ok()], MessageSeverity::Error);
                    }
                }
                UserSelection::GoTo(Menu::EntriesList(s.safe.get_filter()))
            }
            UserSelection::DeleteEntry(index) => {
                debug!("UserSelection::DeleteEntry(index)");
                let _ = s.safe.remove_entry(index).map_err(|err| {
                    error!("Could not delete entry {:?}", err);
                    let _ = s.editor.show_message("Could not delete entry. Please see the logs for more details.", vec![UserOption::ok()], MessageSeverity::Error);
                });
                s.contents_changed = true;
                UserSelection::GoTo(Menu::EntriesList("".to_string()))
            }
            UserSelection::GoTo(Menu::TryFileRecovery) => {
                debug!("UserSelection::GoTo(Menu::TryFileRecovery)");
                let _ = s.editor.show_message("The password entries are corrupted.\n\nPress Enter to attempt recovery...",
                                              vec![UserOption::ok()],
                                              MessageSeverity::Error);
                let mut rec_entries = match file_handler::recover(FILENAME, &s.cryptor) {
                    Ok(recovered_entries) => {
                        let message = r#"
Recovery succeeded...

Note the errors that caused the recovery. You may see some useful information about possible values that could not be recovered.
Press Enter to show the Recovered Entries and if you are ok with it, save them.

Warning: Saving will discard all the entries that could not be recovered.
"#;
                        let _ = s.editor.show_message(message, vec![UserOption::ok()], MessageSeverity::default());
                        s.contents_changed = true;
                        s.safe.entries.clear();
                        recovered_entries
                    }
                    Err(error) => {
                        let message = format!("Recovery failed... Reason {:?}", error);
                        error!("{}", &message);
                        let _ = s.editor.show_message("Recovery failed...", vec![UserOption::ok()], MessageSeverity::Error);
                        s.safe.entries.clone()
                    }
                };
                s.safe.entries.append(&mut rec_entries);

                UserSelection::GoTo(Menu::EntriesList("".to_string()))
            }
            UserSelection::GoTo(Menu::ExportEntries) => {
                debug!("UserSelection::GoTo(Menu::ExportEntries)");
                s.editor.show_menu(&Menu::ExportEntries)
            }
            UserSelection::ExportTo(path) => {
                debug!("UserSelection::ExportTo(path)");
                let do_export = if file_handler::file_exists(&PathBuf::from(&path)) {
                    let selection = s.editor.show_message("This will overwrite an existing file. Do you want to proceed?",
                                                          vec![UserOption::yes(), UserOption::no()],
                                                          MessageSeverity::Warn);

                    debug!("The user selected {:?} as an answer for overwriting the file {}", selection, path);
                    selection == UserSelection::UserOption(UserOption::yes())
                } else {
                    true
                };

                if do_export {
                    match RklContent::from((&s.safe, &s.configuration.nextcloud, &s.configuration.dropbox, &s.configuration.system)) {
                        Ok(c) => {
                            match file_handler::save(c, &path, &s.cryptor, false) {
                                Ok(_) => { let _ = s.editor.show_message("Export completed successfully!", vec![UserOption::ok()], MessageSeverity::default()); }
                                Err(error) => {
                                    error!("Could not export... {:?}", error);
                                    let _ = s.editor.show_message("Could not export...", vec![UserOption::ok()], MessageSeverity::Error);
                                }
                            }
                        }
                        Err(error) => {
                            error!("Could not export... {:?}", error);
                            let _ = s.editor.show_message("Could not export...", vec![UserOption::ok()], MessageSeverity::Error);
                        }
                    };
                    UserSelection::GoTo(Menu::Main)
                } else {
                    UserSelection::GoTo(Menu::ExportEntries)
                }
            }
            UserSelection::GoTo(Menu::ImportEntries) => {
                debug!("UserSelection::GoTo(Menu::ImportEntries)");
                s.editor.show_menu(&Menu::ImportEntries)
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
                            Err(error) => {
                                error!("Could not import... {:?}", error);
                                let _ = s.editor.show_message("Could not import...", vec![UserOption::ok()], MessageSeverity::Error);
                            }
                            Ok(rkl_content) => {
                                let message = format!("Imported {} entries!", &rkl_content.entries.len());
                                debug!("{}", message);
                                // Mark contents changed
                                s.contents_changed = true;
                                // Do the merge
                                s.safe.merge(rkl_content.entries);
                                // Replace the configuration
                                s.configuration.system = rkl_content.system_conf;
                                // Make the last_sync_version equal to the local one.
                                s.configuration.update_system_last_sync();

                                let _ = s.editor.show_message(&message, vec![UserOption::ok()], MessageSeverity::default());
                            }
                        };
                    }
                    _ => {}
                };

                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::ShowConfiguration) => {
                debug!("UserSelection::GoTo(Menu::ShowConfiguration)");
                s.editor.show_configuration(s.configuration.nextcloud.clone(), s.configuration.dropbox.clone())
            }
            UserSelection::UpdateConfiguration(new_conf) => {
                debug!("UserSelection::UpdateConfiguration");
                if new_conf.nextcloud.is_filled() &&
                    new_conf.dropbox.is_filled() {
                    error!("Cannot update the configuration because both Nextcloud and Dropbox are configured");
                    s.editor.show_message("Having both Nextcloud and Dropbox configured may lead to unexpected state and currently is not allowed.\
                    Please configure only one of them.", vec![UserOption::ok()], MessageSeverity::Error);
                    UserSelection::GoTo(Menu::Current)
                } else {
                    s.configuration.nextcloud = new_conf.nextcloud;
                    if s.configuration.nextcloud.is_filled() {
                        debug!("A valid configuration for Nextcloud synchronization was found after being updated by the User. Spawning \
                            nextcloud sync task");
                        let (handle, nextcloud_sync_status_rx) = spawn_nextcloud_async_task(FILENAME, &s.configuration, &s.async_task_handles);
                        s.async_task_handles.insert("nextcloud", handle);
                        s.editor.update_nextcloud_rx(Some(nextcloud_sync_status_rx));
                        s.contents_changed = true;
                    }
                    if s.configuration.dropbox.is_filled() {
                        debug!("A valid configuration for dropbox synchronization was found after being updated by the User. Spawning \
                            dropbox sync task");
                        let (handle, dropbox_sync_status_rx) = spawn_dropbox_async_task(FILENAME, &s.configuration, &s.async_task_handles);
                        s.async_task_handles.insert("dropbox", handle);
                        s.editor.update_dropbox_rx(Some(dropbox_sync_status_rx));
                        s.contents_changed = true;
                    }
                    UserSelection::GoTo(Menu::Main)
                }
            }
            UserSelection::AddToClipboard(content) => {
                debug!("UserSelection::AddToClipboard");
                selection_handling::add_to_clipboard(content, &s.editor)
            }
            UserSelection::GoTo(Menu::WaitForDbxTokenCallback(url)) => {
                debug!("UserSelection::GoTo(Menu::WaitForDbxTokenCallback)");
                match dropbox::retrieve_token(url) {
                    Ok(token) => {
                        if token.is_empty() {
                            let _ = s.editor.show_message("Empty Dropbox Authentication token was retrieved.", vec![UserOption::ok()], MessageSeverity::Error);
                            UserSelection::GoTo(Menu::ShowConfiguration)
                        } else {
                            UserSelection::GoTo(Menu::SetDbxToken(token.clone()))
                        }
                    }
                    Err(error) => {
                        error!("Error while retrieving Dropbox Authentication token: {} ({:?})", error, error);
                        let _ = s.editor.show_message(&format!("Error while retrieving Dropbox Authentication token: {}", error), vec![UserOption::ok()], MessageSeverity::Error);
                        UserSelection::GoTo(Menu::ShowConfiguration)
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
                        UserSelection::GoTo(Menu::ShowConfiguration)
                    }
                    Err(error) => {
                        error!("Could not set the Dropbox token: {:?}", error);
                        let _ = s.editor.show_message("Could not obtain the Dropbox token. Please see the logs for more details.", vec![UserOption::ok()], MessageSeverity::Error);
                        UserSelection::GoTo(Menu::ShowConfiguration)
                    }
                }
            }
            UserSelection::GeneratePassphrase(index_opt, mut entry) => {
                debug!("UserSelection::GoTo(Menu::GeneratePassphrase)");
                entry.pass = rs_password_utils::dice::generate(s.props.generated_passphrases_words_count() as usize);
                match index_opt {
                    Some(index) => s.editor.show_entry(entry, index, EntryPresentationType::Edit),
                    None => s.editor.show_menu(&Menu::NewEntry(Some(entry))),
                }
            }
            UserSelection::CheckPasswords => {
                debug!("UserSelection::CheckPasswords");
                let mut pwned: Vec<String> = Vec::new();
                for index in 0..s.safe.get_entries().len() {
                    let entry = s.safe.get_entry_decrypted(index);
                    let pwned_res = rs_password_utils::pwned::blocking::is_pwned(&entry.pass);
                    if pwned_res.is_ok() {
                        if pwned_res.unwrap() {
                            pwned.push(entry.name);
                        }
                    } else {
                        let message = format!("Error while checking passwords: {}", pwned_res.unwrap_err());
                        error!("{}", message);
                        let _ = s.editor.show_message(&message,
                                                      vec![UserOption::ok()],
                                                      MessageSeverity::Error);
                    }
                }
                if !pwned.is_empty() {
                    let message = format!("The following entries have leaked passwords: {}! Please change them immediately!", pwned.join(","));
                    info!("{}", message);
                    let _ = s.editor.show_message(&message,
                                                  vec![UserOption::ok()],
                                                  MessageSeverity::Warn);
                } else {
                    let message = format!("The passwords of all entries look ok!");
                    debug!("{}", message);
                    let _ = s.editor.show_message(&message,
                                                  vec![UserOption::ok()],
                                                  MessageSeverity::Info);
                }
                s.editor.show_menu(&Menu::Current)
            }
            UserSelection::GoTo(Menu::Current) => {
                debug!("UserSelection::GoTo(Menu::Current)");
                s.editor.show_menu(&Menu::Current)
            }
            other => {
                let message = format!("Bug: User Selection '{:?}' should not be handled in the main loop. Please, consider opening a bug \
                                       to the developers.",
                                      &other);
                error!("{}", message);
                panic!(message)
            }
        };

        ok((s, stop))
    }
}

fn handle_provided_password_for_init(provided_password: UserSelection,
                                     filename: &str,
                                     safe: &mut Safe,
                                     configuration: &mut RklConfiguration,
                                     editor: &dyn Editor)
                                     -> (UserSelection, datacrypt::BcryptAes) {
    let user_selection: UserSelection;
    match provided_password {
        UserSelection::ProvidedPassword(pwd, salt_pos) => {
            // New Cryptor here
            let cr = file_handler::create_bcryptor(filename, pwd.clone(), salt_pos, false, true).unwrap();
            // Try to decrypt and load the Entries
            let retrieved_entries = match file_handler::load(filename, &cr, true) {
                // Success, go to the List of entries
                Ok(rkl_content) => {
                    user_selection = UserSelection::GoTo(Menu::EntriesList("".to_string()));
                    // Set the retrieved configuration
                    let new_rkl_conf = RklConfiguration::from((rkl_content.nextcloud_conf, rkl_content.dropbox_conf, rkl_content.system_conf));
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
                                                    MessageSeverity::Error);
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
                              async_task_handles: &HashMap<&'static str, asynch::AsyncTaskHandle>)
                              -> (asynch::AsyncTaskHandle, Receiver<errors::Result<asynch::SyncStatus>>) {
    if let Some(async_task) = async_task_handles.get("nextcloud") {
        debug!("Stopping a previously spawned nextcloud async task");
        let _ = async_task.stop();
    }

    debug!("Spawning nextcloud async task");
    // Create a new channel
    let (tx, rx) = mpsc::channel();
    let every = time::Duration::from_millis(10000);
    let nc = nextcloud::Synchronizer::new(&configuration.nextcloud, &configuration.system, tx, filename).unwrap();
    (asynch::execute_task(Box::new(nc), every), rx)
}

fn spawn_dropbox_async_task(filename: &str,
                            configuration: &RklConfiguration,
                            async_task_handles: &HashMap<&'static str, asynch::AsyncTaskHandle>)
                            -> (asynch::AsyncTaskHandle, Receiver<errors::Result<asynch::SyncStatus>>) {
    if let Some(async_task) = async_task_handles.get("dropbox") {
        debug!("Stopping a previously spawned dropbox async task");
        let _ = async_task.stop();
    }

    debug!("Spawning dropbox async task");
    // Create a new channel
    let (tx, rx) = mpsc::channel();
    let every = time::Duration::from_millis(10000);
    let dbx = dropbox::Synchronizer::new(
        &configuration.dropbox,
        &configuration.system,
        tx,
        filename,
        Box::new(ReqwestClientFactory::new()),
    ).unwrap();
    (asynch::execute_task(Box::new(dbx), every), rx)
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
    fn show_entry(&self, entry: Entry, index: usize, presentation_type: EntryPresentationType) -> UserSelection;
    /// Shows the Exit `Menu` to the User.
    fn exit(&self, contents_changed: bool) -> UserSelection;
    /// Shows the configuration screen.
    fn show_configuration(&self, nextcloud: NextcloudConfiguration, dropbox: DropboxConfiguration) -> UserSelection;
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
    fn show_menu(&self, menu: &Menu) -> Receiver<UserSelection>;
    /// Shows the provided entries to the User. The provided entries are already filtered with the filter argument.
    fn show_entries(&self, entries: Vec<Entry>, filter: String) -> Receiver<UserSelection>;
    /// Shows the provided entry details to the User following a presentation type.
    fn show_entry(&self, entry: Entry, index: usize, presentation_type: EntryPresentationType) -> Receiver<UserSelection>;
    /// Shows the Exit `Menu` to the User.
    fn exit(&self, contents_changed: bool) -> Receiver<UserSelection>;
    /// Shows the configuration screen.
    fn show_configuration(&self, nextcloud: NextcloudConfiguration, dropbox: DropboxConfiguration) -> Receiver<UserSelection>;
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
    use std::sync::mpsc::{self, Sender};
    use std::sync::Mutex;
    use std::time::SystemTime;

    use clipboard::{ClipboardContext, ClipboardProvider};

    use crate::EntryPresentationType;

    use super::api::{AllConfigurations, Entry, Menu, UserOption, UserSelection};
    use super::asynch::dropbox::DropboxConfiguration;
    use super::asynch::nextcloud::NextcloudConfiguration;
    use super::file_handler;

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
//    #[ignore]
    // WARNING: Running this, will mess with the passwords that are stored in the $HOME/.rust-keylock directory
    fn execution_cases() {
        execute_try_pass();
        execute_show_entry();
        execute_add_entry();
        execute_edit_entry();
        execute_delete_entry();
        execute_change_pass();
        execute_export_entries();
        execute_import_entries();
        execute_update_configuration();
        execute_add_to_clipboard();
    }

    fn execute_try_pass() {
        println!("===========execute_try_pass");
        let (tx, rx) = mpsc::channel();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Save
            UserSelection::GoTo(Menu::Save(false)),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::Exit),
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_show_entry() {
        println!("===========execute_show_entry");
        let (tx, rx) = mpsc::channel();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Add an entry
            UserSelection::NewEntry(Entry::new("11nn".to_owned(), "11url".to_owned(), "11un".to_owned(), "11pn".to_owned(), "11sn".to_owned())),
            // Show the first entry
            UserSelection::GoTo(Menu::ShowEntry(0)),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_edit_entry() {
        println!("===========execute_edit_entry");
        let (tx, rx) = mpsc::channel();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Edit the first entry
            UserSelection::GoTo(Menu::EditEntry(0)),
            UserSelection::ReplaceEntry(0, Entry::new("r".to_owned(), "url".to_owned(), "ru".to_owned(), "rp".to_owned(), "rs".to_owned())),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_add_entry() {
        println!("===========execute_add_entry");
        let (tx, rx) = mpsc::channel();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Add an entry
            UserSelection::GoTo(Menu::NewEntry(None)),
            UserSelection::NewEntry(Entry::new("n".to_owned(), "url".to_owned(), "u".to_owned(), "p".to_owned(), "s".to_owned())),
            // Save
            UserSelection::GoTo(Menu::Save(false)),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_delete_entry() {
        println!("===========execute_delete_entry");
        let (tx, rx) = mpsc::channel();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Add an entry
            UserSelection::NewEntry(Entry::new("11nn".to_owned(), "11url".to_owned(), "11un".to_owned(), "11pn".to_owned(), "11sn".to_owned())),
            // Delete the first entry
            UserSelection::GoTo(Menu::DeleteEntry(0)),
            UserSelection::DeleteEntry(0),
            // Save
            UserSelection::GoTo(Menu::Save(false)),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_change_pass() {
        println!("===========execute_change_pass");
        let (tx, rx) = mpsc::channel();
        let editor1 = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Go to change pass
            UserSelection::GoTo(Menu::ChangePass),
            // Return the new password
            UserSelection::ProvidedPassword("321".to_string(), 1),
            // Save
            UserSelection::GoTo(Menu::Save(false)),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx.clone()));

        super::execute(editor1);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());

        // Assert the password is changed
        let editor2 = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("321".to_string(), 1),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx.clone()));

        super::execute(editor2);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());

        // Change the password back to the previous one
        let editor3 = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("321".to_string(), 1),
            // Go to change pass
            UserSelection::GoTo(Menu::ChangePass),
            // Return the new password
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Save
            UserSelection::GoTo(Menu::Save(false)),
            // Ack saved message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor3);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_export_entries() {
        println!("===========execute_export_entries");
        let (tx, rx) = mpsc::channel();
        let mut loc = file_handler::default_rustkeylock_location();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Cannot create the duration for the execute_export_entries").as_secs();
        loc.push(format!("exported{:?}", now));
        let loc_str = loc.into_os_string().into_string().unwrap();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Export entries
            UserSelection::GoTo(Menu::ExportEntries),
            UserSelection::ExportTo(loc_str.clone()),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Export to the same path
            UserSelection::ExportTo(loc_str.clone()),
            // Select not to overwitre
            UserSelection::UserOption(UserOption::no()),
            // Export to the same path once more
            UserSelection::ExportTo(loc_str.clone()),
            // Select to overwitre
            UserSelection::UserOption(UserOption::yes()),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Try exporting to an invalid path
            UserSelection::ExportTo(format!("/exported{:?}", now)),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_import_entries() {
        println!("===========execute_import_entries");
        let (tx, rx) = mpsc::channel();
        let mut loc = file_handler::default_rustkeylock_location();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Cannot create the duration for the execute_export_entries").as_secs();
        loc.push(format!("exported{:?}", now));
        let loc_str = loc.into_os_string().into_string().unwrap();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Export entries
            UserSelection::GoTo(Menu::ImportEntries),
            UserSelection::ExportTo(loc_str.clone()),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Import entries
            UserSelection::ImportFrom(loc_str, "123".to_string(), 0),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Import a non-existing file
            UserSelection::ImportFrom("/non-existing".to_string(), "123".to_string(), 0),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_update_configuration() {
        println!("===========execute_update_configuration");
        let (tx, rx) = mpsc::channel();

        let nc_conf = NextcloudConfiguration::new(
            "u".to_string(),
            "un".to_string(),
            "pw".to_string(),
            false).unwrap();

        let dbx_conf = DropboxConfiguration::default();

        let new_conf = AllConfigurations::new(nc_conf, dbx_conf);

        let new_empty_nc_conf = NextcloudConfiguration::new(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            false).unwrap();

        let new_empty_conf = AllConfigurations::new(new_empty_nc_conf, DropboxConfiguration::default());

        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Update the configuration
            UserSelection::GoTo(Menu::ShowConfiguration),
            UserSelection::UpdateConfiguration(new_conf),
            // Update the configuration with a non-filled one
            UserSelection::UpdateConfiguration(new_empty_conf),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);
        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    fn execute_add_to_clipboard() {
        println!("===========execute_add_to_clipboard");
        let (tx, rx) = mpsc::channel();
        let a_string = "1string".to_string();
        let editor = Box::new(TestEditor::new(vec![
            // Login
            UserSelection::ProvidedPassword("123".to_string(), 0),
            // Add to clipboard
            UserSelection::AddToClipboard(a_string.clone()),
            // Ack message
            UserSelection::UserOption(UserOption::ok()),
            // Exit
            UserSelection::GoTo(Menu::ForceExit)], tx));

        super::execute(editor);

        match ClipboardProvider::new() as Result<ClipboardContext, Box<dyn std::error::Error>> {
            Ok(mut ctx) => {
                let clip_res = ctx.get_contents();
                assert!(clip_res.is_ok());
                assert!(clip_res.unwrap() == a_string);
            }
            Err(_) => {
                assert!(true);
            }
        }

        let res = rx.recv();
        assert!(res.is_ok() && res.unwrap());
    }

    struct TestEditor {
        selections_to_execute: Mutex<Vec<UserSelection>>,
        completed_tx: Sender<bool>,
    }

    impl TestEditor {
        pub fn new(selections_to_execute: Vec<UserSelection>, completed_tx: Sender<bool>) -> TestEditor {
            let mut selections_to_execute_mut = selections_to_execute;
            selections_to_execute_mut.reverse();
            TestEditor { selections_to_execute: Mutex::new(selections_to_execute_mut), completed_tx }
        }

        fn return_first_selection(&self) -> UserSelection {
            let mut available_selections_mut = self.selections_to_execute.lock().unwrap();
            let to_ret = match available_selections_mut.pop() {
                Some(sel) => sel,
                None => panic!("Don't have more user selections to execute"),
            };
            if available_selections_mut.is_empty() {
                self.completed_tx.send(true).expect("Cannot send to signal completion.");
            }
            to_ret
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

        fn show_menu(&self, m: &Menu) -> UserSelection {
            println!("TestEditor::show_menu {:?}", m);
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }

        fn show_entries(&self, entries: Vec<Entry>, filter: String) -> UserSelection {
            println!("TestEditor::show_entries {:?} with filter {}", entries, filter);
            let to_ret = self.return_first_selection();
            println!("Returning {:?}", to_ret);
            to_ret
        }

        fn show_entry(&self, entry: Entry, index: usize, presentation_type: EntryPresentationType) -> UserSelection {
            println!("TestEditor::show_entry {:?} with index {} and presentation_type {:?}", entry, index, presentation_type);
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

        fn show_configuration(&self, nextcloud: NextcloudConfiguration, dropbox: DropboxConfiguration) -> UserSelection {
            println!("TestEditor::show_configuration with {:?} and {:?}", nextcloud, dropbox);
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