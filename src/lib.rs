//! # The _rust-keylock_ library
//!
//! Executes the logic of the _rust-keylock_.
//!
//! This library is the executor of the _rust-keylock_ logic. `Editor` references are used to interact with the _rust-keylock_ users.

#[macro_use]
extern crate log;
extern crate toml;
extern crate crypto;
extern crate sha3;
extern crate base64;
extern crate rand;
extern crate secstr;
extern crate futures;
extern crate hyper;
extern crate tokio_core;
extern crate hyper_tls;
extern crate native_tls;
extern crate xml;
extern crate openssl_probe;
//extern crate clipboard;

use std::error::Error;
use std::time::{self, SystemTime};
use std::sync::mpsc::{self, Sender, Receiver};
use std::path::PathBuf;
//use clipboard::{ClipboardProvider, ClipboardContext};
use api::{
    RklContent,
    SystemConfiguration,
    Props,
};

pub use api::{
    Entry as Entry,
    UserSelection as UserSelection,
    Menu as Menu,
    UserOption as UserOption,
    MessageSeverity as MessageSeverity,
    RklConfiguration as RklConfiguration,
    safe::Safe as Safe,
};

pub use async::nextcloud;

mod file_handler;
mod errors;
mod protected;
pub mod datacrypt;
mod async;
mod api;

/// Takes a reference of `Editor` implementation as argument and executes the _rust-keylock_ logic.
/// The `Editor` is responsible for the interaction with the user. Currently there are `Editor` implementations for __shell__ and for __Android__.
pub fn execute<T: Editor>(editor: &T) {
    openssl_probe::init_ssl_cert_env_vars();
    info!("Starting rust-keylock...");

    let filename = ".sec";
    let props_filename = ".props";
    // Holds the UserSelections
    let mut user_selection;
    // Holds the time of the latest user action
    let mut last_action_time;

    let props = match file_handler::load_properties(props_filename) {
        Ok(m) => m,
        Err(error) => {
            error!("Could not load properties. Using defaults. The error was: {}", error.description());
            Props::default()
        }
    };

    // Keeps the sensitive data
    let mut safe = Safe::new();
    // Keeps the configuration data
    let mut configuration = RklConfiguration::from((async::nextcloud::NextcloudConfiguration::default(), SystemConfiguration::default()));
    // Signals changes that are not saved
    let mut contents_changed = false;
    let mut nextcloud_rx: Option<Receiver<errors::Result<async::nextcloud::SyncStatus>>> = None;
    let mut nextcloud_loop_ctrl_tx: Option<Sender<bool>> = None;

    // Create a Cryptor
    let mut cryptor = {
        // First time run?
        let provided_password = if file_handler::is_first_run(filename) {
            editor.show_change_password()
        } else {
            editor.show_password_enter()
        };

        // Take the provided password and do the initialization
        let (us, cr) = handle_provided_password_for_init(provided_password, filename, &mut safe, &mut configuration, editor);
        // If a valid nextcloud configuration is in place, spawn the background async execution
        if configuration.nextcloud.is_filled() {
            let (nc_rx, loop_ctrl_tx) = spawn_nextcloud_async_task(&filename, &configuration, &nextcloud_loop_ctrl_tx);
            nextcloud_rx = Some(nc_rx);
            nextcloud_loop_ctrl_tx = Some(loop_ctrl_tx);
        }
        // Set the UserSelection
        user_selection = us;
        // Set the time of the action
        last_action_time = SystemTime::now();
        cr
    };

    // Start the backround async tasks
    //    let rx_async_tasks = start_async_tasks(&filename);

    loop {
        editor.sort_entries(&mut safe.entries);
        // Check reception of async message
        async_channel_check(&nextcloud_rx, editor, filename, &mut user_selection);
        // Idle time check only on selections other than GoTo::Main
        if user_selection != UserSelection::GoTo(Menu::Main) {
            user_selection = user_selection_after_idle_check(&last_action_time, props.idle_timeout_seconds(), user_selection, editor);
        }
        // Update the action time
        last_action_time = SystemTime::now();
        // Handle
        user_selection = match user_selection {
            UserSelection::GoTo(Menu::TryPass) => {
                // Cancel any pending background tasks
                let _ = nextcloud_loop_ctrl_tx.as_ref().and_then(|tx| Some(tx.send(true)));
                let (user_selection, cr) =
                    handle_provided_password_for_init(editor.show_password_enter(), filename, &mut safe, &mut configuration, editor);
                // If a valid nextcloud configuration is in place, spawn the background async execution
                if configuration.nextcloud.is_filled() {
                    debug!("A valid configuration for Nextcloud synchronization was found. Spawning async tasks");
                    let (nc_rx, loop_ctrl_tx) = spawn_nextcloud_async_task(&filename, &configuration, &nextcloud_loop_ctrl_tx);
                    nextcloud_rx = Some(nc_rx);
                    nextcloud_loop_ctrl_tx = Some(loop_ctrl_tx);
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
                cryptor = file_handler::create_bcryptor(filename, pwd, salt_pos, true, true).unwrap();
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
                let res = rkl_content.and_then(|c| file_handler::save(c, filename, &cryptor, true));
                match res {
                    Ok(_) => {
                        // Cancel any pending background tasks
                        let _ = nextcloud_loop_ctrl_tx.as_ref().and_then(|tx| Some(tx.send(true)));
                        // Clean the flag for unsaved data
                        contents_changed = false;
                        // Start a new background async task
                        let (nc_rx, loop_ctrl_tx) = spawn_nextcloud_async_task(&filename, &configuration, &nextcloud_loop_ctrl_tx);
                        nextcloud_rx = Some(nc_rx);
                        nextcloud_loop_ctrl_tx = Some(loop_ctrl_tx);
                        let _ =
                            editor.show_message("Encrypted and saved successfully!", vec![UserOption::ok()], MessageSeverity::default());
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
                let mut rec_entries = match file_handler::recover(filename, &cryptor) {
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
                    let (nc_rx, loop_ctrl_tx) = spawn_nextcloud_async_task(&filename, &configuration, &nextcloud_loop_ctrl_tx);
                    nextcloud_rx = Some(nc_rx);
                    nextcloud_loop_ctrl_tx = Some(loop_ctrl_tx);
                    contents_changed = true;
                }
                UserSelection::GoTo(Menu::Main)
            }
            UserSelection::GoTo(Menu::Synchronize) => {
                debug!("UserSelection::GoTo(Menu::Synchronize)");
                let mut tmp_nextcloud_loop_ctrl_tx: Option<Sender<bool>> = None;
                let (nc_rx, loop_ctrl_tx) = spawn_nextcloud_async_task(&filename, &configuration, &tmp_nextcloud_loop_ctrl_tx);
                let timeout = time::Duration::from_millis(30000);
                let to_ret = match nc_rx.recv_timeout(timeout) {
                    Ok(sync_status_res) => {
                        match sync_status_res {
                            Ok(sync_status) => {
                                let mut tmp_user_selection = UserSelection::GoTo(Menu::Main);
                                handle_sync_status_success(sync_status, editor, &filename, &mut tmp_user_selection, false);
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

                // Stop the async task
                let _ = loop_ctrl_tx.send(true);
                // Return the result
                to_ret
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
    info!("Exiting rust-keylock...");
}

fn async_channel_check(nextcloud_rx: &Option<Receiver<errors::Result<async::nextcloud::SyncStatus>>>,
                       editor: &Editor,
                       filename: &str,
                       user_selection: &mut UserSelection) {
    match nextcloud_rx.as_ref() {
        Some(rx) => {
            match rx.try_recv() {
                Ok(sync_status_res) => {
                    match sync_status_res {
                        Ok(sync_status) => handle_sync_status_success(sync_status, editor, filename, user_selection, true),
                        Err(_) => {
                            // ignore
                        }
                    }
                }
                _ => {
                    // ignore
                }
            }
        }
        _ => {
            // ignore
        }
    }
}

fn handle_sync_status_success(sync_status: async::nextcloud::SyncStatus,
                              editor: &Editor,
                              filename: &str,
                              user_selection: &mut UserSelection,
                              ignore_contents_identical_message: bool) {
    match sync_status {
        async::nextcloud::SyncStatus::UploadSuccess => {
            let _ =
                editor.show_message("The nextcloud server was updated with the local data", vec![UserOption::ok()], MessageSeverity::Info);
        }
        async::nextcloud::SyncStatus::NewAvailable(downloaded_filename) => {
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
        async::nextcloud::SyncStatus::NewToMerge(downloaded_filename) => {
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
        async::nextcloud::SyncStatus::None if !ignore_contents_identical_message => {
            let _ = editor.show_message("No need to sync. The contents are identical", vec![UserOption::ok()], MessageSeverity::Info);
        }
        _ => {
            // ignore
        }
    }
}

fn user_selection_after_idle_check(last_action_time: &SystemTime,
                                   timeout_seconds: i64,
                                   us: UserSelection,
                                   editor: &Editor)
                                   -> UserSelection {
    match last_action_time.elapsed() {
        Ok(elapsed) => {
            let elapsed_seconds = elapsed.as_secs();
            if elapsed_seconds as i64 > timeout_seconds {
                warn!("Idle time of {} seconds elapsed! Locking...", timeout_seconds);
                let message = format!("Idle time of {} seconds elapsed! Locking...", timeout_seconds);
                let _ = editor.show_message(&message, vec![UserOption::ok()], MessageSeverity::default());
                UserSelection::GoTo(Menu::TryPass)
            } else {
                us
            }
        }
        Err(error) => {
            error!("Cannot get the elapsed time since the last action of the user: {:?}", &error);
            us
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
        _ => {
            panic!("Wrong initialization sequence... The editor.show_password_enter must always return a UserSelection::ProvidedPassword. \
                    Please, consider opening a bug to the developers.")
        }
    }
}

fn spawn_nextcloud_async_task(filename: &str,
                              configuration: &RklConfiguration,
                              async_task_control_tx_opt: &Option<Sender<bool>>)
                              -> (Receiver<errors::Result<async::nextcloud::SyncStatus>>, Sender<bool>) {
    match async_task_control_tx_opt.as_ref() {
        Some(ctrl_tx) => {
            debug!("Stopping a previously spawned nextcloud async task");
            let _ = ctrl_tx.send(true);
        }
        None => {
            // ignore
        }
    }
    debug!("Spawning nextcloud async task");
    // Create a new channel
    let (tx, rx): (Sender<errors::Result<async::nextcloud::SyncStatus>>, Receiver<errors::Result<async::nextcloud::SyncStatus>>) =
        mpsc::channel();
    let every = time::Duration::from_millis(10000);
    let nc = async::nextcloud::Synchronizer::new(&configuration.nextcloud, &configuration.system, tx, filename).unwrap();
    let async_task_control_tx = async::execute_task(Box::new(nc), every);
    (rx, async_task_control_tx)
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

#[cfg(test)]
mod unit_tests {
    use super::api::{Menu, UserSelection, UserOption, Entry};
    use std::time::SystemTime;
    use std::sync::Mutex;
    use std;

    #[test]
    fn user_selection_after_idle_check_timed_out() {
        let time = SystemTime::now();
        std::thread::sleep(std::time::Duration::new(2, 0));
        let user_selection = super::user_selection_after_idle_check(
            &time,
            1,
            UserSelection::GoTo(Menu::Main),
            &TestEditor::new(vec![UserSelection::ProvidedPassword("dummy".to_string(), 0)]));
        assert!(user_selection == UserSelection::GoTo(Menu::TryPass));
    }

    #[test]
    fn user_selection_after_idle_check_not_timed_out() {
        let time = SystemTime::now();
        let user_selection = super::user_selection_after_idle_check(
            &time,
            10,
            UserSelection::GoTo(Menu::Main),
            &TestEditor::new(vec![UserSelection::ProvidedPassword("dummy".to_string(), 0)]));
        assert!(user_selection == UserSelection::GoTo(Menu::Main));
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
            UserSelection::NewEntry(Entry::new("n".to_owned(), "u".to_owned(), "p".to_owned(), "s".to_owned())),
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
            UserSelection::NewEntry(Entry::new("11nn".to_owned(), "11un".to_owned(), "11pn".to_owned(), "11sn".to_owned())),
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