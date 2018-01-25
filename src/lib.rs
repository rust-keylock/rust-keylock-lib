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

use toml::value::Table;
use std::error::Error;
use std::time::{self, SystemTime, UNIX_EPOCH};
use std::sync::mpsc::{self, Sender, Receiver};
use std::iter::FromIterator;
pub use async::nextcloud;

mod file_handler;
mod errors;
mod protected;
pub mod datacrypt;
mod async;

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
        let (us, cr) = handle_provided_password_for_init(provided_password, filename, &mut safe, &mut configuration, editor, true);
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
        // Idle time check
        user_selection = user_selection_after_idle_check(&last_action_time, props.idle_timeout_seconds, user_selection, editor);
        // Update the action time
        last_action_time = SystemTime::now();
        // Handle
        user_selection = match user_selection {
            UserSelection::GoTo(Menu::TryPass) => {
                // Cancel any pending background tasks
                let _ = nextcloud_loop_ctrl_tx.as_ref().and_then(|tx| Some(tx.send(true)));
                let (user_selection, cr) =
                    handle_provided_password_for_init(editor.show_password_enter(), filename, &mut safe, &mut configuration, editor, true);
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
                cryptor = file_handler::create_bcryptor(filename, pwd, salt_pos, true, true, true).unwrap();
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
                safe.replace_entry(index, entry);
                UserSelection::GoTo(Menu::EntriesList(safe.get_filter()))
            }
            UserSelection::DeleteEntry(index) => {
                debug!("UserSelection::DeleteEntry(index)");
                safe.remove_entry(index);
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
                        let cr = file_handler::create_bcryptor(&path, pwd, salt_pos, false, import_from_default_location, true).unwrap();
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
                Ok(sync_status) => {
                    match sync_status {
                        Ok(async::nextcloud::SyncStatus::UploadSuccess) => {
                            let _ = editor.show_message("The nextcloud server was updated with the local data",
                                                        vec![UserOption::ok()],
                                                        MessageSeverity::Info);
                        }
                        Ok(async::nextcloud::SyncStatus::NewAvailable(downloaded_filename)) => {
                            let selection =
                                editor.show_message("Downloaded new data from the nextcloud server. Do you want to apply them locally now?",
                                                  vec![UserOption::yes(), UserOption::no()],
                                                  MessageSeverity::Info);

                            debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
                            if selection == UserSelection::UserOption(UserOption::yes()) {
                                debug!("Replacing the local file with the one downloaded from the server");
                                let _ = file_handler::replace(&downloaded_filename, filename);
                                *user_selection = UserSelection::GoTo(Menu::TryPass);
                            }
                        }
                        Ok(async::nextcloud::SyncStatus::NewToMerge(downloaded_filename)) => {
                            let selection =
                                editor.show_message("Downloaded data from the nextcloud server, but conflicts were identified. The \
                                                     contents will be merged but nothing will be saved. You will need to explicitly save \
                                                     after reviewing the merged data. Do you want to do the merge now?",
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
                                        let message = format!("Expected a ProvidedPassword but received '{:?}'. Please, consider opening \
                                                               a bug to the developers.",
                                                              &other);
                                        error!("{}", message);
                                        let _ =
                                            editor.show_message("Unexpected result when waiting for password. See the logs for more \
                                                                 details. Please consider opening a but to the developers.",
                                                                vec![UserOption::ok()],
                                                                MessageSeverity::Error);
                                        *user_selection = UserSelection::GoTo(Menu::TryPass);
                                    }
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
                                     editor: &Editor,
                                     expanded_key: bool)
                                     -> (UserSelection, datacrypt::BcryptAes) {
    let user_selection: UserSelection;
    match provided_password {
        UserSelection::ProvidedPassword(pwd, salt_pos) => {
            // New Cryptor here
            let cr = file_handler::create_bcryptor(filename, pwd.clone(), salt_pos, false, true, expanded_key).unwrap();
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
                            let just_upgraded_opt =
                                UserOption::new("Just Upgraded...", UserOptionType::String("just_upgraded".to_string()), "j");
                            let s =
                                editor.show_message("Wrong password or number! Please make sure that both the password and number that you \
                                                   provide are correct. If this is the case, the rust-keylock data is corrupted and \
                                                   nothing can be done about it.",
                                                  vec![UserOption::ok(), just_upgraded_opt],
                                                  MessageSeverity::Error);
                            match s {
                                UserSelection::UserOption(uo) => {
                                    if uo.short_label == "j" {
                                        let usel = UserSelection::ProvidedPassword(pwd.clone(), salt_pos);
                                        let _ = handle_provided_password_for_init(usel, filename, safe, configuration, editor, false);
                                        user_selection = UserSelection::GoTo(Menu::Main);
                                        safe.get_entries_decrypted()
                                    } else {
                                        user_selection = UserSelection::GoTo(Menu::TryPass);
                                        Vec::new()
                                    }
                                }
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
            let cr = file_handler::create_bcryptor(filename, "dummy".to_string(), 33, false, true, true).unwrap();
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

/// Struct to use for retrieving and saving data from/to the file
pub struct RklContent {
    entries: Vec<Entry>,
    nextcloud_conf: async::nextcloud::NextcloudConfiguration,
    system_conf: SystemConfiguration,
}

impl RklContent {
    pub fn new(entries: Vec<Entry>,
               nextcloud_conf: async::nextcloud::NextcloudConfiguration,
               system_conf: SystemConfiguration)
               -> RklContent {
        RklContent {
            entries: entries,
            nextcloud_conf: nextcloud_conf,
            system_conf: system_conf,
        }
    }

    pub fn from(tup: (&Safe, &async::nextcloud::NextcloudConfiguration, &SystemConfiguration)) -> errors::Result<RklContent> {
        let entries = tup.0.get_entries_decrypted();
        let nextcloud_conf = async::nextcloud::NextcloudConfiguration::new(tup.1.server_url.clone(),
                                                                           tup.1.username.clone(),
                                                                           tup.1.decrypted_password()?,
                                                                           tup.1.use_self_signed_certificate);
        let system_conf = SystemConfiguration::new(tup.2.saved_at, tup.2.version, tup.2.last_sync_version);

        Ok(RklContent::new(entries, nextcloud_conf?, system_conf))
    }
}

/// Keeps the Configuration
#[derive(Debug, PartialEq)]
pub struct RklConfiguration {
    pub system: SystemConfiguration,
    pub nextcloud: async::nextcloud::NextcloudConfiguration,
}

impl RklConfiguration {
    pub fn update_system_for_save(&mut self) -> errors::Result<()> {
        self.system.version = Some((self.system.version.unwrap_or(0)) + 1);
        // When uploaded, the last_sync_version should be the same with the version
        self.system.last_sync_version = self.system.version;
        let local_time_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.system.saved_at = Some(local_time_seconds as i64);
        Ok(())
    }
}

impl From<(async::nextcloud::NextcloudConfiguration, SystemConfiguration)> for RklConfiguration {
    fn from(confs: (async::nextcloud::NextcloudConfiguration, SystemConfiguration)) -> Self {
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
            saved_at: saved_at,
            version: version,
            last_sync_version: last_sync_version,
        }
    }

    pub fn from_table(table: &Table) -> Result<SystemConfiguration, errors::RustKeylockError> {
        let saved_at = table.get("saved_at").and_then(|value| value.as_integer().and_then(|int_ref| Some(int_ref)));
        let version = table.get("version").and_then(|value| value.as_integer().and_then(|int_ref| Some(int_ref)));
        let last_sync_version = table.get("last_sync_version").and_then(|value| value.as_integer().and_then(|int_ref| Some(int_ref)));
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
    /// The username
    pub user: String,
    /// The password
    pub pass: String,
    /// A description of the `Entry`
    pub desc: String,
    /// Whether the Entry has encrypted elements (like password)
    pub encrypted: bool,
}

impl Entry {
    /// Creates a new `Entry` using the provided name, username, password and description
    pub fn new(name: String, user: String, pass: String, desc: String) -> Entry {
        Entry {
            name: name,
            user: user,
            pass: pass,
            desc: desc,
            encrypted: false,
        }
    }

    /// Creates an empty `Entry`
    pub fn empty() -> Entry {
        Entry {
            name: "".to_string(),
            user: "".to_string(),
            pass: "".to_string(),
            desc: "".to_string(),
            encrypted: false,
        }
    }

    fn from_table(table: &Table) -> Result<Entry, errors::RustKeylockError> {
        let name = table.get("name").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let user = table.get("user").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let pass = table.get("pass").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let desc = table.get("desc").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));

        match (name, user, pass, desc) {
            (Some(n), Some(u), Some(p), Some(d)) => Ok(Self::new(n, u, p, d)),
            _ => Err(errors::RustKeylockError::ParseError(toml::ser::to_string(&table).unwrap_or("Cannot serialize toml".to_string()))),
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

    fn encrypted(&self, cryptor: &datacrypt::EntryPasswordCryptor) -> Entry {
        let (encrypted_password, encryption_succeeded) = match cryptor.encrypt_str(&self.pass) {
            Ok(encrypted) => (encrypted, true),
            Err(_) => {
                error!("Could not encrypt password for {}. Defaulting in keeping it in plain...", &self.name);
                (self.pass.clone(), false)
            }
        };
        Entry {
            name: self.name.clone(),
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
        Entry::new(self.name.clone(), self.user.clone(), decrypted_password, self.desc.clone())
    }
}

/// Holds the data that should be safe and secret.
///
/// This includes the password entries and a Cryptor that is used to encrypt the passwords of the entries when they are stored in memory
/// and decrypt them when needed (to be presented to the User)
pub struct Safe {
    entries: Vec<Entry>,
    filtered_entries: Vec<Entry>,
    password_cryptor: datacrypt::EntryPasswordCryptor,
    filter: String,
}

impl Default for Safe {
    fn default() -> Self {
        Safe {
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            password_cryptor: datacrypt::EntryPasswordCryptor::new(),
            filter: "".to_string(),
        }
    }
}

impl Safe {
    pub fn new() -> Safe {
        Safe {
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            password_cryptor: datacrypt::EntryPasswordCryptor::new(),
            filter: "".to_string(),
        }
    }

    /// Adds an Entry to the Safe, with the Entry password encrypted
    fn add_entry(&mut self, new_entry: Entry) {
        self.entries.push(new_entry.encrypted(&self.password_cryptor));
        self.apply_filter();
    }

    /// Replaces an Entry in the Safe, with a new Entry that has the password encrypted
    fn replace_entry(&mut self, index: usize, entry: Entry) {
        self.entries.push(entry.encrypted(&self.password_cryptor));
        self.entries.swap_remove(index);
        self.apply_filter();
    }

    /// Removes an Entry from the Safe
    fn remove_entry(&mut self, index: usize) {
        self.entries.remove(index);
        self.apply_filter();
    }

    /// Merges the Entries, by appending the incoming elements that are not the same with some existing one in Safe
    fn merge(&mut self, incoming: Vec<Entry>) {
        let mut to_add = {
            incoming.into_iter()
                .filter(|entry| {
                    let mut main_iter = self.entries.iter();
                    let opt = main_iter.find(|main_entry| {
                        let enrypted_entry = entry.encrypted(&self.password_cryptor);
                        main_entry.name == enrypted_entry.name && main_entry.user == enrypted_entry.user &&
                        main_entry.pass == enrypted_entry.pass && main_entry.desc == enrypted_entry.desc
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
    fn add_all(&mut self, incoming: Vec<Entry>) {
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

    /// Retrieves all Entries with the passwords decrypted, after applying the filter to the Vector
    fn get_entries_decrypted(&self) -> Vec<Entry> {
        self.get_entries()
            .into_iter()
            .map(|entry| entry.decrypted(&self.password_cryptor))
            .collect()
    }

    /// Sets a filter to be applied when retrieving the entries
    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.apply_filter();
    }

    /// Gets the filter of the Safe
    pub fn get_filter(&self) -> String {
        self.filter.clone()
    }

    fn apply_filter(&mut self) {
        let m: Vec<Entry> = if self.filter.len() > 0 {
            let ref lower_filter = self.filter.to_lowercase();
            self.entries
                .clone()
                .into_iter()
                .filter(|entry| {
                    entry.name.to_lowercase().contains(lower_filter) || entry.user.to_lowercase().contains(lower_filter) ||
                    entry.desc.to_lowercase().contains(lower_filter)
                })
                .collect()
        } else {
            self.entries.clone()
        };

        self.filtered_entries = m;
    }

    pub fn clear(&mut self) {
        self.filtered_entries = Vec::new();
        self.entries = Vec::new();
        self.filter = "".to_string();
    }
}

/// A struct that allows storing general configuration values.
/// The configuration values are stored in plaintext.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Props {
    /// Inactivity timeout seconds
    idle_timeout_seconds: i64,
}

impl Default for Props {
    fn default() -> Self {
        Props { idle_timeout_seconds: 180 }
    }
}

impl Props {
    fn new(idle_timeout_seconds: i64) -> Props {
        Props { idle_timeout_seconds: idle_timeout_seconds }
    }

    fn from_table(table: &Table) -> Result<Props, errors::RustKeylockError> {
        let idle_timeout_seconds = table.get("idle_timeout_seconds").and_then(|value| value.as_integer().and_then(|i_ref| Some(i_ref)));

        match idle_timeout_seconds {
            Some(s) => Ok(Self::new(s)),
            _ => Err(errors::RustKeylockError::ParseError(toml::ser::to_string(&table).unwrap_or("Cannot serialize toml".to_string()))),
        }
    }

    #[allow(dead_code)]
    fn to_table(&self) -> Table {
        let mut table = Table::new();
        table.insert("idle_timeout_seconds".to_string(), toml::Value::Integer(self.idle_timeout_seconds));

        table
    }
}

/// Enumeration of the several different Menus that an `Editor` implementation should handle.
#[derive(Debug, PartialEq)]
pub enum Menu {
    /// The User should provide a password and a number.
    TryPass,
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
    Save,
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
    /// Perform Synchronization
    Syncronize,
}

impl Menu {
    /// Returns the name of a `Menu`.
    pub fn get_name(&self) -> String {
        match self {
            &Menu::TryPass => format!("{:?}", Menu::TryPass),
            &Menu::ChangePass => format!("{:?}", Menu::ChangePass),
            &Menu::Main => format!("{:?}", Menu::Main),
            &Menu::EntriesList(_) => "EntriesList".to_string(),
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
            &Menu::ShowConfiguration => format!("{:?}", Menu::ShowConfiguration),
            &Menu::Syncronize => format!("{:?}", Menu::Syncronize),
        }
    }

    /// Parses a String and creates a `Menu`.
    ///
    /// Menus that have additional `usize` and `String` arguments exist. Thus the existence of the `Option`al arguments during parsing.
    pub fn from(name: String, opt_num: Option<usize>, opt_string: Option<String>) -> Menu {
        debug!("Creating Menu from name {} and additional arguments usize: {:?}, String: {:?}", &name, &opt_num, &opt_string);
        match (name, opt_num, opt_string.clone()) {
            (ref n, None, None) if &Menu::TryPass.get_name() == n => Menu::TryPass,
            (ref n, None, None) if &Menu::ChangePass.get_name() == n => Menu::ChangePass,
            (ref n, None, None) if &Menu::Main.get_name() == n => Menu::Main,
            (ref n, None, Some(ref arg)) if &Menu::EntriesList(arg.clone()).get_name() == n => Menu::EntriesList(arg.clone()),
            (ref n, None, None) if &Menu::NewEntry.get_name() == n => Menu::NewEntry,
            (ref n, Some(arg), None) if &Menu::ShowEntry(arg).get_name() == n => Menu::ShowEntry(arg),
            (ref n, Some(arg), None) if &Menu::EditEntry(arg).get_name() == n => Menu::EditEntry(arg),
            (ref n, Some(arg), None) if &Menu::DeleteEntry(arg).get_name() == n => Menu::DeleteEntry(arg),
            (ref n, None, None) if &Menu::Save.get_name() == n => Menu::Save,
            (ref n, None, None) if &Menu::Exit.get_name() == n => Menu::Exit,
            (ref n, None, None) if &Menu::ForceExit.get_name() == n => Menu::ForceExit,
            (ref n, None, None) if &Menu::TryFileRecovery.get_name() == n => Menu::TryFileRecovery,
            (ref n, None, None) if &Menu::ImportEntries.get_name() == n => Menu::ImportEntries,
            (ref n, None, None) if &Menu::ExportEntries.get_name() == n => Menu::ExportEntries,
            (ref n, None, None) if &Menu::ShowConfiguration.get_name() == n => Menu::ShowConfiguration,
            (ref n, None, None) if &Menu::Syncronize.get_name() == n => Menu::Syncronize,
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
#[derive(Debug, PartialEq)]
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
    /// The User updates the configuration
    UpdateConfiguration(nextcloud::NextcloudConfiguration),
}

#[derive(Debug, PartialEq)]
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
    fn extract_value_from_string(str: &str) -> errors::Result<String> {
        println!("Extracting value from {}", str);
        let s = str.clone();
        let start = s.find("(");
        if s.ends_with(")") {
            match start {
                Some(st) => {
                    let i = s.chars().skip(st + 1).take(str.len() - st - 2);
                    let s = String::from_iter(i);
                    println!("returning {}", s);
                    Ok(s)
                }
                _ => {
                    Err(errors::RustKeylockError::ParseError(format!("Could not extract UserOptionType value from {}. The \
                                                                      UserOptionType can be extracted from strings like String(value)",
                                                                     str)))
                }
            }
        } else {
            Err(errors::RustKeylockError::ParseError(format!("Could not extract UserOptionType value from {}. The UserOptionType can be \
                                                              extracted from strings like String(value)",
                                                             str)))
        }
    }
}

impl ToString for UserOptionType {
    fn to_string(&self) -> String {
        match self {
            &UserOptionType::String(ref s) => format!("String({})", s),
            _ => String::from(format!("{:?}", &self)),
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

/// Severity for the messages presented to tthe Users
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
        String::from(format!("{:?}", &self))
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
    use toml;
    use super::{Menu, Entry, UserSelection};
    use super::datacrypt::EntryPasswordCryptor;
    use std::time::SystemTime;
    use std;

    #[test]
    fn entry_from_table_success() {
        let toml = r#"
			name = "name1"
			user = "user1"
			pass = "123"
			desc = "some description"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
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

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
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

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
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
        let entry = super::Entry::new("name".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string());
        let enc_entry = entry.encrypted(&cryptor);
        assert!(enc_entry.name == entry.name);
        assert!(enc_entry.user == entry.user);
        assert!(enc_entry.pass != entry.pass);
        assert!(enc_entry.desc == entry.desc);
        let dec_entry = enc_entry.decrypted(&cryptor);
        assert!(dec_entry.pass == entry.pass);
    }

    #[test]
    fn entry_to_encrypted_encryption_may_fail() {
        let cryptor = EntryPasswordCryptor::new();
        let entry = super::Entry::new("name".to_string(), "user".to_string(), "pass".to_string(), "desc".to_string());
        let dec_entry = entry.decrypted(&cryptor);
        assert!(dec_entry.pass == entry.pass);
    }

    #[test]
    fn props_from_table_success() {
        let toml = r#"idle_timeout_seconds = 33"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let props_opt = super::Props::from_table(&table);
        assert!(props_opt.is_ok());
        let props = props_opt.unwrap();
        assert!(props.idle_timeout_seconds == 33);
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
        let toml = r#"idle_timeout_seconds = 33"#;

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
        let m1 = Menu::TryPass.get_name();
        assert!(m1 == "TryPass");
        let m2 = Menu::EntriesList("".to_string()).get_name();
        assert!(m2 == "EntriesList");
        let m3 = Menu::EditEntry(33).get_name();
        assert!(m3 == "EditEntry");
    }

    #[test]
    fn menu_from_name() {
        let m1 = Menu::from("TryPass".to_string(), None, None);
        assert!(m1 == Menu::TryPass);
        let m2 = Menu::from("EntriesList".to_string(), None, Some("".to_string()));
        assert!(m2 == Menu::EntriesList("".to_string()));
        let m3 = Menu::from("ShowEntry".to_string(), Some(1), None);
        assert!(m3 == Menu::ShowEntry(1));
    }

    #[test]
    fn merge_entries() {
        let mut safe = super::Safe::new();
        assert!(safe.entries.len() == 0);

        // Add some initial Entries
        let all = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string()),
                       Entry::new("2".to_string(), "2".to_string(), "2".to_string(), "2".to_string())];
        safe.add_all(all);

        // This one should be added
        let first = vec![Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string())];
        safe.merge(first);
        assert!(safe.entries.len() == 3);

        // This one should not be added
        let second = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "1".to_string())];
        safe.merge(second);
        assert!(safe.entries.len() == 3);

        // This one should not be added either (the description is not the same with any of the existing ones
        let third = vec![Entry::new("1".to_string(), "1".to_string(), "1".to_string(), "3".to_string())];
        safe.merge(third);
        assert!(safe.entries.len() == 4);
    }

    #[test]
    fn add_entry() {
        let mut safe = super::Safe::new();
        let entry = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry.clone());
        assert!(safe.entries.len() == 1);
        assert!(safe.entries[0].name == entry.name);
        assert!(safe.entries[0].user == entry.user);
        assert!(safe.entries[0].pass != entry.pass);
        assert!(safe.entries[0].desc == entry.desc);
    }

    #[test]
    fn replace_entry() {
        let mut safe = super::Safe::new();
        let entry = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry.clone());
        let new_entry = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        safe.replace_entry(1, new_entry.clone());

        assert!(safe.entries.len() == 1);
        assert!(safe.entries[0].name != new_entry.name);
        assert!(safe.entries[0].user != new_entry.user);
        assert!(safe.entries[0].pass != new_entry.pass);
        assert!(safe.entries[0].desc != new_entry.desc);
    }

    #[test]
    fn remove_entry() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        safe.add_entry(entry1.clone());
        safe.add_entry(entry2.clone());

        safe.remove_entry(1);

        assert!(safe.entries.len() == 1);
        assert!(safe.entries[0].name == entry1.name);
        assert!(safe.entries[0].user == entry1.user);
        assert!(safe.entries[0].pass != entry1.pass);
        assert!(safe.entries[0].desc == entry1.desc);
    }

    #[test]
    fn add_all() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];

        safe.add_all(entries);

        assert!(safe.entries.len() == 2);
        assert!(safe.entries[0].pass != entry1.pass && safe.entries[0].pass != entry2.pass);
        assert!(safe.entries[1].pass != entry1.pass && safe.entries[0].pass != entry2.pass);
    }

    #[test]
    fn get_entry() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entry = safe.get_entry(1);
        assert!(got_entry.name == entry2.name);
        assert!(got_entry.user == entry2.user);
        assert!(got_entry.pass != entry2.pass);
        assert!(got_entry.desc == entry2.desc);
    }

    #[test]
    fn get_entry_decrypted() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entry = safe.get_entry_decrypted(1);
        assert!(got_entry.name == entry2.name);
        assert!(got_entry.user == entry2.user);
        assert!(got_entry.pass == entry2.pass);
        assert!(got_entry.desc == entry2.desc);
    }

    #[test]
    fn get_entries() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
        let entries = vec![entry1.clone(), entry2.clone()];
        safe.add_all(entries);

        let got_entries = safe.get_entries();
        assert!(got_entries.len() == 2);
    }

    #[test]
    fn get_entries_decrypted() {
        let mut safe = super::Safe::new();
        let entry1 = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        let entry2 = Entry::new("33".to_string(), "33".to_string(), "33".to_string(), "33".to_string());
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
        let entry1 = Entry::new("1".to_string(), "2".to_string(), "4".to_string(), "3".to_string());
        let entry2 = Entry::new("11".to_string(), "12".to_string(), "14".to_string(), "13".to_string());
        let entries = vec![entry1, entry2];
        safe.add_all(entries);

        // Assert that the filter can be applied on name, user and desc fields of Entries
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

        // The filter cannot be applied on password
        safe.set_filter("4".to_string());
        assert!(safe.get_entries().len() == 0);

        // The filter should by applied ignoring the case
        let entry3 = Entry::new("NAME".to_string(), "User".to_string(), "pass".to_string(), "Desc".to_string());
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
        let entry = Entry::new("3".to_string(), "3".to_string(), "3".to_string(), "3".to_string());
        safe.add_entry(entry.clone());
        safe.set_filter("a_filter".to_string());

        safe.clear();

        assert!(safe.entries.len() == 0);
        assert!(safe.filtered_entries.len() == 0);
        assert!(safe.filter.len() == 0);
    }

    #[test]
    fn user_selection_after_idle_check_timed_out() {
        let time = SystemTime::now();
        std::thread::sleep(std::time::Duration::new(2, 0));
        let user_selection = super::user_selection_after_idle_check(&time, 1, UserSelection::GoTo(Menu::Main), &DummyEditor::new());
        assert!(user_selection == UserSelection::GoTo(Menu::TryPass));
    }

    #[test]
    fn user_selection_after_idle_check_not_timed_out() {
        let time = SystemTime::now();
        let user_selection = super::user_selection_after_idle_check(&time, 10, UserSelection::GoTo(Menu::Main), &DummyEditor::new());
        assert!(user_selection == UserSelection::GoTo(Menu::Main));
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

    struct DummyEditor;

    impl DummyEditor {
        pub fn new() -> DummyEditor {
            DummyEditor {}
        }
    }

    impl super::Editor for DummyEditor {
        fn show_password_enter(&self) -> UserSelection {
            UserSelection::ProvidedPassword("dummy".to_string(), 0)
        }

        fn show_change_password(&self) -> UserSelection {
            self.show_password_enter()
        }

        fn show_menu(&self, _: &Menu, _: &super::Safe, _: &super::RklConfiguration) -> UserSelection {
            UserSelection::GoTo(Menu::Main)
        }

        fn exit(&self, _: bool) -> UserSelection {
            UserSelection::Ack
        }

        fn show_message(&self, _: &str, _: Vec<super::UserOption>, _: super::MessageSeverity) -> UserSelection {
            UserSelection::Ack
        }
    }
}
