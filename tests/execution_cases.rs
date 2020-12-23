use std::sync::mpsc::{self, Sender};
use std::sync::Mutex;
use std::time::SystemTime;

use clipboard::{ClipboardContext, ClipboardProvider};

use rust_keylock::{AllConfigurations, Entry, EntryMeta, EntryPresentationType, Menu, UserOption, UserSelection, execute, Editor, MessageSeverity};
use rust_keylock::dropbox::DropboxConfiguration;
use rust_keylock::nextcloud::NextcloudConfiguration;
use std::path::PathBuf;
use std::fs::DirBuilder;

const INTEGRATION_TESTS_TMP_PATH_STR: &str = "./target/integration_tests_tmp";

#[test]
// WARNING: Running this, will mess with the passwords that are stored in the $HOME/.rust-keylock directory
fn execution_cases() {
    // Create the tmp directory
    DirBuilder::new()
        .recursive(true)
        .create(INTEGRATION_TESTS_TMP_PATH_STR).unwrap();
    // Proceed with the tests
    execute_login_success();
    execute_exit_without_login();
    execute_show_entry();
    execute_add_entry();
    execute_add_entry_with_leaked_password();
    execute_add_entry_with_leaked_password_and_fix_it();
    execute_edit_entry();
    execute_edit_entry_define_leaked_password();
    execute_edit_entry_define_leaked_password_and_fix_it();
    execute_delete_entry();
    execute_change_pass();
    execute_export_entries();
    execute_import_entries();
    execute_update_configuration();
    execute_add_to_clipboard();
    execute_file_recovery();
    execute_check_passwords();
    // This should be after setting nextcloud or dropbox in order to include testing with the configurations filled
    execute_login_fail_and_then_sucess();
}

fn execute_login_success() {
    println!("===========execute_login_success");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::Exit),
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_exit_without_login() {
    println!("===========execute_exit_without_login");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login for failure
        UserSelection::new_provided_password("12311".to_string(), 0),
        // Ack wrong password message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::Exit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_login_fail_and_then_sucess() {
    println!("===========execute_login_fail_and_then_sucess");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login for failure
        UserSelection::new_provided_password("12311".to_string(), 0),
        // Ack wrong password message
        UserSelection::UserOption(UserOption::ok()),
        // Login for success
        UserSelection::new_provided_password("123".to_string(), 0),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::Exit),
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_show_entry() {
    println!("===========execute_show_entry");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Add an entry
        UserSelection::NewEntry(Entry::new("11nn".to_owned(), "11url".to_owned(), "11un".to_owned(), "11pn".to_owned(), "11sn".to_owned(), EntryMeta::default())),
        // Show the first entry
        UserSelection::GoTo(Menu::ShowEntry(0)),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_edit_entry() {
    println!("===========execute_edit_entry");
    let (tx, rx) = mpsc::channel();
    let pass = rs_password_utils::dice::generate(6);
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Edit the first entry
        UserSelection::GoTo(Menu::EditEntry(0)),
        UserSelection::ReplaceEntry(0, Entry::new("r".to_owned(), "url".to_owned(), "ru".to_owned(), pass, "rs".to_owned(), EntryMeta::default())),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_edit_entry_define_leaked_password() {
    println!("===========execute_edit_entry_define_leaked_password");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Edit the first entry
        UserSelection::GoTo(Menu::EditEntry(0)),
        UserSelection::ReplaceEntry(0, Entry::new("r".to_owned(), "url".to_owned(), "ru".to_owned(), "123".to_string(), "rs".to_owned(), EntryMeta::default())),
        // Answer ok to the warning about the leaked password
        UserSelection::UserOption(UserOption::yes()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_edit_entry_define_leaked_password_and_fix_it() {
    println!("===========execute_edit_entry_define_leaked_password_and_fix_it");
    let (tx, rx) = mpsc::channel();
    let pass = rs_password_utils::dice::generate(6);
    let anentry = Entry::new("r".to_owned(), "url".to_owned(), "ru".to_owned(), "123".to_string(), "rs".to_owned(), EntryMeta::default());
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Edit the first entry
        UserSelection::GoTo(Menu::EditEntry(0)),
        UserSelection::ReplaceEntry(0, anentry.clone()),
        // Answer no to the warning about the leaked password
        UserSelection::UserOption(UserOption::no()),
        // Generate a strong password
        UserSelection::GeneratePassphrase(Some(0), anentry),
        UserSelection::ReplaceEntry(0, Entry::new("r".to_owned(), "url".to_owned(), "ru".to_owned(), pass, "rs".to_owned(), EntryMeta::default())),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_add_entry() {
    println!("===========execute_add_entry");
    let (tx, rx) = mpsc::channel();
    let pass = rs_password_utils::dice::generate(6);
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Add an entry
        UserSelection::GoTo(Menu::NewEntry(None)),
        UserSelection::NewEntry(Entry::new("n".to_owned(), "url".to_owned(), "u".to_owned(), pass, "s".to_owned(), EntryMeta::default())),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_add_entry_with_leaked_password() {
    println!("===========execute_add_entry_with_leaked_password");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Add an entry
        UserSelection::GoTo(Menu::NewEntry(None)),
        UserSelection::NewEntry(Entry::new("n".to_owned(), "url".to_owned(), "u".to_owned(), "123".to_string(), "s".to_owned(), EntryMeta::default())),
        // Answer ok to the warning about the leaked password
        UserSelection::UserOption(UserOption::yes()),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_add_entry_with_leaked_password_and_fix_it() {
    println!("===========execute_add_entry_with_leaked_password_and_fix_it");
    let pass = rs_password_utils::dice::generate(6);
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Add an entry
        UserSelection::GoTo(Menu::NewEntry(None)),
        UserSelection::NewEntry(Entry::new("n".to_owned(), "url".to_owned(), "u".to_owned(), "123".to_string(), "s".to_owned(), EntryMeta::default())),
        // Answer no to the warning about the leaked password
        UserSelection::UserOption(UserOption::no()),
        // Add an entry with not leaked password
        UserSelection::NewEntry(Entry::new("n".to_owned(), "url".to_owned(), "u".to_owned(), pass, "s".to_owned(), EntryMeta::default())),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_delete_entry() {
    println!("===========execute_delete_entry");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Add an entry
        UserSelection::NewEntry(Entry::new("11nn".to_owned(), "11url".to_owned(), "11un".to_owned(), "11pn".to_owned(), "11sn".to_owned(), EntryMeta::default())),
        // Delete the first entry
        UserSelection::GoTo(Menu::DeleteEntry(0)),
        UserSelection::DeleteEntry(0),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_change_pass() {
    println!("===========execute_change_pass");
    let (tx, rx) = mpsc::channel();
    let editor1 = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Go to change pass
        UserSelection::GoTo(Menu::ChangePass),
        // Return the new password
        UserSelection::new_provided_password("321".to_string(), 1),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx.clone()));

    execute(editor1);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());

    // Assert the password is changed
    let editor2 = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("321".to_string(), 1),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx.clone()));

    execute(editor2);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());

    // Change the password back to the previous one
    let editor3 = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("321".to_string(), 1),
        // Go to change pass
        UserSelection::GoTo(Menu::ChangePass),
        // Return the new password
        UserSelection::new_provided_password("123".to_string(), 0),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor3);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_export_entries() {
    println!("===========execute_export_entries");
    let (tx, rx) = mpsc::channel();
    let mut loc = PathBuf::from(INTEGRATION_TESTS_TMP_PATH_STR);
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Cannot create the duration for the execute_export_entries").as_secs();
    loc.push(format!("exported{:?}", now));
    let loc_str = loc.into_os_string().into_string().unwrap();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
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

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_import_entries() {
    println!("===========execute_import_entries");
    let (tx, rx) = mpsc::channel();
    let mut loc = PathBuf::from(INTEGRATION_TESTS_TMP_PATH_STR);
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Cannot create the duration for the execute_export_entries").as_secs();
    loc.push(format!("exported{:?}", now));
    let loc_str = loc.into_os_string().into_string().unwrap();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Export entries
        UserSelection::GoTo(Menu::ImportEntries),
        UserSelection::ExportTo(loc_str.clone()),
        // Ack message
        UserSelection::UserOption(UserOption::ok()),
        // Import entries
        UserSelection::new_import_from(loc_str, "123".to_string(), 0),
        // Ack message
        UserSelection::UserOption(UserOption::ok()),
        // Import a non-existing file
        UserSelection::new_import_from("/non-existing".to_string(), "123".to_string(), 0),
        // Ack message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
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

    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Update the configuration
        UserSelection::GoTo(Menu::ShowConfiguration),
        UserSelection::UpdateConfiguration(new_conf),
        // Save
        UserSelection::GoTo(Menu::Save(false)),
        // Ack saved message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_add_to_clipboard() {
    println!("===========execute_add_to_clipboard");
    let (tx, rx) = mpsc::channel();
    let a_string = "1string".to_string();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Add to clipboard
        UserSelection::AddToClipboard(a_string.clone()),
        // Ack message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);

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

fn execute_file_recovery() {
    println!("===========execute_file_recovery");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Trigger to recovery
        UserSelection::GoTo(Menu::TryFileRecovery),
        // Ack messages. One for recovery start and one for completion
        UserSelection::UserOption(UserOption::ok()),
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::Exit),
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
    let res = rx.recv();
    assert!(res.is_ok() && res.unwrap());
}

fn execute_check_passwords() {
    println!("===========execute_check_passwords");
    let (tx, rx) = mpsc::channel();
    let editor = Box::new(TestEditor::new(vec![
        // Login
        UserSelection::new_provided_password("123".to_string(), 0),
        // Trigger check
        UserSelection::CheckPasswords,
        // Ack message
        UserSelection::UserOption(UserOption::ok()),
        // Exit
        UserSelection::GoTo(Menu::Exit),
        UserSelection::GoTo(Menu::ForceExit)], tx));

    execute(editor);
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

impl Editor for TestEditor {
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

    fn show_message(&self, m: &str, _: Vec<UserOption>, _: MessageSeverity) -> UserSelection {
        println!("TestEditor::show_message {}", m);
        let to_ret = self.return_first_selection();
        println!("Returning {:?}", to_ret);
        to_ret
    }
}