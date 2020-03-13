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

use std;

use clipboard::{ClipboardContext, ClipboardProvider};
use log::*;

use crate::{Editor, errors};
use crate::api::{Menu, MessageSeverity, UserOption, UserSelection};

pub(crate) fn add_to_clipboard(content: String, editor: &dyn Editor) -> UserSelection {
    let res = match ClipboardProvider::new() as Result<ClipboardContext, Box<dyn std::error::Error>> {
        Ok(mut ctx) => {
            ctx.set_contents(content).map_err(|error| errors::RustKeylockError::GeneralError(error.to_string()))
        }
        Err(error) => {
            Err(errors::RustKeylockError::GeneralError(error.to_string()))
        }
    };
    match res {
        Ok(_) => {
            let _ = editor.show_message("Copied!", vec![UserOption::ok()], MessageSeverity::default());
        }
        Err(error) => {
            error!("Could not copy: {:?}", error);
            let error_message = format!("Could not copy... Reason: {}", error);
            let _ = editor.show_message(&error_message, vec![UserOption::ok()], MessageSeverity::Error);
        }
    };

    // Do not change Menu
    UserSelection::GoTo(Menu::Current)
}

#[cfg(test)]
mod selection_handling_unit_tests {
    use std;

    use clipboard::{ClipboardContext, ClipboardProvider};

    use crate::{DropboxConfiguration, Editor, Entry, EntryPresentationType, NextcloudConfiguration};
    use crate::api::{Menu, MessageSeverity, UserOption, UserSelection};

    #[test]
    fn add_to_clipboard_success() {
        let content = String::from("This is content");
        let u = super::add_to_clipboard(content.clone(), &TestEditor::new());
        assert!(u == UserSelection::GoTo(Menu::Current));
        match ClipboardProvider::new() as Result<ClipboardContext, Box<dyn std::error::Error>> {
            Ok(mut ctx) => {
                let clip_res = ctx.get_contents();
                assert!(clip_res.is_ok());
                assert!(clip_res.unwrap() == content);
            }
            Err(_) => assert!(true),
        };
    }

    struct TestEditor {}

    impl TestEditor {
        pub fn new() -> TestEditor {
            TestEditor {}
        }
    }

    impl Editor for TestEditor {
        fn show_password_enter(&self) -> UserSelection {
            UserSelection::Ack
        }

        fn show_change_password(&self) -> UserSelection {
            UserSelection::Ack
        }

        fn show_menu(&self, _: &Menu) -> UserSelection {
            UserSelection::Ack
        }

        fn show_entries(&self, _: Vec<Entry>, _: String) -> UserSelection {
            UserSelection::Ack
        }

        fn show_entry(&self, _: Entry, _: usize, _: EntryPresentationType) -> UserSelection {
            UserSelection::Ack
        }

        fn exit(&self, _: bool) -> UserSelection {
            UserSelection::Ack
        }

        fn show_configuration(&self, _: NextcloudConfiguration, _: DropboxConfiguration) -> UserSelection {
            UserSelection::Ack
        }

        fn show_message(&self, _: &str, _: Vec<UserOption>, _: MessageSeverity) -> UserSelection {
            UserSelection::Ack
        }
    }
}