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
use std::error::Error;
use clipboard::{ClipboardProvider, ClipboardContext};
use ::errors;
use ::Editor;
use ::api::{UserSelection, UserOption, MessageSeverity, Menu};

pub(crate) fn add_to_clipboard(content: String, editor: &Editor) -> UserSelection {
    let res = match ClipboardProvider::new() as Result<ClipboardContext, Box<std::error::Error>> {
        Ok(mut ctx) => {
            ctx.set_contents(content).map_err(|error| errors::RustKeylockError::GeneralError(format!("{}", error.description())))
        }
        Err(error) => {
            Err(errors::RustKeylockError::GeneralError(format!("{}", error.description())))
        }
    };
    match res {
        Ok(_) => {
            let _ = editor.show_message("Copied!", vec![UserOption::ok()], MessageSeverity::default());
        }
        Err(error) => {
            let error_message = format!("Could not copy... Reason: {}", error.description());
            let _ = editor.show_message(&error_message, vec![UserOption::ok()], MessageSeverity::Error);
        }
    };

    // Do not change Menu
    UserSelection::GoTo(Menu::Current)
}

#[cfg(test)]
mod selection_handling_unit_tests {
    use clipboard::{ClipboardProvider, ClipboardContext};
    use ::Editor;
    use ::api::{UserSelection, Menu, RklConfiguration, UserOption, MessageSeverity};
    use ::api::safe::Safe;

    #[test]
    fn add_to_clipboard_success() {
        let content = String::from("This is content");
        let u = super::add_to_clipboard(content.clone(), &TestEditor::new());
        assert!(u == UserSelection::GoTo(Menu::Current));
        let mut ctx: ClipboardContext = ClipboardProvider::new().expect("Cannot create ClipboardProvider in tests");
        let clip_res = ctx.get_contents();
        assert!(clip_res.is_ok());
        assert!(clip_res.unwrap() == content);
    }

    struct TestEditor {}

    impl TestEditor {
        pub fn new() -> TestEditor {
            TestEditor {}
        }
    }

    impl super::Editor for TestEditor {
        fn show_password_enter(&self) -> UserSelection {
            UserSelection::Ack
        }

        fn show_change_password(&self) -> UserSelection {
            UserSelection::Ack
        }

        fn show_menu(&self, _: &Menu, _: &Safe, _: &RklConfiguration) -> UserSelection {
            UserSelection::Ack
        }

        fn exit(&self, _: bool) -> UserSelection {
            UserSelection::Ack
        }

        fn show_message(&self, _: &str, _: Vec<UserOption>, _: MessageSeverity) -> UserSelection {
            UserSelection::Ack
        }
    }
}