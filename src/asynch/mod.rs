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

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{self, Duration, SystemTime, Instant};
use tokio::prelude::*;
use tokio::prelude::future::{ok, Loop, loop_fn};
use tokio::timer::Delay;
use log::*;

use super::{Editor, Menu, MessageSeverity, Props, RklConfiguration, Safe, UserOption, UserSelection};
use super::api::UiCommand;
use super::errors;

use self::nextcloud::SyncStatus;

pub mod nextcloud;

pub const ASYNC_EDITOR_PARK_TIMEOUT: Duration = time::Duration::from_millis(10);

/// Executes a task in a new thread
pub fn execute_task(task: Box<AsyncTask>, every: time::Duration) -> AsyncTaskHandle {
    let (tx_loop_control, rx_loop_control): (Sender<bool>, Receiver<bool>) = mpsc::channel();

    let mut task = task;
    task.init();

    let loop_future = loop_fn((task, every, rx_loop_control), |(task, every, rx_loop_control)| {
        Delay::new(Instant::now() + every.clone())
            .map_err(|_| ())
            .and_then(move |_| {
                task.execute()
                    .map_err(|_| ())
                    .and_then(|_| ok(task))
            })
            .map_err(|_| ())
            .and_then(move |task| {
                let mut stop = false;

                match rx_loop_control.try_recv() {
                    Ok(stop_received) => {
                        if stop_received {
                            debug!("Stopping async task...");
                            stop = true;
                        }
                    }
                    Err(TryRecvError::Disconnected) => { /* ignore (maybe a debug to show that the handle got disconnected?) */ }
                    Err(TryRecvError::Empty) => { /* ignore */ }
                }


                if stop {
                    Ok(Loop::Break((task, every, rx_loop_control)))
                } else {
                    Ok(Loop::Continue((task, every, rx_loop_control)))
                }
            })
    }).map(|_| ()).map_err(|_| ());

    tokio::spawn(loop_future);

    AsyncTaskHandle::new(tx_loop_control)
}

/// Defines a task that runs asynchronously in the background.
pub trait AsyncTask: Send {
    /// Initializes a task
    fn init(&mut self);
    /// Executes the task
    fn execute(&self) -> Box<dyn Future<Item=(), Error=()> + Send>;
}

/// A handle to a created AsyncTask
pub struct AsyncTaskHandle {
    stop_tx: Sender<bool>,
}

impl AsyncTaskHandle {
    fn new(stop_tx: Sender<bool>) -> AsyncTaskHandle {
        AsyncTaskHandle {
            stop_tx,
        }
    }

    pub fn stop(&self) -> errors::Result<()> {
        debug!("Stopping async task...");

        match self.stop_tx.send(true) {
            Ok(_) => Ok(()),
            Err(error) => {
                warn!("Could not stop async task... {:?}", error);
                Err(errors::RustKeylockError::from(error))
            }
        }
    }
}


// Used in the execute function
pub(crate) struct AsyncEditorFacade {
    user_selection_rx: Receiver<UserSelection>,
    nextcloud_rx: Option<Receiver<errors::Result<SyncStatus>>>,
    command_tx: Sender<UiCommand>,
    props: Props,
}

impl AsyncEditorFacade {
    pub fn new(user_selection_rx: Receiver<UserSelection>, command_tx: Sender<UiCommand>, props: Props) -> AsyncEditorFacade {
        AsyncEditorFacade { user_selection_rx, nextcloud_rx: None, command_tx, props }
    }

    pub fn update_nextcloud_rx(&mut self, new_nextcloud_rx: Option<Receiver<errors::Result<SyncStatus>>>) {
        self.nextcloud_rx = new_nextcloud_rx;
    }

    pub fn send(&self, command: UiCommand) {
        match self.command_tx.send(command) {
            Ok(_) => { /* ignore */ }
            Err(error) => error!("Could not send UiCommand to the Editor: {:?}", error),
        }
    }

    fn receive(&self) -> UserSelection {
        let user_selection;
        // Holds the time of the latest user action
        let last_action_time = SystemTime::now();
        loop {
            thread::park_timeout(ASYNC_EDITOR_PARK_TIMEOUT);

            // Check if idle timeout
            match timeout_check(&last_action_time, self.props.idle_timeout_seconds()) {
                Some(_) => {
                    let message = format!("Idle time of {} seconds elapsed! Locking...", self.props.idle_timeout_seconds());
                    self.send(UiCommand::ShowMessage(message, vec![UserOption::ok()], MessageSeverity::default()));
                    let _ = self.receive();
                    self.send(UiCommand::ShowPasswordEnter);
                    user_selection = self.receive();
                    break;
                }
                None => { /*ignore*/ }
            };

            // Get a possible user input
            match self.user_selection_rx.try_recv() {
                Ok(sel) => {
                    user_selection = sel;
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    warn!("The Editor got disconnected");
                    user_selection = UserSelection::GoTo(Menu::Current);
                    break;
                }
                Err(TryRecvError::Empty) => { /* ignore */ }
            }

            if let Some(sel) = self.check_nextcloud_message() {
                user_selection = sel;
                break;
            }
        }

        user_selection
    }

    // Get a possible nextcloud async task message
    fn check_nextcloud_message(&self) -> Option<UserSelection> {
        self.nextcloud_rx.as_ref().and_then(|rx| {
            match rx.try_recv() {
                Ok(sync_status_res) => {
                    match sync_status_res {
                        Ok(sync_status) => self.handle_sync_status_success(sync_status, super::PROPS_FILENAME),
                        Err(_) => None,
                    }
                }
                _ => None,
            }
        })
    }

    fn handle_sync_status_success(&self, sync_status: SyncStatus, filename: &str) -> Option<UserSelection> {
        match sync_status {
            SyncStatus::UploadSuccess => {
                debug!("The nextcloud server was updated with the local data");
                let _ = self.show_message("The nextcloud server was updated with the local data", vec![UserOption::ok()], MessageSeverity::Info);
                Some(UserSelection::GoTo(Menu::Current))
            }
            SyncStatus::NewAvailable(downloaded_filename) => {
                debug!("Downloaded new data from the nextcloud server.");
                let selection = self.show_message("Downloaded new data from the nextcloud server. Do you want to apply them locally now?",
                                                  vec![UserOption::yes(), UserOption::no()],
                                                  MessageSeverity::Info);

                debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
                if selection == UserSelection::UserOption(UserOption::yes()) {
                    debug!("Replacing the local file with the one downloaded from the server");
                    let _ = super::file_handler::replace(&downloaded_filename, filename);
                    Some(UserSelection::GoTo(Menu::TryPass))
                } else {
                    Some(UserSelection::GoTo(Menu::Current))
                }
            }
            SyncStatus::NewToMerge(downloaded_filename) => {
                debug!("Downloaded data from the nextcloud server, but conflicts were identified. The contents will be merged.");
                let selection =
                    self.show_message("Downloaded data from the nextcloud server, but conflicts were identified. The contents will be merged \
                                   but nothing will be saved. You will need to explicitly save after reviewing the merged data. Do you \
                                   want to do the merge now?",
                                      vec![UserOption::yes(), UserOption::no()],
                                      MessageSeverity::Info);

                debug!("The user selected {:?} as an answer for applying the downloaded data locally", &selection);
                if selection == UserSelection::UserOption(UserOption::yes()) {
                    debug!("Merging the local data with the downloaded from the server");

                    match self.show_password_enter() {
                        UserSelection::ProvidedPassword(pwd, salt_pos) => {
                            Some(UserSelection::ImportFromDefaultLocation(downloaded_filename, pwd, salt_pos))
                        }
                        other => {
                            let message = format!("Expected a ProvidedPassword but received '{:?}'. Please, consider opening a bug to the \
                                               developers.",
                                                  &other);
                            error!("{}", message);
                            let _ =
                                self.show_message("Unexpected result when waiting for password. See the logs for more details. Please \
                                                 consider opening a but to the developers.",
                                                  vec![UserOption::ok()],
                                                  MessageSeverity::Error);
                            Some(UserSelection::GoTo(Menu::TryPass))
                        }
                    }
                } else {
                    Some(UserSelection::GoTo(Menu::Current))
                }
            }
            SyncStatus::None => {
                None
            }
        }
    }
}

impl Editor for AsyncEditorFacade {
    fn show_password_enter(&self) -> UserSelection {
        self.send(UiCommand::ShowPasswordEnter);
        self.receive()
    }

    fn show_change_password(&self) -> UserSelection {
        self.send(UiCommand::ShowChangePassword);
        self.receive()
    }

    fn show_menu(&self, menu: &Menu, safe: &Safe, configuration: &RklConfiguration) -> UserSelection {
        self.send(UiCommand::ShowMenu(menu.clone(), safe.clone(), configuration.clone()));
        self.receive()
    }

    fn exit(&self, contents_changed: bool) -> UserSelection {
        self.send(UiCommand::Exit(contents_changed));
        self.receive()
    }

    fn show_message(&self, message: &str, options: Vec<UserOption>, severity: MessageSeverity) -> UserSelection {
        self.send(UiCommand::ShowMessage(message.to_string(), options, severity));
        let mut opt = None;
        while opt.is_none() {
            opt = match self.receive() {
                uo @ UserSelection::UserOption(_) => {
                    Some(uo)
                }
                other => {
                    debug!("Ignoring {:?} while waiting for UserOption.", other);
                    None
                }
            };
        }
        opt.unwrap()
    }
}

fn timeout_check(last_action_time: &SystemTime, timeout_seconds: i64) -> Option<()> {
    match last_action_time.elapsed() {
        Ok(elapsed) => {
            let elapsed_seconds = elapsed.as_secs();
            if elapsed_seconds as i64 > timeout_seconds {
                warn!("Idle time of {} seconds elapsed! Locking...", timeout_seconds);
                Some(())
            } else {
                None
            }
        }
        Err(error) => {
            error!("Cannot get the elapsed time since the last action of the user: {:?}", &error);
            Some(())
        }
    }
}

#[cfg(test)]
mod async_tests {
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::{self, SystemTime};
    use tokio::prelude::*;
    use tokio::prelude::future::{lazy, ok};
    use std::thread;

    use super::super::errors;
    use super::super::{UserOption, MessageSeverity, UserSelection, Editor, UiCommand};

    #[test]
    fn facade_show_change_password() {
        let (user_selection_tx, user_selection_rx) = mpsc::channel();
        let (command_tx, command_rx) = mpsc::channel();

        let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
        assert!(user_selection_tx.send(UserSelection::Ack).is_ok());
        let user_selection = facade.show_change_password();
        assert!(user_selection == UserSelection::Ack);
        let command_res = command_rx.recv();
        assert!(command_res.is_ok());
        match command_res.unwrap() {
            UiCommand::ShowChangePassword => assert!(true),
            _ => assert!(false),
        };
    }

    #[test]
    fn facade_show_password_enter() {
        let (user_selection_tx, user_selection_rx) = mpsc::channel();
        let (command_tx, command_rx) = mpsc::channel();

        let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
        assert!(user_selection_tx.send(UserSelection::Ack).is_ok());
        let user_selection = facade.show_password_enter();
        assert!(user_selection == UserSelection::Ack);
        let command_res = command_rx.recv();
        assert!(command_res.is_ok());
        match command_res.unwrap() {
            UiCommand::ShowPasswordEnter => assert!(true),
            _ => assert!(false),
        };
    }

    #[test]
    fn facade_show_message() {
        let (user_selection_tx, user_selection_rx) = mpsc::channel();
        let (command_tx, command_rx) = mpsc::channel();

        let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
        assert!(user_selection_tx.send(UserSelection::UserOption(UserOption::ok())).is_ok());
        let user_selection = facade.show_message("message", vec![UserOption::ok()], MessageSeverity::Info);
        assert!(user_selection == UserSelection::UserOption(UserOption::ok()));
        let command_res = command_rx.recv();
        assert!(command_res.is_ok());
        match command_res.unwrap() {
            UiCommand::ShowMessage(_, _, _) => assert!(true),
            _ => assert!(false),
        };
    }

    #[test]
    fn facade_show_message_waits_only_for_user_options() {
        let (user_selection_tx, user_selection_rx) = mpsc::channel();
        let (command_tx, _) = mpsc::channel();

        let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
        // Send a non-UserOption first. This should be ignored.
        assert!(user_selection_tx.send(UserSelection::Ack).is_ok());
        // Send a UserOption.
        assert!(user_selection_tx.send(UserSelection::UserOption(UserOption::ok())).is_ok());
        let user_selection = facade.show_message("message", vec![UserOption::ok()], MessageSeverity::Info);
        assert!(user_selection == UserSelection::UserOption(UserOption::ok()));
    }

    #[test]
    fn user_selection_after_idle_check_timed_out() {
        let time = SystemTime::now();
        std::thread::sleep(std::time::Duration::new(2, 0));
        let opt = super::timeout_check(&time, 1);
        assert!(opt.is_some());
    }

    #[test]
    fn user_selection_after_idle_check_not_timed_out() {
        let time = SystemTime::now();
        let opt = super::timeout_check(&time, 10);
        assert!(opt.is_none());
    }

    #[test]
    fn async_execution() {
        let (tx, rx): (Sender<errors::Result<&'static str>>, Receiver<errors::Result<&'static str>>) = mpsc::channel();
        let task = DummyTask { tx: tx };

        thread::spawn(|| {
            tokio::run(lazy(|| {
                let ten_millis = time::Duration::from_millis(10);
                let _dummy = super::execute_task(Box::new(task), ten_millis);
                Ok(())
            }));
        });
        std::thread::sleep(std::time::Duration::new(2, 0));

        assert!(rx.recv_timeout(time::Duration::from_millis(10000)).is_ok());
        assert!(rx.recv_timeout(time::Duration::from_millis(10000)).is_ok());
        assert!(rx.recv_timeout(time::Duration::from_millis(10000)).is_ok());
    }

    pub struct DummyTask {
        tx: Sender<errors::Result<&'static str>>,
    }

    impl super::AsyncTask for DummyTask {
        fn init(&mut self) {}

        fn execute(&self) -> Box<dyn Future<Item=(), Error=()> + Send> {
            let _ = self.tx.send(Ok("dummy"));
            Box::new(lazy(|| ok(())))
        }
    }
}
