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
use std::time::{self, Duration, SystemTime};
use super::{Editor, Menu, MessageSeverity, Props, RklConfiguration, Safe, UserOption, UserSelection};
use super::api::UiCommand;

pub mod nextcloud;

pub const ASYNC_EDITOR_PARK_TIMEOUT: Duration = time::Duration::from_millis(10);

/// Executes a task in a new thread
pub fn execute_task<T: 'static>(task: Box<AsyncTask<T=T>>, every: time::Duration) -> Sender<bool> {
    let (tx_loop_control, rx_loop_control): (Sender<bool>, Receiver<bool>) = mpsc::channel();

    let mut mut_task = task;
    mut_task.init();
    thread::spawn(move || {
        debug!("Spawned async task");
        loop {
            mut_task.execute();
            thread::park_timeout(every);
            // Check if the loop should be stopped
            match rx_loop_control.try_recv() {
                Ok(stop) => {
                    if stop {
                        debug!("Stopping async task...");
                        break;
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    debug!("Stopping async task because the channel got disconnected");
                    break;
                }
                Err(TryRecvError::Empty) => {
                    // ignore
                }
            }
        }
    });

    tx_loop_control
}

/// Defines a task that runs asynchronously in the background.
pub trait AsyncTask: Send {
    type T;
    /// Initializes a task
    fn init(&mut self);
    /// Executes the task
    fn execute(&self);
}


// Used in the execute function
pub(crate) struct AsyncEditorFacade {
    user_selection_rx: Receiver<UserSelection>,
    command_tx: Sender<UiCommand>,
    props: Props,
}

impl AsyncEditorFacade {
    pub fn new(user_selection_rx: Receiver<UserSelection>, command_tx: Sender<UiCommand>, props: Props) -> AsyncEditorFacade {
        AsyncEditorFacade { user_selection_rx, command_tx, props }
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

            // Get a possible input
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
        }

        user_selection
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
        self.receive()
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
    use super::super::errors;

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
        let ten_millis = time::Duration::from_millis(10);
        let task = DummyTask { tx: tx };
        let _dummy = super::execute_task(Box::new(task), ten_millis);

        assert!(rx.recv_timeout(time::Duration::from_millis(1000)).is_ok());
        assert!(rx.recv_timeout(time::Duration::from_millis(1000)).is_ok());
        assert!(rx.recv_timeout(time::Duration::from_millis(1000)).is_ok());
    }

    pub struct DummyTask {
        tx: Sender<errors::Result<&'static str>>,
    }

    impl super::AsyncTask for DummyTask {
        type T = &'static str;

        fn init(&mut self) {}

        fn execute(&self) {
            let _ = self.tx.send(Ok("Dummy"));
        }
    }
}
