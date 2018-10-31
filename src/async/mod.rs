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

use std::{thread, time};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

pub mod nextcloud;

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

#[cfg(test)]
mod async_tests {
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time;
    use super::super::errors;

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
