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

use std::str::{self, FromStr};

use async_trait::async_trait;
use http::{HeaderMap, HeaderValue};
use http::header::HeaderName;
use log::*;
use reqwest;
use reqwest::{Client as OfficialReqwestClient, Response};

use super::errors::{self, RustKeylockError};

pub mod nextcloud;
pub mod dropbox;

pub(crate) type BoxedRklHttpAsyncClient = Box<dyn RklHttpAsyncClient<ResType=Vec<u8>>>;

/// Defines a task that runs asynchronously in the background.
#[async_trait]
pub trait AsyncTask: Send {
    /// Initializes a task
    async fn init(&mut self);
    /// Executes the task
    async fn execute(&self) -> errors::Result<SyncStatus>;
}

#[derive(PartialEq, Debug)]
pub(crate) struct ServerVersionData {
    version: String,
    last_modified: String,
}

impl Default for ServerVersionData {
    fn default() -> Self {
        ServerVersionData {
            version: "0".to_string(),
            last_modified: "0".to_string(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub(crate) enum SynchronizerAction {
    Download,
    Upload,
    Ignore,
    DownloadMergeAndUpload,
}

/// Returns the action that should be taken after parsing a Webdav response
///
/// ## Algorithm:
///
/// |           version_local        |     last_sync_version    |          Action
/// | :---------------------------:  | :----------------------: | :------------------------:
/// | bigger than server             | equal to server          | Upload
/// | bigger than server             | smaller than server      | Merge
/// | bigger than server             | bigger than server       | Upload
///
/// | smaller than server            | not equal to local       | Merge
/// | smaller than server            | equal to local           | Download
///
/// | equal to server                | equal to server          | Ignore
///
/// | equal to server                | not equal to server      | Merge
///
/// | non-existing                   | *                        | Download
///
/// | *                              | no information           | Merge (Try to download and then upload)
///
/// | other                          | other                    | Ignore (Error)

pub(crate) fn synchronizer_action(svd: &ServerVersionData,
                                  filename: &str,
                                  saved_at_local: &Option<i64>,
                                  version_local: &Option<i64>,
                                  last_sync_version: &Option<i64>)
                                  -> errors::Result<SynchronizerAction> {
    debug!("The file '{}' on the server was saved at {} with version {}",
           filename,
           svd.last_modified,
           svd.version);
    let version_server = i64::from_str(&svd.version)?;

    debug!("The file '{}' locally was saved at {:?} with version {:?}. Last sync version is {:?}",
           filename,
           saved_at_local,
           version_local,
           last_sync_version);

    match (version_local, version_server, last_sync_version) {
        (&Some(vl), vs, &Some(lsv)) if vl > vs && lsv == vs => {
            debug!("The local version is bigger than the server. The last sync version is equal to the server. \
                        Need to Upload");
            Ok(SynchronizerAction::Upload)
        }
        (&Some(vl), vs, &Some(lsv)) if vl > vs && lsv < vs => {
            debug!("The local version is bigger than the server. The last sync version is smaller than the server. \
                        Need to Merge");
            Ok(SynchronizerAction::DownloadMergeAndUpload)
        }
        (&Some(vl), vs, &Some(lsv)) if vl > vs && lsv > vs => {
            debug!("The local version is bigger than the server. The last sync version is bigger than the server. \
                        Need to Upload");
            Ok(SynchronizerAction::Upload)
        }
        (&Some(vl), vs, &Some(lsv)) if vl < vs && vl != lsv => {
            debug!("The local version is smaller than the server The last sync version is not equal to the local version. \
                        Need to Merge");
            Ok(SynchronizerAction::DownloadMergeAndUpload)
        }
        (&Some(vl), vs, &Some(lsv)) if vl < vs && vl == lsv => {
            debug!("The local version is smaller than the server The last sync version equal to the local version. \
                        Need to Download");
            Ok(SynchronizerAction::Download)
        }
        (&Some(vl), vs, &Some(lsv)) if vl == vs && lsv == vs => {
            debug!("The local version is equal to the server. The last sync version is equal to the server. \
                        Ignoring");
            Ok(SynchronizerAction::Ignore)
        }
        (&Some(vl), vs, &Some(lsv)) if vl == vs && lsv != vs => {
            debug!("The local version is equal to the server. The last sync version is not equal to the server. \
                        Need to merge");
            Ok(SynchronizerAction::DownloadMergeAndUpload)
        }
        (&None, _, _) => {
            debug!("Nothing is saved locally... Need to download");
            Ok(SynchronizerAction::Download)
        }
        (&Some(_), _, &None) => {
            debug!("No information about server... Need to merge");
            Ok(SynchronizerAction::DownloadMergeAndUpload)
        }
        (_, _, _) => {
            error!("The local version, server version and last sync version seem corrupted.");
            Ok(SynchronizerAction::Ignore)
        }
    }
}

/// The status of the synchronize actions
#[derive(PartialEq, Debug)]
pub(crate) enum SyncStatus {
    /// An update is available from the server.
    /// The &'static str is the sync that sends the message, String is the name of the file that is ready to be used if the user selects so.
    NewAvailable(&'static str, String),
    /// The local file was uploaded to the nextcloud server. The &'static str is the sync that sends the message.
    UploadSuccess(&'static str),
    /// An update is available from the nextcloud server but instead of replacing the contents, merging needs to be done.
    /// The &'static str is the sync that sends the message.
    /// The String is the name of the file that is ready to be used if the user selects so.
    NewToMerge(&'static str, String),
    /// None
    None,
}

/// The trait to be implemented by HTTP clients. Used for synchronization with dropbox, nextcloud etc.
#[async_trait]
pub(crate) trait RklHttpAsyncClient: Send {
    type ResType;
    fn header(&mut self, k: &str, v: &str);
    #[allow(dead_code)]
    async fn get(&mut self, uri: &str, additional_headers: &[(&str, &str)]) -> errors::Result<Self::ResType>;
    async fn post(&mut self, uri: &str, additional_headers: &[(&str, &str)], body: Vec<u8>) -> errors::Result<Self::ResType>;
}

#[derive(Debug, Clone)]
pub(crate) struct ReqwestClient {
    headers: HeaderMap,
    client: OfficialReqwestClient,
}

impl Default for ReqwestClient {
    fn default() -> Self {
        ReqwestClient::new()
    }
}

impl ReqwestClient {
    pub(crate) fn new() -> ReqwestClient {
        let client = OfficialReqwestClient::new();
        let headers = HeaderMap::new();
        ReqwestClient { headers, client }
    }

    async fn validate_response(resp: Response) -> errors::Result<Response> {
        if resp.status().is_client_error() || resp.status().is_server_error() {
            let message= format!("Error during HTTP request: {}.", resp.status().to_string());
            let body_bytes = Self::get_body(resp).await?;
            let body_str = str::from_utf8(&body_bytes)?;
            error!("{}: {}", message, body_str);
            Err(RustKeylockError::HttpError(message))
        } else {
            Ok(resp)
        }
    }

    async fn get_body(response: Response) -> errors::Result<Vec<u8>> {
        Ok(response.bytes().await?.to_vec())
    }
}

#[async_trait]
impl RklHttpAsyncClient for ReqwestClient {
    type ResType = Vec<u8>;

    fn header(&mut self, k: &str, v: &str) {
        self.headers.insert(HeaderName::from_str(k).unwrap_or_else(|error| {
            error!("{:?}", error);
            HeaderName::from_static("")
        }), HeaderValue::from_str(v).unwrap_or_else(|error| {
            error!("{:?}", error);
            HeaderValue::from_static("")
        }));
    }

    async fn get(&mut self, uri: &str, additional_headers: &[(&str, &str)]) -> errors::Result<Vec<u8>> {
        let mut builder = self.client
            .get(uri)
            .headers(self.headers.clone());
        for (k, v) in additional_headers {
            builder = builder.header(HeaderName::from_str(k).unwrap_or_else(|error| {
                error!("{:?}", error);
                HeaderName::from_static("")
            }), HeaderValue::from_str(v).unwrap_or_else(|error| {
                error!("{:?}", error);
                HeaderValue::from_static("")
            }));
        }

        let resp = builder.send().await?;
        let resp = Self::validate_response(resp).await?;
        Self::get_body(resp).await
    }

    async fn post(&mut self, uri: &str, additional_headers: &[(&str, &str)], body: Vec<u8>) -> errors::Result<Vec<u8>> {
        let mut builder = self.client
            .post(uri)
            .headers(self.headers.clone())
            .body(body);
        for (k, v) in additional_headers {
            builder = builder.header(HeaderName::from_str(k).unwrap_or_else(|error| {
                error!("{:?}", error);
                HeaderName::from_static("")
            }), HeaderValue::from_str(v).unwrap_or_else(|error| {
                error!("{:?}", error);
                HeaderValue::from_static("")
            }));
        }
        let resp = builder.send().await?;
        let resp = Self::validate_response(resp).await?;
        Self::get_body(resp).await
    }
}

/// The trait to be implemented by HTTP client factories. Provides the needed abstraction that makes the RklHttpAsyncClients testable.
pub(crate) trait RklHttpAsyncFactory: Send + Sync {
    type ClientResType;
    #[allow(dead_code)]
    fn init_factory(&mut self);
    fn create(&self) -> Box<dyn RklHttpAsyncClient<ResType=Self::ClientResType>>;
}

pub(crate) struct ReqwestClientFactory {}

impl ReqwestClientFactory {
    pub(crate) fn new() -> ReqwestClientFactory {
        ReqwestClientFactory {}
    }
}

impl RklHttpAsyncFactory for ReqwestClientFactory {
    type ClientResType = Vec<u8>;

    fn init_factory(&mut self) {
        // Nothing needed yet
    }

    fn create(&self) -> Box<dyn RklHttpAsyncClient<ResType=Self::ClientResType>> {
        Box::new(ReqwestClient::default())
    }
}

#[cfg(test)]
mod async_tests {
    use std::fs::{self, File};
    use std::io::prelude::*;
    use std::sync::mpsc::SyncSender;
    use std::time::SystemTime;

    use crate::file_handler;

    use super::*;

    // #[test]
    // fn facade_show_change_password() {
    //     let (user_selection_tx, user_selection_rx) = mpsc::channel();
    //     let (command_tx, command_rx) = mpsc::channel();

    //     let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
    //     assert!(user_selection_tx.send(UserSelection::Ack).is_ok());
    //     let user_selection = facade.show_change_password();
    //     assert!(user_selection == UserSelection::Ack);
    //     let command_res = command_rx.recv();
    //     assert!(command_res.is_ok());
    //     match command_res.unwrap() {
    //         UiCommand::ShowChangePassword => assert!(true),
    //         _ => assert!(false),
    //     };
    // }

    // #[test]
    // fn facade_show_password_enter() {
    //     let (user_selection_tx, user_selection_rx) = mpsc::channel();
    //     let (command_tx, command_rx) = mpsc::channel();

    //     let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
    //     assert!(user_selection_tx.send(UserSelection::Ack).is_ok());
    //     let user_selection = facade.show_password_enter();
    //     assert!(user_selection == UserSelection::Ack);
    //     let command_res = command_rx.recv();
    //     assert!(command_res.is_ok());
    //     match command_res.unwrap() {
    //         UiCommand::ShowPasswordEnter => assert!(true),
    //         _ => assert!(false),
    //     };
    // }

    // #[test]
    // fn facade_show_message() {
    //     let (user_selection_tx, user_selection_rx) = mpsc::channel();
    //     let (command_tx, command_rx) = mpsc::channel();

    //     let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
    //     assert!(user_selection_tx.send(UserSelection::UserOption(UserOption::ok())).is_ok());
    //     let user_selection = facade.show_message("message", vec![UserOption::ok()], MessageSeverity::Info);
    //     assert!(user_selection == UserSelection::UserOption(UserOption::ok()));
    //     let command_res = command_rx.recv();
    //     assert!(command_res.is_ok());
    //     match command_res.unwrap() {
    //         UiCommand::ShowMessage(_, _, _) => assert!(true),
    //         _ => assert!(false),
    //     };
    // }

    // #[test]
    // fn facade_show_message_waits_only_for_user_options() {
    //     let (user_selection_tx, user_selection_rx) = mpsc::channel();
    //     let (command_tx, _) = mpsc::channel();

    //     let facade = super::AsyncEditorFacade::new(user_selection_rx, command_tx, super::Props::default());
    //     // Send a non-UserOption first. This should be ignored.
    //     assert!(user_selection_tx.send(UserSelection::Ack).is_ok());
    //     // Send a UserOption.
    //     assert!(user_selection_tx.send(UserSelection::UserOption(UserOption::ok())).is_ok());
    //     let user_selection = facade.show_message("message", vec![UserOption::ok()], MessageSeverity::Info);
    //     assert!(user_selection == UserSelection::UserOption(UserOption::ok()));
    // }

    // TODO: Test timeout mechanism

    #[test]
    fn parse_web_dav_response() {
        let filename = "parse_web_dav_response";
        create_file_with_contents(filename, "This is a test file");

        // Upload because version_local is bigger than version_server and last_sync_version is equal to version_server
        let wdr1 = ServerVersionData {
            last_modified: "133".to_string(),
            version: "1".to_string(),
        };
        let res1 = synchronizer_action(
            &wdr1,
            filename,
            &Some(133),
            &Some(2),
            &Some(1));
        assert!(res1.is_ok());
        assert!(res1.as_ref().unwrap() == &SynchronizerAction::Upload);

        // Merge because version_local is bigger than version_server and last_sync_version is not equal to version_server
        let wdr2 = ServerVersionData {
            last_modified: "133".to_string(),
            version: "2".to_string(),
        };
        let res2 = synchronizer_action(
            &wdr2,
            filename,
            &Some(133),
            &Some(3),
            &Some(1));
        assert!(res2.is_ok());
        assert!(res2.as_ref().unwrap() == &SynchronizerAction::DownloadMergeAndUpload);

        // Merge because version_local is smaller than version_server and last_sync_version is not equal to version_local
        let wdr3 = ServerVersionData {
            last_modified: "133".to_string(),
            version: "3".to_string(),
        };
        let res3 = synchronizer_action(
            &wdr3,
            filename,
            &Some(133),
            &Some(2),
            &Some(1));
        assert!(res3.is_ok());
        assert!(res3.as_ref().unwrap() == &SynchronizerAction::DownloadMergeAndUpload);

        // Download because version_local is smaller than version_server and last_sync_version equal to version_local
        let wdr4 = ServerVersionData {
            last_modified: "133".to_string(),
            version: "3".to_string(),
        };
        let res4 = synchronizer_action(
            &wdr4,
            filename,
            &Some(133),
            &Some(2),
            &Some(2));
        assert!(res4.is_ok());
        assert!(res4.as_ref().unwrap() == &SynchronizerAction::Download);

        // Ignore because version_local is equal to version_server and last_sync_version equal to version_server
        let wdr5 = ServerVersionData {
            last_modified: "133".to_string(),
            version: "3".to_string(),
        };
        let res5 = synchronizer_action(
            &wdr5,
            filename,
            &Some(133),
            &Some(3),
            &Some(3));
        assert!(res5.is_ok());
        assert!(res5.as_ref().unwrap() == &SynchronizerAction::Ignore);

        // Merge because version_local is equal to version_server and last_sync_version is not equal to version_server
        let wdr6 = ServerVersionData {
            last_modified: "133".to_string(),
            version: "3".to_string(),
        };
        let res6 = synchronizer_action(
            &wdr6,
            filename,
            &Some(133),
            &Some(3),
            &Some(2));
        assert!(res6.is_ok());
        assert!(res6.as_ref().unwrap() == &SynchronizerAction::DownloadMergeAndUpload);

        let _ = file_handler::delete_file(filename);
    }

    fn create_file_with_contents(filename: &str, contents: &str) {
        let default_rustkeylock_dir_path_buf = file_handler::default_rustkeylock_location();
        let default_rustkeylock_dir = default_rustkeylock_dir_path_buf.to_str().unwrap();
        let creation_result = fs::create_dir_all(default_rustkeylock_dir).map(|_| {
            let path_buf = file_handler::default_toml_path(filename);
            let path = path_buf.to_str().unwrap();
            let mut file = File::create(path).unwrap();
            assert!(file.write_all(contents.as_bytes()).is_ok());
        });
        assert!(creation_result.is_ok());
    }
}
