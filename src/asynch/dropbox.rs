// Copyright 2019 astonbitecode
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

use std::error::Error;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time;

use base64;
use futures::future::{ok, result};
use futures::Stream;
use futures::sync::oneshot;
use http::StatusCode;
use hyper::{self, Body, Request, Response, Server};
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use log::*;
use percent_encoding::{percent_decode, USERINFO_ENCODE_SET, utf8_percent_encode};
use toml;
use toml::value::Table;
use url::Url;

use crate::asynch::{self, BoxedRklHttpAsyncClient, RklHttpAsyncFactory, ServerVersionData, SynchronizerAction, SyncStatus};
use crate::datacrypt::{create_random, EntryPasswordCryptor};
use crate::errors;
use crate::errors::RustKeylockError;
use crate::file_handler;
use crate::SystemConfiguration;
use crate::utils;

type ArcMutexRklHttpAsyncClient = Arc<Mutex<BoxedRklHttpAsyncClient>>;

const APP_KEY: &str = "7git6ovjwtdbfvm";
const HTTP_GET_RESPONSE_BODY: &str = r#"
<!DOCTYPE html>
<html>
<head>
<title>rust-keylock</title>
</head>
<body onload="submitToken()">

<form id="tknform" name="tknform" action="/" method="post">
    <input type="hidden" name="tkninput" id="tkninput"/>
</form>

<script>
function submitToken() {
    var hiddentkn = document.getElementById("tkninput");
    hiddentkn.value = getToken();
    var form = document.getElementById("tknform");
    form.submit();
}

function getToken() {
  return window.location.hash;
}
</script>

</body>
</html>
"#;

const HTTP_POST_RESPONSE_BODY: &str = r#"
<!DOCTYPE html>
<html>
<head>
<title>rust-keylock</title>
</head>
<body">

<p style="text-align: center;">&nbsp;</p>
<p style="text-align: center;">Your application was authenticated with Dropbox!</p>
<p style="text-align: center;">You may now close this window...</p>
<p style="text-align: center;"><img src="https://raw.githubusercontent.com/rust-keylock/rust-keylock.github.io/master/img/rust-keylock.png" alt="rust-keylock" width="111" /></p>
<p style="text-align: center;">Thank you for using rust-keylock.</p>

</body>
</html>
"#;

/// A Dropbox synchronizer
pub(crate) struct Synchronizer {
    /// The configuration needed for this synchronizer
    conf: DropboxConfiguration,
    /// The TX to notify about sync status
    tx: Sender<errors::Result<SyncStatus>>,
    /// The rust-keylock file name to synchronize
    file_name: String,
    /// The saved_at value read locally from the file
    saved_at_local: Option<i64>,
    /// The version value read locally from the file
    version_local: Option<i64>,
    /// The version that was set during the last sync
    last_sync_version: Option<i64>,
    /// The factory that creates HTTP clients
    client_factory: Box<dyn RklHttpAsyncFactory<CLIENT_RES_TYPE=Vec<u8>>>,
}

impl Synchronizer {
    pub(crate) fn new(dbc: &DropboxConfiguration,
                      sys_conf: &SystemConfiguration,
                      tx: Sender<errors::Result<SyncStatus>>,
                      f: &str,
                      client_factory: Box<dyn RklHttpAsyncFactory<CLIENT_RES_TYPE=Vec<u8>>>)
                      -> errors::Result<Synchronizer> {
        let s = Synchronizer {
            conf: dbc.clone(),
            tx,
            file_name: f.to_string(),
            saved_at_local: sys_conf.saved_at,
            version_local: sys_conf.version,
            last_sync_version: sys_conf.last_sync_version,
            client_factory,
        };
        Ok(s)
    }

    /// Returns the password decrypted
    fn use_token(&self) -> errors::Result<String> {
        self.conf.decrypted_token()
    }

    fn do_execute(&self) -> impl Future<Item=SyncStatus, Error=RustKeylockError> {
        let file_name = self.file_name.clone();
        let saved_at_local = self.saved_at_local.clone();
        let version_local = self.version_local.clone();
        let last_sync_version = self.last_sync_version.clone();
        let mut client = self.client_factory.create();
        result(self.use_token())
            .and_then(move |token| {
                client.header("Authorization", &format!("Bearer {}", token));
                ok(Arc::new(Mutex::new(client)))
            })
            .and_then(move |client| {
                let c = Arc::clone(&client);
                Self::get_version(c)
                    .map(move |sv| (
                        sv,
                        client,
                        file_name,
                        saved_at_local,
                        version_local,
                        last_sync_version))
            })
            .and_then(|(server_version, client, file_name, saved_at_local, version_local, last_sync_version)| {
                asynch::synchronizer_action(&server_version, &file_name, &saved_at_local, &version_local, &last_sync_version)
                    .map(move |sa| (sa, client, file_name, version_local, saved_at_local))
            })
            .and_then(|(synchronizer_action, client, file_name, version_local, saved_at_local)| {
                Self::parse_synchronizer_action(synchronizer_action, &file_name, client, version_local, saved_at_local)
            })
    }

    fn get_version(client: ArcMutexRklHttpAsyncClient) -> impl Future<Item=ServerVersionData, Error=RustKeylockError> {
        let mut client = client.lock().expect("Locking the client during get_version");
        client.post(
            "https://content.dropboxapi.com/2/files/download",
            &[("Dropbox-API-Arg", r#"{"path": "/.version"}"#)],
            Vec::new())
            .and_then(|bytes| {
                let s = std::str::from_utf8(bytes.as_ref())?;
                parse_version_str(s)
            })
            .or_else(|_| ok(ServerVersionData::default()))
            .and_then(|version_data| ok(version_data))
    }

    fn download(filename: &str, client: ArcMutexRklHttpAsyncClient) -> impl Future<Item=String, Error=RustKeylockError> {
        let mut client = client.lock().expect("Locking the client during download");
        let tmp_file_name = format!("tmp_{}", filename);

        client.post(
            "https://content.dropboxapi.com/2/files/download",
            &[("Dropbox-API-Arg", &format!(r#"{{"path": "/{}"}}"#, filename))],
            Vec::new())
            .and_then(|bytes| {
                file_handler::save_bytes(&tmp_file_name, &bytes, false)
                    .map(|_| tmp_file_name)
            })
            .and_then(|tmp_file_name| {
                ok(tmp_file_name)
            })
    }

    fn upload(filename: &str, client: ArcMutexRklHttpAsyncClient) -> impl Future<Item=(), Error=RustKeylockError> {
        let filename_string = filename.to_string();
        result(file_handler::get_file(filename))
            .and_then(|mut file| {
                let mut post_body: Vec<u8> = Vec::new();
                result(file.read_to_end(&mut post_body))
                    .from_err()
                    .and_then(move |_| {
                        let mut client = client.lock().expect("Locking the client during upload");
                        client.post(
                            "https://content.dropboxapi.com/2/files/upload",
                            &[
                                ("Dropbox-API-Arg", &format!(r#"{{"path":"/{}","mode":"overwrite"}}"#, filename_string)),
                                ("Content-Type", "application/octet-stream"),
                            ],
                            post_body).map(|_| ())
                    })
            })
    }

    fn parse_synchronizer_action(sa: SynchronizerAction, filename: &str, client: ArcMutexRklHttpAsyncClient, version_local: Option<i64>, saved_at_local: Option<i64>) -> Box<dyn Future<Item=SyncStatus, Error=RustKeylockError> + Send> {
        match sa {
            SynchronizerAction::Download => {
                info!("Downloading file from the server");
                Box::new(Self::download(filename, client)
                    .and_then(|tmp_file_name| ok(SyncStatus::NewAvailable("dropbox", tmp_file_name))))
            }
            SynchronizerAction::Ignore => {
                debug!("No sync is needed");
                Box::new(ok(SyncStatus::None))
            }
            SynchronizerAction::Upload => {
                info!("Uploading file on the server");
                Box::new(Self::upload_all(filename, client, version_local, saved_at_local)
                    .and_then(|_| ok(SyncStatus::UploadSuccess("dropbox"))))
            }
            SynchronizerAction::DownloadMergeAndUpload => {
                let filename_clone = filename.to_string();
                let client2 = Arc::clone(&client);
                Box::new(Self::download(filename, client)
                    .and_then(|tmp_file_name| {
                        ok(SyncStatus::NewToMerge("dropbox", tmp_file_name))
                    })
                    .or_else(move |_| {
                        info!("Could not download from the server and do the merge. The files do not exist. Uploading...");
                        Self::upload_all(&filename_clone, client2, version_local, saved_at_local)
                            .and_then(|_| {
                                ok(SyncStatus::UploadSuccess("dropbox"))
                            })
                    }))
            }
        }
    }

    fn upload_all(filename: &str, client: ArcMutexRklHttpAsyncClient, version_local: Option<i64>, saved_at_local: Option<i64>) -> impl Future<Item=(), Error=RustKeylockError> {
        let client2 = Arc::clone(&client);
        Self::upload(filename, client)
            .and_then(move |_| {
                create_version_file_locally(version_local, saved_at_local)
            })
            .and_then(|_| Self::upload(".version", client2))
            .and_then(|_| {
                let _ = file_handler::delete_file(".version");
                ok(())
            })
    }

    fn send_to_channel(res: errors::Result<SyncStatus>, tx: Sender<errors::Result<SyncStatus>>) {
        match res {
            Ok(ref r) => debug!("Dropbox Async Task sends to the channel {:?}", r),
            Err(ref error) => error!("Dropbox Async Tasks reported error: {:?}", error),
        };


        match tx.send(res) {
            Ok(_) => {
                // ignore
            }
            Err(error) => {
                error!("Error while the Dropbox synchronizer attempted to send the status to the channel: {:?}.", error);
            }
        }
    }
}

impl super::AsyncTask for Synchronizer {
    fn init(&mut self) {}

    fn execute(&self) -> Box<dyn Future<Item=bool, Error=()> + Send> {
        let cloned_tx_ok = self.tx.clone();
        let cloned_tx_err = self.tx.clone();

        let f = self.do_execute()
            .map(move |sync_status| {
                // Return true to continue the task only if the SyncStatus was None.
                // In all the other cases we need to stop the task in order to allow the user to take an action.
                let to_ret = sync_status == SyncStatus::None;
                Self::send_to_channel(Ok(sync_status), cloned_tx_ok);
                to_ret
            })
            .map_err(move |error| Self::send_to_channel(Err(error), cloned_tx_err));

        Box::new(f)
    }
}

fn parse_version_str(s: &str) -> errors::Result<ServerVersionData> {
    let v: Vec<String> = s.split(",")
        .map(|entry| {
            let s = entry.trim();
            s.to_string()
        })
        .collect();

    Ok(ServerVersionData {
        version: utils::to_result(v.get(0))?.to_owned(),
        last_modified: utils::to_result(v.get(1))?.to_owned(),
    })
}

fn create_version_file_locally(version: Option<i64>, last_modified: Option<i64>) -> errors::Result<()> {
    let contents = format!("{},{}", version.unwrap_or(0), last_modified.unwrap_or(0));
    file_handler::save_bytes(".version", contents.as_bytes(), false)
}

/// The configuration that is retrieved from the rust-keylock encrypted file
#[derive(Debug, PartialEq, Clone)]
pub struct DropboxConfiguration {
    /// The token for a dropbox account
    pub token: String,
    token_cryptor: EntryPasswordCryptor,
}

impl DropboxConfiguration {
    /// Creates a new DropboxConfiguration
    pub fn new(token: String) -> errors::Result<DropboxConfiguration> {
        let mut s = DropboxConfiguration::default();
        s.token = s.token_cryptor.encrypt_str(&token)?;
        Ok(s)
    }

    pub fn decrypted_token(&self) -> errors::Result<String> {
        self.token_cryptor.decrypt_str(&self.token)
    }

    pub fn dropbox_url() -> String {
        let random_bytes = create_random(128);
        let b64 = base64::encode(&random_bytes);
        let random_string = utf8_percent_encode(&b64, USERINFO_ENCODE_SET).to_string();
        format!("https://www.dropbox.com/1/oauth2/authorize?client_id={}&response_type=token&redirect_uri=http://localhost:8899&state={}", APP_KEY, random_string)
    }

    /// Creates a TOML table form this NextcloudConfiguration. The resulted table contains the decrypted password.
    pub(crate) fn to_table(&self) -> errors::Result<Table> {
        let mut table = Table::new();
        table.insert("token".to_string(), toml::Value::String(self.decrypted_token()?));
        Ok(table)
    }

    /// Creates a NextcloudConfiguration from a TOML table. The password gets encrypted once the `new` function is called.
    pub(crate) fn from_table(table: &Table) -> Result<DropboxConfiguration, errors::RustKeylockError> {
        let token = table.get("token").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        match token {
            Some(tok) => DropboxConfiguration::new(tok),
            None => Ok(DropboxConfiguration::default()),
        }
    }

    /// Returns true is the configuration contains the needed values to operate correctly
    pub fn is_filled(&self) -> bool {
        let res = self.decrypted_token();
        (res.is_ok() && res.unwrap() != "")
    }
}

impl Default for DropboxConfiguration {
    fn default() -> DropboxConfiguration {
        DropboxConfiguration {
            token: "".to_string(),
            token_cryptor: EntryPasswordCryptor::new(),
        }
    }
}

pub(crate) fn retrieve_token(url_string: String) -> errors::Result<String> {
    debug!("Retrieving a token for dropbox");
    // Define the server shutdown handle
    let (tx_shutdown, rx_shutdown) = oneshot::channel::<()>();
    // Define the channel that will be used by the server to send the retrieved token
    let (tx, rx) = mpsc::channel();

    // Spawn the server in a different thread
    thread::spawn(move || {
        // Get the port and state from the URL
        let (port, state) = parse_url(url_string).unwrap();
        // The tx to be shared between threads (used by the server function).
        let tx_arc = Arc::new(Mutex::new(tx));
        // The state to be shared between threads (used by the server function).
        let state_arc = Arc::new(state);
        // The server function
        let s = move || {
            let shared_tx = tx_arc.clone();
            let shared_state = state_arc.clone();
            service_fn_ok(move |req: Request<Body>| {
                let mut resp_builder = Response::builder();

                if req.method() == &hyper::Method::GET {
                    // Something like http://localhost:8899/#access_token=blabla&token_type=bearer&state=blabla&uid=blabla&account_id=blabla
                    resp_builder.status(StatusCode::OK);
                    resp_builder.body(Body::from(HTTP_GET_RESPONSE_BODY)).unwrap()
                } else if req.method() == &hyper::Method::POST {
                    // The post body should be like:
                    // tkninput=%23access_token%thisisatoken%26token_type%3Dbearer%26state%3DmiRHqBMRYjKMd089A4904USkjjrV7uh7mrrFaU1MrtXQPstDuf4ojC2bFQjkS83kslXrlhksomcopvFHV6e0BF7Ta6c4D1sDsOhYA864b6rwrqJlZzJZ%2B%252FpUeaQ4NvpP1tV%252FhCqUqdj5juK1h49x5DbCYNQMe54DeZe5XBPYl%2Bs%253D%26uid%3D1417302560%26account_id%3Ddbid%253AAAABRSgfZEneZO8ogIDXa0EH3BdpFWNRVc0
                    let shared_tx_2 = shared_tx.clone();
                    let shared_state_2 = shared_state.clone();
                    let bdy = req_to_body(req)
                        .and_then(move |v| {
                            let tx = shared_tx_2.lock().unwrap();
                            let state = &shared_state_2.to_string();
                            let _ = String::from_utf8(v)
                                .map_err(|error| RustKeylockError::GeneralError(format!("Could not retrieve the request body: {}", error.description())))
                                .map(|bdy| {
                                    let fragment = bdy.replace("tkninput=%23", "");
                                    percent_decode(fragment.as_bytes())
                                        .decode_utf8().unwrap()
                                        .to_string()
                                })
                                .map(|fragment| {
                                    retrieve_token_and_state_from_post_body(&fragment).unwrap()
                                })
                                .map(|m| {
                                    let (found_token, found_state) = m;
                                    let decoded_state = percent_decode(found_state.as_bytes())
                                        .decode_utf8().unwrap()
                                        .to_string();

                                    if state == &decoded_state {
                                        let _ = tx.send(Ok(found_token));
                                    } else {
                                        let _ = tx.send(Err(RustKeylockError::GeneralError(format!("Invalid request state. Expected: {}, found: {}", state, decoded_state))));
                                    }
                                })
                                .map_err(|error| { let _ = tx.send(Err(error)); });

                            ok(())
                        })
                        .map_err(|_| ());
                    hyper::rt::spawn(bdy);
                    resp_builder.status(StatusCode::OK);
                    resp_builder.body(Body::from(HTTP_POST_RESPONSE_BODY)).unwrap()
                } else {
                    let tx = shared_tx.lock().unwrap();
                    let _ = tx.send(Err(RustKeylockError::GeneralError("error".to_string())));
                    resp_builder.status(StatusCode::BAD_REQUEST);
                    resp_builder.body(Body::empty()).unwrap()
                }
            })
        };

        // The server will run on the localhost
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        // Bind the server
        let server = Server::bind(&addr).serve(s);
        // Set the graceful shutdown handle
        let graceful = server
            .with_graceful_shutdown(rx_shutdown)
            .map_err(|err| error!("HTTP Server Error during retrieving Dropbox token: {}", err));

        hyper::rt::run(graceful);
    });


    debug!("Waiting for Dropbox Token...");
    let rec = rx.recv_timeout(time::Duration::from_millis(60000))
        .map_err(|error| RustKeylockError::from(error))
        .and_then(|rec_res| rec_res);
    debug!("Dropbox Token retrieved. Stopping temporary server...");
    // Shutdown the server
    let _ = tx_shutdown.send(());

    rec
}

fn req_to_body(req: Request<Body>) -> impl Future<Item=Vec<u8>, Error=RustKeylockError> {
    req.into_body().concat2()
        .map_err(|error| RustKeylockError::SyncError(errors::debug_error_string(error)))
        .map(move |chunk| {
            let body: Vec<u8> = chunk.to_vec();
            body
        })
}

fn parse_url(url_string: String) -> errors::Result<(u16, String)> {
    let url = Url::parse(&url_string)?;
    let mut port = 8899;
    let mut redirect_url_string = "".to_string();
    let mut state = "".to_string();

    for pair in url.query_pairs() {
        if &pair.0 == "redirect_uri" {
            redirect_url_string = pair.1.to_string();
        } else if &pair.0 == "state" {
            state = pair.1.to_string().replace(' ', "+")
        }
    }

    if !redirect_url_string.is_empty() {
        let redirect_url = Url::parse(&redirect_url_string)?;
        port = redirect_url.port().unwrap_or(8899);
    }

    Ok((port, state))
}

fn retrieve_token_and_state_from_post_body(post_body: &str) -> errors::Result<(String, String)> {
    let access_token_tups: Vec<(&str, &str)> = post_body.split('&')
        .map(|s| {
            let v: Vec<&str> = s.splitn(2, '=').collect();
            v
        })
        .map(|elems| {
            if elems.len() == 2 {
                (elems.get(0).unwrap().clone(), elems.get(1).unwrap().clone())
            } else {
                ("", "")
            }
        })
        .filter(|tup| tup.0 == "access_token" || tup.0 == "state")
        .collect();
    let mut access_token = "".to_string();
    let mut state = "".to_string();
    for tup in access_token_tups {
        if tup.0 == "access_token" {
            access_token = tup.1.to_string();
        } else if tup.0 == "state" {
            state = tup.1.to_string();
        }
    }
    Ok((access_token, state))
}

#[cfg(test)]
mod dropbox_tests {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    use std::thread;
    use std::time;

    use hyper::{Client, Method, Request};
    use hyper::rt::{self, Future};

    use crate::asynch::RklHttpAsyncClient;

    use super::*;

    #[test]
    fn test_parse_version_str() {
        let sv = parse_version_str("123,321").unwrap();
        assert!(sv.version == "123");
        assert!(sv.last_modified == "321");
    }

    #[test]
    fn retrieve_a_token_and_a_state_from_post_body() {
        let res = retrieve_token_and_state_from_post_body("access_token=mytoken&token_type=bearer&state=mystate&uid=myuid&account_id=myaccountid");
        let (token, state) = res.unwrap();
        assert!(token == "mytoken");
        assert!(state == "mystate");
    }

    #[test]
    fn token_retrieval_success_and_failure() {
        retrieval_success();
        retrieval_failure();
    }

    fn retrieval_success() {
        let (tx, rx) = mpsc::channel();
        // The state
        let state = "cyrNicoWwMP%2FVKd%2FwunLPVO6ZU+D4UwQQ9BDeckxJwL5vlQGDf4Kt2J49bfJ+V3qnI7TTtLq3PZRJY9Sn0p3S4EfYBNSPtdIHNWsSLoFz7u1FnVXbOdfjrjybKLusY4Eu+usJP+e86tnJi4lCDrYXy6O7hMZZmAvj1%2FmykZhgmQ";
        // The redirect URI that is included in the request to dropbox
        let redirect_uri = format!("http://localhost:8899&state={}", state);
        let redirect_uri_clone = redirect_uri.clone();
        thread::spawn(move || {
            let url_string = format!("https://www.dropbox.com/1/oauth2/authorize?client_id=7git6ovjwtdbfvm&response_type=token&redirect_uri={}", redirect_uri_clone);
            let token_res = retrieve_token(url_string);
            let _ = tx.send(token_res);
        });
        // Sleep to give time to the server to start
        thread::sleep(time::Duration::from_millis(1000));

        // Send the HTTP POST request
        rt::run(rt::lazy(move || {
            let client = Client::new();
            let uri: hyper::Uri = "http://localhost:8899/".parse().unwrap();
            let post_body = format!("tkninput=%23access_token%3DAHO6fSqhEBAAAAAAAAAAZeiCpsEkwQSDd4bgz3vOWTsx2RnZ1uQ2NyS5N315lGRq%26token_type%3Dbearer%26state%3D{}%26uid%3D1417302560%26account_id%3Ddbid%253AAAABRSgfZEneZO8ogIDXa0EH3BdpFWNRVc0", state);
            let mut req = Request::new(Body::from(post_body));
            *req.method_mut() = Method::POST;
            *req.uri_mut() = uri.clone();

            client.request(req)
                .map(|res| {
                    println!("POST Response OK: {:?}", res);
                })
                .map_err(|error| {
                    println!("POST Response Error: {:?}", error);
                })
        }));
        // Wait for the token from the retrieve_token function (it is spawned above)
        let res = rx.recv_timeout(time::Duration::from_millis(10000));
        assert!(res.unwrap().is_ok());
    }

    fn retrieval_failure() {
        let (tx, rx) = mpsc::channel();
        // The state
        let state = "astate";
        // The redirect URI that is included in the request to dropbox
        let redirect_uri = format!("http://localhost:8899&state={}", state);
        let redirect_uri_clone = redirect_uri.clone();
        thread::spawn(move || {
            let url_string = format!("https://www.dropbox.com/1/oauth2/authorize?client_id=7git6ovjwtdbfvm&response_type=token&redirect_uri={}", redirect_uri_clone);
            let token_res = retrieve_token(url_string);
            let _ = tx.send(token_res);
        });
        // Sleep to give time to the server to start
        thread::sleep(time::Duration::from_millis(1000));

        // Send the HTTP POST request
        rt::run(rt::lazy(move || {
            let client = Client::new();
            let uri: hyper::Uri = "http://localhost:8899/".parse().unwrap();
            let invalid_state = "anotherstate";
            let post_body = format!("tkninput=%23access_token%3DAHO6fSqhEBAAAAAAAAAAZeiCpsEkwQSDd4bgz3vOWTsx2RnZ1uQ2NyS5N315lGRq%26token_type%3Dbearer%26state%3D{}%26uid%3D1417302560%26account_id%3Ddbid%253AAAABRSgfZEneZO8ogIDXa0EH3BdpFWNRVc0", invalid_state);
            let mut req = Request::new(Body::from(post_body));
            *req.method_mut() = Method::POST;
            *req.uri_mut() = uri.clone();

            client.request(req)
                .map(|res| {
                    println!("POST Response OK: {:?}", res);
                })
                .map_err(|error| {
                    println!("POST Response Error: {:?}", error);
                })
        }));
        // Wait for the token from the retrieve_token function (it is spawned above)
        let res = rx.recv_timeout(time::Duration::from_millis(10000));
        assert!(res.unwrap().is_err());
    }

    #[test]
    fn dbx_url() {
        assert!(DropboxConfiguration::dropbox_url().starts_with("https://www.dropbox.com/1/oauth2/authorize?client_id=7git6ovjwtdbfvm&response_type=token&redirect_uri=http://localhost:8899&"))
    }

    #[test]
    fn parse_a_url() {
        let res = parse_url(DropboxConfiguration::dropbox_url());
        assert!(res.is_ok());
        let (port, state) = res.unwrap();
        assert!(port == 8899);
        assert!(!state.is_empty());
    }

    #[test]
    fn dbx_configuration_to_table() {
        let toml = r#"
                token = "thisisatoken"
            "#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let dbx_res = DropboxConfiguration::from_table(&table);
        assert!(dbx_res.is_ok());
        let dbx = dbx_res.unwrap();
        let new_table = dbx.to_table().unwrap();
        assert!(table == &new_table);
    }

    #[test]
    fn dbx_configuration_from_table_success() {
        let toml = r#"
                token = "thisisatoken"
            "#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let dbx_res = DropboxConfiguration::from_table(&table);
        assert!(dbx_res.is_ok());
        let dbx = dbx_res.unwrap();
        assert!(dbx.decrypted_token().unwrap() == "thisisatoken");
    }

    #[test]
    fn dbx_configuration_is_filled() {
        let dbx1 = DropboxConfiguration::new("thisisatoken".to_string()).unwrap();
        assert!(dbx1.is_filled());
        let dbx2 = DropboxConfiguration::default();
        assert!(!dbx2.is_filled());
    }

    #[test]
    fn use_the_token_derypted() {
        let token = "thisisatoken";
        let dbx = DropboxConfiguration::new(token.to_string()).unwrap();
        assert!(dbx.decrypted_token().unwrap() == token);
    }

    #[test]
    fn download() {
        let (tx, rx): (Sender<errors::Result<String>>, Receiver<errors::Result<String>>) = mpsc::channel();
        let tx_clone = tx.clone();

        let mut client = TestHttpClient::new();
        client.header("Authorization", "Bearer thisisatoken");

        let mut validation_headers = HashMap::new();
        validation_headers.insert("Dropbox-API-Arg".to_string(), format!(r#"{{"path": "/afile"}}"#));
        validation_headers.insert("Authorization".to_string(), "Bearer thisisatoken".to_string());

        client.add_validation_step(TestHttpClientValidationStep {
            uri: Some("https://content.dropboxapi.com/2/files/download".to_string()),
            response: Vec::from("tmp_afile"),
            headers: validation_headers,
        });

        tokio::run(Synchronizer::download("afile", client.to_arc())
            .map(move |tmp_file_name| {
                let _ = tx.send(Ok(tmp_file_name));
            })
            .map_err(move |error| {
                let _ = tx_clone.send(Err(error));
            }));

        rx.recv_timeout(time::Duration::from_millis(10000)).unwrap().unwrap();
    }

    #[test]
    fn upload() {
        let (tx, rx): (Sender<errors::Result<()>>, Receiver<errors::Result<()>>) = mpsc::channel();
        let tx_clone = tx.clone();

        let mut client = TestHttpClient::new();
        client.header("Authorization", "Bearer thisisatoken");

        let mut validation_headers = HashMap::new();
        validation_headers.insert("Authorization".to_string(), "Bearer thisisatoken".to_string());
        validation_headers.insert("Dropbox-API-Arg".to_string(), format!(r#"{{"path":"/afile","mode":"overwrite"}}"#));
        validation_headers.insert("Content-Type".to_string(), "application/octet-stream".to_string());

        client.add_validation_step(TestHttpClientValidationStep {
            uri: Some("https://content.dropboxapi.com/2/files/upload".to_string()),
            response: Vec::from("tmp_afile"),
            headers: validation_headers,
        });

        file_handler::save_bytes("afile", "123".as_bytes(), false).unwrap();

        tokio::run(Synchronizer::upload("afile", client.to_arc())
            .map(move |_| {
                let _ = tx.send(Ok(()));
            })
            .map_err(move |error| {
                let _ = tx_clone.send(Err(error));
            }));

        rx.recv_timeout(time::Duration::from_millis(10000)).unwrap().unwrap();
        let _ = file_handler::delete_file("afile");
    }

    #[test]
    fn get_version() {
        let (tx, rx): (Sender<errors::Result<ServerVersionData>>, Receiver<errors::Result<ServerVersionData>>) = mpsc::channel();
        let tx_clone = tx.clone();

        let mut client = TestHttpClient::new();
        client.header("Authorization", "Bearer thisisatoken");

        let mut validation_headers = HashMap::new();
        validation_headers.insert("Authorization".to_string(), "Bearer thisisatoken".to_string());
        validation_headers.insert("Dropbox-API-Arg".to_string(), r#"{"path": "/.version"}"#.to_string());

        client.add_validation_step(TestHttpClientValidationStep {
            uri: Some("https://content.dropboxapi.com/2/files/download".to_string()),
            response: Vec::from("1,2"),
            headers: validation_headers,
        });


        tokio::run(Synchronizer::get_version(client.to_arc())
            .map(move |svd| {
                let _ = tx.send(Ok(svd));
            })
            .map_err(move |error| {
                let _ = tx_clone.send(Err(error));
            }));

        let svd = rx.recv_timeout(time::Duration::from_millis(10000)).unwrap().unwrap();
        assert!(svd.version == "1");
        assert!(svd.last_modified == "2");
    }

    #[derive(Debug, Clone)]
    struct TestHttpClientValidationStep {
        headers: HashMap<String, String>,
        response: Vec<u8>,
        uri: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct TestHttpClient {
        headers: HashMap<String, String>,
        validation_steps: Vec<TestHttpClientValidationStep>,
    }

    impl TestHttpClient {
        fn to_arc(self) -> Arc<Mutex<Box<dyn RklHttpAsyncClient<RES_TYPE=Vec<u8>>>>> {
            Arc::new(Mutex::new(Box::new(self)))
        }

        fn new() -> TestHttpClient {
            TestHttpClient {
                headers: HashMap::new(),
                validation_steps: Vec::new(),
            }
        }

        fn add_validation_step(&mut self, validation_step: TestHttpClientValidationStep) {
            self.validation_steps.push(validation_step);
        }

        fn validate_headers(current: &HashMap<String, String>, correct: &HashMap<String, String>) -> errors::Result<()> {
            if current == correct {
                Ok(())
            } else {
                Err(RustKeylockError::GeneralError(format!("Headers validation failed. Should be {:?} but was {:?}", correct, current)))
            }
        }

        fn validate_uris(current: &str, correct: &Option<String>) -> errors::Result<()> {
            if correct.is_some() {
                if current == correct.as_ref().unwrap() {
                    Ok(())
                } else {
                    Err(RustKeylockError::GeneralError(format!("URIs validation failed. Should be {:?} but was {:?}", correct, current)))
                }
            } else {
                Ok(())
            }
        }

        fn handle_request(&mut self, uri: &str, additional_headers: &[(&str, &str)]) -> Box<dyn Future<Item=Vec<u8>, Error=RustKeylockError> + Send> {
            let mut current_headers = self.headers.clone();
            let current_uri = uri.to_owned();
            for (additional_k, additional_v) in additional_headers {
                current_headers.insert(additional_k.to_string(), additional_v.to_string());
            }
            let headers_and_responses_result = self.validation_steps.pop().ok_or(RustKeylockError::GeneralError("There are no available responses".to_string()));
            Box::new(
                result(headers_and_responses_result)
                    .and_then(move |validation_step| {
                        let response_to_send: Vec<u8> = validation_step.response.iter().cloned().collect();
                        Self::validate_headers(&current_headers, &validation_step.headers)
                            .and_then(|_| Self::validate_uris(&current_uri, &validation_step.uri))
                            .map(|_| response_to_send)
                    })
                    .and_then(|response_to_send| {
                        ok(response_to_send)
                    }))
        }
    }

    impl RklHttpAsyncClient for TestHttpClient {
        type RES_TYPE = Vec<u8>;

        fn header(&mut self, k: &str, v: &str) {
            self.headers.insert(k.to_string(), v.to_string());
        }

        fn get(&mut self, uri: &str, additional_headers: &[(&str, &str)]) -> Box<dyn Future<Item=Vec<u8>, Error=RustKeylockError> + Send> {
            self.handle_request(uri, additional_headers)
        }

        fn post(&mut self, uri: &str, additional_headers: &[(&str, &str)], _body: Vec<u8>) -> Box<dyn Future<Item=Vec<u8>, Error=RustKeylockError> + Send> {
            self.handle_request(uri, additional_headers)
        }
    }
}
