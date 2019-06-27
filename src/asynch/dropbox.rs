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
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
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
use j4rs::{Instance, InvocationArg, Jvm, JvmBuilder};
use log::*;
use percent_encoding::{percent_decode, USERINFO_ENCODE_SET, utf8_percent_encode};
use toml;
use toml::value::Table;
use url::Url;

use crate::asynch::{self, ServerVersionData, SynchronizerAction, SyncStatus};
use crate::datacrypt::{create_random, EntryPasswordCryptor};
use crate::errors;
use crate::errors::RustKeylockError;
use crate::file_handler;
use crate::file_handler::default_toml_path;
use crate::SystemConfiguration;
use crate::utils;

const APP_KEY:&str = "7git6ovjwtdbfvm";
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
pub struct Synchronizer {
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
}

impl Synchronizer {
    pub(crate) fn new(dbc: &DropboxConfiguration,
                      sys_conf: &SystemConfiguration,
                      tx: Sender<errors::Result<SyncStatus>>,
                      f: &str)
                      -> errors::Result<Synchronizer> {
        let s = Synchronizer {
            conf: dbc.clone(),
            tx,
            file_name: f.to_string(),
            saved_at_local: sys_conf.saved_at,
            version_local: sys_conf.version,
            last_sync_version: sys_conf.last_sync_version,
        };
        Ok(s)
    }

    /// Returns the password decrypted
    fn use_token(&self) -> errors::Result<String> {
        self.conf.decrypted_token()
    }

    fn do_execute(&self) -> errors::Result<SyncStatus> {
        let jvm = JvmBuilder::new().build().unwrap();

        let request_config = jvm.create_instance(
            "com.dropbox.core.DbxRequestConfig",
            &[InvocationArg::from("rkl-operations")],
        )?;
        let dbx_client = jvm.create_instance(
            "com.dropbox.core.v2.DbxClientV2",
            &[InvocationArg::from(request_config), InvocationArg::from(self.use_token()?)],
        )?;

        let server_version = self.get_version(&jvm, &dbx_client)?;
        let synchronizer_action = asynch::synchronizer_action(&server_version, &self.file_name, &self.saved_at_local, &self.version_local, &self.last_sync_version)?;
        Self::parse_synchronizer_action(synchronizer_action, &self.file_name, &jvm, &dbx_client, self.version_local, self.saved_at_local)
    }

    fn get_version(&self, jvm: &Jvm, client: &Instance) -> errors::Result<ServerVersionData> {
        match Self::download(".version", jvm, client) {
            Ok(tmp_file_name) => {
                let tmp_file_pb = default_toml_path(&tmp_file_name);
                let svd = parse_version_file(&tmp_file_pb)?;

                let _ = file_handler::delete_file(&tmp_file_name);

                Ok(svd)
            }
            Err(_) => {
                let svd = ServerVersionData {
                    version: "0".to_string(),
                    last_modified: "0".to_string(),
                };
                Ok(svd)
            }
        }
    }

    fn download(filename: &str, jvm: &Jvm, client: &Instance) -> errors::Result<String> {
        let tmp_file_name = format!("tmp_{}", filename);
        let tmp_file_pb = default_toml_path(&tmp_file_name);
        let tmp_file_path_str = tmp_file_pb.to_str().unwrap();

        let fos = jvm.create_instance("java.io.FileOutputStream", &vec![InvocationArg::from(tmp_file_path_str.clone())])?;
        let os = jvm.cast(&fos, "java.io.OutputStream")?;

        let downloader = jvm.chain(jvm.clone_instance(client)?)
            .invoke("files", &[])?
            .invoke("download", &vec![InvocationArg::from(InvocationArg::from(format!("/{}", filename)))])?
            .collect();

        jvm.invoke(&downloader, "download", &vec![InvocationArg::from(os)])?;
        jvm.invoke(&downloader, "close", &[])?;

        Ok(tmp_file_name)
    }

    fn upload(filename: &str, jvm: &Jvm, client: &Instance) -> errors::Result<()> {
        let file_pb = default_toml_path(&filename);
        let file_path_str = file_pb.to_str().unwrap();

        let fis = jvm.create_instance("java.io.FileInputStream", &vec![InvocationArg::from(file_path_str.clone())])?;
        let is = jvm.cast(&fis, "java.io.InputStream")?;
        let wm = jvm.static_class("com.dropbox.core.v2.files.WriteMode")?;
        let mode_overwrite = jvm.field(&wm, "OVERWRITE")?;

        let uploader = jvm.chain(jvm.clone_instance(client)?)
            .invoke("files", &[])?
            .invoke("uploadBuilder", &vec![InvocationArg::from(format!("/{}", filename))])?
            .invoke("withMode", &vec![InvocationArg::from(mode_overwrite)])?
            .collect();

        let uploader_base = jvm.cast(&uploader, "com.dropbox.core.v2.DbxUploadStyleBuilder")?;

        jvm.invoke(&uploader_base, "uploadAndFinish", &vec![InvocationArg::from(is)])?;

        Ok(())
    }

    fn parse_synchronizer_action(sa: SynchronizerAction, filename: &str, jvm: &Jvm, client: &Instance, version_local: Option<i64>, saved_at_local: Option<i64>) -> errors::Result<SyncStatus> {
        match sa {
            SynchronizerAction::Download => {
                info!("Downloading file from the server");
                let tmp_file_name = Self::download(filename, jvm, client)?;
                Ok(SyncStatus::NewAvailable("dropbox", tmp_file_name))
            }
            SynchronizerAction::Ignore => {
                debug!("No sync is needed");
                Ok(SyncStatus::None)
            }
            SynchronizerAction::Upload => {
                info!("Uploading file on the server");
                Self::upload(filename, jvm, client)?;
                create_version_file_locally(version_local, saved_at_local)?;
                Self::upload(".version", jvm, client)?;
                let _ = file_handler::delete_file(".version");
                Ok(SyncStatus::UploadSuccess("dropbox"))
            }
            SynchronizerAction::DownloadMergeAndUpload => {
                let tmp_file_name = Self::download(filename, jvm, client)?;
                Ok(SyncStatus::NewToMerge("dropbox", tmp_file_name))
            }
        }
    }

    fn send_to_channel(res: errors::Result<SyncStatus>, tx: Sender<errors::Result<SyncStatus>>) {
        match res {
            Ok(ref r) => debug!("Nextcloud Async Task sends to the channel {:?}", r),
            Err(ref error) => error!("Nextcloud Async Tasks reported error: {:?}", error),
        };


        match tx.send(res) {
            Ok(_) => {
                // ignore
            }
            Err(error) => {
                error!("Error while the Nextcloud synchronizer attempted to send the status to the channel: {:?}.", error);
            }
        }
    }
}

impl super::AsyncTask for Synchronizer {
    fn init(&mut self) {}

    fn execute(&self) -> Box<dyn Future<Item=bool, Error=()> + Send> {
        let cloned_tx_ok = self.tx.clone();
        let cloned_tx_err = self.tx.clone();

        let f = result(self.do_execute())
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

fn parse_version_file(pb: &PathBuf) -> errors::Result<ServerVersionData> {
    let v_content = fs::read_to_string(&pb)?;
    let v: Vec<String> = v_content.split(",")
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
    pub fn to_table(&self) -> errors::Result<Table> {
        let mut table = Table::new();
        table.insert("token".to_string(), toml::Value::String(self.decrypted_token()?));
        Ok(table)
    }

    /// Creates a NextcloudConfiguration from a TOML table. The password gets encrypted once the `new` function is called.
    pub fn from_table(table: &Table) -> Result<DropboxConfiguration, errors::RustKeylockError> {
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
    use std::env;
    use std::sync::mpsc;
    use std::thread;
    use std::time;

    use hyper::{Client, Method, Request};
    use hyper::rt::{self, Future};

    use crate::file_handler;

    use super::*;

//        #[test]
//    #[ignore]
    fn _invoke() {
        let (tx, _rx) = mpsc::channel();

        let sc = SystemConfiguration::new(Some(11), Some(11), None);
        let s = Synchronizer::new(
            &DropboxConfiguration::new(env::var("DBX_TOKEN").unwrap().to_string()).unwrap(),
            &sc,
            tx,
            ".sec").unwrap();

        s.do_execute().unwrap();
    }

    //    #[test]
//    #[ignore]
    fn _dummy() {
        let token = env::var("DBX_TOKEN").unwrap();
        let jvm = JvmBuilder::new().build().unwrap();

        let request_config = jvm.create_instance(
            "com.dropbox.core.DbxRequestConfig",
            &[InvocationArg::from("rkl-operations")],
        ).unwrap();
        let dbx_client = jvm.create_instance(
            "com.dropbox.core.v2.DbxClientV2",
            &[InvocationArg::from(request_config), InvocationArg::from(token.clone())],
        ).unwrap();

        let filename = "tmp_dummy";
        let _ = file_handler::save_bytes(filename, "123,321".as_bytes(), false);

        Synchronizer::upload(filename, &jvm, &dbx_client).unwrap();
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn test_parse_version_file() {
        let filename = "tmp_version";
        let _ = file_handler::save_bytes(filename, "123,321".as_bytes(), false);
        let pb = file_handler::default_toml_path(filename);
        let sv = parse_version_file(&pb).unwrap();
        assert!(sv.version == "123");
        assert!(sv.last_modified == "321");
        let _ = file_handler::delete_file(&filename);
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
}
