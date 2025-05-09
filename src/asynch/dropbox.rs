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

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use async_trait::async_trait;
use http::{StatusCode, Uri};
use http_body_util::BodyExt;
use reqwest::Body;
use std::convert::Infallible;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use log::*;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use toml;
use toml::value::Table;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::asynch::{
    self, BoxedRklHttpAsyncClient, ReqwestClientFactory, RklHttpAsyncFactory, ServerVersionData,
    SyncStatus, SynchronizerAction,
};
use crate::datacrypt::{create_random_utf_string, EntryPasswordCryptor};
use crate::errors;
use crate::errors::RustKeylockError;
use crate::file_handler;
use crate::utils;
use crate::SystemConfiguration;
use std::collections::HashMap;

const FRAGMENT: &AsciiSet = &CONTROLS.add(b'+').add(b'/');
const APP_KEY: &str = "7git6ovjwtdbfvm";

const HTTP_GET_RESPONSE_BODY: &str = r#"
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
    /// The rust-keylock file name to synchronize
    file_name: String,
    /// The saved_at value read locally from the file
    saved_at_local: Option<i64>,
    /// The version value read locally from the file
    version_local: Option<i64>,
    /// The version that was set during the last sync
    last_sync_version: Option<i64>,
    /// The factory that creates HTTP clients
    client_factory: Box<dyn RklHttpAsyncFactory<ClientResType = Vec<u8>>>,
}

impl Synchronizer {
    pub(crate) fn new(
        dbc: &DropboxConfiguration,
        sys_conf: &SystemConfiguration,
        f: &str,
        client_factory: Box<dyn RklHttpAsyncFactory<ClientResType = Vec<u8>>>,
    ) -> errors::Result<Synchronizer> {
        let s = Synchronizer {
            conf: dbc.clone(),
            file_name: f.to_string(),
            saved_at_local: sys_conf.saved_at,
            version_local: sys_conf.version,
            last_sync_version: sys_conf.last_sync_version,
            client_factory,
        };
        Ok(s)
    }

    /// Returns the refresh token decrypted
    fn use_token(&self) -> errors::Result<Zeroizing<String>> {
        self.conf.decrypted_token()
    }

    /// Returns the short-lived token decrypted
    fn use_short_lived_token(&self) -> errors::Result<Zeroizing<String>> {
        self.conf.decrypted_short_lived_token()
    }

    async fn do_execute(&self) -> errors::Result<SyncStatus> {
        let file_name = self.file_name.clone();
        let saved_at_local = self.saved_at_local.clone();
        let version_local = self.version_local.clone();
        let last_sync_version = self.last_sync_version.clone();
        let mut client = self.client_factory.create();
        client.header(
            "Authorization",
            &format!("Bearer {}", self.use_short_lived_token()?.as_str()),
        );
        let server_version = Self::get_version(&mut client).await?;
        let synchronizer_action = asynch::synchronizer_action(
            &server_version,
            &file_name,
            &saved_at_local,
            &version_local,
            &last_sync_version,
        )?;
        Self::parse_synchronizer_action(
            synchronizer_action,
            &file_name,
            &mut client,
            version_local,
            saved_at_local,
        )
        .await
    }

    async fn get_short_lived_token(&self) -> errors::Result<Zeroizing<String>> {
        let mut client = self.client_factory.create();
        debug!("DBX: Retrieving a short-lived token");

        let post_body: Vec<u8> = format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}",
            utf8_percent_encode(&self.use_token()?.as_str(), FRAGMENT),
            APP_KEY
        )
        .into_bytes();

        let response_bytes = client
            .post(
                "https://api.dropbox.com/oauth2/token",
                &[("Content-Type", "application/x-www-form-urlencoded")],
                post_body,
            )
            .await?;
        let response_string = String::from_utf8(response_bytes)?;
        let dbx_auth_response: DbxAuthResponse = serde_json::from_str(&response_string)?;

        Ok(Zeroizing::new(dbx_auth_response.access_token.clone()))
    }

    async fn get_version(
        client: &mut BoxedRklHttpAsyncClient,
    ) -> errors::Result<ServerVersionData> {
        debug!("DBX: Getting version");
        let bytes_res = client
            .post(
                "https://content.dropboxapi.com/2/files/download",
                &[("Dropbox-API-Arg", r#"{"path": "/.version"}"#)],
                Vec::new(),
            )
            .await;

        let bytes = bytes_res.unwrap_or("0,0".as_bytes().to_vec());
        let s = std::str::from_utf8(bytes.as_ref())?;
        let version_data = parse_version_str(s).unwrap_or(ServerVersionData::default());
        debug!("DBX: Got version");
        Ok(version_data)
    }

    async fn download(
        filename: &str,
        client: &mut BoxedRklHttpAsyncClient,
    ) -> errors::Result<String> {
        debug!("DBX: Download");
        let tmp_file_name = format!("tmp_{}", filename);

        let bytes = client
            .post(
                "https://content.dropboxapi.com/2/files/download",
                &[(
                    "Dropbox-API-Arg",
                    &format!(r#"{{"path": "/{}"}}"#, filename),
                )],
                Vec::new(),
            )
            .await?;
        file_handler::save_bytes(&tmp_file_name, &bytes, false)?;
        debug!("DBX: Downloaded");
        Ok(tmp_file_name)
    }

    async fn upload(filename: &str, client: &mut BoxedRklHttpAsyncClient) -> errors::Result<()> {
        debug!("DBX: Upload");
        let filename_string = filename.to_string();
        let mut file = file_handler::get_file(filename)?;
        let mut post_body: Vec<u8> = Vec::new();
        file.read_to_end(&mut post_body)?;
        client
            .post(
                "https://content.dropboxapi.com/2/files/upload",
                &[
                    (
                        "Dropbox-API-Arg",
                        &format!(r#"{{"path":"/{}","mode":"overwrite"}}"#, filename_string),
                    ),
                    ("Content-Type", "application/octet-stream"),
                ],
                post_body,
            )
            .await?;

        debug!("DBX: Uploaded");
        Ok(())
    }

    async fn parse_synchronizer_action(
        sa: SynchronizerAction,
        filename: &str,
        client: &mut BoxedRklHttpAsyncClient,
        version_local: Option<i64>,
        saved_at_local: Option<i64>,
    ) -> errors::Result<SyncStatus> {
        match sa {
            SynchronizerAction::Download => {
                info!("Downloading file from the server");
                let tmp_file_name = Self::download(filename, client).await?;
                Ok(SyncStatus::NewAvailable("dropbox", tmp_file_name))
            }
            SynchronizerAction::Ignore => {
                debug!("No sync is needed");
                Ok(SyncStatus::None)
            }
            SynchronizerAction::Upload => {
                info!("Uploading file on the server");
                Self::upload_all(filename, client, version_local, saved_at_local).await?;
                Ok(SyncStatus::UploadSuccess("dropbox"))
            }
            SynchronizerAction::DownloadMergeAndUpload => {
                let filename_clone = filename.to_string();
                if let Ok(tmp_file_name) = Self::download(filename, client).await {
                    Ok(SyncStatus::NewToMerge("dropbox", tmp_file_name))
                } else {
                    info!("Could not download from the server and do the merge. The files do not exist. Uploading...");
                    Self::upload_all(&filename_clone, client, version_local, saved_at_local)
                        .await?;
                    Ok(SyncStatus::UploadSuccess("dropbox"))
                }
            }
        }
    }

    async fn upload_all(
        filename: &str,
        client: &mut BoxedRklHttpAsyncClient,
        version_local: Option<i64>,
        saved_at_local: Option<i64>,
    ) -> errors::Result<()> {
        debug!("DBX: Uploading all");
        Self::upload(filename, client).await?;
        create_version_file_locally(version_local, saved_at_local)?;
        Self::upload(".version", client).await?;
        file_handler::delete_file(".version")?;
        debug!("DBX: Uploaded all");
        Ok(())
    }

    fn send_to_channel(
        res: errors::Result<SyncStatus>,
        tx: SyncSender<errors::Result<SyncStatus>>,
    ) {
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

#[async_trait]
impl super::AsyncTask for Synchronizer {
    async fn init(&mut self) {
        if self.conf.is_filled() {
            match self.get_short_lived_token().await {
                Ok(short_lived_token) => {
                    if let Err(error) = self.conf.set_short_lived_token(short_lived_token) {
                        error!("Could not initialize the Dropbox synchronizer: {}", error);
                    }
                }
                Err(error) => {
                    error!("Could not initialize the Dropbox synchronizer - error while retrieving short-lived token: {}", error);
                }
            }
        }
    }

    async fn execute(&self) -> errors::Result<SyncStatus> {
        if self.conf.is_filled() {
            loop {
                match self.do_execute().await {
                    Ok(SyncStatus::None) => {

                    },
                    Ok(sync_status) => {
                        return Ok(sync_status)
                    }
                    Err(error) => {
                        return Err(error);
                    }
                }
            }
        } else {
            return Ok(SyncStatus::None);
        }
    }
}

fn parse_version_str(s: &str) -> errors::Result<ServerVersionData> {
    let v: Vec<String> = s
        .split(",")
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

fn create_version_file_locally(
    version: Option<i64>,
    last_modified: Option<i64>,
) -> errors::Result<()> {
    let contents = format!("{},{}", version.unwrap_or(0), last_modified.unwrap_or(0));
    file_handler::save_bytes(".version", contents.as_bytes(), false)
}

/// The configuration that is retrieved from the rust-keylock encrypted file
#[derive(Debug, PartialEq, Clone, Zeroize)]
#[zeroize(drop)]
pub struct DropboxConfiguration {
    /// The refresh token for a dropbox account
    pub token: String,
    /// The short-lived token that is used for dbx API authentication.
    /// This is retrieved during the dropbox synchronizer intialization and is transient.
    pub short_lived_token: String,
    token_cryptor: EntryPasswordCryptor,
}

impl DropboxConfiguration {
    /// Creates a new DropboxConfiguration
    pub fn new<T: Into<Zeroizing<String>>>(token: T) -> errors::Result<DropboxConfiguration> {
        let mut s = DropboxConfiguration::default();
        s.token = s.token_cryptor.encrypt_str(&token.into())?;
        Ok(s)
    }

    /// Encrypts a short_lived_token and sets it to self
    pub fn set_short_lived_token<T: Into<Zeroizing<String>>>(
        &mut self,
        short_lived_token: T,
    ) -> errors::Result<()> {
        self.short_lived_token = self.token_cryptor.encrypt_str(&short_lived_token.into())?;
        Ok(())
    }

    pub fn decrypted_token(&self) -> errors::Result<Zeroizing<String>> {
        self.token_cryptor
            .decrypt_str(&self.token)
            .map(|token| Zeroizing::new(token))
    }

    pub fn decrypted_short_lived_token(&self) -> errors::Result<Zeroizing<String>> {
        self.token_cryptor
            .decrypt_str(&self.short_lived_token)
            .map(|short_lived_token| Zeroizing::new(short_lived_token))
    }

    pub fn dropbox_url() -> String {
        let random_string = create_random_utf_string(128);
        // PKCE flow
        format!("https://www.dropbox.com/oauth2/authorize?client_id={}&response_type=code&code_challenge={}&code_challenge_method=plain&redirect_uri=http://localhost:8899&token_access_type=offline",
                APP_KEY,
                random_string)
    }

    /// Creates a TOML table form this NextcloudConfiguration. The resulted table contains the decrypted password.
    pub(crate) fn to_table(&self) -> errors::Result<Table> {
        let mut table = Table::new();
        table.insert(
            "token".to_string(),
            toml::Value::String(self.decrypted_token()?.as_str().to_string()),
        );
        Ok(table)
    }

    /// Creates a NextcloudConfiguration from a TOML table. The password gets encrypted once the `new` function is called.
    pub(crate) fn from_table(
        table: &Table,
    ) -> Result<DropboxConfiguration, errors::RustKeylockError> {
        let token = table
            .get("token")
            .and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        match token {
            Some(tok) => DropboxConfiguration::new(tok),
            None => Ok(DropboxConfiguration::default()),
        }
    }

    /// Returns true is the configuration contains the needed values to operate correctly
    pub fn is_filled(&self) -> bool {
        let res = self.decrypted_token();
        res.is_ok() && res.unwrap().as_str() != ""
    }
}

impl Default for DropboxConfiguration {
    fn default() -> DropboxConfiguration {
        DropboxConfiguration {
            token: "".to_string(),
            short_lived_token: "".to_string(),
            token_cryptor: EntryPasswordCryptor::new(),
        }
    }
}

pub(crate) fn retrieve_token(url_string: String) -> errors::Result<Zeroizing<String>> {
    debug!("Retrieving a token for dropbox");
    // Define the channel that will be used by the server to send the retrieved token
    let (tx, rx) = mpsc::channel();

    // Spawn the server in a different thread
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect(
            "Cannot create tokio runtime to start the server for handling the dropbox token",
        );
        let f = async {
            // Get the port and state from the URL
            let (port, code_challenge) = parse_url(url_string).unwrap();
            // The tx to be shared between threads (used by the server function).
            let tx_arc = Arc::new(Mutex::new(tx));
            // The state to be shared between threads (used by the server function).
            let code_challenge_arc = Arc::new(code_challenge);
            // The server function
            let make_svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let shared_tx = tx_arc.clone();
                let shared_code_challenge = code_challenge_arc.clone();
                async move {
                    let shared_tx = shared_tx.clone();
                    let shared_code_challenge = shared_code_challenge.clone();
                    Ok::<_, Infallible>({
                        let resp_builder = Response::builder();

                        if req.method() == &hyper::Method::GET {
                            let code = parse_get_uri(req.uri()).unwrap();
                            let reqwest_client_factory = Box::new(ReqwestClientFactory::new());
                            let mut client = reqwest_client_factory.create();
                            handle_get(&code, &shared_code_challenge, &mut client, port).await
                        } else if req.method() == &hyper::Method::POST {
                            let error_message = format!("Could not get the body of the request to {}. Using an empty body instead.", req.uri());
                            let v = req_to_body(req).await.unwrap_or_else(move |error| {
                                error!("{} {}", error_message, error);
                                Vec::new()
                            });
                            let found_token = String::from_utf8(v).unwrap();
                            let tx = shared_tx.lock().unwrap();
                            let _ = tx.send(Ok(Zeroizing::new(found_token)));

                            resp_builder
                                .status(StatusCode::OK)
                                .body(reqwest::Body::from(Vec::new()))
                                .unwrap()
                        } else {
                            let tx = shared_tx.lock().unwrap();
                            let _ =
                                tx.send(Err(RustKeylockError::GeneralError("error".to_string())));
                            resp_builder
                                .status(StatusCode::BAD_REQUEST)
                                .body(reqwest::Body::from(Vec::new()))
                                .unwrap()
                        }
                    })
                }
            });

            // The server will run on the localhost
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
            let listener = TcpListener::bind(addr)
                .await
                .expect("Cannot bind TcpListener to retrive the dropbox token");
            let (tcp, _) = listener
                .accept()
                .await
                .expect("Cannot accept TcpStream for listener");
            let io = TokioIo::new(tcp);
            if let Err(error) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, make_svc)
                .await
            {
                error!(
                    "HTTP Server Error during retrieving Dropbox token: {}",
                    error
                )
            }
        };
        rt.block_on(f);
        debug!("Temporary server stopped!");
    });

    debug!("Waiting for Dropbox Token...");
    let rec = rx
        .recv_timeout(time::Duration::from_millis(600000))
        .map_err(|error| RustKeylockError::from(error))
        .and_then(|rec_res| rec_res);
    debug!("Dropbox Token retrieved. Stopping temporary server...");

    rec
}

async fn handle_get(
    code: &str,
    shared_code_challenge: &str,
    client: &mut BoxedRklHttpAsyncClient,
    port: u16,
) -> Response<Body> {
    let resp_builder = Response::builder();
    match get_refresh_token(code, shared_code_challenge, client).await {
        Ok(short_lived_token) => {
            client
                .post(
                    &format!("http://localhost:{}/", port),
                    &[],
                    short_lived_token.to_string().into_bytes(),
                )
                .await
                .unwrap();
            resp_builder
                .status(StatusCode::OK)
                .body(Body::from(HTTP_GET_RESPONSE_BODY))
                .unwrap()
        }
        Err(error) => {
            let message = format!(
                "Error while retrieving the dropbox short lived token: {}",
                error
            );
            error!("{}", message);
            resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(message))
                .unwrap()
        }
    }
}

async fn req_to_body(req: Request<hyper::body::Incoming>) -> errors::Result<Vec<u8>> {
    Ok(req.into_body().collect().await?.to_bytes().into())
}

fn parse_url(url_string: String) -> errors::Result<(u16, String)> {
    let url = Url::parse(&url_string)?;
    let mut port = 8899;
    let mut redirect_url_string = "".to_string();
    let mut code_challenge = "".to_string();

    for pair in url.query_pairs() {
        if &pair.0 == "redirect_uri" {
            redirect_url_string = pair.1.to_string();
        } else if &pair.0 == "code_challenge" {
            code_challenge = pair.1.to_string().replace(' ', "+")
        }
    }

    if !redirect_url_string.is_empty() {
        let redirect_url = Url::parse(&redirect_url_string)?;
        port = redirect_url.port().unwrap_or(8899);
    }

    Ok((port, code_challenge))
}

fn parse_get_uri(uri: &Uri) -> errors::Result<Zeroizing<String>> {
    let params: HashMap<String, String> = uri
        .query()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_else(HashMap::new);
    let code = Zeroizing::new(
        params
            .get("code")
            .map(|s| s.to_owned())
            .unwrap_or_else(String::new),
    );

    Ok(code)
}

async fn get_refresh_token(
    code: &str,
    code_challenge: &str,
    client: &mut BoxedRklHttpAsyncClient,
) -> errors::Result<Zeroizing<String>> {
    debug!("DBX: Retrieving a refresh token");

    let post_body: Vec<u8> = format!("code={}&grant_type=authorization_code&redirect_uri=http://localhost:8899&code_verifier={}&client_id={}",
                                     utf8_percent_encode(&code, FRAGMENT),
                                     utf8_percent_encode(&code_challenge, FRAGMENT),
                                     APP_KEY).into_bytes();

    let response_bytes = client
        .post(
            "https://api.dropbox.com/oauth2/token",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            post_body,
        )
        .await?;
    let response_string = String::from_utf8(response_bytes)?;
    let dbx_auth_response: DbxAuthResponse = serde_json::from_str(&response_string)?;

    Ok(Zeroizing::new(dbx_auth_response.refresh_token.clone()))
}

#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
struct DbxAuthResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    uid: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    scope: String,
    expires_in: isize,
    #[serde(default)]
    refresh_token: String,
}

#[cfg(test)]
mod dropbox_tests {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use std::time;

    use async_trait::async_trait;

    use crate::asynch::RklHttpAsyncClient;

    use super::*;

    #[test]
    fn test_parse_version_str() {
        let sv = parse_version_str("123,321").unwrap();
        assert!(sv.version == "123");
        assert!(sv.last_modified == "321");
    }

    #[test]
    fn token_retrieval_success() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (tx, rx) = mpsc::channel();
        // The code_challenge
        let code_challenge = "AAO6fShhDBAAAAAAAAABPuYM0gnquccZyc1c9LfQI3Y";
        // The redirect URI that is included in the request to dropbox
        let redirect_uri = format!("http://localhost:8899&code_challenge={}", code_challenge);
        thread::spawn(move || {
            let url_string = format!("https://www.dropbox.com/oauth2/authorize?client_id={}&response_type=code&code_challenge={}&code_challenge_method=plain&token_access_type=offline",
                                     APP_KEY,
                                     redirect_uri);
            let token_res = retrieve_token(url_string);
            let _ = tx.send(token_res);
        });
        // Sleep to give time to the server to start
        thread::sleep(time::Duration::from_millis(1000));

        // Send the HTTP POST request
        let uri = "http://localhost:8899/";
        let refresh_token = "a-refresh-token-generated-by-drobpox-servers".to_owned();
        let reqwest_client_factory = ReqwestClientFactory::new();
        let mut client = reqwest_client_factory.create();
        let f = client.post(uri, &[], refresh_token.clone().into_bytes());

        let response = rt.block_on(f);

        if response.is_ok() {
            println!("POST Response OK: {:?}", response.unwrap());
        } else {
            println!("POST Response Error: {:?}", response.unwrap_err());
        }

        // Wait for the token from the retrieve_token function (it is spawned above)
        let res = rx.recv_timeout(time::Duration::from_millis(10000));
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res.is_ok());
        let token = res.unwrap().to_string();
        assert!(token == refresh_token);
    }

    #[test]
    fn test_handle_get_success() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let code = "acode";
        let code_challenge = "acode_challenge";
        let port = 8899;
        let mut client = Box::new(AlwaysSuccessfulHttpClient::new());
        // Client initialization: This is the post response from the local temporary server
        client.add_response(Vec::new());
        // Client initialization: This is the response from the dropbox servers
        let json_response: Vec<u8> = r#"{
                                    "uid": "123",
                                    "access_token": "an.access-token",
                                    "expires_in": 14399,
                                    "token_type": "bearer",
                                    "scope": "scope1 scope2",
                                    "refresh_token": "a-refresh-token",
                                    "account_id": "dbid:MYACCOUNTID"
                                    }"#
        .to_owned()
        .into_bytes();
        client.add_response(json_response);
        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let response = rt.block_on(handle_get(code, code_challenge, &mut dyn_client, port));
        assert!(response.status().is_success());
    }

    #[test]
    fn test_handle_get_failure_on_dbx_token_api_call() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let code = "acode";
        let code_challenge = "acode_challenge";
        let port = 8899;
        let mut client = Box::new(AlwaysSuccessfulHttpClient::new());
        // Client initialization: This is the post response from the local temporary server
        client.add_response(Vec::new());
        // Client initialization: This is the response from the dropbox servers.
        // It is a wrong JSON to force a failure
        let json_response: Vec<u8> = r#"{
                                    "uid": "123",
                                    "account_id": "dbid:MYACCOUNTID"
                                    }"#
        .to_owned()
        .into_bytes();
        client.add_response(json_response);
        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let response = rt.block_on(handle_get(code, code_challenge, &mut dyn_client, port));
        assert!(response.status().is_client_error());
    }

    #[test]
    fn dbx_url() {
        assert!(DropboxConfiguration::dropbox_url().starts_with("https://www.dropbox.com/oauth2/authorize?client_id=7git6ovjwtdbfvm&response_type=code&code_challenge="))
    }

    #[test]
    fn parse_a_get_uri() {
        let test_code = "AHO6fSqhEBAAAAAAAAABPuYM0gnquccZyc1c3LfQI1Y";
        let res = parse_get_uri(&Uri::from_str(&format!("/?code={}", test_code)).unwrap());
        assert!(res.is_ok());
        let code = res.unwrap();
        assert!(code.as_str() == test_code);
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
        assert!(dbx.decrypted_token().unwrap().as_str() == "thisisatoken");
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
        assert!(dbx.decrypted_token().unwrap().as_str() == token);
    }

    #[test]
    fn download() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = Box::new(TestHttpClient::new());
        client.header("Authorization", "Bearer thisisatoken");

        let mut validation_headers = HashMap::new();
        validation_headers.insert(
            "Dropbox-API-Arg".to_string(),
            format!(r#"{{"path": "/afile_dld"}}"#),
        );
        validation_headers.insert(
            "Authorization".to_string(),
            "Bearer thisisatoken".to_string(),
        );

        client.add_validation_step(TestHttpClientValidationStep {
            uri: Some("https://content.dropboxapi.com/2/files/download".to_string()),
            response: Vec::from("tmp_afile_dld"),
            headers: validation_headers,
        });

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::download("afile_dld", &mut dyn_client));
        assert!(res.is_ok());
    }

    #[test]
    fn upload() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = Box::new(TestHttpClient::new());
        client.header("Authorization", "Bearer thisisatoken");

        let mut validation_headers = HashMap::new();
        validation_headers.insert(
            "Authorization".to_string(),
            "Bearer thisisatoken".to_string(),
        );
        validation_headers.insert(
            "Dropbox-API-Arg".to_string(),
            format!(r#"{{"path":"/afile_upld","mode":"overwrite"}}"#),
        );
        validation_headers.insert(
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        );

        client.add_validation_step(TestHttpClientValidationStep {
            uri: Some("https://content.dropboxapi.com/2/files/upload".to_string()),
            response: Vec::from("tmp_afile_upld"),
            headers: validation_headers,
        });

        file_handler::save_bytes("afile_upld", "123".as_bytes(), false).unwrap();

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::upload("afile_upld", &mut dyn_client));
        assert!(res.is_ok());
    }

    #[test]
    fn get_version() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = Box::new(TestHttpClient::new());
        client.header("Authorization", "Bearer thisisatoken");

        let mut validation_headers = HashMap::new();
        validation_headers.insert(
            "Authorization".to_string(),
            "Bearer thisisatoken".to_string(),
        );
        validation_headers.insert(
            "Dropbox-API-Arg".to_string(),
            r#"{"path": "/.version"}"#.to_string(),
        );

        client.add_validation_step(TestHttpClientValidationStep {
            uri: Some("https://content.dropboxapi.com/2/files/download".to_string()),
            response: Vec::from("1,2"),
            headers: validation_headers,
        });

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::get_version(&mut dyn_client));
        assert!(res.is_ok());
        let svd = res.unwrap();
        assert!(svd.version == "1");
        assert!(svd.last_modified == "2");
    }

    #[test]
    fn parse_synchronizer_action_download() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = Box::new(AlwaysSuccessfulHttpClient::new());

        client.add_response(Vec::from("irrelevant"));

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::parse_synchronizer_action(
            SynchronizerAction::Download,
            "afile_sa_dld",
            &mut dyn_client,
            Some(1),
            Some(2),
        ));
        assert!(res.is_ok());

        match res.unwrap() {
            SyncStatus::NewAvailable(from, filename) => {
                assert!(from == "dropbox");
                assert!(filename == "tmp_afile_sa_dld");
            }
            other => panic!("Unexpected SyncStatus: {:?}", other),
        };
        let _ = file_handler::delete_file("afile_sa_dld");
    }

    #[test]
    fn parse_synchronizer_action_ignore() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = Box::new(AlwaysSuccessfulHttpClient::new());

        client.add_response(Vec::from("irrelevant"));

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::parse_synchronizer_action(
            SynchronizerAction::Ignore,
            "afile_sa_ign",
            &mut dyn_client,
            Some(1),
            Some(2),
        ));
        assert!(res.is_ok());

        match res.unwrap() {
            SyncStatus::None => assert!(true),
            other => panic!("Unexpected SyncStatus: {:?}", other),
        };
        let _ = file_handler::delete_file("afile_sa_ign");
    }

    #[test]
    fn parse_synchronizer_action_upload() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        file_handler::save_bytes("afile_upload", "123".as_bytes(), false).unwrap();
        file_handler::save_bytes(".version", "123,321".as_bytes(), false).unwrap();
        let mut client = Box::new(AlwaysSuccessfulHttpClient::new());

        // We need two responses because the upload_all is called, which makes 2 requests for upload.
        // One for the .sec file and one for the .version file.
        client.add_response(Vec::from("irrelevant"));
        client.add_response(Vec::from("irrelevant"));

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::parse_synchronizer_action(
            SynchronizerAction::Upload,
            "afile_upload",
            &mut dyn_client,
            Some(1),
            Some(2),
        ));
        assert!(res.is_ok());

        match res.unwrap() {
            SyncStatus::UploadSuccess(from) => assert!(from == "dropbox"),
            other => panic!("Unexpected SyncStatus: {:?}", other),
        };
        let _ = file_handler::delete_file("afile_upload");
        let _ = file_handler::delete_file(".version");
    }

    #[test]
    fn parse_synchronizer_action_download_merge_and_upload() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = Box::new(AlwaysSuccessfulHttpClient::new());
        client.add_response(Vec::from("irrelevant"));

        let mut dyn_client = client as BoxedRklHttpAsyncClient;
        let res = rt.block_on(Synchronizer::parse_synchronizer_action(
            SynchronizerAction::DownloadMergeAndUpload,
            "afile_dmu",
            &mut dyn_client,
            Some(1),
            Some(2),
        ));
        assert!(res.is_ok());

        match res.unwrap() {
            SyncStatus::NewToMerge(from, filename) => {
                assert!(from == "dropbox");
                assert!(filename == "tmp_afile_dmu");
            }
            other => panic!("Unexpected SyncStatus: {:?}", other),
        };
        let _ = file_handler::delete_file("afile_dmu");
    }

    struct AlwaysSuccessfulHttpClient {
        responses: Vec<Vec<u8>>,
    }

    impl AlwaysSuccessfulHttpClient {
        fn new() -> AlwaysSuccessfulHttpClient {
            AlwaysSuccessfulHttpClient {
                responses: Vec::new(),
            }
        }

        fn add_response(&mut self, response: Vec<u8>) {
            self.responses.push(response);
        }

        async fn handle_request(&mut self) -> errors::Result<Vec<u8>> {
            self.responses.pop().ok_or(RustKeylockError::GeneralError(
                "There are no available responses".to_string(),
            ))
        }
    }

    #[async_trait]
    impl RklHttpAsyncClient for AlwaysSuccessfulHttpClient {
        type ResType = Vec<u8>;

        fn header(&mut self, _: &str, _: &str) {}

        async fn get(&mut self, _: &str, _: &[(&str, &str)]) -> errors::Result<Vec<u8>> {
            self.handle_request().await
        }

        async fn post(
            &mut self,
            _: &str,
            _: &[(&str, &str)],
            _: Vec<u8>,
        ) -> errors::Result<Vec<u8>> {
            self.handle_request().await
        }
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
        fn new() -> TestHttpClient {
            TestHttpClient {
                headers: HashMap::new(),
                validation_steps: Vec::new(),
            }
        }

        fn add_validation_step(&mut self, validation_step: TestHttpClientValidationStep) {
            self.validation_steps.push(validation_step);
        }

        fn validate_headers(
            current: &HashMap<String, String>,
            correct: &HashMap<String, String>,
        ) -> errors::Result<()> {
            if current == correct {
                Ok(())
            } else {
                Err(RustKeylockError::GeneralError(format!(
                    "Headers validation failed. Should be {:?} but was {:?}",
                    correct, current
                )))
            }
        }

        fn validate_uris(current: &str, correct: &Option<String>) -> errors::Result<()> {
            if correct.is_some() {
                if current == correct.as_ref().unwrap() {
                    Ok(())
                } else {
                    Err(RustKeylockError::GeneralError(format!(
                        "URIs validation failed. Should be {:?} but was {:?}",
                        correct, current
                    )))
                }
            } else {
                Ok(())
            }
        }

        fn handle_request(
            &mut self,
            uri: &str,
            additional_headers: &[(&str, &str)],
        ) -> errors::Result<Vec<u8>> {
            let mut current_headers = self.headers.clone();
            let current_uri = uri.to_owned();
            for (additional_k, additional_v) in additional_headers {
                current_headers.insert(additional_k.to_string(), additional_v.to_string());
            }
            let validation_step =
                self.validation_steps
                    .pop()
                    .ok_or(RustKeylockError::GeneralError(
                        "There are no available responses".to_string(),
                    ))?;
            let response_to_send: Vec<u8> = validation_step.response.iter().cloned().collect();
            Self::validate_headers(&current_headers, &validation_step.headers)
                .and_then(|_| Self::validate_uris(&current_uri, &validation_step.uri))
                .map(|_| response_to_send)
        }
    }

    #[async_trait]
    impl RklHttpAsyncClient for TestHttpClient {
        type ResType = Vec<u8>;

        fn header(&mut self, k: &str, v: &str) {
            self.headers.insert(k.to_string(), v.to_string());
        }

        async fn get(
            &mut self,
            uri: &str,
            additional_headers: &[(&str, &str)],
        ) -> errors::Result<Vec<u8>> {
            self.handle_request(uri, additional_headers)
        }

        async fn post(
            &mut self,
            uri: &str,
            additional_headers: &[(&str, &str)],
            _body: Vec<u8>,
        ) -> errors::Result<Vec<u8>> {
            self.handle_request(uri, additional_headers)
        }
    }
}
