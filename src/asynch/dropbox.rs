use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time;

use base64;
use futures::future::ok;
use http::StatusCode;
use hyper::{self, Body, Request, Response, Server};
use hyper::rt::Future;
use hyper::service::service_fn_ok;
use log::*;
use percent_encoding::{USERINFO_ENCODE_SET, utf8_percent_encode};
use toml;
use toml::value::Table;
use url::Url;

use crate::asynch::SyncStatus;
use crate::datacrypt::{create_random, EntryPasswordCryptor};
use crate::errors;
use crate::SystemConfiguration;

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
    pub fn new(dbc: &DropboxConfiguration,
               sys_conf: &SystemConfiguration,
               tx: Sender<errors::Result<SyncStatus>>,
               f: &str)
               -> errors::Result<Synchronizer> {
        let dbc = DropboxConfiguration::new(dbc.token.clone())?;
        let s = Synchronizer {
            conf: dbc,
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
}

impl super::AsyncTask for Synchronizer {
    fn init(&mut self) {}

    fn execute(&self) -> Box<dyn Future<Item=bool, Error=()> + Send> {
        Box::new(ok(true))
    }
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
        format!("https://www.dropbox.com/1/oauth2/authorize?client_id=7git6ovjwtdbfvm&response_type=token&redirect_uri=http://localhost:8899&state={}", random_string)
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

    thread::spawn(move || {
        let (port, state) = parse_url(url_string).unwrap();

        let s = || {
            service_fn_ok(|req: Request<Body>| {
                let mut resp_builder = Response::builder();

                if req.method() == &hyper::Method::GET {
                    resp_builder.status(StatusCode::OK);
                    resp_builder.body(Body::empty()).unwrap()
                } else {
                    resp_builder.status(StatusCode::BAD_REQUEST);
                    resp_builder.body(Body::empty()).unwrap()
                }
            })
        };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        let server = Server::bind(&addr)
            .serve(s)
            .map_err(|e| {
                error!("Cannot start an HTTP server to retrieve the Dropbox token: {}", e)
            });

        hyper::rt::run(server);
    });

    let timeout = time::Duration::from_millis(10);
    Ok("".to_string())
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
            state = pair.1.to_string();
        }
    }

    if !redirect_url_string.is_empty() {
        let redirect_url = Url::parse(&redirect_url_string)?;
        port = redirect_url.port().unwrap_or(8899);
    }

    Ok((port, state))
}

#[cfg(test)]
mod dropbox_tests {
    use super::*;

    #[test]
    fn dbx_url() {
        dbg!(DropboxConfiguration::dropbox_url());
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
}
