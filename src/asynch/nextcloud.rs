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

use std::io::prelude::*;
use std::str::FromStr;
use std::sync::mpsc::Sender;

use base64;
use futures::future::{err, FutureResult, ok, result};
use http::StatusCode;
use hyper::{self, Body, Client, Request, Response};
use hyper::header;
use hyper::rt::{Future, Stream};
use hyper_tls::HttpsConnector;
use log::*;
use toml;
use toml::value::Table;
use xml::reader::{EventReader, XmlEvent};

use crate::{errors, file_handler};
use crate::datacrypt::EntryPasswordCryptor;
use crate::errors::{debug_error_string, RustKeylockError};
use crate::SystemConfiguration;
use crate::asynch::SyncStatus;

/// A (Next/Own)cloud synchronizer
pub struct Synchronizer {
    /// The configuration needed for this synchronizer
    conf: NextcloudConfiguration,
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
    pub fn new(ncc: &NextcloudConfiguration,
               sys_conf: &SystemConfiguration,
               tx: Sender<errors::Result<SyncStatus>>,
               f: &str)
               -> errors::Result<Synchronizer> {
        let ncc = NextcloudConfiguration::new(ncc.server_url.clone(),
                                              ncc.username.clone(),
                                              ncc.decrypted_password()?,
                                              ncc.use_self_signed_certificate)?;
        let s = Synchronizer {
            conf: ncc,
            tx,
            file_name: f.to_string(),
            saved_at_local: sys_conf.saved_at,
            version_local: sys_conf.version,
            last_sync_version: sys_conf.last_sync_version,
        };
        Ok(s)
    }

    /// Returns the password decrypted
    fn use_password(&self) -> errors::Result<String> {
        self.conf.decrypted_password()
    }

    fn do_request(req: Request<Body>, is_not_https: bool, use_self_signed: bool) -> impl Future<Item=Response<Body>, Error=RustKeylockError> {
        if is_not_https {
            // Use HTTP
            let client = Client::new();

            client.request(req).from_err()
        } else if use_self_signed {
            // Use HTTPS with a self signed certificate
            let mut self_signed_cert_path = file_handler::create_certs_path().expect("Could not create the certificates directory");
            self_signed_cert_path.push("cacert.pem");
            ::std::env::set_var("SSL_CERT_FILE", self_signed_cert_path.to_str().unwrap());
            let client = Client::builder().build(HttpsConnector::new(1).unwrap());

            client.request(req).from_err()
        } else {
            // Use HTTPS
            let connector = HttpsConnector::new(1).expect("Could not create Https Connector");
            let client = Client::builder().build(connector);
            client.request(req).from_err()
        }
    }

    fn to_status_and_body(response: Response<Body>) -> impl Future<Item=(StatusCode, Vec<u8>), Error=RustKeylockError> {
        let status = response.status().clone();
        // Create a Future from the Stream of the Body
        response.into_body().concat2()
            .map_err(|error| RustKeylockError::SyncError(debug_error_string(error)))
            .map(move |chunk| {
                let body: Vec<u8> = chunk.to_vec();
                (status, body)
            })
    }

    fn do_execute(capsule: ArgsCapsule) -> impl Future<Item=SyncStatus, Error=RustKeylockError> {
        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", capsule.server_url(), capsule.username(), capsule.file_name());
        debug!("Syncing with {}", uri);

        // Set the body of the request so that it returns the oc:rklsavedat and oc:rklversion properties
        let xml_body = r#"<d:propfind xmlns:d="DAV:"><d:prop xmlns:oc="http://owncloud.org/ns"><oc:rklsavedat/><oc:rklversion/></d:prop></d:propfind>"#;
        let mut req_builder = Request::builder();
        let req_res = req_builder
            .method("PROPFIND")
            .uri(uri)
            .extension("PROPFIND")
            .header(header::AUTHORIZATION, basic_auth(capsule.username().as_ref(), capsule.password().as_ref()))
            .body(Body::from(xml_body.as_bytes()))
            .map_err(|error| RustKeylockError::SyncError(debug_error_string(error)));

        let cloned_capsule = capsule.clone();
        result(req_res)
            // Do the request
            .and_then(move |req| Self::do_request(req, cloned_capsule.is_not_https(), cloned_capsule.use_self_signed()))
            .and_then(|res| Self::to_status_and_body(res))
            // Handle the response
            .and_then(move |(status, body)| {
                Self::match_propfind_status(status, body, capsule)
            })
    }

    fn match_propfind_status(http_status: hyper::StatusCode, body: Vec<u8>, capsule: ArgsCapsule) -> Box<dyn Future<Item=SyncStatus, Error=RustKeylockError> + Send> {
        match http_status {
            hyper::StatusCode::NOT_FOUND => {
                if capsule.version_local.is_some() {
                    info!("Creating rust-keylock-resources on the server");
                    let f = Self::create_rust_keylock_col(&capsule.username,
                                                          capsule.password(),
                                                          &capsule.server_url,
                                                          capsule.is_not_https(),
                                                          capsule.use_self_signed())
                        .and_then(move |_| Self::put(capsule.username(),
                                                     capsule.password(),
                                                     capsule.server_url(),
                                                     capsule.file_name(),
                                                     capsule.saved_at_local(),
                                                     capsule.version_local(),
                                                     capsule.is_not_https(),
                                                     capsule.use_self_signed()))
                        .and_then(|_| ok(SyncStatus::UploadSuccess("nextcloud")));

                    Box::new(f)
                } else {
                    debug!("Resources not found on the server, but nothing is yet saved locally. Save needs to be performed first.");
                    Box::new(ok(SyncStatus::None).and_then(|_| ok(SyncStatus::None)))
                }
            }
            hyper::StatusCode::MULTI_STATUS => {
                debug!("Parsing nextcoud response");
                let parse_web_dav_resp_res = Self::parse_xml(body.as_slice(), &capsule.file_name)
                    .and_then(|web_dav_resp| Self::parse_web_dav_response(&web_dav_resp,
                                                                          &capsule.file_name,
                                                                          &capsule.saved_at_local,
                                                                          &capsule.version_local,
                                                                          &capsule.last_sync_version));
                let f = result(parse_web_dav_resp_res)
                    .and_then(|parse_web_dav_resp| Self::parse_multi_status_response(parse_web_dav_resp, capsule));

                Box::new(f)
            }
            other => {
                Box::new(err(RustKeylockError::SyncError(format!("Cannot handle status {:?} while handling propfind response", other))))
            }
        }
    }

    fn parse_multi_status_response(parse_web_dav_resp: ParseWebDavResponse, capsule: ArgsCapsule) -> Box<dyn Future<Item=SyncStatus, Error=RustKeylockError> + Send> {
        match parse_web_dav_resp {
            ParseWebDavResponse::Download => {
                info!("Downloading file from the server");
                Box::new(Self::get(&capsule.username,
                                   capsule.password(),
                                   &capsule.server_url,
                                   &capsule.file_name,
                                   capsule.is_not_https,
                                   capsule.use_self_signed)
                    .and_then(|tmp_file_name| ok(SyncStatus::NewAvailable("nextcloud", tmp_file_name))))
            }
            ParseWebDavResponse::Ignore => {
                debug!("No sync is needed");
                Box::new(ok(SyncStatus::None))
            }
            ParseWebDavResponse::Upload => {
                info!("Uploading file on the server");
                Box::new(Self::put(capsule.username(),
                                   capsule.password(),
                                   capsule.server_url(),
                                   capsule.file_name(),
                                   capsule.saved_at_local(),
                                   capsule.version_local(),
                                   capsule.is_not_https(),
                                   capsule.use_self_signed())
                    .and_then(|_| ok(SyncStatus::UploadSuccess("nextcloud"))))
            }
            ParseWebDavResponse::DownloadMergeAndUpload => {
                Box::new(Self::get(&capsule.username,
                                   capsule.password(),
                                   &capsule.server_url,
                                   &capsule.file_name,
                                   capsule.is_not_https,
                                   capsule.use_self_signed)
                    .and_then(|tmp_file_name| ok(SyncStatus::NewToMerge("nextcloud", tmp_file_name))))
            }
        }
    }

    /// Returns the action that should be taken after parsing a Webdav response
    ///
    /// ## Algorithm:
    ///
    /// |           version_local        |       version_server     |     last_sync_version    |          Action
    /// | :---------------------------:  | :----------------------: | :----------------------: | :------------------------:
    /// | bigger than server             | smaller than local       | *                        | Upload
    /// | smaller than server            | bigger than local        | smaller than server      | Download
    /// | smaller than server            | bigger than local        | smaller than local       | Download and Megre
    /// | same everywhere                | same everywhere          | same everywhere          | Ignore
    /// | smaller than last_sync_version | *                        | bigger than local        | Ignore (Error)

    fn parse_web_dav_response(web_dav_response: &WebDavResponse,
                              filename: &str,
                              saved_at_local: &Option<i64>,
                              version_local: &Option<i64>,
                              last_sync_version: &Option<i64>)
                              -> errors::Result<ParseWebDavResponse> {
        debug!("The file '{}' on the server was saved at {} with version {}",
               filename,
               web_dav_response.last_modified,
               web_dav_response.version);
        let version_server = i64::from_str(&web_dav_response.version)?;

        debug!("The file '{}' locally was saved at {:?} with version {:?}. Last sync version is {:?}",
               filename,
               saved_at_local,
               version_local,
               last_sync_version);

        match (version_local, version_server, last_sync_version) {
            (&Some(vl), vs, _) if vl > vs => {
                debug!("The local version is bigger than the server. Need to upload");
                Ok(ParseWebDavResponse::Upload)
            }
            (&Some(vl), vs, &Some(lsv)) if vl < vs && vl == lsv => {
                debug!("The local version is smaller than the server and the last sync version is smaller than the server. Need to \
                            download");
                Ok(ParseWebDavResponse::Download)
            }
            (&Some(vl), vs, &Some(lsv)) if vl < vs && lsv < vl => {
                debug!("The local version is smaller than the server and the last sync version is smaller than the local. Need to \
                            download and merge");
                Ok(ParseWebDavResponse::DownloadMergeAndUpload)
            }
            (&Some(vl), vs, &Some(lsv)) if vl == vs && vs == lsv => {
                debug!("The versions locally and on the server are equal. Ignoring...");
                Ok(ParseWebDavResponse::Ignore)
            }
            (&None, _, _) => {
                debug!("First time contacting the server... Need to download");
                Ok(ParseWebDavResponse::Download)
            }
            (_, _, _) => Ok(ParseWebDavResponse::Ignore),
        }
    }

    fn parse_xml(bytes: &[u8], filename: &str) -> errors::Result<WebDavResponse> {
        let parser = EventReader::new(bytes);

        // The current element that is being parsed
        let mut curr_elem_name = "".to_string();
        // The data of the element that we are interested in
        let mut web_dav_resp = WebDavResponse {
            href: "".to_string(),
            last_modified: "".to_string(),
            version: "".to_string(),
            status: "".to_string(),
        };
        let mut web_dav_resp_result: errors::Result<WebDavResponse> =
            Err(errors::RustKeylockError::ParseError("Could not parse WebDav response. The required elements could not be found."
                .to_string()));

        for elem in parser {
            match elem {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    curr_elem_name = name.to_string();
                }
                Ok(XmlEvent::Characters(string)) => {
                    debug!("Parsing element {} that has characters {}", curr_elem_name, string);
                    match curr_elem_name.as_ref() {
                        "{DAV:}d:href" => web_dav_resp.href = string,
                        "{http://owncloud.org/ns}oc:rklsavedat" => web_dav_resp.last_modified = string,
                        "{http://owncloud.org/ns}oc:rklversion" => web_dav_resp.version = string,
                        "{DAV:}d:status" => web_dav_resp.status = string,
                        _ => {
                            // ignore
                        }
                    }
                }
                Ok(XmlEvent::EndElement { name, .. }) => {
                    if name.to_string() == "{DAV:}d:response" {
                        // Check if the file is the one where the passwords are stored and that the gathered data are all present
                        if web_dav_resp.href.ends_with(filename) && web_dav_resp.href != "" && web_dav_resp.last_modified != "" &&
                            web_dav_resp.status != "" && web_dav_resp.version != "" {
                            if web_dav_resp.status.contains("200 OK") {
                                web_dav_resp_result = Ok(web_dav_resp);
                            } else {
                                web_dav_resp_result = Err(errors::RustKeylockError::SyncError(format!("WebDav response for file {} \
                                                                                                           returned {}",
                                                                                                      filename,
                                                                                                      web_dav_resp.status)));
                            }
                            break;
                        }
                    }
                    curr_elem_name = name.to_string();
                }
                Err(error) => {
                    error!("Error while parsing a WebDav response {:?}", error);
                    web_dav_resp_result = Err(errors::RustKeylockError::ParseError(format!("{:?}", error)));
                    break;
                }
                _ => {}
            }
        }

        web_dav_resp_result
    }

    fn create_rust_keylock_col(username: &str,
                               password: String,
                               server_url: &str,
                               is_not_https: bool,
                               use_self_signed: bool) -> impl Future<Item=(), Error=RustKeylockError> {
        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock", server_url, username);
        let mut req_builder = Request::builder();
        let req_res = req_builder
            .uri(uri)
            .extension("MKCOL")
            .method("MKCOL")
            .header(header::AUTHORIZATION, basic_auth(username, password.as_ref()))
            .body(Body::from("".as_bytes()));

        result(req_res)
            .from_err()
            .and_then(move |req| Self::do_request(req, is_not_https, use_self_signed))
            .and_then(|resp| Self::to_status_and_body(resp))
            .and_then(|(status, _)| {
                debug!("Response for creating rust_keylock_col: {}", status);
                if status.is_client_error() || status.is_server_error() {
                    err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
                } else {
                    ok(())
                }
            })
    }

    fn get(username: &str,
           password: String,
           server_url: &str,
           filename: &str,
           is_not_https: bool,
           use_self_signed: bool) -> impl Future<Item=String, Error=RustKeylockError> {
        let tmp_file_name = format!("tmp_{}", filename);
        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", server_url, username, filename);
        let mut req_builder = Request::get(uri);
        let req_res = req_builder
            .header(header::AUTHORIZATION, basic_auth(username, password.as_ref()))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from("".as_bytes()));

        result(req_res)
            .from_err()
            .and_then(move |req| Self::do_request(req, is_not_https, use_self_signed))
            .and_then(|resp| Self::to_status_and_body(resp))
            .and_then(move |(status, body)| {
                debug!("Response for GET: {}", status);
                let res = {
                    if status.is_client_error() || status.is_server_error() {
                        Err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
                    } else {
                        file_handler::save_bytes(&tmp_file_name, &body, false).map(|_| tmp_file_name)
                    }
                };

                FutureResult::from(res)
            })
    }

    /// Put the file and update the property with the file creation seconds using PROPPATCH
    fn put(username: String,
           password: String,
           server_url: String,
           filename: String,
           local_saved_at: Option<i64>,
           local_version: Option<i64>,
           is_not_https: bool,
           use_self_signed: bool) -> impl Future<Item=(), Error=RustKeylockError> {
        let mut file = file_handler::get_file(&filename).expect(&format!("Could get the file {} while performing HTTP PUT", filename));
        let mut file_bytes: Vec<_> = Vec::new();
        file.read_to_end(&mut file_bytes).expect(&format!("Could not read the file {} while performing HTTP PUT", filename));

        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", server_url, username, filename);
        let mut req_builder = Request::put(uri);
        let req_res = req_builder
            .header(header::AUTHORIZATION, basic_auth(&username, password.as_ref()))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(file_bytes));

        result(req_res)
            .from_err()
            .and_then(move |req| Self::do_request(req, is_not_https, use_self_signed))
            .and_then(|resp| Self::to_status_and_body(resp))
            .and_then(|(status, _)| {
                debug!("Response for PUT: {}", status);
                let res = {
                    if status.is_client_error() || status.is_server_error() {
                        Err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
                    } else {
                        Ok(())
                    }
                };

                result(res)
            })
            .and_then(move |_| {
                // PROPPATCH starts here
                let xml_body: String = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:set>
<d:prop>
  <oc:rklsavedat>{}</oc:rklsavedat>
  <oc:rklversion>{}</oc:rklversion>
</d:prop>
</d:set>
</d:propertyupdate>"#,
                                               local_saved_at.map(|s| s.to_string()).unwrap_or("".to_string()),
                                               local_version.map(|s| s.to_string()).unwrap_or("".to_string()));

                let uri_pp = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", server_url, username, filename);
                let mut req_builder = Request::builder();
                let req_pp_res = req_builder
                    .uri(uri_pp)
                    .extension("PROPPATCH")
                    .method("PROPPATCH")
                    .header(header::AUTHORIZATION, basic_auth(&username, password.as_ref()))
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(Body::from(xml_body))
                    .map_err(|error| errors::RustKeylockError::SyncError(format!("{:?}", error)));

                result(req_pp_res)
            })
            .and_then(move |req| Self::do_request(req, is_not_https, use_self_signed))
            .and_then(|resp| Self::to_status_and_body(resp))
            .and_then(move |(status, _)| {
                debug!("Response for PROPPATCH: {}", status);
                let res = {
                    if status.is_client_error() || status.is_server_error() {
                        Err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
                    } else {
                        Ok(())
                    }
                };

                FutureResult::from(res)
            })
    }

    fn send_to_channel(res: errors::Result<SyncStatus>, tx: Sender<errors::Result<SyncStatus>>) {
        match &res {
            &Ok(ref r) => debug!("Nextcloud Async Task sends to the channel {:?}", r),
            &Err(ref error) => error!("Nextcloud Async Tasks reported error: {:?}", error),
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

    fn execute(&self) -> Box<dyn Future<Item=(), Error=()> + Send> {
        let capsule = ArgsCapsule::new(
            self.conf.server_url.clone(),
            self.conf.username.clone(),
            self.file_name.clone(),
            self.use_password().expect("Could not retrieve the password for the nextcloud server"),
            self.conf.server_url.starts_with("http://"),
            self.conf.use_self_signed_certificate,
            self.saved_at_local,
            self.version_local,
            self.last_sync_version,
        );

        let cloned_tx_ok = self.tx.clone();
        let cloned_tx_err = self.tx.clone();

        let f = Self::do_execute(capsule)
            .map(move |sync_status| Self::send_to_channel(Ok(sync_status), cloned_tx_ok))
            .map_err(move |error| Self::send_to_channel(Err(error), cloned_tx_err));

        Box::new(f)
    }
}

#[derive(PartialEq, Debug)]
enum ParseWebDavResponse {
    Download,
    Upload,
    Ignore,
    DownloadMergeAndUpload,
}

/// The configuration that is retrieved from the rust-keylock encrypted file
#[derive(Debug, PartialEq, Clone)]
pub struct NextcloudConfiguration {
    /// The server base URL (eg. https://my.nextcloud.server/nextcloud)
    pub server_url: String,
    /// The username of a nextcoud account
    pub username: String,
    /// The password of a nextcoud account
    password: String,
    password_cryptor: EntryPasswordCryptor,
    /// If a self-signed certificate is needed in order to communicate with the Nextcloud server over HTTPS,
    /// this boolean should be true. In that case, the application will use the certificate __cacert.pem__ located in
    /// `$HOME/.rust-keylock/etc/ssl/certs` and in `/sdcard/Download/rust-keylock/etc/ssl/certs` for Android devices.
    /// The user is responsible to place the self-signed .pem file into this location with this exact name.
    pub use_self_signed_certificate: bool,
}

impl NextcloudConfiguration {
    /// Creates a new NextcloudConfiguration
    pub fn new(u: String, un: String, pw: String, use_self_signed_certificate: bool) -> errors::Result<NextcloudConfiguration> {
        let mut s = NextcloudConfiguration {
            username: un,
            password: "".to_string(),
            password_cryptor: EntryPasswordCryptor::new(),
            server_url: u.to_string(),
            use_self_signed_certificate: use_self_signed_certificate,
        };
        s.password = s.password_cryptor.encrypt_str(&pw)?;
        Ok(s)
    }

    pub fn decrypted_password(&self) -> errors::Result<String> {
        self.password_cryptor.decrypt_str(&self.password)
    }

    /// Creates a TOML table form this NextcloudConfiguration. The resulted table contains the decrypted password.
    pub fn to_table(&self) -> errors::Result<Table> {
        let mut table = Table::new();
        table.insert("url".to_string(), toml::Value::String(self.server_url.clone()));
        table.insert("user".to_string(), toml::Value::String(self.username.clone()));
        table.insert("pass".to_string(), toml::Value::String(self.decrypted_password()?));
        table.insert("use_self_signed_certificate".to_string(), toml::Value::Boolean(self.use_self_signed_certificate));

        Ok(table)
    }

    /// Creates a NextcloudConfiguration from a TOML table. The password gets encrypted once the `new` function is called.
    pub fn from_table(table: &Table) -> Result<NextcloudConfiguration, errors::RustKeylockError> {
        let url = table.get("url").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let user = table.get("user").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let pass = table.get("pass").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let use_self_signed_certificate = table.get("use_self_signed_certificate")
            .and_then(|value| value.as_bool().and_then(|bool_ref| Some(bool_ref)));
        match (url, user, pass, use_self_signed_certificate) {
            (Some(ul), Some(u), Some(p), Some(ssc)) => NextcloudConfiguration::new(ul, u, p, ssc),
            _ => Err(errors::RustKeylockError::ParseError(toml::ser::to_string(&table).unwrap_or("Cannot deserialize toml".to_string()))),
        }
    }

    /// Returns true is the configuration contains the needed values to operate correctly
    pub fn is_filled(&self) -> bool {
        let dp = self.decrypted_password();
        (dp.is_ok() && dp.unwrap() != "") && self.server_url != "" && self.username != ""
    }
}

impl Default for NextcloudConfiguration {
    fn default() -> NextcloudConfiguration {
        NextcloudConfiguration {
            username: "".to_string(),
            password: "".to_string(),
            password_cryptor: EntryPasswordCryptor::new(),
            server_url: "".to_string(),
            use_self_signed_certificate: false,
        }
    }
}

#[derive(Debug)]
struct WebDavResponse {
    href: String,
    last_modified: String,
    version: String,
    status: String,
}

fn basic_auth(username: &str, password: &str) -> String {
    let encoded = base64::encode(&format!("{}:{}", username, password));
    format!("Basic {}", encoded)
}

/// Convenience struct to use during function calls
#[derive(Clone)]
struct ArgsCapsule {
    server_url: String,
    username: String,
    file_name: String,
    password: String,
    is_not_https: bool,
    use_self_signed: bool,
    saved_at_local: Option<i64>,
    version_local: Option<i64>,
    last_sync_version: Option<i64>,
}

impl ArgsCapsule {
    pub fn new(server_url: String,
               username: String,
               file_name: String,
               password: String,
               is_not_https: bool,
               use_self_signed: bool,
               saved_at_local: Option<i64>,
               version_local: Option<i64>,
               last_sync_version: Option<i64>) -> ArgsCapsule {
        ArgsCapsule {
            server_url,
            username,
            file_name,
            password,
            is_not_https,
            use_self_signed,
            saved_at_local,
            version_local,
            last_sync_version,
        }
    }

    fn server_url(&self) -> String {
        self.server_url.clone()
    }

    fn username(&self) -> String {
        self.username.clone()
    }

    fn file_name(&self) -> String {
        self.file_name.clone()
    }

    fn password(&self) -> String {
        self.password.clone()
    }

    fn is_not_https(&self) -> bool {
        self.is_not_https
    }

    fn use_self_signed(&self) -> bool {
        self.use_self_signed
    }

    fn saved_at_local(&self) -> Option<i64> {
        self.saved_at_local
    }

    fn version_local(&self) -> Option<i64> {
        self.version_local
    }

    #[allow(dead_code)]
    fn last_sync_version(&self) -> Option<i64> {
        self.last_sync_version
    }
}

#[cfg(test)]
mod nextcloud_tests {
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use std::fs;
    use std::fs::File;
    use std::io::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::Mutex;
    use std::thread;
    use std::time;
    use tokio;
    use tokio::prelude::future::{lazy, ok};

    use hyper::{self, Body, Request, Response, Server, StatusCode};
    use hyper::rt::Future;
    use hyper::service::service_fn_ok;
    use toml;

    use super::super::AsyncTask;
    use super::super::super::{errors, file_handler, SystemConfiguration};

    lazy_static! {
        static ref TXMAP: Mutex < HashMap < String, Sender < bool > > > = Mutex::new(HashMap::new());
    }

    fn get_tx_for(command: &str) -> Sender<bool> {
        let map = TXMAP.lock().unwrap();
        let tx_ref = map.get(&command.to_string()).unwrap();
        tx_ref.clone()
    }

    fn set_tx_for(command: &str, tx: Sender<bool>) {
        let mut map = TXMAP.lock().unwrap();
        (*map).insert(command.to_string(), tx);
    }

    #[test]
    fn synchronizer_stores_encrypted_password() {
        let password = "password".to_string();
        let (tx, _rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc =
            super::NextcloudConfiguration::new("https://localhost/nextcloud".to_string(), "username".to_string(), password.clone(), false)
                .unwrap();
        let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, "filename").unwrap();

        assert!(nc.conf.decrypted_password().unwrap() == password)
    }

    #[test]
    fn nextcloud_configuration_stores_encrypted_password() {
        let password = "password".to_string();
        let ncc =
            super::NextcloudConfiguration::new("https://localhost/nextcloud".to_string(), "username".to_string(), password.clone(), false)
                .unwrap();

        assert!(ncc.password != password)
    }

    #[test]
    fn nextcloud_configuration_to_table() {
        let toml = r#"
                url = "http://a/url"
                user = "user1"
                pass = "123"
                use_self_signed_certificate = true
            "#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let ncc_res = super::NextcloudConfiguration::from_table(&table);
        assert!(ncc_res.is_ok());
        let ncc = ncc_res.unwrap();
        let new_table = ncc.to_table().unwrap();
        assert!(table == &new_table);
    }

    #[test]
    fn nextcloud_configuration_from_table_success() {
        let toml = r#"
                url = "http://a/url"
                user = "user1"
                pass = "123"
                use_self_signed_certificate = true
            "#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let ncc_res = super::NextcloudConfiguration::from_table(&table);
        assert!(ncc_res.is_ok());
        let ncc = ncc_res.unwrap();
        assert!(ncc.server_url == "http://a/url");
        assert!(ncc.username == "user1");
        // The password is encrypted
        assert!(ncc.password != "123");
        assert!(ncc.use_self_signed_certificate);
    }

    #[test]
    fn nextcloud_configuration_is_filled() {
        let ncc1 = super::NextcloudConfiguration::new("https://localhost/nextcloud".to_string(),
                                                      "username".to_string(),
                                                      "password".to_string(),
                                                      false)
            .unwrap();
        assert!(ncc1.is_filled());
        let ncc2 = super::NextcloudConfiguration::default();
        assert!(!ncc2.is_filled());
    }

    #[test]
    fn create_file_if_collection_not_exists() {
        // Create a dummy file
        let filename = "filename";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        set_tx_for("run_col_not_exists", tx_assert);
        thread::spawn(move || {
            start_web_dav_server("run_col_not_exists", 8080);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8080".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();

        thread::spawn(move || {
            tokio::run(lazy(move || {
                let sys_config = SystemConfiguration::new(Some(123), Some(1), None);
                let nc = super::Synchronizer::new(&ncc, &sys_config, tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(10000000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the MKCOL that creates the collection
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the PUT that creates the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the PROPPATCH for the oc:rklsavedat and oc:rklversion
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that the file is ready to be downloaded
        assert!(rx.recv_timeout(timeout).unwrap().unwrap() == super::SyncStatus::UploadSuccess("nextcloud"));

        // Delete the dummy file
        delete_file(filename);
    }

    #[test]
    fn download_a_file_from_the_server() {
        // Create a dummy file
        let filename = "download_a_file_from_the_server";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        set_tx_for("run_download_a_file_from_the_server", tx_assert);
        thread::spawn(move || {
            start_web_dav_server("run_download_a_file_from_the_server", 8081);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8081".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();

        thread::spawn(move || {
            tokio::run(lazy(move || {
                let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the Get that downlaods the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that the file is ready to be downloaded
        assert!(rx.recv_timeout(timeout).unwrap().unwrap() ==
            super::SyncStatus::NewAvailable("nextcloud", "tmp_download_a_file_from_the_server".to_string()));

        // Delete the dummy file
        delete_file(filename);
        delete_file("tmp_download_a_file_from_the_server");
    }

    #[test]
    fn http_error_response_on_propfind() {
        // Create a dummy file
        let filename = "http_error_response_on_propfind";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        set_tx_for("run_http_error_response_on_propfind", tx_assert);
        thread::spawn(move || {
            start_web_dav_server("run_http_error_response_on_propfind", 8082);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8082".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();
        thread::spawn(move || {
            tokio::run(lazy(move || {
                let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        delete_file(filename);
    }

    #[test]
    fn http_error_response_on_mkcol() {
        // Create a dummy file
        let filename = "http_error_response_on_mkcol";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        set_tx_for("run_http_error_response_on_mkcol", tx_assert);
        thread::spawn(move || {
            start_web_dav_server("run_http_error_response_on_mkcol", 8083);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8083".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1), None);

        thread::spawn(move || {
            tokio::run(lazy(move || {
                let nc = super::Synchronizer::new(&ncc, &sys_config, tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the MKCOL that creates the collection
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        delete_file(filename);
    }

    #[test]
    fn http_error_response_on_put() {
        // Create a dummy file
        let filename = "http_error_response_on_put";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        set_tx_for("run_http_error_response_on_put", tx_assert);
        thread::spawn(move || {
            start_web_dav_server("run_http_error_response_on_put", 8084);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8084".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1), None);

        thread::spawn(move || {
            tokio::run(lazy(move || {
                let nc = super::Synchronizer::new(&ncc, &sys_config, tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the MKCOL that creates the collection
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the put that creates a new file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        delete_file(filename);
    }

    #[test]
    fn http_error_response_on_get() {
        // Create a dummy file
        let filename = "http_error_response_on_get";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        set_tx_for("run_http_error_response_on_get", tx_assert);
        thread::spawn(move || {
            start_web_dav_server("run_http_error_response_on_get", 8085);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8085".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();
        thread::spawn(move || {
            tokio::run(lazy(move || {
                let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the Get that downlaods the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        delete_file(filename);
    }

    #[test]
    fn server_not_found() {
        // Create a dummy file
        let filename = "server_not_found";
        create_file_with_contents(filename, "This is a test file");

        // Do not start the HTTP server
        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1".to_string(), "username".to_string(), password.clone(), false)
            .unwrap();
        thread::spawn(move || {
            tokio::run(lazy(move || {
                let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
                tokio::spawn(nc.execute());
                ok(())
            }));
        });

        let timeout = time::Duration::from_millis(1000000);

        let stat = rx.recv_timeout(timeout).unwrap();
        // Assert that the file is ready to be downloaded
        assert!(stat.is_err());

        // Delete the dummy file
        delete_file(filename);
    }

    #[test]
    fn parse_xml_success() {
        let filename = "afilename";
        let xml = format!(r#"
                <?xml version="1.0"?>
                <d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
                 <d:response>
                  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/{}</d:href>
                  <d:propstat>
                   <d:prop>
                    <oc:rklsavedat>1234567</oc:rklsavedat>
                    <oc:rklversion>1</oc:rklversion>
                   </d:prop>
                   <d:status>HTTP/1.1 200 OK</d:status>
                  </d:propstat>
                 </d:response>
                </d:multistatus>
            "#, filename);

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().href == "/nextcloud/remote.php/dav/files/user/.rust-keylock/afilename");
        assert!(res.as_ref().unwrap().last_modified == "1234567");
        assert!(res.as_ref().unwrap().status == "HTTP/1.1 200 OK");
        assert!(res.as_ref().unwrap().version == "1");
    }

    #[test]
    fn parse_xml_error_no_file_is_present() {
        let filename = "afilename";
        // The file element is not present
        let xml = r#"
                <?xml version="1.0"?>
                <d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
                 <d:response>
                  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/</d:href>
                  <d:propstat>
                   <d:prop>
                    <d:getlastmodified>Thu, 30 Nov 2017 14:09:58 GMT</d:getlastmodified>
                    <d:resourcetype>
                     <d:collection/>
                    </d:resourcetype>
                    <d:quota-used-bytes>205</d:quota-used-bytes>
                    <d:quota-available-bytes>-3</d:quota-available-bytes>
                    <d:getetag>&quot;5a201136966e1&quot;</d:getetag>
                   </d:prop>
                   <d:status>HTTP/1.1 200 OK</d:status>
                  </d:propstat>
                 </d:response>
                </d:multistatus>
            "#;

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_err());
    }

    #[test]
    fn parse_xml_error_not_all_elements_are_present() {
        let filename = "afilename";
        // The oc:rklsavedat element is not present
        let xml = format!(r#"
                <?xml version="1.0"?>
                <d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
                 <d:response>
                  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/{}</d:href>
                  <d:propstat>
                   <d:prop>
                   </d:prop>
                   <d:status>HTTP/1.1 200 OK</d:status>
                  </d:propstat>
                 </d:response>
                </d:multistatus>
            "#, filename);

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_err());
    }

    #[test]
    fn parse_xml_error_in_web_dav_response() {
        let filename = "afilename";
        let xml = format!(r#"
                <?xml version="1.0"?>
                <d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
                 <d:response>
                  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/{}</d:href>
                  <d:propstat>
                   <d:prop>
                    <oc:rklsavedat>1234567</oc:rklsavedat>
                    <oc:rklversion>1</oc:rklversion>
                   </d:prop>
                   <d:status>HTTP/1.1 400 Bad Request</d:status>
                  </d:propstat>
                 </d:response>
                </d:multistatus>
            "#, filename);

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_err());
    }

    #[test]
    fn parse_web_dav_response() {
        let filename = "parse_web_dav_response";
        create_file_with_contents(filename, "This is a test file");

        // Upload because version_local is bigger than version_server
        let wdr1 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "1".to_string(),
            status: "not needed".to_string(),
        };
        let res1 = super::Synchronizer::parse_web_dav_response(&wdr1, filename, &Some(133), &Some(2), &Some(2));
        assert!(res1.is_ok());
        assert!(res1.as_ref().unwrap() == &super::ParseWebDavResponse::Upload);

        // Download because version_server is bigger than version_local
        let wdr2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "2".to_string(),
            status: "not needed".to_string(),
        };
        let res2 = super::Synchronizer::parse_web_dav_response(&wdr2, filename, &Some(133), &Some(1), &Some(1));
        assert!(res2.is_ok());
        assert!(res2.as_ref().unwrap() == &super::ParseWebDavResponse::Download);

        // Download and Merge because of version_server is bigger than version_local and last_sync_version is smaller than the version_local
        let wdr2_2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "3".to_string(),
            status: "not needed".to_string(),
        };
        let res2_2 = super::Synchronizer::parse_web_dav_response(&wdr2_2, filename, &Some(133), &Some(2), &Some(1));
        assert!(res2_2.is_ok());
        assert!(res2_2.as_ref().unwrap() == &super::ParseWebDavResponse::DownloadMergeAndUpload);

        // Ignore when all versions are equal
        let wdr3 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "3".to_string(),
            status: "not needed".to_string(),
        };
        let res3 = super::Synchronizer::parse_web_dav_response(&wdr3, filename, &Some(133), &Some(3), &Some(3));
        assert!(res3.is_ok());
        assert!(res3.as_ref().unwrap() == &super::ParseWebDavResponse::Ignore);

        // Ignore when error (the last_sync_version is bigger than the version_local)
        let wdr3 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "3".to_string(),
            status: "not needed".to_string(),
        };
        let res3 = super::Synchronizer::parse_web_dav_response(&wdr3, filename, &Some(133), &Some(1), &Some(3));
        assert!(res3.is_ok());
        assert!(res3.as_ref().unwrap() == &super::ParseWebDavResponse::Ignore);

        delete_file(filename);
    }

    fn start_web_dav_server(command: &'static str, port: u16) {
        match command {
            "run_col_not_exists" => {
                let s = || {
                    service_fn_ok(|req: Request<Body>| {
                        let tx_assert = get_tx_for("run_col_not_exists");
                        let mut resp_builder = Response::builder();

                        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::NOT_FOUND);
                            resp_builder.body(Body::empty()).unwrap()
                        } else if req.method() == &hyper::Method::from_bytes("MKCOL".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::OK);
                            resp_builder.body(Body::empty()).unwrap()
                        } else if req.method() == &hyper::Method::PUT {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::OK);
                            resp_builder.body(Body::empty()).unwrap()
                        } else if req.method() == &hyper::Method::from_bytes("PROPPATCH".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::OK);
                            resp_builder.body(Body::empty()).unwrap()
                        } else {
                            let _ = tx_assert.send(false);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        }
                    })
                };
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                let server = Server::bind(&addr)
                    .serve(s)
                    .map_err(|e| eprintln!("server error: {}", e));

                hyper::rt::run(server);
            }
            "run_download_a_file_from_the_server" => {
                let s = || {
                    service_fn_ok(|req: Request<Body>| {
                        let tx_assert = get_tx_for("run_download_a_file_from_the_server");
                        let mut resp_builder = Response::builder();

                        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            let xml = r#"
                        <?xml version="1.0"?>
                        <d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
                         <d:response>
                          <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/download_a_file_from_the_server</d:href>
                          <d:propstat>
                           <d:prop>
                            <oc:rklsavedat>4667760000</oc:rklsavedat>
                            <oc:rklversion>1</oc:rklversion>
                           </d:prop>
                           <d:status>HTTP/1.1 200 OK</d:status>
                          </d:propstat>
                         </d:response>
                        </d:multistatus>
                    "#;
                            resp_builder.status(StatusCode::MULTI_STATUS);
                            resp_builder.body(Body::from(xml)).unwrap()
                        } else if req.method() == &hyper::Method::GET {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::MULTI_STATUS);
                            resp_builder.body(Body::from("This is a file from the server")).unwrap()
                        } else {
                            let _ = tx_assert.send(false);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        }
                    })
                };
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                let server = Server::bind(&addr)
                    .serve(s)
                    .map_err(|e| println!("server error: {}", e));

                hyper::rt::run(server);
            }
            "run_http_error_response_on_propfind" => {
                let s = || {
                    service_fn_ok(|req: Request<Body>| {
                        let tx_assert = get_tx_for("run_http_error_response_on_propfind");
                        let mut resp_builder = Response::builder();

                        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                        }
                        resp_builder.status(StatusCode::BAD_REQUEST);
                        resp_builder.body(Body::empty()).unwrap()
                    })
                };
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                let server = Server::bind(&addr)
                    .serve(s)
                    .map_err(|e| println!("server error: {}", e));

                hyper::rt::run(server);
            }
            "run_http_error_response_on_mkcol" => {
                let s = || {
                    service_fn_ok(|req: Request<Body>| {
                        let tx_assert = get_tx_for("run_http_error_response_on_mkcol");
                        let mut resp_builder = Response::builder();

                        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::NOT_FOUND);
                            resp_builder.body(Body::empty()).unwrap()
                        } else if req.method() == &hyper::Method::from_bytes("MKCOL".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        } else {
                            let _ = tx_assert.send(false);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        }
                    })
                };
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                let server = Server::bind(&addr)
                    .serve(s)
                    .map_err(|e| println!("server error: {}", e));

                hyper::rt::run(server);
            }
            "run_http_error_response_on_put" => {
                let s = || {
                    service_fn_ok(|req: Request<Body>| {
                        let tx_assert = get_tx_for("run_http_error_response_on_put");
                        let mut resp_builder = Response::builder();

                        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::NOT_FOUND);
                            resp_builder.body(Body::empty()).unwrap()
                        } else if req.method() == &hyper::Method::from_bytes("MKCOL".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::OK);
                            resp_builder.body(Body::empty()).unwrap()
                        } else if req.method() == &hyper::Method::PUT {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        } else {
                            let _ = tx_assert.send(false);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        }
                    })
                };
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                let server = Server::bind(&addr)
                    .serve(s)
                    .map_err(|e| println!("server error: {}", e));

                hyper::rt::run(server);
            }
            "run_http_error_response_on_get" => {
                let s = || {
                    service_fn_ok(|req: Request<Body>| {
                        let tx_assert = get_tx_for("run_http_error_response_on_get");
                        let mut resp_builder = Response::builder();

                        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
                            let _ = tx_assert.send(true);
                            let xml = r#"
                        <?xml version="1.0"?>
                        <d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
                         <d:response>
                          <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/http_error_response_on_get</d:href>
                          <d:propstat>
                           <d:prop>
                            <oc:rklsavedat>4667760000</oc:rklsavedat>
                            <oc:rklversion>1</oc:rklversion>
                           </d:prop>
                           <d:status>HTTP/1.1 200 OK</d:status>
                          </d:propstat>
                         </d:response>
                        </d:multistatus>
                    "#;
                            resp_builder.status(StatusCode::MULTI_STATUS);
                            resp_builder.body(Body::from(xml)).unwrap()
                        } else if req.method() == &hyper::Method::GET {
                            let _ = tx_assert.send(true);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        } else {
                            let _ = tx_assert.send(false);
                            resp_builder.status(StatusCode::BAD_REQUEST);
                            resp_builder.body(Body::empty()).unwrap()
                        }
                    })
                };
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                let server = Server::bind(&addr)
                    .serve(s)
                    .map_err(|e| println!("server error: {}", e));

                hyper::rt::run(server);
            }
            test_case => {
                panic!("Unknown test case: {}", test_case);
            }
        }
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

    fn delete_file(name: &str) {
        let path_buf = file_handler::default_toml_path(name);
        let path = path_buf.to_str().unwrap();
        assert!(fs::remove_file(path).is_ok());
    }
}
// From https://users.rust-lang.org/t/tls-sockets-without-certificate-validation/13929/4:
//
// It’s also possible to do it through native-tls if one uses a backend-specific connector builder:
//
// extern crate native_tls;
// extern crate openssl;
//
// use native_tls::TlsConnector;
// use native_tls::backend::openssl::TlsConnectorBuilderExt;
// use openssl::ssl::SSL_VERIFY_NONE;
//
// ...
// let mut builder = TlsConnector::builder()?;
// builder.builder_mut().builder_mut().set_verify(SSL_VERIFY_NONE);
// let connector = builder.build()?;
// ...
//
// The connection must be opened with the danger_connect...() method for SSL_VERIFY_NONE to have effect.
//
// This has to be hidden behind some kind of #[cfg(...)] if you’re writing cross-platform code, since there’s no equivalent functionality for non-OpenSSL backends I’m aware of.
//
