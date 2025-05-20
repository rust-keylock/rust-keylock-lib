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

use async_trait::async_trait;
use reqwest::{Body, Client, Request, Response};
use lazy_static::lazy_static;
use tokio::time::sleep;
use std::io::prelude::*;
use std::time::Duration;
use url::Url;
use std::sync::Mutex;

use http::{Method, StatusCode};
use log::*;
use toml;
use toml::value::Table;
use xml::reader::{EventReader, XmlEvent};
use zeroize::{Zeroize, Zeroizing};

use crate::asynch::{self, ServerVersionData, SyncStatus, SynchronizerAction};
use crate::datacrypt::EntryPasswordCryptor;
use crate::errors::RustKeylockError;
use crate::SystemConfiguration;
use crate::{errors, file_handler};

lazy_static! {
    static ref STOP_SYNCHRONIZATION: Mutex<bool> = Mutex::new(false);
}

/// A (Next/Own)cloud synchronizer
pub(crate) struct Synchronizer {
    /// The configuration needed for this synchronizer
    conf: NextcloudConfiguration,
    /// The rust-keylock file name to synchronize
    file_name: String,
    /// The saved_at value read locally from the file
    saved_at_local: Option<i64>,
    /// The version value read locally from the file
    version_local: Option<i64>,
    /// The version that was set during the last sync
    last_sync_version: Option<i64>,
    /// Never stop the synchronization if true
    never_stop_synchronization: bool,
}

impl Synchronizer {
    pub(crate) fn new(
        ncc: &NextcloudConfiguration,
        sys_conf: &SystemConfiguration,
        f: &str,
    ) -> errors::Result<Synchronizer> {
        Self::new2(ncc, sys_conf, f, false)
    }

    pub(crate) fn new2(
        ncc: &NextcloudConfiguration,
        sys_conf: &SystemConfiguration,
        f: &str,
        never_stop_synchronization: bool,
    ) -> errors::Result<Synchronizer> {
        let ncc = NextcloudConfiguration::new(
            ncc.server_url.clone(),
            ncc.username.clone(),
            ncc.decrypted_password()?.to_string(),
            ncc.use_self_signed_certificate,
        )?;
        let s = Synchronizer {
            conf: ncc,
            file_name: f.to_string(),
            saved_at_local: sys_conf.saved_at,
            version_local: sys_conf.version,
            last_sync_version: sys_conf.last_sync_version,
            never_stop_synchronization,
        };
        Ok(s)
    }

    fn is_synchronization_stopped(&self) -> errors::Result<bool> {
        let s = STOP_SYNCHRONIZATION.lock()?;
        Ok(*s)
    }
    
    fn stop_synchronization(&self) -> errors::Result<()> {
        if !self.never_stop_synchronization {
            let mut stop_sync = STOP_SYNCHRONIZATION.lock()?;
            *stop_sync = true;
        }
        Ok(())
    }

    /// Returns the password decrypted
    fn use_password(&self) -> errors::Result<Zeroizing<String>> {
        self.conf.decrypted_password()
    }

    async fn do_request(
        req: Request,
        _is_not_https: bool,
        use_self_signed: bool,
    ) -> errors::Result<Response> {
        let response = reqwest::Client::builder()
            .danger_accept_invalid_certs(use_self_signed)
            .build()
            .unwrap()
            .execute(req)
            .await?;

        Ok(response)
    }

    async fn resp_to_status_and_body(response: Response) -> errors::Result<(StatusCode, Vec<u8>)> {
        let status = response.status();
        let v = response.bytes().await?.into();
        Ok((status, v))
    }

    async fn do_execute(capsule: ArgsCapsule) -> errors::Result<SyncStatus> {
        let url = Url::parse(
            format!(
                "{}/remote.php/dav/files/{}/.rust-keylock/{}",
                capsule.server_url(),
                capsule.username().as_str(),
                capsule.file_name()
            )
            .as_ref(),
        )?;
        debug!("Syncing with {}", url);

        // Set the body of the request so that it returns the oc:rklsavedat and oc:rklversion properties
        let xml_body = r#"<d:propfind xmlns:d="DAV:"><d:prop xmlns:oc="http://owncloud.org/ns"><oc:rklsavedat/><oc:rklversion/></d:prop></d:propfind>"#;

        let req_builder = Client::new()
            .request(Method::from_bytes(b"PROPFIND")?, url)
            .basic_auth(
                capsule.username().as_str(),
                Some(capsule.password().as_str()),
            )
            .body(Body::from(xml_body.as_bytes()));

        let req = req_builder.build()?;

        let cloned_capsule = capsule.clone();
        let response = Self::do_request(
            req,
            cloned_capsule.is_not_https(),
            cloned_capsule.use_self_signed(),
        )
        .await?;
        let (status, body) = Self::resp_to_status_and_body(response).await?;
        Ok(Self::match_propfind_status(status, body, capsule).await?)
    }

    async fn match_propfind_status(
        http_status: hyper::StatusCode,
        body: Vec<u8>,
        capsule: ArgsCapsule,
    ) -> errors::Result<SyncStatus> {
        match http_status {
            hyper::StatusCode::NOT_FOUND => {
                if capsule.version_local.is_some() {
                    info!("Creating rust-keylock-resources on the server");
                    Self::create_rust_keylock_col(
                        &capsule.username,
                        capsule.password(),
                        &capsule.server_url,
                        capsule.is_not_https(),
                        capsule.use_self_signed(),
                    )
                    .await?;
                    Self::put(
                        capsule.username(),
                        capsule.password(),
                        capsule.server_url(),
                        capsule.file_name(),
                        capsule.saved_at_local(),
                        capsule.version_local(),
                        capsule.is_not_https(),
                        capsule.use_self_signed(),
                    )
                    .await?;

                    Ok(SyncStatus::UploadSuccess("nextcloud"))
                } else {
                    debug!("Resources not found on the server, but nothing is yet saved locally. Save needs to be performed first.");
                    Ok(SyncStatus::None)
                }
            }
            hyper::StatusCode::MULTI_STATUS => {
                debug!("Parsing nextcoud response");
                let web_dav_resp = Self::parse_xml(body.as_slice(), &capsule.file_name)?;
                let synchronizer_action = Self::parse_web_dav_response(
                    &web_dav_resp,
                    &capsule.file_name,
                    &capsule.saved_at_local,
                    &capsule.version_local,
                    &capsule.last_sync_version,
                )?;
                Ok(Self::parse_synchronizer_action(synchronizer_action, capsule).await?)
            }
            other => Err(RustKeylockError::SyncError(format!(
                "Cannot handle status {:?} while handling propfind response",
                other
            ))),
        }
    }

    async fn parse_synchronizer_action(
        sa: SynchronizerAction,
        capsule: ArgsCapsule,
    ) -> errors::Result<SyncStatus> {
        match sa {
            SynchronizerAction::Download => {
                info!("Downloading file from the server");
                let tmp_file_name = Self::get(
                    &capsule.username,
                    capsule.password(),
                    &capsule.server_url,
                    &capsule.file_name,
                    capsule.is_not_https,
                    capsule.use_self_signed,
                )
                .await?;

                Ok(SyncStatus::NewAvailable("nextcloud", tmp_file_name))
            }
            SynchronizerAction::Ignore => {
                debug!("No sync is needed");
                Ok(SyncStatus::None)
            }
            SynchronizerAction::Upload => {
                info!("Uploading file on the server");
                Self::put(
                    capsule.username(),
                    capsule.password(),
                    capsule.server_url(),
                    capsule.file_name(),
                    capsule.saved_at_local(),
                    capsule.version_local(),
                    capsule.is_not_https(),
                    capsule.use_self_signed(),
                )
                .await?;
                Ok(SyncStatus::UploadSuccess("nextcloud"))
            }
            SynchronizerAction::DownloadMergeAndUpload => {
                let tmp_file_name = Self::get(
                    &capsule.username,
                    capsule.password(),
                    &capsule.server_url,
                    &capsule.file_name,
                    capsule.is_not_https,
                    capsule.use_self_signed,
                )
                .await?;
                Ok(SyncStatus::NewToMerge("nextcloud", tmp_file_name))
            }
        }
    }

    fn parse_web_dav_response(
        web_dav_response: &WebDavResponse,
        filename: &str,
        saved_at_local: &Option<i64>,
        version_local: &Option<i64>,
        last_sync_version: &Option<i64>,
    ) -> errors::Result<SynchronizerAction> {
        let svd = &ServerVersionData {
            version: web_dav_response.version.clone(),
            last_modified: web_dav_response.last_modified.clone(),
        };
        asynch::synchronizer_action(
            &svd,
            filename,
            saved_at_local,
            version_local,
            last_sync_version,
        )
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
            Err(errors::RustKeylockError::ParseError(
                "Could not parse WebDav response. The required elements could not be found."
                    .to_string(),
            ));

        for elem in parser {
            match elem {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    curr_elem_name = name.to_string();
                }
                Ok(XmlEvent::Characters(string)) => {
                    debug!(
                        "Parsing element {} that has characters {}",
                        curr_elem_name, string
                    );
                    match curr_elem_name.as_ref() {
                        "{DAV:}d:href" => web_dav_resp.href = string,
                        "{http://owncloud.org/ns}oc:rklsavedat" => {
                            web_dav_resp.last_modified = string
                        }
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
                        if web_dav_resp.href.ends_with(filename)
                            && web_dav_resp.href != ""
                            && web_dav_resp.last_modified != ""
                            && web_dav_resp.status != ""
                            && web_dav_resp.version != ""
                        {
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
                    web_dav_resp_result =
                        Err(errors::RustKeylockError::ParseError(format!("{:?}", error)));
                    break;
                }
                _ => {}
            }
        }

        web_dav_resp_result
    }

    #[allow(clippy::string_lit_as_bytes)]
    async fn create_rust_keylock_col(
        username: &str,
        password: Zeroizing<String>,
        server_url: &str,
        is_not_https: bool,
        use_self_signed: bool,
    ) -> errors::Result<()> {
        let url = Url::parse(
            format!(
                "{}/remote.php/dav/files/{}/.rust-keylock",
                server_url, username
            )
            .as_ref(),
        )?;

        let req_builder = Client::new()
            .request(Method::from_bytes(b"MKCOL")?, url)
            .basic_auth(username, Some(password.as_str()))
            .body(Body::from("".as_bytes()));

        let req = req_builder.build()?;

        let response = Self::do_request(req, is_not_https, use_self_signed).await?;
        let (status, _) = Self::resp_to_status_and_body(response).await?;
        debug!("Response for creating rust_keylock_col: {}", status);
        if status.is_client_error() || status.is_server_error() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
        } else {
            Ok(())
        }
    }

    /// Put the file and update the property with the file creation seconds using PROPPATCH
    #[allow(clippy::too_many_arguments)]
    async fn put(
        username: Zeroizing<String>,
        password: Zeroizing<String>,
        server_url: String,
        filename: String,
        local_saved_at: Option<i64>,
        local_version: Option<i64>,
        is_not_https: bool,
        use_self_signed: bool,
    ) -> errors::Result<()> {
        let mut file = file_handler::get_file(&filename).unwrap_or_else(|_| {
            panic!("Could get the file {} while performing HTTP PUT", filename)
        });
        let mut file_bytes: Vec<_> = Vec::new();
        file.read_to_end(&mut file_bytes).unwrap_or_else(|_| {
            panic!(
                "Could not read the file {} while performing HTTP PUT",
                filename
            )
        });

        let url = Url::parse(
            format!(
                "{}/remote.php/dav/files/{}/.rust-keylock/{}",
                server_url,
                username.as_str(),
                filename
            )
            .as_ref(),
        )?;

        let req_builder = Client::new()
            .request(Method::PUT, url)
            .basic_auth(username.as_str(), Some(password.as_str()))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(file_bytes));

        let req = req_builder.build()?;

        let response = Self::do_request(req, is_not_https, use_self_signed).await?;
        let (status, _) = Self::resp_to_status_and_body(response).await?;
        debug!("Response for PUT: {}", status);
        if status.is_client_error() || status.is_server_error() {
            return Err(errors::RustKeylockError::SyncError(format!("{:?}", status)));
        }
        // PROPPATCH starts here
        let xml_body: String = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:set>
<d:prop>
  <oc:rklsavedat>{}</oc:rklsavedat>
  <oc:rklversion>{}</oc:rklversion>
</d:prop>
</d:set>
</d:propertyupdate>"#,
            local_saved_at
                .map(|s| s.to_string())
                .unwrap_or_else(String::new),
            local_version
                .map(|s| s.to_string())
                .unwrap_or_else(String::new)
        );

        let url_pp = Url::parse(
            format!(
                "{}/remote.php/dav/files/{}/.rust-keylock/{}",
                server_url,
                username.as_str(),
                filename
            )
            .as_ref(),
        )?;

        let req_builder_pp = Client::new()
            .request(Method::from_bytes(b"PROPPATCH")?, url_pp)
            .basic_auth(username.as_str(), Some(password.as_str()))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(xml_body));

        let req_pp = req_builder_pp.build()?;

        let resp_pp = Self::do_request(req_pp, is_not_https, use_self_signed).await?;
        let (status_pp, _) = Self::resp_to_status_and_body(resp_pp).await?;
        debug!("Response for PROPPATCH: {}", status_pp);
        let res = {
            if status.is_client_error() || status.is_server_error() {
                Err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
            } else {
                Ok(())
            }
        };
        res
    }

    #[allow(clippy::string_lit_as_bytes)]
    async fn get(
        username: &str,
        password: Zeroizing<String>,
        server_url: &str,
        filename: &str,
        is_not_https: bool,
        use_self_signed: bool,
    ) -> errors::Result<String> {
        let tmp_file_name = format!("tmp_{}", filename);
        let url = Url::parse(
            format!(
                "{}/remote.php/dav/files/{}/.rust-keylock/{}",
                server_url, username, filename
            )
            .as_ref(),
        )?;

        let req_builder = Client::new()
            .request(Method::GET, url)
            .basic_auth(username, Some(password.as_str()))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from("".as_bytes()));

        let req = req_builder.build()?;

        let response = Self::do_request(req, is_not_https, use_self_signed).await?;
        let (status, body) = Self::resp_to_status_and_body(response).await?;
        debug!("Response for GET: {}", status);
        let res = {
            if status.is_client_error() || status.is_server_error() {
                Err(errors::RustKeylockError::SyncError(format!("{:?}", status)))
            } else {
                file_handler::save_bytes(&tmp_file_name, &body, false).map(|_| tmp_file_name)
            }
        };

        res
    }
}

#[async_trait]
impl super::AsyncTask for Synchronizer {
    async fn init(&mut self) {}

    async fn execute(&self) -> errors::Result<SyncStatus> {
        if self.conf.is_filled() {
            loop {
                if self.is_synchronization_stopped()? {
                    return Ok(SyncStatus::None);
                }
                let capsule = ArgsCapsule::new(
                    self.conf.server_url.clone(),
                    self.conf.username.clone(),
                    self.file_name.clone(),
                    self.use_password()
                        .expect("Could not retrieve the password for the nextcloud server")
                        .to_string(),
                    self.conf.server_url.starts_with("http://"),
                    self.conf.use_self_signed_certificate,
                    self.saved_at_local,
                    self.version_local,
                    self.last_sync_version,
                );

                match Self::do_execute(capsule).await {
                    Ok(SyncStatus::None) => {}
                    Ok(sync_status) => return Ok(sync_status),
                    Err(error) => {
                        self.stop_synchronization()?;
                        return Err(error);
                    }
                }
                sleep(Duration::from_millis(10000)).await;
            }
        } else {
            return Ok(SyncStatus::None);
        }
    }
}

/// The configuration that is retrieved from the rust-keylock encrypted file
#[derive(Debug, PartialEq, Clone, Zeroize)]
#[zeroize(drop)]
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
    pub fn new(
        u: String,
        un: String,
        pw: String,
        use_self_signed_certificate: bool,
    ) -> errors::Result<NextcloudConfiguration> {
        let mut s = NextcloudConfiguration {
            username: un,
            password: "".to_string(),
            password_cryptor: EntryPasswordCryptor::new(),
            server_url: u.to_string(),
            use_self_signed_certificate,
        };
        s.password = s.password_cryptor.encrypt_str(&pw)?;
        Ok(s)
    }

    pub fn decrypted_password(&self) -> errors::Result<Zeroizing<String>> {
        self.password_cryptor
            .decrypt_str(&self.password)
            .map(|s| Zeroizing::new(s))
    }

    /// Creates a TOML table form this NextcloudConfiguration. The resulted table contains the decrypted password.
    pub(crate) fn to_table(&self) -> errors::Result<Table> {
        let mut table = Table::new();
        table.insert(
            "url".to_string(),
            toml::Value::String(self.server_url.clone()),
        );
        table.insert(
            "user".to_string(),
            toml::Value::String(self.username.clone()),
        );
        table.insert(
            "pass".to_string(),
            toml::Value::String(self.decrypted_password()?.as_str().to_string()),
        );
        table.insert(
            "use_self_signed_certificate".to_string(),
            toml::Value::Boolean(self.use_self_signed_certificate),
        );

        Ok(table)
    }

    /// Creates a NextcloudConfiguration from a TOML table. The password gets encrypted once the `new` function is called.
    pub(crate) fn from_table(
        table: &Table,
    ) -> Result<NextcloudConfiguration, errors::RustKeylockError> {
        let url = table
            .get("url")
            .and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let user = table
            .get("user")
            .and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let pass = table
            .get("pass")
            .and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let use_self_signed_certificate = table
            .get("use_self_signed_certificate")
            .and_then(|value| value.as_bool().and_then(Some));
        match (url, user, pass, use_self_signed_certificate) {
            (Some(ul), Some(u), Some(p), Some(ssc)) => NextcloudConfiguration::new(ul, u, p, ssc),
            _ => Err(errors::RustKeylockError::ParseError(
                toml::ser::to_string(&table)
                    .unwrap_or_else(|_| "Cannot deserialize toml".to_string()),
            )),
        }
    }

    /// Returns true is the configuration contains the needed values to operate correctly
    pub(crate) fn is_filled(&self) -> bool {
        let dp = self.decrypted_password();
        (dp.is_ok() && dp.unwrap().as_str() != "") && self.server_url != "" && self.username != ""
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

/// Convenience struct to use during function calls
#[derive(Clone)]
struct ArgsCapsule {
    server_url: String,
    username: Zeroizing<String>,
    file_name: String,
    password: Zeroizing<String>,
    is_not_https: bool,
    use_self_signed: bool,
    saved_at_local: Option<i64>,
    version_local: Option<i64>,
    last_sync_version: Option<i64>,
}

impl ArgsCapsule {
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: Into<Zeroizing<String>>>(
        server_url: String,
        username: T,
        file_name: String,
        password: T,
        is_not_https: bool,
        use_self_signed: bool,
        saved_at_local: Option<i64>,
        version_local: Option<i64>,
        last_sync_version: Option<i64>,
    ) -> ArgsCapsule {
        ArgsCapsule {
            server_url,
            username: username.into(),
            file_name,
            password: password.into(),
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

    fn username(&self) -> Zeroizing<String> {
        self.username.clone()
    }

    fn file_name(&self) -> String {
        self.file_name.clone()
    }

    fn password(&self) -> Zeroizing<String> {
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
    use std::collections::HashMap;
    use std::fs;
    use std::fs::File;
    use std::io::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::sync::Mutex;
    use std::thread;
    use std::time;

    use http::StatusCode;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioIo, TokioTimer};
    use lazy_static::lazy_static;
    use std::convert::Infallible;
    use tokio;
    use toml;

    use hyper::server::conn::http1;
    use tokio::net::TcpListener;

    use super::super::super::{errors, file_handler, SystemConfiguration};
    use super::super::AsyncTask;

    lazy_static! {
        static ref TXMAP: Mutex<HashMap<String, SyncSender<bool>>> = Mutex::new(HashMap::new());
    }

    fn get_tx_for(command: &str) -> SyncSender<bool> {
        let map = TXMAP.lock().unwrap();
        let tx_ref = map.get(&command.to_string()).unwrap();
        tx_ref.clone()
    }

    fn set_tx_for(command: &str, tx: SyncSender<bool>) {
        let mut map = TXMAP.lock().unwrap();
        (*map).insert(command.to_string(), tx);
    }

    #[test]
    fn synchronizer_stores_encrypted_password() {
        let password = "password".to_string();
        let ncc = super::NextcloudConfiguration::new(
            "https://localhost/nextcloud".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();
        let nc =
            super::Synchronizer::new2(&ncc, &SystemConfiguration::default(), "filename", true).unwrap();

        assert!(nc.conf.decrypted_password().unwrap().as_str() == password)
    }

    #[test]
    fn nextcloud_configuration_stores_encrypted_password() {
        let password = "password".to_string();
        let ncc = super::NextcloudConfiguration::new(
            "https://localhost/nextcloud".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
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
        let ncc1 = super::NextcloudConfiguration::new(
            "https://localhost/nextcloud".to_string(),
            "username".to_string(),
            "password".to_string(),
            false,
        )
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
        let (tx_assert, rx_assert): (SyncSender<bool>, Receiver<bool>) = mpsc::sync_channel(10);
        set_tx_for("run_col_not_exists", tx_assert);
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let f = start_web_dav_server("run_col_not_exists", 8080);
            rt.block_on(f);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1:8080".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let sys_config = SystemConfiguration::new(Some(123), Some(1), None);
            let nc = super::Synchronizer::new2(&ncc, &sys_config, filename, true).unwrap();
            let f = nc.execute();
            let res = rt.block_on(f);
            let _ = tx.send(res);
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
        assert!(
            rx.recv_timeout(timeout).unwrap().unwrap()
                == super::SyncStatus::UploadSuccess("nextcloud")
        );

        // Delete the dummy file
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn download_a_file_from_the_server() {
        // Create a dummy file
        let filename = "download_a_file_from_the_server";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (SyncSender<bool>, Receiver<bool>) = mpsc::sync_channel(10);
        set_tx_for("run_download_a_file_from_the_server", tx_assert);
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let f = start_web_dav_server("run_download_a_file_from_the_server", 8081);
            rt.block_on(f);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1:8081".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let nc =
                super::Synchronizer::new2(&ncc, &SystemConfiguration::default(), filename, true).unwrap();
            let res = rt.block_on(nc.execute());
            let _ = tx.send(res);
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the Get that downlaods the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that the file is ready to be downloaded
        assert!(
            rx.recv_timeout(timeout).unwrap().unwrap()
                == super::SyncStatus::NewAvailable(
                    "nextcloud",
                    "tmp_download_a_file_from_the_server".to_string()
                )
        );

        // Delete the dummy file
        let _ = file_handler::delete_file(filename);
        let _ = file_handler::delete_file("tmp_download_a_file_from_the_server");
    }

    #[test]
    fn http_error_response_on_propfind() {
        // Create a dummy file
        let filename = "http_error_response_on_propfind";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (SyncSender<bool>, Receiver<bool>) = mpsc::sync_channel(10);
        set_tx_for("run_http_error_response_on_propfind", tx_assert);
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let f = start_web_dav_server("run_http_error_response_on_propfind", 8082);
            rt.block_on(f);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1:8082".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let nc =
                super::Synchronizer::new2(&ncc, &SystemConfiguration::default(), filename, true).unwrap();
            let res = rt.block_on(nc.execute());
            let _ = tx.send(res);
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn http_error_response_on_mkcol() {
        // Create a dummy file
        let filename = "http_error_response_on_mkcol";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (SyncSender<bool>, Receiver<bool>) = mpsc::sync_channel(10);
        set_tx_for("run_http_error_response_on_mkcol", tx_assert);
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let f = start_web_dav_server("run_http_error_response_on_mkcol", 8083);
            rt.block_on(f);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1:8083".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1), None);

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let nc = super::Synchronizer::new2(&ncc, &sys_config, filename, true).unwrap();
            let res = rt.block_on(nc.execute());
            let _ = tx.send(res);
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the MKCOL that creates the collection
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn http_error_response_on_put() {
        // Create a dummy file
        let filename = "http_error_response_on_put";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (SyncSender<bool>, Receiver<bool>) = mpsc::sync_channel(10);
        set_tx_for("run_http_error_response_on_put", tx_assert);
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let f = start_web_dav_server("run_http_error_response_on_put", 8084);
            rt.block_on(f);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1:8084".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1), None);

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let nc = super::Synchronizer::new2(&ncc, &sys_config, filename, true).unwrap();
            let res = rt.block_on(nc.execute());
            let _ = tx.send(res);
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
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn http_error_response_on_get() {
        // Create a dummy file
        let filename = "http_error_response_on_get";
        create_file_with_contents(filename, "This is a test file");

        // Start the HTTP server
        let (tx_assert, rx_assert): (SyncSender<bool>, Receiver<bool>) = mpsc::sync_channel(10);
        set_tx_for("run_http_error_response_on_get", tx_assert);
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let f = start_web_dav_server("run_http_error_response_on_get", 8085);
            rt.block_on(f);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1:8085".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let nc =
                super::Synchronizer::new2(&ncc, &SystemConfiguration::default(), filename, true).unwrap();
            let res = rt.block_on(nc.execute());
            let _ = tx.send(res);
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the Get that downlaods the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that an error is occured
        assert!(rx.recv_timeout(timeout).unwrap().is_err());

        // Delete the dummy file
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn server_not_found() {
        // Create a dummy file
        let filename = "server_not_found";
        create_file_with_contents(filename, "This is a test file");

        // Do not start the HTTP server
        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (
            SyncSender<errors::Result<super::SyncStatus>>,
            Receiver<errors::Result<super::SyncStatus>>,
        ) = mpsc::sync_channel(10);
        let ncc = super::NextcloudConfiguration::new(
            "http://127.0.0.1".to_string(),
            "username".to_string(),
            password.clone(),
            false,
        )
        .unwrap();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let nc =
                super::Synchronizer::new2(&ncc, &SystemConfiguration::default(), filename, true).unwrap();
            let res = rt.block_on(nc.execute());
            let _ = tx.send(res);
        });

        let timeout = time::Duration::from_millis(1000000);

        let stat = rx.recv_timeout(timeout).unwrap();
        // Assert that the file is ready to be downloaded
        assert!(stat.is_err());

        // Delete the dummy file
        let _ = file_handler::delete_file(filename);
    }

    #[test]
    fn parse_xml_success() {
        let filename = "afilename";
        let xml = format!(
            r#"<?xml version="1.0"?>
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
                        "#,
            filename
        );

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_ok());
        assert!(
            res.as_ref().unwrap().href
                == "/nextcloud/remote.php/dav/files/user/.rust-keylock/afilename"
        );
        assert!(res.as_ref().unwrap().last_modified == "1234567");
        assert!(res.as_ref().unwrap().status == "HTTP/1.1 200 OK");
        assert!(res.as_ref().unwrap().version == "1");
    }

    #[test]
    fn parse_xml_error_no_file_is_present() {
        let filename = "afilename";
        // The file element is not present
        let xml = r#"<?xml version="1.0"?>
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
        let xml = format!(
            r#"<?xml version="1.0"?>
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
                        "#,
            filename
        );

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_err());
    }

    #[test]
    fn parse_xml_error_in_web_dav_response() {
        let filename = "afilename";
        let xml = format!(
            r#"<?xml version="1.0"?>
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
                        "#,
            filename
        );

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_err());
    }

    async fn run_col_not_exists_web_dav_service(
        req: Request<impl hyper::body::Body>,
    ) -> Result<Response<String>, Infallible> {
        let tx_assert = get_tx_for("run_col_not_exists");
        let resp_builder = hyper::Response::builder();

        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::NOT_FOUND)
                .body("".to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::from_bytes("MKCOL".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::OK)
                .body("".to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::PUT {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::OK)
                .body("".to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::from_bytes("PROPPATCH".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::OK)
                .body("".to_owned())
                .unwrap())
        } else {
            let _ = tx_assert.send(false);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        }
    }

    async fn run_download_a_file_from_the_server_web_dav_service(
        req: Request<impl hyper::body::Body>,
    ) -> Result<Response<String>, Infallible> {
        let tx_assert = get_tx_for("run_download_a_file_from_the_server");
        let resp_builder = Response::builder();

        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            let xml = r#"<?xml version="1.0"?>
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
            Ok(resp_builder
                .status(StatusCode::MULTI_STATUS)
                .body(xml.to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::GET {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::MULTI_STATUS)
                .body("This is a file from the server".to_owned())
                .unwrap())
        } else {
            let _ = tx_assert.send(false);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        }
    }

    async fn run_http_error_response_on_propfind_web_dav_service(
        req: Request<impl hyper::body::Body>,
    ) -> Result<Response<String>, Infallible> {
        let tx_assert = get_tx_for("run_http_error_response_on_propfind");
        let resp_builder = Response::builder();

        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
        }
        Ok(resp_builder
            .status(StatusCode::BAD_REQUEST)
            .body("".to_owned())
            .unwrap())
    }

    async fn run_http_error_response_on_mkcol_web_dav_service(
        req: Request<impl hyper::body::Body>,
    ) -> Result<Response<String>, Infallible> {
        let tx_assert = get_tx_for("run_http_error_response_on_mkcol");
        let resp_builder = Response::builder();

        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::NOT_FOUND)
                .body("".to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::from_bytes("MKCOL".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        } else {
            let _ = tx_assert.send(false);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        }
    }

    async fn run_http_error_response_on_put_web_dav_service(
        req: Request<impl hyper::body::Body>,
    ) -> Result<Response<String>, Infallible> {
        let tx_assert = get_tx_for("run_http_error_response_on_put");
        let resp_builder = Response::builder();

        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::NOT_FOUND)
                .body("".to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::from_bytes("MKCOL".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::OK)
                .body("".to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::PUT {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        } else {
            let _ = tx_assert.send(false);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        }
    }

    async fn run_http_error_response_on_get_web_dav_service(
        req: Request<impl hyper::body::Body>,
    ) -> Result<Response<String>, Infallible> {
        let tx_assert = get_tx_for("run_http_error_response_on_get");
        let resp_builder = Response::builder();

        if req.method() == &hyper::Method::from_bytes("PROPFIND".as_ref()).unwrap() {
            let _ = tx_assert.send(true);
            let xml = r#"<?xml version="1.0"?>
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
            Ok(resp_builder
                .status(StatusCode::MULTI_STATUS)
                .body(xml.to_owned())
                .unwrap())
        } else if req.method() == &hyper::Method::GET {
            let _ = tx_assert.send(true);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        } else {
            let _ = tx_assert.send(false);
            Ok(resp_builder
                .status(StatusCode::BAD_REQUEST)
                .body("".to_owned())
                .unwrap())
        }
    }

    async fn start_web_dav_server(command: &'static str, port: u16) {
        loop {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
            let listener = TcpListener::bind(addr).await.unwrap();
            let (tcp, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(tcp);

            match command {
                "run_col_not_exists" => {
                    if let Err(err) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(io, service_fn(run_col_not_exists_web_dav_service))
                        .await
                    {
                        println!(
                            "Error serving connection for run_col_not_exists_web_dav_service: {:?}",
                            err
                        );
                    }
                }
                "run_download_a_file_from_the_server" => {
                    if let Err(err) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(
                            io,
                            service_fn(run_download_a_file_from_the_server_web_dav_service),
                        )
                        .await
                    {
                        println!("Error serving connection for run_download_a_file_from_the_server_web_dav_service: {:?}", err);
                    }
                }
                "run_http_error_response_on_propfind" => {
                    if let Err(err) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(
                            io,
                            service_fn(run_http_error_response_on_propfind_web_dav_service),
                        )
                        .await
                    {
                        println!("Error serving connection for run_http_error_response_on_propfind_web_dav_service: {:?}", err);
                    }
                }
                "run_http_error_response_on_mkcol" => {
                    if let Err(err) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(
                            io,
                            service_fn(run_http_error_response_on_mkcol_web_dav_service),
                        )
                        .await
                    {
                        println!("Error serving connection for run_http_error_response_on_mkcol_web_dav_service: {:?}", err);
                    }
                }
                "run_http_error_response_on_put" => {
                    if let Err(err) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(
                            io,
                            service_fn(run_http_error_response_on_put_web_dav_service),
                        )
                        .await
                    {
                        println!("Error serving connection for run_http_error_response_on_put_web_dav_service: {:?}", err);
                    }
                }
                "run_http_error_response_on_get" => {
                    if let Err(err) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(
                            io,
                            service_fn(run_http_error_response_on_get_web_dav_service),
                        )
                        .await
                    {
                        println!("Error serving connection for run_http_error_response_on_get_web_dav_service: {:?}", err);
                    }
                }
                test_case => {
                    panic!("Unknown test case: {}", test_case);
                }
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
