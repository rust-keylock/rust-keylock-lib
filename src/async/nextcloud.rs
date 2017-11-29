use std::sync::mpsc::Sender;
use std::time::UNIX_EPOCH;
use super::super::{errors, file_handler};
use super::super::datacrypt::EntryPasswordCryptor;
use std::io::Write;
use std::fs::File;
use std::io::prelude::*;
use futures::{Future, Stream};
use httpdate;
use hyper::Client;
use hyper::client::{Request, HttpConnector, FutureResponse};
use hyper;
use hyper::header;
use hyper_tls::{self, HttpsConnector};
use tokio_core::reactor::{Core, Handle};
use toml;
use toml::value::Table;
use hyper::header::{Headers, Authorization, Basic};
use xml::reader::{EventReader, XmlEvent};
use native_tls;

/// A (Next/Own)cloud synchronizer
pub struct Synchronizer {
    /// The configuration needed for this synchronizer
    conf: NextcloudConfiguration,
    /// The TX to notify about sync status
    tx: Sender<errors::Result<SyncStatus>>,
    /// The rust-keylock file name to synchronize
    file_name: String,
}

impl Synchronizer {
    pub fn new(ncc: &NextcloudConfiguration, tx: Sender<errors::Result<SyncStatus>>, f: &str) -> errors::Result<Synchronizer> {
        let ncc = NextcloudConfiguration::new(ncc.server_url.clone(),
                                              ncc.username.clone(),
                                              ncc.decrypted_password()?,
                                              ncc.self_signed_der_certificate_location.clone())?;
        let s = Synchronizer {
            conf: ncc,
            tx: tx,
            file_name: f.to_string(),
        };
        Ok(s)
    }

    /// Returns the password decrypted
    fn use_password(&self) -> errors::Result<String> {
        self.conf.decrypted_password()
    }

    fn do_execute(&self) -> errors::Result<SyncStatus> {
        let mut core = Core::new()?;
        let handle = core.handle();

        let client: Box<RequestClient> = if self.conf.server_url.starts_with("http://") {
            // Use HTTP
            debug!("The Nextcloud async task uses HTTP connector");
            Self::connect_with_http(&handle)
        } else if self.conf.self_signed_der_certificate_location.len() > 0 {
            // Use HTTPS with a self signed certificate
            debug!("The Nextcloud async task uses HTTPS connector with a self-signed certificate located at {}",
                   &self.conf.self_signed_der_certificate_location);
            Self::connect_with_https_self_signed(&handle, &self.conf.self_signed_der_certificate_location)
        } else {
            // Use HTTPS
            debug!("The Nextcloud async task uses HTTPS connector");
            Self::connect_with_https(&handle)
        };

        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock", self.conf.server_url, self.conf.username).parse()?;
        debug!("Syncing with {}", uri);

        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: self.conf.username.to_owned(),
            password: Some(self.use_password()?),
        }));

        let mut req: Request = Request::new(hyper::Method::Extension("PROPFIND".to_string()), uri);
        *req.headers_mut() = headers;

        let mut resp_bytes: Vec<u8> = Vec::new();
        let mut http_status = None;
        {
            let work = client.request(req).and_then(|res| {
                http_status = Some(res.status());
                debug!("PROPFIND returned: {}", res.status());

                res.body().for_each(|chunk| {
                    resp_bytes.write_all(&chunk)
                        .map(|_| ())
                        .map_err(From::from)
                })
            });

            core.run(work)?;
        }

        match http_status {
            Some(hyper::StatusCode::NotFound) => {
                info!("Creating rust-keylock-resources on the server");
                Self::create_rust_keylock_col(&self.conf.username, self.use_password()?, &self.conf.server_url, &client, &mut core)?;
                Self::put(&self.conf.username, self.use_password()?, &self.conf.server_url, &client, &mut core, &self.file_name)?;
                Ok(SyncStatus::UploadSuccess)
            }
            Some(hyper::StatusCode::MultiStatus) => {
                info!("Parsing nextcoud response");
                let web_dav_resp = Self::parse_xml(resp_bytes.as_slice(), &self.file_name)?;
                match Self::parse_web_dav_response(&web_dav_resp, &self.file_name)? {
                    -1 => {
                        info!("Downloading file from the server");
                        let tmp_file_name = Self::get(&self.conf.username,
                                                      self.use_password()?,
                                                      &self.conf.server_url,
                                                      &client,
                                                      &mut core,
                                                      &self.file_name)?;
                        Ok(SyncStatus::NewAvailable(tmp_file_name))
                    }
                    0 => {
                        debug!("No sync is needed");
                        Ok(SyncStatus::None)
                    }
                    1 => {
                        info!("Uploading file on the server");
                        Self::put(&self.conf.username, self.use_password()?, &self.conf.server_url, &client, &mut core, &self.file_name)?;
                        Ok(SyncStatus::UploadSuccess)
                    }
                    other => {
                        Err(errors::RustKeylockError::SyncError(format!("parse_web_dav_response returned unexpected result ({}). Please \
                                                                         consider opening a bug to the developers.",
                                                                        other)))
                    }
                }
            }
            Some(other) => Err(errors::RustKeylockError::SyncError(format!("Encountered WebDav error response: {:?}", other))),
            None => Err(errors::RustKeylockError::SyncError("Could not execute sync http request".to_string())),
        }
    }

    /// Returns:
    /// -1 if the server last modified time is greater than the local last modified time
    /// 1 if the server last modified time is less than the local last modified time
    /// 0 if the server last modified time is equal to the local last modified time
    /// All with an accepted deviation of 1 minute
    fn parse_web_dav_response(web_dav_response: &WebDavResponse, filename: &str) -> errors::Result<isize> {
        let server_time = httpdate::parse_http_date(&web_dav_response.last_modified)?;
        let server_time_seconds = server_time.duration_since(UNIX_EPOCH)?.as_secs();

        debug!("The file '{}' on the server was last modified at {}. The derived seconds are {:?}",
               filename,
               web_dav_response.last_modified,
               server_time_seconds);

        let file = file_handler::get_file(filename)?;
        let file_metadata = file.metadata()?;
        let local_time = file_metadata.modified()?;
        let local_time_seconds = local_time.duration_since(UNIX_EPOCH)?.as_secs();
        debug!("The file '{}' locally was last modified seconds {:?}", filename, local_time_seconds);

        if server_time_seconds > local_time_seconds {
            let diff_seconds = server_time_seconds - local_time_seconds;
            if diff_seconds > 60 {
                debug!("The server time is after the local time");
                Ok(-1)
            } else {
                Ok(0)
            }
        } else if server_time < local_time {
            let diff_seconds = local_time_seconds - server_time_seconds;
            if diff_seconds > 60 {
                debug!("The server time is before the local time");
                Ok(1)
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
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
                        "{DAV:}d:getlastmodified" => web_dav_resp.last_modified = string,
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
                           web_dav_resp.status != "" {
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
                               client: &Box<RequestClient>,
                               core: &mut Core)
                               -> errors::Result<()> {

        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: username.to_owned(),
            password: Some(password),
        }));

        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock", server_url, username).parse()?;
        let mut req: Request = Request::new(hyper::Method::Extension("MKCOL".to_string()), uri);
        *req.headers_mut() = headers;

        let mut resp_bytes: Vec<u8> = Vec::new();
        let mut status_opt = None;
        {
            let work = client.request(req).and_then(|res| {
                status_opt = Some(res.status());
                debug!("Response for col creation: {}", res.status());

                res.body().for_each(|chunk| {
                    resp_bytes.write_all(&chunk)
                        .map(|_| ())
                        .map_err(From::from)
                })
            });

            core.run(work)?;
        }

        let stat = status_opt.unwrap_or(hyper::StatusCode::BadRequest);
        if stat.is_client_error() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", stat)))
        } else {
            Ok(())
        }
    }

    fn get(username: &str,
           password: String,
           server_url: &str,
           client: &Box<RequestClient>,
           core: &mut Core,
           filename: &str)
           -> errors::Result<String> {

        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: username.to_owned(),
            password: Some(password),
        }));

        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", server_url, username, filename).parse()?;
        let mut req: Request = Request::new(hyper::Method::Get, uri);
        *req.headers_mut() = headers;
        req.headers_mut().set(header::ContentType::octet_stream());

        let mut resp_bytes: Vec<u8> = Vec::new();
        let mut status_opt = None;
        {
            let work = client.request(req).and_then(|res| {
                status_opt = Some(res.status());
                debug!("Response for GET: {}", res.status());

                res.body().for_each(|chunk| {
                    resp_bytes.write_all(&chunk)
                        .map(|_| ())
                        .map_err(From::from)
                })
            });

            core.run(work)?;
        }

        let stat = status_opt.unwrap_or(hyper::StatusCode::BadRequest);
        if stat.is_client_error() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", stat)))
        } else {
            let tmp_file_name = format!("tmp_{}", filename);
            file_handler::save_bytes(&tmp_file_name, &resp_bytes)?;
            Ok(tmp_file_name)
        }
    }

    fn put(username: &str,
           password: String,
           server_url: &str,
           client: &Box<RequestClient>,
           core: &mut Core,
           filename: &str)
           -> errors::Result<()> {

        let mut file = file_handler::get_file(filename)?;
        let mut file_bytes: Vec<_> = Vec::new();
        file.read_to_end(&mut file_bytes)?;
        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: username.to_owned(),
            password: Some(password),
        }));

        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", server_url, username, filename).parse()?;
        let mut req: Request = Request::new(hyper::Method::Put, uri);
        *req.headers_mut() = headers;
        req.headers_mut().set(header::ContentType::octet_stream());
        req.set_body(file_bytes);

        let mut resp_bytes: Vec<u8> = Vec::new();
        let mut status_opt = None;
        {
            let work = client.request(req).and_then(|res| {
                status_opt = Some(res.status());
                debug!("Response: {}", res.status());

                res.body().for_each(|chunk| {
                    resp_bytes.write_all(&chunk)
                        .map(|_| ())
                        .map_err(From::from)
                })
            });

            core.run(work)?;
        }

        let stat = status_opt.unwrap_or(hyper::StatusCode::BadRequest);
        if stat.is_client_error() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", stat)))
        } else {
            Ok(())
        }

    }

    fn connect_with_http(handle: &Handle) -> Box<RequestClient> {
        Box::new(HttpRequestClient { client: Client::new(&handle) }) as Box<RequestClient>
    }

    fn connect_with_https(handle: &Handle) -> Box<RequestClient> {
        let client = Client::configure()
            .connector(HttpsConnector::new(4, &handle).unwrap())
            .build(&handle);

        Box::new(HttpsRequestClient { client: client }) as Box<RequestClient>
    }

    fn connect_with_https_self_signed(handle: &Handle, der_path: &str) -> Box<RequestClient> {
        let mut f = File::open(der_path).unwrap();
        let mut buffer = vec![];
        f.read_to_end(&mut buffer).unwrap();
        let cert = native_tls::Certificate::from_der(buffer.as_slice()).unwrap();

        let mut http = HttpConnector::new(4, &handle);
        http.enforce_http(false);

        let mut tls = native_tls::TlsConnector::builder().unwrap();
        tls.add_root_certificate(cert).unwrap();
        let tls = tls.build().unwrap();

        let ct = HttpsConnector::from((http, tls));

        Box::new(HttpsRequestClientSelfSignedCertificate { client: Client::configure().connector(ct).build(&handle) }) as Box<RequestClient>
    }
}

impl super::AsyncTask for Synchronizer {
    type T = SyncStatus;

    fn init(&mut self) {}

    fn execute(&self) {
        let status = self.do_execute();
        debug!("Nextcloud Async Task sends to the channel {:?}", &status);

        match self.tx.send(status) {
            Ok(_) => {
                // ignore
            }
            Err(error) => {
                error!("Error while the Nextcloud synchronizer attempted to send the status to the channel: {:?}.", error);
            }
        }
    }
}

/// The status of the sync actions
#[derive(PartialEq, Debug)]
pub enum SyncStatus {
    /// An update is available from the nextcloud server
    /// The String is the name of the file that is ready to be used if the user selects so
    NewAvailable(String),
    /// The local file was uploaded to the nextcloud server
    UploadSuccess,
    /// None
    None,
}

/// Trait that is used to abstract upon HTTP and HTTPS clients
trait RequestClient {
    fn request(&self, req: Request) -> FutureResponse;
}

/// A client that executes HTTP requests
struct HttpRequestClient {
    client: hyper::Client<hyper::client::HttpConnector>,
}

impl RequestClient for HttpRequestClient {
    fn request(&self, req: Request) -> FutureResponse {
        self.client.request(req)
    }
}

/// A client that executes HTTPS requests
struct HttpsRequestClient {
    client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>,
}

impl RequestClient for HttpsRequestClient {
    fn request(&self, req: Request) -> FutureResponse {
        self.client.request(req)
    }
}

/// A client that executes HTTPS requests using a self signed certificate
struct HttpsRequestClientSelfSignedCertificate {
    client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>,
}

impl RequestClient for HttpsRequestClientSelfSignedCertificate {
    fn request(&self, req: Request) -> FutureResponse {
        self.client.request(req)
    }
}

/// The configuration that is retrieved from the rust-keylock encrypted file
#[derive(Debug, PartialEq)]
pub struct NextcloudConfiguration {
    /// The server base URL (eg. https://my.nextcloud.server/nextcloud)
    pub server_url: String,
    /// The username of a nextcoud account
    pub username: String,
    /// The password of a nextcoud account
    password: String,
    password_cryptor: EntryPasswordCryptor,
    /// In the case that the server's certificate is self signed the following steps need to be done:
    /// * Get the server certificate:
    ///
    /// `openssl s_client -showcerts -connect my.nextcloud.server:443 > server.crt`
    /// * Transform it to DER:
    ///
    /// `openssl x509 -in server.crt -outform der -out server.der`
    ///
    /// The path of the DER file should be passed here.
    pub self_signed_der_certificate_location: String,
}

impl NextcloudConfiguration {
    /// Creates a new NextcloudConfiguration
    pub fn new(u: String, un: String, pw: String, self_signed_der_certificate_location: String) -> errors::Result<NextcloudConfiguration> {
        let mut s = NextcloudConfiguration {
            username: un,
            password: "".to_string(),
            password_cryptor: EntryPasswordCryptor::new(),
            server_url: u.to_string(),
            self_signed_der_certificate_location: self_signed_der_certificate_location.to_owned(),
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
        table.insert("self_signed_cert".to_string(), toml::Value::String(self.self_signed_der_certificate_location.clone()));

        Ok(table)
    }

    /// Creates a NextcloudConfiguration from a TOML table. The password gets encrypted once the `new` function is called.
    pub fn from_table(table: &Table) -> Result<NextcloudConfiguration, errors::RustKeylockError> {
        let url = table.get("url").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let user = table.get("user").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let pass = table.get("pass").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        let self_signed_cert = table.get("self_signed_cert").and_then(|value| value.as_str().and_then(|str_ref| Some(str_ref.to_string())));
        match (url, user, pass, self_signed_cert) {
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
            self_signed_der_certificate_location: "".to_string(),
        }
    }
}

#[derive(Debug)]
struct WebDavResponse {
    href: String,
    last_modified: String,
    status: String,
}

#[cfg(test)]
mod nextcloud_tests {
    use std::time;
    use std::thread;
    use toml;
    use std::sync::mpsc::{self, Sender, Receiver};
    use std::io::prelude::*;
    use std::fs;
    use std::fs::File;
    use super::super::super::errors;
    use super::super::super::file_handler;
    use super::super::AsyncTask;
    use futures;
    use futures::future::Future;
    use hyper;
    use hyper::server::{Http, Request, Response, Service};

    #[test]
    fn synchronizer_stores_encrypted_password() {
        let password = "password".to_string();
        let (tx, _rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("https://localhost/nextcloud", "username".to_string(), password.clone(), "", tx, "filename")
            .unwrap();

        assert!(nc.password != password)
    }

    #[test]
    fn nextcloud_configuration_stores_encrypted_password() {
        let password = "password".to_string();
        let ncc = super::NextcloudConfiguration::new("https://localhost/nextcloud", "username".to_string(), password.clone(), "path")
            .unwrap();

        assert!(ncc.password != password)
    }

    #[test]
    fn apply_a_nextcloud_configuration() {
        let password = "password".to_string();
        let ncc = super::NextcloudConfiguration::new("https://localhost/nextcloud", "username".to_string(), password.clone(), "path")
            .unwrap();
        let mut ncc_new = super::NextcloudConfiguration::default();

        ncc_new.apply(&ncc);

        assert!(ncc_new.self_signed_der_certificate_location == ncc.self_signed_der_certificate_location);
        assert!(ncc_new.server_url == ncc.server_url);
        assert!(ncc_new.username == ncc.username);
        // The passwords should not be the same as they are encrypted using different keys
        assert!(ncc_new.password != ncc.password);
    }

    #[test]
    fn nextcloud_configuration_to_table() {
        let toml = r#"
			url = "http://a/url"
			user = "user1"
			pass = "123"
			self_signed_cert = "/a/path"
		"#;

        let value = toml.parse::<toml::value::Value>().unwrap();
        let table = value.as_table().unwrap();
        let ncc_res = super::NextcloudConfiguration::from_table(&table);
        assert!(ncc_res.is_ok());
        let ncc = ncc_res.unwrap();
        let new_table = ncc.to_table();
        assert!(table == &new_table);
    }

    #[test]
    fn nextcloud_configuration_from_table_success() {
        let toml = r#"
			url = "http://a/url"
			user = "user1"
			pass = "123"
			self_signed_cert = "/a/path"
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
        assert!(ncc.self_signed_der_certificate_location == "/a/path");
    }

    #[test]
    fn nextcloud_configuration_is_filled() {
        let ncc1 =
            super::NextcloudConfiguration::new("https://localhost/nextcloud", "username".to_string(), "password".to_string(), "path")
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
        thread::spawn(move || {
            WebDavServer::start("run_col_not_exists", tx_assert, 8080);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("http://127.0.0.1:8080", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the MKCOL that creates the collection
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the PUT that creates the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that the file is ready to be downloaded
        assert!(rx.recv_timeout(timeout).unwrap().unwrap() == super::SyncStatus::UploadSuccess);

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
        thread::spawn(move || {
            WebDavServer::start("run_download_a_file_from_the_server", tx_assert, 8081);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("http://127.0.0.1:8081", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
        });

        let timeout = time::Duration::from_millis(10000);
        // Assert the PROPFIND that asks for the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());
        // Assert the Get that downlaods the file
        assert!(rx_assert.recv_timeout(timeout).unwrap());

        // Assert that the file is ready to be downloaded
        assert!(rx.recv_timeout(timeout).unwrap().unwrap() ==
                super::SyncStatus::NewAvailable("tmp_download_a_file_from_the_server".to_string()));

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
        thread::spawn(move || {
            WebDavServer::start("run_http_error_response_on_propfind", tx_assert, 8082);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("http://127.0.0.1:8082", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
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
        thread::spawn(move || {
            WebDavServer::start("run_http_error_response_on_mkcol", tx_assert, 8083);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("http://127.0.0.1:8083", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
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
        thread::spawn(move || {
            WebDavServer::start("run_http_error_response_on_put", tx_assert, 8084);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("http://127.0.0.1:8084", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
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
        thread::spawn(move || {
            WebDavServer::start("run_http_error_response_on_get", tx_assert, 8085);
        });

        // Execute the synchronizer
        let password = "password".to_string();
        let (tx, rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let nc = super::Synchronizer::new("http://127.0.0.1:8085", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
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
        let nc = super::Synchronizer::new("http://127.0.0.1:8081", "username".to_string(), password.clone(), "", tx, filename).unwrap();
        thread::spawn(move || {
            nc.execute();
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
			 <d:response>
			  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/afilename</d:href>
			  <d:propstat>
			   <d:prop>
			    <d:getlastmodified>Thu, 30 Nov 2017 14:09:58 GMT</d:getlastmodified>
			    <d:getcontentlength>205</d:getcontentlength>
			    <d:resourcetype/>
			    <d:getetag>&quot;6ec537df6db0d41af34c14c527a1c6d9&quot;</d:getetag>
			    <d:getcontenttype>application/octet-stream</d:getcontenttype>
			   </d:prop>
			   <d:status>HTTP/1.1 200 OK</d:status>
			  </d:propstat>
			 </d:response>
			</d:multistatus>
    	"#;

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().href == "/nextcloud/remote.php/dav/files/user/.rust-keylock/afilename");
        assert!(res.as_ref().unwrap().last_modified == "Thu, 30 Nov 2017 14:09:58 GMT");
        assert!(res.as_ref().unwrap().status == "HTTP/1.1 200 OK");
    }

    #[test]
    fn parse_xml_error_no_file_element_is_present() {
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
        // The file element is not present (getLastModified)
        let xml = r#"
	    	<?xml version="1.0"?>
			<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
			 <d:response>
			  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/afilename</d:href>
			  <d:propstat>
			   <d:prop>
			    <!-- <d:getlastmodified>Thu, 30 Nov 2017 14:09:58 GMT</d:getlastmodified> -->
			    <d:getcontentlength>205</d:getcontentlength>
			    <d:resourcetype/>
			    <d:getetag>&quot;6ec537df6db0d41af34c14c527a1c6d9&quot;</d:getetag>
			    <d:getcontenttype>application/octet-stream</d:getcontenttype>
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
    fn parse_xml_error_in_web_dav_response() {
        let filename = "afilename";
        // The file element is not present (getLastModified)
        let xml = r#"
	    	<?xml version="1.0"?>
			<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
			 <d:response>
			  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/afilename</d:href>
			  <d:propstat>
			   <d:prop>
			    <d:getlastmodified>Thu, 30 Nov 2017 14:09:58 GMT</d:getlastmodified>
			    <d:getcontentlength>205</d:getcontentlength>
			    <d:resourcetype/>
			    <d:getetag>&quot;6ec537df6db0d41af34c14c527a1c6d9&quot;</d:getetag>
			    <d:getcontenttype>application/octet-stream</d:getcontenttype>
			   </d:prop>
			   <d:status>HTTP/1.1 400 Bad Request</d:status>
			  </d:propstat>
			 </d:response>
			</d:multistatus>
    	"#;

        let res = super::Synchronizer::parse_xml(xml.as_bytes(), filename);

        assert!(res.is_err());
    }

    #[test]
    // Note: the test will fail on 01/12 of year 2117 ;-)
    fn parse_web_dav_response() {
        let filename = "parse_web_dav_response";
        create_file_with_contents(filename, "This is a test file");

        let wdr1 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "Thu, 30 Nov 2017 14:09:58 GMT".to_string(),
            status: "not needed".to_string(),
        };
        let res1 = super::Synchronizer::parse_web_dav_response(&wdr1, filename);
        assert!(res1.is_ok());
        assert!(res1.as_ref().unwrap() == &isize::from(1 as i8));

        let wdr2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "Thu, 30 Nov 2117 14:09:58 GMT".to_string(),
            status: "not needed".to_string(),
        };
        let res2 = super::Synchronizer::parse_web_dav_response(&wdr2, filename);
        assert!(res2.is_ok());
        assert!(res2.as_ref().unwrap() == &isize::from(-1 as i8));

        delete_file(filename);
    }

    /// This is an WebDav server for testing the nextcloud client
    ///
    /// It accepts a command in order to understand the testing scenario and a tx to notfy the test method for assertions
    struct WebDavServer {
        command: &'static str,
        tx_assert: Sender<bool>,
    }

    impl WebDavServer {
        pub fn start(command: &'static str, tx: Sender<bool>, port: isize) {
            let addr = format!("127.0.0.1:{}", port).parse().unwrap();
            let server = Http::new()
                .bind(&addr, move || {
                    Ok(WebDavServer {
                        command: command,
                        tx_assert: tx.clone(),
                    })
                })
                .unwrap();
            server.run().unwrap();
        }
    }

    impl Service for WebDavServer {
        type Request = Request;
        type Response = Response;
        type Error = hyper::Error;
        type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

        fn call(&self, req: Request) -> Self::Future {
            match self.command {
                "run_col_not_exists" => {
                    if req.method() == &hyper::Method::Extension("PROPFIND".to_string()) {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::NotFound)))
                    } else if req.method() == &hyper::Method::Extension("MKCOL".to_string()) {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::Ok)))
                    } else if req.method() == &hyper::Method::Put {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::Ok)))
                    } else {
                        let _ = self.tx_assert.send(false);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    }
                }
                "run_download_a_file_from_the_server" => {
                    if req.method() == &hyper::Method::Extension("PROPFIND".to_string()) {
                        let _ = self.tx_assert.send(true);
                        let xml = r#"
					    	<?xml version="1.0"?>
							<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
							 <d:response>
							  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/download_a_file_from_the_server</d:href>
							  <d:propstat>
							   <d:prop>
							    <d:getlastmodified>Thu, 30 Nov 2117 14:09:58 GMT</d:getlastmodified>
							    <d:getcontentlength>205</d:getcontentlength>
							    <d:resourcetype/>
							    <d:getetag>&quot;6ec537df6db0d41af34c14c527a1c6d9&quot;</d:getetag>
							    <d:getcontenttype>application/octet-stream</d:getcontenttype>
							   </d:prop>
							   <d:status>HTTP/1.1 200 OK</d:status>
							  </d:propstat>
							 </d:response>
							</d:multistatus>
				    	"#;
                        Box::new(futures::future::ok(Response::new()
                            .with_status(hyper::StatusCode::MultiStatus)
                            .with_body(xml)))
                    } else if req.method() == &hyper::Method::Get {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new()
                            .with_status(hyper::StatusCode::MultiStatus)
                            .with_body("This is a file from the server")))
                    } else {
                        let _ = self.tx_assert.send(false);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    }
                }
                "run_http_error_response_on_propfind" => {
                    if req.method() == &hyper::Method::Extension("PROPFIND".to_string()) {
                        let _ = self.tx_assert.send(true);
                    }
                    Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                }
                "run_http_error_response_on_mkcol" => {
                    if req.method() == &hyper::Method::Extension("PROPFIND".to_string()) {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::NotFound)))
                    } else if req.method() == &hyper::Method::Extension("MKCOL".to_string()) {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    } else {
                        let _ = self.tx_assert.send(false);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    }
                }
                "run_http_error_response_on_put" => {
                    if req.method() == &hyper::Method::Extension("PROPFIND".to_string()) {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::NotFound)))
                    } else if req.method() == &hyper::Method::Extension("MKCOL".to_string()) {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::Ok)))
                    } else if req.method() == &hyper::Method::Put {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    } else {
                        let _ = self.tx_assert.send(false);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    }
                }
                "run_http_error_response_on_get" => {
                    if req.method() == &hyper::Method::Extension("PROPFIND".to_string()) {
                        let _ = self.tx_assert.send(true);
                        let xml = r#"
					    	<?xml version="1.0"?>
							<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
							 <d:response>
							  <d:href>/nextcloud/remote.php/dav/files/user/.rust-keylock/http_error_response_on_get</d:href>
							  <d:propstat>
							   <d:prop>
							    <d:getlastmodified>Thu, 30 Nov 2117 14:09:58 GMT</d:getlastmodified>
							    <d:getcontentlength>205</d:getcontentlength>
							    <d:resourcetype/>
							    <d:getetag>&quot;6ec537df6db0d41af34c14c527a1c6d9&quot;</d:getetag>
							    <d:getcontenttype>application/octet-stream</d:getcontenttype>
							   </d:prop>
							   <d:status>HTTP/1.1 200 OK</d:status>
							  </d:propstat>
							 </d:response>
							</d:multistatus>
				    	"#;
                        Box::new(futures::future::ok(Response::new()
                            .with_status(hyper::StatusCode::MultiStatus)
                            .with_body(xml)))
                    } else if req.method() == &hyper::Method::Get {
                        let _ = self.tx_assert.send(true);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    } else {
                        let _ = self.tx_assert.send(false);
                        Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
                    }
                }
                _ => {
                    let _ = self.tx_assert.send(false);
                    Box::new(futures::future::ok(Response::new().with_status(hyper::StatusCode::BadRequest)))
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

    fn delete_file(name: &str) {
        let path_buf = file_handler::default_toml_path(name);
        let path = path_buf.to_str().unwrap();
        assert!(fs::remove_file(path).is_ok());
    }
}
