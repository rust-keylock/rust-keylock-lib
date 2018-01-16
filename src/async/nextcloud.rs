use std::sync::mpsc::Sender;
use std::str::FromStr;
use super::super::SystemConfiguration;
use super::super::{errors, file_handler};
use super::super::datacrypt::EntryPasswordCryptor;
use std::fs::File;
use std::io::prelude::*;
use futures::{Future, Stream};
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
#[allow(unused_imports)]
use native_tls::backend::openssl::TlsConnectorBuilderExt;
#[cfg(target_os = "android")]
use openssl;
#[cfg(target_os = "android")]
use std::fs;

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
                                              ncc.self_signed_der_certificate_location.clone())?;
        let s = Synchronizer {
            conf: ncc,
            tx: tx,
            file_name: f.to_string(),
            saved_at_local: sys_conf.saved_at,
            version_local: sys_conf.version,
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
        } else if cfg!(target_os = "android") && self.conf.server_url.starts_with("https://") {
            // Use HTTPS in Android
            debug!("The Nextcloud async task uses HTTPS connector in Android");
            Self::connect_with_https_android(&handle)?
        } else if self.conf.self_signed_der_certificate_location.len() > 0 {
            // Use HTTPS with a self signed certificate
            debug!("The Nextcloud async task uses HTTPS connector with a self-signed certificate located at {}",
                   &self.conf.self_signed_der_certificate_location);
            Self::connect_with_https_self_signed(&handle, &self.conf.self_signed_der_certificate_location)?
        } else {
            // Use HTTPS
            debug!("The Nextcloud async task uses HTTPS connector");
            Self::connect_with_https(&handle)?
        };

        let uri = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", self.conf.server_url, self.conf.username, self.file_name).parse()?;
        debug!("Syncing with {}", uri);

        let mut headers = Headers::new();
        headers.set(Authorization(Basic {
            username: self.conf.username.to_owned(),
            password: Some(self.use_password()?),
        }));

        let mut req: Request = Request::new(hyper::Method::Extension("PROPFIND".to_string()), uri);
        *req.headers_mut() = headers;
        // Set the body of the request so that it returns the oc:rklsavedat and oc:rklversion properties
        let xml_body = r#"<d:propfind xmlns:d="DAV:"><d:prop xmlns:oc="http://owncloud.org/ns"><oc:rklsavedat/><oc:rklversion/></d:prop></d:propfind>"#;
        req.set_body(xml_body.as_bytes());

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
                if self.version_local.is_some() {
                    info!("Creating rust-keylock-resources on the server");
                    Self::create_rust_keylock_col(&self.conf.username, self.use_password()?, &self.conf.server_url, &client, &mut core)?;
                    Self::put(&self.conf.username,
                              self.use_password()?,
                              &self.conf.server_url,
                              &client,
                              &mut core,
                              &self.file_name,
                              &self.saved_at_local,
                              &self.version_local)?;
                    Ok(SyncStatus::UploadSuccess)
                } else {
                    debug!("Resources not found on the server, but nothing is yet saved locally. Save needs to be performed first.");
                    Ok(SyncStatus::None)
                }
            }
            Some(hyper::StatusCode::MultiStatus) => {
                debug!("Parsing nextcoud response");
                let web_dav_resp = Self::parse_xml(resp_bytes.as_slice(), &self.file_name)?;
                match Self::parse_web_dav_response(&web_dav_resp, &self.file_name, &self.saved_at_local, &self.version_local)? {
                    ParseWebDavResponse::Download => {
                        info!("Downloading file from the server");
                        let tmp_file_name = Self::get(&self.conf.username,
                                                      self.use_password()?,
                                                      &self.conf.server_url,
                                                      &client,
                                                      &mut core,
                                                      &self.file_name)?;
                        Ok(SyncStatus::NewAvailable(tmp_file_name))
                    }
                    ParseWebDavResponse::Ignore => {
                        debug!("No sync is needed");
                        Ok(SyncStatus::None)
                    }
                    ParseWebDavResponse::Upload => {
                        info!("Uploading file on the server");
                        Self::put(&self.conf.username,
                                  self.use_password()?,
                                  &self.conf.server_url,
                                  &client,
                                  &mut core,
                                  &self.file_name,
                                  &self.saved_at_local,
                                  &self.version_local)?;
                        Ok(SyncStatus::UploadSuccess)
                    }
                    ParseWebDavResponse::DownloadMergeAndUpload => Ok(SyncStatus::None),
                }
            }
            Some(other) => Err(errors::RustKeylockError::SyncError(format!("Encountered WebDav error response: {:?}", other))),
            None => Err(errors::RustKeylockError::SyncError("Could not execute sync http request".to_string())),
        }
    }

    /// Returns the action that should be taken after parsing a Webdav response
    ///
    /// Algorithm: (The _bigger_, _smaller_ and _equal_ words represent values for comparing saved_at_local with saved_at_server and version_local with version_server)
    ///
    /// | version_local | version_server | saved_at_local | saved_at_server |            Action
    /// | :-----------: | :------------: | :------------: | :-------------: | :------------------------:
    /// | bigger        | smaller        | *              | *               | Upload
    /// | smaller       | bigger         | *              | *               | Download
    /// | equal         | equal          | bigger         | smaller         | Download, Merge and Upload
    /// | equal         | equal          | smaller        | bigger          | Download, Merge and Upload
    /// | equal         | equal          | equal          | equal           | Ignore
    /// | None          | *              | *              | *               | Download
    fn parse_web_dav_response(web_dav_response: &WebDavResponse,
                              filename: &str,
                              saved_at_local: &Option<i64>,
                              version_local: &Option<i64>)
                              -> errors::Result<ParseWebDavResponse> {

        debug!("The file '{}' on the server was saved at {} with version {}",
               filename,
               web_dav_response.last_modified,
               web_dav_response.version);
        let saved_at_server = i64::from_str(&web_dav_response.last_modified)?;
        let version_server = i64::from_str(&web_dav_response.version)?;

        debug!("The file '{}' locally was saved at {:?} with version {:?}", filename, saved_at_local, version_local);

        match (version_local, version_server, saved_at_local, saved_at_server) {
            (&Some(vl), vs, _, _) if vl > vs => {
                debug!("The local version is bigger than the server. Need to upload");
                Ok(ParseWebDavResponse::Upload)
            }
            (&Some(vl), vs, _, _) if vl < vs => {
                debug!("The local version is smaller that the server. Need to download");
                Ok(ParseWebDavResponse::Download)
            }
            (&Some(vl), vs, &Some(sl), ss) if vl == vs && sl != ss => {
                debug!("The local and server versions are equal, but the saved_at are different. Need to download, merge and upload");
                Ok(ParseWebDavResponse::DownloadMergeAndUpload)
            }
            (&Some(vl), vs, &Some(sl), ss) if vl == vs && sl == ss => {
                debug!("Both the version and saved_at are equal locally and on the server. Ignoring...");
                Ok(ParseWebDavResponse::Ignore)
            }
            (&None, _, _, _) => {
                debug!("First time contacting the server... Need to download");
                Ok(ParseWebDavResponse::Download)
            }
            (_, _, _, _) => Ok(ParseWebDavResponse::Ignore),
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
        if stat.is_client_error() || stat.is_server_error() || stat.is_strange_status() {
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
        if stat.is_client_error() || stat.is_server_error() || stat.is_strange_status() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", stat)))
        } else {
            let tmp_file_name = format!("tmp_{}", filename);
            file_handler::save_bytes(&tmp_file_name, &resp_bytes)?;
            Ok(tmp_file_name)
        }
    }

    /// Put the file and update the property with the file creation seconds using PROPPATCH
    fn put(username: &str,
           password: String,
           server_url: &str,
           client: &Box<RequestClient>,
           core: &mut Core,
           filename: &str,
           local_saved_at: &Option<i64>,
           local_version: &Option<i64>)
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
        *req.headers_mut() = headers.clone();
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

        // PROPPATCH starts here
        let uri_pp = format!("{}/remote.php/dav/files/{}/.rust-keylock/{}", server_url, username, filename).parse()?;
        let mut req_pp: Request = Request::new(hyper::Method::Extension("PROPPATCH".to_string()), uri_pp);

        *req_pp.headers_mut() = headers;
        req_pp.headers_mut().set(header::ContentType::octet_stream());

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
        req_pp.set_body(xml_body);

        let mut resp_bytes_pp: Vec<u8> = Vec::new();
        let mut status_opt_pp = None;
        {
            let work = client.request(req_pp).and_then(|res| {
                status_opt_pp = Some(res.status());
                debug!("Response for PROPPATCH: {}", res.status());

                res.body().for_each(|chunk| {
                    resp_bytes_pp.write_all(&chunk)
                        .map(|_| ())
                        .map_err(From::from)
                })
            });

            core.run(work)?;
        }

        let stat_pp = status_opt_pp.unwrap_or(hyper::StatusCode::BadRequest);

        // Check the two statuses
        if stat.is_client_error() || stat.is_server_error() || stat.is_strange_status() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", stat)))
        } else if stat_pp.is_client_error() || stat_pp.is_server_error() || stat_pp.is_strange_status() {
            Err(errors::RustKeylockError::SyncError(format!("{:?}", stat_pp)))
        } else {
            Ok(())
        }

    }

    fn connect_with_http(handle: &Handle) -> Box<RequestClient> {
        Box::new(HttpRequestClient { client: Client::new(&handle) }) as Box<RequestClient>
    }

    fn connect_with_https(handle: &Handle) -> errors::Result<Box<RequestClient>> {
        let client = Client::configure()
            .connector(HttpsConnector::new(4, &handle)?)
            .build(&handle);

        Ok(Box::new(HttpsRequestClient { client: client }) as Box<RequestClient>)
    }

    //        fn connect_with_https_android_2(handle: &Handle) -> errors::Result<Box<RequestClient>> {
    //            let mut http = HttpConnector::new(4, &handle);
    //            http.enforce_http(false);
    //
    //            let mut tls = native_tls::TlsConnector::builder().unwrap();
    //            match fs::read_dir("/data/misc/keystore/") {
    //            	Ok(certs) => {
    //     	            for entry in certs.filter_map(|r| r.ok()).filter(|e| e.path().is_file()) {
    //     	                debug!("========Adding file {:?}", entry.path());
    //     	                let mut buffer = vec![];
    //     	                match fs::File::open(entry.path()).and_then(|mut f| f.read_to_end(&mut buffer)) {
    //     	                    Ok(_) => {
    //     	                        debug!("File read");
    //     	                        match openssl::x509::X509::from_pem(buffer.as_slice()) {
    //     	                            Ok(cert_x509) => {
    //     	                                let der_bytes = cert_x509.to_der().unwrap();
    //     	                                debug!("Transformed to DER");
    //     	                                let cert = native_tls::Certificate::from_der(&der_bytes).unwrap();
    //     	                                tls.add_root_certificate(cert).unwrap();
    //     	                                debug!("Added!");
    //     	                            }
    //     	                            Err(error) => {
    //     	                                error!("Could not transform to DER: {:?}", error);
    //     	                            }
    //     	                        }
    //     	                    }
    //     	                    Err(error) => {
    //     	                        error!("Could not retrieve certificate data: {:?}", error);
    //     	                    }
    //     	                }
    //     	            }
    //     	            debug!("Certificates added");
    //            	}
    //            	Err(error) => {
    //            		error!("Could not read certificates directory: {:?}", error);
    //            	}
    //            }
    //
    //            let tls = tls.build().unwrap();
    //
    //            let ct = HttpsConnector::from((http, tls));
    //
    //            Ok(Box::new(HttpsRequestClientSelfSignedCertificate {
    //                client: Client::configure().connector(ct).build(&handle),
    //            }) as Box<RequestClient>)
    //        }

    #[cfg(not(target_os = "android"))]
    fn connect_with_https_android(_: &Handle) -> errors::Result<Box<RequestClient>> {
        Err(errors::RustKeylockError::GeneralError("Cannot call the connect_with_https_android function in non-android environment"
            .to_string()))
    }

    #[cfg(target_os = "android")]
    fn connect_with_https_android(handle: &Handle) -> errors::Result<Box<RequestClient>> {
        let mut ssl_connector_builder = openssl::ssl::SslConnectorBuilder::new(openssl::ssl::SslMethod::tls())?;
        {
            let ref mut ssl_context_builder = *ssl_connector_builder;

            let cert_store = ssl_context_builder.cert_store_mut();

            if let Ok(certs) = fs::read_dir("/data/misc/keychain/cacerts-added") {
                for entry in certs.filter_map(|r| r.ok()).filter(|e| e.path().is_file()) {
                    debug!("Adding Certificate file {:?}", entry.path());
                    let mut cert_str = String::new();
                    if let Ok(_) = fs::File::open(entry.path()).and_then(|mut f| f.read_to_string(&mut cert_str)) {
                        match openssl::x509::X509::from_pem(cert_str.as_bytes()) {
                            Ok(cert) => {
                                let m = cert_store.add_cert(cert);
                                debug!("Added certificate: {:?}", m);
                            }
                            Err(error) => error!("Could not parse certificate: {:?}", error),
                        }
                    } else {
                        error!("Could not retrieve certificate data");
                    }
                }
            }
            if let Ok(certs) = fs::read_dir("/system/etc/security/cacerts") {
                for entry in certs.filter_map(|r| r.ok()).filter(|e| e.path().is_file()) {
                    debug!("Adding SYSTEM Certificate file {:?}", entry.path());
                    let mut cert_str = String::new();
                    if let Ok(_) = fs::File::open(entry.path()).and_then(|mut f| f.read_to_string(&mut cert_str)) {
                        match openssl::x509::X509::from_pem(cert_str.as_bytes()) {
                            Ok(cert) => {
                                let m = cert_store.add_cert(cert);
                                debug!("Added SYSTEM certificate: {:?}", m);
                            }
                            Err(error) => error!("Could not parse SYSTEM certificate: {:?}", error),
                        }
                    } else {
                        error!("Could not retrieve certificate data");
                    }
                }
            }
            debug!("Certificates added");
        }

        let tls_connector_builder: native_tls::TlsConnectorBuilder =
            native_tls::backend::openssl::TlsConnectorBuilderExt::from_openssl(ssl_connector_builder);
        let tls_connector = tls_connector_builder.build()?;
        let client = Client::configure()
            .connector(HttpsConnector::from((HttpsConnector::new(4, &handle)?, tls_connector)))
            .build(&handle);

        Ok(Box::new(AndroidHttpsRequestClient { client: client }) as Box<RequestClient>)
    }

    // 	#[cfg(target_os = "android")]
    //    fn connect_with_https_android0(handle: &Handle) -> errors::Result<Box<RequestClient>> {
    //    	let mut tls_connector_builder = native_tls::TlsConnector::builder()?;
    //    	tls_connector_builder.builder_mut().builder_mut().set_verify(openssl::ssl::SSL_VERIFY_NONE);
    //
    //        let tls_connector = tls_connector_builder.build()?;
    //        let hct = HttpsConnector::new(4, &handle)?;
    //        let mut ct = HttpsConnector::from((hct, tls_connector));
    //        ct.danger_disable_hostname_verification(true);
    //        let client = Client::configure()
    //            .connector(ct)
    //            .build(&handle);
    //
    //        Ok(Box::new(AndroidHttpsRequestClient { client: client }) as Box<RequestClient>)
    //    }

    // 	fn connect_with_https_android(handle: &Handle) -> errors::Result<Box<RequestClient>> {
    //        let mut ssl_connector_builder = openssl::ssl::SslConnectorBuilder::new(openssl::ssl::SslMethod::tls()).unwrap();
    //        {
    //            let ref mut ssl_context_builder = *ssl_connector_builder;
    //            let path = Path::new("/data/misc/keystore/gtca.pem");
    //            match ssl_context_builder.set_ca_file(&path) {
    //            	Ok(_) => debug!("CACERT WAS SET"),
    //            	Err(error) => error!("Could not set CACERT: {:?}", error),
    //            };
    //            debug!("Certificates added");
    //        }
    //
    //        let tls_connector_builder: native_tls::TlsConnectorBuilder =
    //            native_tls::backend::openssl::TlsConnectorBuilderExt::from_openssl(ssl_connector_builder);
    //        let tls_connector = tls_connector_builder.build()?;
    //        let client = Client::configure()
    //            .connector(HttpsConnector::from((HttpsConnector::new(4, &handle)?, tls_connector)))
    //            .build(&handle);
    //
    //        Ok(Box::new(AndroidHttpsRequestClient { client: client }) as Box<RequestClient>)
    //
    //    }

    fn connect_with_https_self_signed(handle: &Handle, der_path: &str) -> errors::Result<Box<RequestClient>> {
        debug!("---{:?}", der_path);
        let mut f = File::open(der_path)?;
        debug!("---2");
        let mut buffer = vec![];
        f.read_to_end(&mut buffer)?;
        debug!("---3");
        let cert = native_tls::Certificate::from_der(buffer.as_slice())?;
        debug!("---4");

        let mut http = HttpConnector::new(4, &handle);
        http.enforce_http(false);

        let mut tls = native_tls::TlsConnector::builder()?;
        tls.add_root_certificate(cert)?;
        let tls = tls.build()?;

        let mut ct = HttpsConnector::from((http, tls));
        ct.danger_disable_hostname_verification(true);

        Ok(Box::new(HttpsRequestClientSelfSignedCertificate {
            client: Client::configure().connector(ct).build(&handle),
        }) as Box<RequestClient>)
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
    /// An update is available from the nextcloud server.
    /// The String is the name of the file that is ready to be used if the user selects so.
    NewAvailable(String),
    /// The local file was uploaded to the nextcloud server.
    UploadSuccess,
    /// An update is available from the nextcloud server but instead of replacing the contents, merging needs to be done.
    /// The String is the name of the file that is ready to be used if the user selects so.
    NewToMerge(String),
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

/// A client that executes HTTPS requests in Android
#[allow(dead_code)]
struct AndroidHttpsRequestClient {
    client: hyper::Client<hyper_tls::HttpsConnector<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>>,
}

impl RequestClient for AndroidHttpsRequestClient {
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

#[derive(PartialEq, Debug)]
enum ParseWebDavResponse {
    Download,
    Upload,
    Ignore,
    DownloadMergeAndUpload,
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
    version: String,
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
    use super::super::super::{errors, file_handler, SystemConfiguration};
    use super::super::AsyncTask;
    use futures;
    use futures::future::Future;
    use hyper;
    use hyper::server::{Http, Request, Response, Service};

    #[test]
    fn synchronizer_stores_encrypted_password() {
        let password = "password".to_string();
        let (tx, _rx): (Sender<errors::Result<super::SyncStatus>>, Receiver<errors::Result<super::SyncStatus>>) = mpsc::channel();
        let ncc = super::NextcloudConfiguration::new("https://localhost/nextcloud".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, "filename").unwrap();

        assert!(nc.conf.decrypted_password().unwrap() == password)
    }

    #[test]
    fn nextcloud_configuration_stores_encrypted_password() {
        let password = "password".to_string();
        let ncc = super::NextcloudConfiguration::new("https://localhost/nextcloud".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "path".to_string())
            .unwrap();

        assert!(ncc.password != password)
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
        let new_table = ncc.to_table().unwrap();
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
        let ncc1 = super::NextcloudConfiguration::new("https://localhost/nextcloud".to_string(),
                                                      "username".to_string(),
                                                      "password".to_string(),
                                                      "path".to_string())
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
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8080".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1));

        let nc = super::Synchronizer::new(&ncc, &sys_config, tx, filename).unwrap();
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
        // Assert the PROPPATCH for the oc:rklsavedat and oc:rklversion
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
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8081".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
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
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8082".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
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
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8083".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1));

        let nc = super::Synchronizer::new(&ncc, &sys_config, tx, filename).unwrap();
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
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8084".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let sys_config = SystemConfiguration::new(Some(123), Some(1));

        let nc = super::Synchronizer::new(&ncc, &sys_config, tx, filename).unwrap();
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
        let ncc = super::NextcloudConfiguration::new("http://127.0.0.1:8085".to_string(),
                                                     "username".to_string(),
                                                     password.clone(),
                                                     "".to_string())
            .unwrap();
        let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
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
        let ncc =
            super::NextcloudConfiguration::new("http://127.0.0.1".to_string(), "username".to_string(), password.clone(), "".to_string())
                .unwrap();
        let nc = super::Synchronizer::new(&ncc, &SystemConfiguration::default(), tx, filename).unwrap();
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

        // Upload because of version (saved_at bigger locally)
        let wdr1 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "100".to_string(),
            version: "1".to_string(),
            status: "not needed".to_string(),
        };
        let res1 = super::Synchronizer::parse_web_dav_response(&wdr1, filename, &Some(133), &Some(2));
        assert!(res1.is_ok());
        assert!(res1.as_ref().unwrap() == &super::ParseWebDavResponse::Upload);

        // Upload because of version (saved_at bigger on server)
        let wdr1_2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "1".to_string(),
            status: "not needed".to_string(),
        };
        let res1_2 = super::Synchronizer::parse_web_dav_response(&wdr1_2, filename, &Some(100), &Some(2));
        assert!(res1_2.is_ok());
        assert!(res1_2.as_ref().unwrap() == &super::ParseWebDavResponse::Upload);

        // Download because of version (saved_at bigger locally)
        let wdr2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "100".to_string(),
            version: "2".to_string(),
            status: "not needed".to_string(),
        };
        let res2 = super::Synchronizer::parse_web_dav_response(&wdr2, filename, &Some(133), &Some(1));
        assert!(res2.is_ok());
        assert!(res2.as_ref().unwrap() == &super::ParseWebDavResponse::Download);

        // Download because of version (saved_at bigger on server)
        let wdr2_2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "2".to_string(),
            status: "not needed".to_string(),
        };
        let res2_2 = super::Synchronizer::parse_web_dav_response(&wdr2_2, filename, &Some(100), &Some(1));
        assert!(res2_2.is_ok());
        assert!(res2_2.as_ref().unwrap() == &super::ParseWebDavResponse::Download);

        // Download merge and upload because of saved_at bigger locally
        let wdr3 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "100".to_string(),
            version: "1".to_string(),
            status: "not needed".to_string(),
        };
        let res3 = super::Synchronizer::parse_web_dav_response(&wdr3, filename, &Some(133), &Some(1));
        assert!(res3.is_ok());
        assert!(res3.as_ref().unwrap() == &super::ParseWebDavResponse::DownloadMergeAndUpload);

        // Download merge and upload because of saved_at bigger on the server
        let wdr3_2 = super::WebDavResponse {
            href: "not needed".to_string(),
            last_modified: "133".to_string(),
            version: "1".to_string(),
            status: "not needed".to_string(),
        };
        let res3_2 = super::Synchronizer::parse_web_dav_response(&wdr3_2, filename, &Some(100), &Some(1));
        assert!(res3_2.is_ok());
        assert!(res3_2.as_ref().unwrap() == &super::ParseWebDavResponse::DownloadMergeAndUpload);

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
                    } else if req.method() == &hyper::Method::Extension("PROPPATCH".to_string()) {
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
							    <oc:rklsavedat>4667760000</oc:rklsavedat>
							    <oc:rklversion>1</oc:rklversion>
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
							    <oc:rklsavedat>4667760000</oc:rklsavedat>
							    <oc:rklversion>1</oc:rklversion>
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
/*
From https://users.rust-lang.org/t/tls-sockets-without-certificate-validation/13929/4:

It’s also possible to do it through native-tls if one uses a backend-specific connector builder:

extern crate native_tls;
extern crate openssl;

use native_tls::TlsConnector;
use native_tls::backend::openssl::TlsConnectorBuilderExt;
use openssl::ssl::SSL_VERIFY_NONE;

...
let mut builder = TlsConnector::builder()?;
builder.builder_mut().builder_mut().set_verify(SSL_VERIFY_NONE);
let connector = builder.build()?;
...

The connection must be opened with the danger_connect...() method for SSL_VERIFY_NONE to have effect.

This has to be hidden behind some kind of #[cfg(...)] if you’re writing cross-platform code, since there’s no equivalent functionality for non-OpenSSL backends I’m aware of.
*/