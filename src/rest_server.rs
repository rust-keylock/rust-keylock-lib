// Copyright 2025 astonbitecode
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
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use rand::{thread_rng, Rng};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::form_urlencoded;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, sync::MutexGuard};

type Counter = usize;
const TICKET_HEADER: &str = "ticket";

use crate::{
    errors::{self, RustKeylockError},
    Entry, Safe,
};

lazy_static! {
    static ref SESSION_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref COUNTER: Mutex<Counter> = Mutex::new(0);
    static ref LOST_COUNTS: Mutex<Vec<Counter>> = Mutex::new(Vec::new());
}

fn get_session_key_opt() -> Option<Vec<u8>> {
    SESSION_KEY.lock().expect("Session Key is poisoned").clone()
}

fn get_session_key() -> Vec<u8> {
    get_session_key_opt().expect("Session key is not established yet")
}

fn set_session_key(key: Vec<u8>) {
    let mut session_key_opt = SESSION_KEY
        .lock()
        .expect("Session Key is poisoned during setting");
    *session_key_opt = Some(key);
}

fn get_counter() -> MutexGuard<'static, Counter> {
    COUNTER.lock().expect("Counter is poisoned")
}

fn get_lost_counts() -> MutexGuard<'static, Vec<Counter>> {
    LOST_COUNTS.lock().expect("Lost Counts is poisoned")
}

#[derive(Clone)]
pub(crate) struct RestService {
    listener: Arc<TcpListener>,
    safe: Arc<Mutex<Option<Safe>>>,
    token: Arc<Mutex<String>>,
}

impl RestService {
    pub(crate) async fn new() -> errors::Result<Self> {
        let addr: SocketAddr = ([127, 0, 0, 1], 9876).into();
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on http://{}", addr);

        Ok(RestService {
            listener: Arc::new(listener),
            safe: Arc::new(Mutex::new(None)),
            token: Arc::new(Mutex::new("".to_string())),
        })
    }

    pub(crate) async fn serve(&mut self) -> errors::Result<JoinHandle<()>> {
        let (stream, _) = self.listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc_clone = self.clone();
        Ok(tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                println!("Failed to serve connection: {:?}", err);
            }
        }))
    }

    pub(crate) fn update_safe(&self, safe: Safe) -> errors::Result<()> {
        *self.safe.lock()? = Some(safe);
        Ok(())
    }

    pub(crate) fn update_token(&self, token: String) -> errors::Result<()> {
        *self.token.lock()? = token;
        Ok(())
    }
}

impl Service<Request<IncomingBody>> for RestService {
    type Response = Response<Full<Bytes>>;
    type Error = errors::RustKeylockError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        fn mk_response_bytes(bytes: Vec<u8>) -> errors::Result<Response<Full<Bytes>>> {
            let encrypted = encrypt(&get_session_key(), &bytes)?;
            Ok(Response::builder().body(Full::new(encrypted.into()))?)
        }

        fn mk_response_bytes_with_ticket_header(
            bytes: Vec<u8>,
            ticket: Counter,
        ) -> errors::Result<Response<Full<Bytes>>> {
            let key = get_session_key();
            let encrypted_ticket = encrypt_to_base_64(&key, ticket.to_string().as_bytes())?;
            Ok(Response::builder()
                .header(TICKET_HEADER, encrypted_ticket)
                .body(Full::new(bytes.into()))?)
        }

        fn mk_403_response() -> errors::Result<Response<Full<Bytes>>> {
            Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Vec::new().into()))?)
        }

        fn mk_404_response() -> errors::Result<Response<Full<Bytes>>> {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Vec::new().into()))?)
        }

        fn mk_400_response() -> Response<Full<Bytes>> {
            let mut r = Response::new(Vec::new().into());
            let s = r.status_mut();
            *s = StatusCode::BAD_REQUEST;
            r
        }

        if req.uri().path() != "/pake" {
            if get_session_key_opt().is_none() {
                return Box::pin(std::future::ready(
                    mk_403_response().or_else(|_| Ok(mk_400_response())),
                ));
            }
            let mut counter = get_counter();
            let mut lost_counters = get_lost_counts();
            if let Err(_) = handle_headers(req.headers(), &mut counter, &mut lost_counters) {
                return Box::pin(std::future::ready(
                    mk_403_response().or_else(|_| Ok(mk_400_response())),
                ));
            }
        }

        let safe_opt = self.safe.lock().expect("Safe poisoned").clone();
        let token_clone = self.token.lock().expect("Token poisoned").clone();
        let res = async move {
            match (req.method(), req.uri().path(), req.uri().query()) {
                (&Method::POST, "/pake", _) => {
                    debug!("Initializing pake...");
                    let outbound_key = do_pake(req, &token_clone).await?;

                    let mut counter = get_counter();
                    let random_initial_counter = thread_rng().gen_range(0..100000);
                    debug!("Initializing counter to {random_initial_counter}");
                    *counter = random_initial_counter;

                    mk_response_bytes_with_ticket_header(outbound_key, *counter)
                }
                (&Method::GET, "/entries", query_opt) => {
                    debug!("Getting entries...");
                    let resp_string = match safe_opt {
                        Some(mut safe) => {
                            safe.set_filter("".to_string());
                            if let Some(query) = query_opt {
                                let params = form_urlencoded::parse(query.as_bytes())
                                    .into_owned()
                                    .collect::<HashMap<String, String>>();
                                if let Some(f) = params.get("filter") {
                                    debug!("Using filter {f}");
                                    safe.set_filter(f.to_string());
                                }
                            }
                            serde_json::to_string(&safe.get_entries())?
                        }
                        None => "Not loaded yet".to_string(),
                    };
                    mk_response_bytes(resp_string.into_bytes())
                }
                (&Method::GET, path, _) if path.starts_with("/decrypted") => {
                    debug!("Getting decrypted: {path}");
                    let resp_string = match safe_opt {
                        Some(mut safe) => {
                            safe.set_filter("".to_string());
                            let name_to_find = path.replace("/decrypted/", "");
                            debug!("Searching for name: {name_to_find}");
                            let found_entries: Vec<Entry> = safe
                                .get_entries()
                                .iter()
                                .enumerate()
                                .filter(|(_, entry)| entry.name == name_to_find)
                                .map(|(pos, _)| safe.get_entry_decrypted(pos))
                                .collect();
                            debug!("Found {} entries", found_entries.len());
                            serde_json::to_string(&found_entries)?
                        }
                        None => "Not loaded yet".to_string(),
                    };
                    mk_response_bytes(resp_string.into_bytes())
                }
                _ => mk_404_response(),
            }
        };

        Box::pin(res)
    }
}

fn handle_headers(
    headers: &HeaderMap<HeaderValue>,
    counter: &mut usize,
    lost_counters: &mut Vec<usize>,
) -> errors::Result<()> {
    if let Some((_, header_value)) = headers
        .clone()
        .iter()
        .find(|(h_name, _)| TICKET_HEADER == h_name.as_str())
    {
        let ticket_str = header_value
            .to_str()
            .map_err(|_| errors::RustKeylockError::ParseError(format!("Ticket header not valid")))
            .and_then(|s| {
                let key = get_session_key();
                decrypt_base_64(&key, s)
            })
            .and_then(|decrypted_bytes| Ok(String::from_utf8(decrypted_bytes)?))
            .map_err(|_| {
                RustKeylockError::ParseError("Ticket is not valid UTF string".to_string())
            })?;
        let received_ticket: usize = ticket_str.parse::<usize>()?;

        if received_ticket == *counter + 1 {
            debug!("Ticket is valid as expected");
            *counter += 1;
        } else if lost_counters.contains(&received_ticket) {
            debug!("Ticket found in lost counters");
            let index = lost_counters
                .iter()
                .position(|x| *x == received_ticket)
                .ok_or(errors::RustKeylockError::ParseError(
                    "Ticket not found".to_string(),
                ))?;
            lost_counters.remove(index);
        } else if received_ticket > *counter + 1 {
            debug!("Ticket is bigger than expected");
            let mut v: Vec<usize> = (*counter + 1..received_ticket).collect();
            lost_counters.append(&mut v);
            *counter = received_ticket;
        } else {
            warn!("Ticket out of order");
            return Err(errors::RustKeylockError::ParseError(
                "Ticket out of order".to_string(),
            ));
        }
    } else {
        warn!("Ticket header not found");
        return Err(errors::RustKeylockError::ParseError(
            "Ticket header not found".to_string(),
        ));
    }
    Ok(())
}

async fn do_pake(req: Request<IncomingBody>, token: &str) -> errors::Result<Vec<u8>> {
    debug!("Executing PAKE");
    let inbound_msg = req.collect().await?.to_bytes();
    let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(token),
        &Identity::new(b"rust-keylock-browser-extension"),
        &Identity::new(b"rust-keylock-lib"),
    );

    let key = s1.finish(&inbound_msg)?;
    debug!("Generated outbound bytestring");

    debug!("Key generated");
    set_session_key(key);

    Ok(outbound_msg)
}

fn encrypt(key: &[u8], data: &[u8]) -> errors::Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data)?;
    let to_ret = [nonce.to_vec(), ciphertext].concat();
    Ok(to_ret)
}

fn encrypt_to_base_64(key: &[u8], data: &[u8]) -> errors::Result<String> {
    let encrypted_bytes = encrypt(key, data)?;
    Ok(general_purpose::STANDARD.encode(&encrypted_bytes))
}

fn decrypt_base_64(key: &[u8], product: &str) -> errors::Result<Vec<u8>> {
    let encrypted_bytes = general_purpose::STANDARD.decode(&product)?;
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    if product.len() > 12 {
        let (nonce, data) = encrypted_bytes.split_at(12);
        let plain = cipher.decrypt(Nonce::from_slice(nonce), data)?;
        Ok(plain)
    } else {
        Err(errors::RustKeylockError::DecryptionError(
            "Error during decryption. Unexpected bytes to decrypt".to_string(),
        ))
    }
}

#[cfg(test)]
mod rest_server_tests {
    use super::*;

    lazy_static! {
        static ref SYNC_GUARD: Mutex<()> = Mutex::new(());
    }

    fn init_tests() {
        let _guard = SYNC_GUARD.lock().unwrap();
        let b = { SESSION_KEY.lock().expect("Session Key is poisoned").clone() };
        if let None = b {
            let r = crate::datacrypt::create_random(32);
            println!("Creating new session key...{:x?}", r);
            set_session_key(r);
        }
    }

    fn get_encrypted_base_64_header_value(s: &str) -> HeaderValue {
        encrypt_to_base_64(&get_session_key(), s.as_bytes())
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn encrypt_decrypt_plus_base_64() {
        init_tests();
        let plain = "plaintext";
        let encrypted_res = encrypt_to_base_64(&get_session_key(), plain.as_bytes());
        assert!(encrypted_res.is_ok());
        let retrieved_plain_res =
            decrypt_base_64(&get_session_key(), encrypted_res.unwrap().as_str());
        assert!(retrieved_plain_res.is_ok());
        let retrieved_plain_str = String::from_utf8(retrieved_plain_res.unwrap()).unwrap();
        assert_eq!(retrieved_plain_str, plain);
    }

    #[test]
    fn handle_headers_fail_without_counter_header() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let headers = HeaderMap::new();

        let res = handle_headers(&headers, &mut counter, &mut lost_counters);
        assert!(res.is_err(), "{:?} was not en error", res);
        assert_eq!(counter, 1000);
        assert!(lost_counters.is_empty())
    }

    #[test]
    fn handle_headers_fail_with_empty_counter_header() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let mut headers = HeaderMap::new();
        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value(""));

        let res = handle_headers(&headers, &mut counter, &mut lost_counters);
        assert!(res.is_err(), "{:?} was not en error", res);
        assert_eq!(counter, 1000);
        assert!(lost_counters.is_empty())
    }

    #[test]
    fn handle_headers_fail_with_counter_header_not_a_usize() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let mut headers = HeaderMap::new();
        headers.insert(
            TICKET_HEADER,
            get_encrypted_base_64_header_value("A string"),
        );

        let res = handle_headers(&headers, &mut counter, &mut lost_counters);
        assert!(res.is_err(), "{:?} was not en error", res);
        assert_eq!(counter, 1000);
        assert!(lost_counters.is_empty())
    }

    #[test]
    fn handle_headers_succeed_expected_counter() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let mut headers = HeaderMap::new();
        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value("1001"));

        let res = handle_headers(&headers, &mut counter, &mut lost_counters);
        assert!(res.is_ok(), "{:?} was not ok", res);
        assert_eq!(counter, 1001);
        assert!(lost_counters.is_empty())
    }

    #[test]
    fn handle_headers_succeed_counter_bigger_than_expected() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let mut headers = HeaderMap::new();
        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value("1002"));

        let res = handle_headers(&headers, &mut counter, &mut lost_counters);
        assert!(res.is_ok(), "{:?} was not ok", res);
        assert_eq!(counter, 1002);
        assert!(lost_counters.contains(&1001));
        assert_eq!(lost_counters.len(), 1);
    }

    #[test]
    fn handle_headers_succeed_counter_bigger_than_expected_2() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let mut headers = HeaderMap::new();
        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value("1002"));
        let _ = handle_headers(&headers, &mut counter, &mut lost_counters);

        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value("1003"));
        let _ = handle_headers(&headers, &mut counter, &mut lost_counters);

        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value("1005"));
        let res = handle_headers(&headers, &mut counter, &mut lost_counters);

        assert!(res.is_ok(), "{:?} was not ok", res);
        assert_eq!(counter, 1005);
        assert!(lost_counters.contains(&1001));
        assert!(lost_counters.contains(&1004));
        assert_eq!(lost_counters.len(), 2);
    }

    #[test]
    fn handle_headers_counter_out_of_order() {
        init_tests();
        let mut counter: usize = 1000;
        let mut lost_counters: Vec<usize> = Vec::new();
        let mut headers = HeaderMap::new();
        headers.insert(TICKET_HEADER, get_encrypted_base_64_header_value("999"));

        let res = handle_headers(&headers, &mut counter, &mut lost_counters);
        assert!(res.is_err(), "{:?} was ok", res);
        assert_eq!(counter, 1000);
        assert!(lost_counters.is_empty())
    }
}
