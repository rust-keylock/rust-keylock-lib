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
use bytes::Bytes;
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use log::{debug, info};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::form_urlencoded;

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

type Counter = i32;

use crate::{errors, Entry, Safe};

#[derive(Clone)]
pub(crate) struct RestService {
    listener: Arc<TcpListener>,
    counter: Arc<Mutex<Counter>>,
    safe: Arc<Mutex<Option<Safe>>>,
}

impl RestService {
    pub(crate) async fn new() -> errors::Result<Self> {
        let addr: SocketAddr = ([127, 0, 0, 1], 9876).into();
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on http://{}", addr);

        Ok(RestService {
            listener: Arc::new(listener),
            counter: Arc::new(Mutex::new(0)),
            safe: Arc::new(Mutex::new(None)),
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
}

impl Service<Request<IncomingBody>> for RestService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        fn mk_response(s: String) -> Result<Response<Full<Bytes>>, hyper::Error> {
            Ok(Response::builder().body(Full::new(Bytes::from(s))).unwrap())
        }

        fn mk_response_bytes(bytes: Vec<u8>) -> Result<Response<Full<Bytes>>, hyper::Error> {
            Ok(Response::builder().body(Full::new(bytes.into())).unwrap())
        }

        if req.uri().path() != "/favicon.ico" {
            *self.counter.lock().expect("lock poisoned") += 1;
        }

        let safe_opt = self.safe.lock().expect("Safe poisoned").clone();
        let res = async move {
            match (req.method(), req.uri().path(), req.uri().query()) {
                // (&Method::GET, "/") => async {mk_response(format!("home! counter = {:?}", self.counter))},
                (&Method::POST, "/pake", _) => {
                    let key = do_pake(req).await.unwrap();
                    mk_response_bytes(key)
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
                            serde_json::to_string(&safe.get_entries()).unwrap()
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
                            serde_json::to_string(&found_entries).unwrap()
                        }
                        None => "Not loaded yet".to_string(),
                    };
                    mk_response_bytes(resp_string.into_bytes())
                }
                _ => mk_response("not found".to_string()),
            }
        };

        Box::pin(res)
    }
}

async fn do_pake(req: Request<IncomingBody>) -> errors::Result<Vec<u8>> {
    debug!("Executing PAKE");
    let inbound_msg = req.collect().await?.to_bytes();
    let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(b"password"),
        &Identity::new(b"rust-keylock-browser-extension"),
        &Identity::new(b"rust-keylock-lib"),
    );

    let key = s1.finish(&inbound_msg).unwrap();
    debug!("Generated outbound bytestring");

    debug!("Key generated");
    debug!("key: {:x?}", key);

    Ok(outbound_msg)
}
