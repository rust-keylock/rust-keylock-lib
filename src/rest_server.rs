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

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

type Counter = i32;

use crate::errors;

pub(crate) async fn init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = ([127, 0, 0, 1], 9876).into();

    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    let svc = Svc {
        counter: Arc::new(Mutex::new(0)),
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc_clone = svc.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Debug, Clone)]
struct Svc {
    counter: Arc<Mutex<Counter>>,
}

impl Service<Request<IncomingBody>> for Svc {
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

        let res = async {match (req.method(), req.uri().path()) {
            // (&Method::GET, "/") => async {mk_response(format!("home! counter = {:?}", self.counter))},
            (&Method::POST, "/pake") => {
                    let key = do_pake(req).await.unwrap();
                    mk_response_bytes(key)
            },
            _ => mk_response("not found".to_string()),
        }};

        Box::pin(res)
    }
}

async fn do_pake(req: Request<IncomingBody>) -> errors::Result<Vec<u8>> {
    debug!("Executing PAKE");
    let inbound_msg = req.collect().await?.to_bytes();
    let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(b"patates"),
        &Identity::new(b"rust-keylock-browser-extension"),
        &Identity::new(b"rust-keylock-lib"),
    );

    let key = s1.finish(&inbound_msg).unwrap();
    debug!("Generated outbound bytestring");

    debug!("Key generated");
    debug!("key: {:x?}", key);

    Ok(outbound_msg)
}
