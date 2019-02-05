// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
A (mostly) pure-Rust implementation of various common cryptographic algorithms.
Fork of [Rust-Crypto by DaGenix: https://github.com/DaGenix/rust-crypto](https://github.com/DaGenix/rust-crypto "Rust-Crypto").

This fork aims to maintain Rust-Crypto because it is unmainained.

Rust-Crypto seeks to create practical, auditable, pure-Rust implementations of common cryptographic
algorithms with a minimum amount of assembly code where appropriate. The x86-64, x86, and
ARM architectures are supported, although the x86-64 architecture receives the most testing.

Rust-Crypto targets the current, stable build of Rust.
If you are having issues while using an older version, please try upgrading to the latest stable.

__Warning__: Rust-crypto-maintained has not been thoroughly
audited for correctness, so any use where security is important is not recommended at this time.

## Usage

Rust-crypto-maintained isn't yet uploaded to crates.io.
To use Rust-crypto-maintained, add the following to your Cargo.toml:

```toml
[dependencies]
rust-crypto-maintained = { git = "https://github.com/niluxv/rust-crypto", branch = "stable_0.2" }
```

and the following to your crate root:

```rust
extern crate crypto;
```

## Algorithms

Rust-crypto-maintained supports the same algorithems as Rust-Crypto. Currently supported algorithms include:

* AES
* Bcrypt
* BLAKE2b
* BLAKE2s
* Blowfish
* ChaCha20
* Curve25519
* ECB, CBC, and CTR block cipher modes
* Ed25519
* Fortuna
* Ghash
* HC128
* HMAC
* MD5
* PBKDF2
* PKCS padding for CBC block cipher mode
* Poly1305
* RC4
* RIPEMD-160
* Salsa20 and XSalsa20
* Scrypt
* Sha1
* Sha2 (All fixed output size variants)
* Sha3
* Sosemanuk
* Whirlpool
*/

#![allow(unused_parens)]

#![deny(unsafe_code)] // unsafe code is allowed on a per module basis

#![forbid(future_incompatible)]

#![cfg_attr(feature = "with-bench", feature(test))]

extern crate rand;
extern crate rustc_serialize as serialize;
extern crate time;
extern crate libc;

#[cfg(all(test, feature = "with-bench"))]
extern crate test;

pub mod aead;
pub mod aes;
pub mod aes_gcm;
pub mod aessafe;
pub mod bcrypt;
pub mod bcrypt_pbkdf;
pub mod blake2b;
pub mod blake2s;
pub mod blockmodes;
pub mod blowfish;
pub mod buffer;
pub mod chacha20;
pub mod chacha20poly1305;
#[allow(unsafe_code)]
mod cryptoutil;
pub mod curve25519;
pub mod digest;
pub mod ed25519;
pub mod fortuna;
#[allow(unsafe_code)]
pub mod ghash;
#[allow(unsafe_code)]
pub mod hc128;
pub mod hmac;
pub mod hkdf;
pub mod mac;
pub mod md5;
pub mod pbkdf2;
pub mod poly1305;
pub mod rc4;
pub mod ripemd160;
pub mod salsa20;
pub mod scrypt;
pub mod sha1;
pub mod sha2;
pub mod sha3;
mod simd;
pub mod sosemanuk;
mod step_by;
pub mod symmetriccipher;
#[allow(unsafe_code)]
pub mod util;
#[allow(unsafe_code)]
pub mod whirlpool;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod aesni;
