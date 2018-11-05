![Build Status](https://travis-ci.org/rust-keylock/rust-keylock-lib.svg?branch=master)
[![crates.io](https://img.shields.io/crates/v/rust_keylock.svg)](https://crates.io/crates/rust_keylock)
[![codecov](https://codecov.io/gh/rust-keylock/rust-keylock-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/rust-keylock/rust-keylock-lib)

## General

___rust-keylock___ is a password manager and its goals are to be:

* Secure
* Simple to use
* Portable
* Extensible

The core logic is written in [Rust](https://www.rust-lang.org), but the presentation/User interaction parts are in different languages.

## Features

### Security

 * The data is locked with a user-defined master password, using _bcrypt_ password hashing
 * Encryption using _AES_ with _CTR_ mode
 * Data integrity checks with SHA3 (Keccak)
 * Encrypted bytes blending
 * Passwords are kept encrypted in memory
 * Encryption keys on runtime are stored in safe, non-swappable memory
 * Encryption keys change upon saving, even if the user master password remains the same. This results to different encrypted products, even if the data that is being encrypted is the same.

### Data Availability

 * Synchronization over Nextcloud or Owncloud
 * Export/import encrypted passwords to/from the filesystem
 * _Automatic backups (TODO)_
 
### Application Portability


 * [Shell implementation](https://github.com/rust-keylock/rust-keylock-shell).
 * [JavaFX implementation](https://github.com/rust-keylock/rust-keylock-ui).
    * Using the [j4rs crate](https://github.com/astonbitecode/j4rs)
 * [Android implementation](https://github.com/rust-keylock/rust-keylock-android)
    * Using [xargo](https://github.com/japaric/xargo) and [JNA](https://github.com/java-native-access/jna)

See how to [download and install](https://rust-keylock.github.io/download/rkl/).

## FAQ

On the Project [website](https://rust-keylock.github.io/faq/rkl/).

## Wiki

On the Project [website](https://rust-keylock.github.io/wiki/).

## The _rust-keylock_ library and the _Editors_

The idea is that the [rust-keylock library](https://github.com/rust-keylock/rust-keylock-lib) handles the core application logic, whereas the interaction with the _rust-keylock_ users is done via libraries that have presentation responsibilities (aka [Editors](https://rust-keylock.github.io/rust-keylock-lib/rust_keylock/trait.Editor.html)).

This library is responsible for the core operations, like encryption/decryption, storing and retrieving encrypted data from the filesystem, performing synchronization tasks etc.

The Editors are driven by the rust-keylock library and are responsible for interacting with the Users and transfer the Users' input to the library.
