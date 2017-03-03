![Build Status](https://travis-ci.org/rust-keylock/rust-keylock-lib.svg?branch=master)

## General

___rust-keylock___ is a password manager and its goals are to be:

* Secure
* Simple to use
* Portable
* Extensible

The main logic is written in [Rust](https://www.rust-lang.org), but the presentation/User interaction parts are written in different languages.

## Features

* __Security__
 * Encryption using _AES_ with _CTR_ mode
 * Password hashing with _bcrypt_
 * Encrypted bytes blending
 * Passwords are kept encrypted in memory
 * Encryption keys on runtime stored in safe, non-swappable memory
 * Encryption keys change upon saving
* __Application Portability__
 * Shell implementation running on Linux and Windows
 * Android implementation
 * JavaFX implementation (TODO)
* __Import/export mechanism__

## The _rust-keylock_ library

This library is the executor of the _rust-keylock_ logic. The interaction with the _rust-keylock_ users is done via other libraries, that have presentation responsibilities (aka [Editors](https://rust-keylock.github.io/rust-keylock-lib/rust_keylock/trait.Editor.html)).

The documentation of the library can be found [here](https://rust-keylock.github.io/rust-keylock-lib/rust_keylock/).

## Availability

Currently, there are Editors and executables for [Android](https://github.com/rust-keylock/rust-keylock-android) and [Terminal](https://github.com/rust-keylock/rust-keylock-shell).
