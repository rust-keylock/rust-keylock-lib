[![Build Status](https://travis-ci.org/rust-keylock/rust-keylock-lib.svg?branch=master)](https://travis-ci.org/rust-keylock/rust-keylock-lib)
[![crates.io](https://img.shields.io/crates/v/rust_keylock.svg)](https://crates.io/crates/rust_keylock)
[![codecov](https://codecov.io/gh/rust-keylock/rust-keylock-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/rust-keylock/rust-keylock-lib)

[![snapcraft](https://img.shields.io/f-droid/v/org.astonbitecode.rustkeylock.svg)](https://f-droid.org/en/packages/org.astonbitecode.rustkeylock/)
[![rust-keylock-ui](https://snapcraft.io//rust-keylock-ui/badge.svg)](https://snapcraft.io/rust-keylock-ui)



## General

___rust-keylock___ is a password manager and its goals are to be:

* Secure
* Simple to use
* Portable
* Extensible

The core logic is written in [Rust](https://www.rust-lang.org), but the presentation/User interaction parts are in different languages.

## Warning

The project has not yet received any formal / official security reviews. Use it at your own risk.

## Features

### Security

 * The data is locked with a user-defined master password, using _bcrypt_ password hashing
 * Encryption using _AES_ with _CTR_ mode
 * Data integrity checks with SHA3 (Keccak)
 * During runtime, the passwords are kept encrypted in memory
 * During runtime, the encryption keys are stored in safe, non-swappable memory
 * Upon saving, the encryption keys change, even if the user master password remains the same. This results to different encrypted products, even if the data that is being encrypted is the same.
 * Passphrases generation using [Diceware](https://theworld.com/~reinhold/diceware.html).
 * Passwords health check against [pwned passwords list](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/), leveraging the [k-anonimity API](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/).

### Data Availability

 * Synchronization over Dropbox
 * Synchronization over Nextcloud or Owncloud
 * Export/import encrypted passwords to/from the filesystem
 * Automatic local backups
 
### Application Portability

 * [Shell implementation](https://github.com/rust-keylock/rust-keylock-shell).
 * [JavaFX implementation](https://github.com/rust-keylock/rust-keylock-ui).
    * Using the [j4rs crate](https://github.com/astonbitecode/j4rs)
 * [Android implementation](https://github.com/rust-keylock/rust-keylock-android)
    * Using the [j4rs crate](https://github.com/astonbitecode/j4rs)

See how to [download and install](https://rust-keylock.github.io/download/rkl/).

## FAQ

On the Project [website](https://rust-keylock.github.io/faq/rkl/).

## Wiki

On the Project [website](https://rust-keylock.github.io/wiki/).