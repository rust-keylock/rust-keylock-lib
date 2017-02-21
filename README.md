![Build Status](https://travis-ci.org/rust-keylock/rust-keylock-lib.svg?branch=master)

___rust-keylock___ is a password manager. The main logic is written in [Rust](https://www.rust-lang.org), but the presentation/User interaction parts are written in different languages.

Goals are that _rust-keylock_ must be:

* Secure
* Simple to use
* Portable
* Extensible

# The _rust-keylock_ library

This library is the executor of the _rust-keylock_ logic. The interaction with the _rust-keylock_ users is done via other libraries, that have presentation responsibilities (aka [Editors](https://rust-keylock.github.io/rust-keylock-lib/rust_keylock/trait.Editor.html)).

The documentation of the library can be found [here](https://rust-keylock.github.io/rust-keylock-lib/rust_keylock/).

Currently, there are Editors and executables for [Android](https://github.com/rust-keylock/rust-keylock-android) and [Terminal](https://github.com/rust-keylock/rust-keylock-shell).