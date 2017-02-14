___rust-keylock___ is a password manager. The main logic is written in [Rust](https://www.rust-lang.org), but the presentation/User interaction parts are written in different languages.

Our goals are that _rust-keylock_ must be:

* Secure
* Simple to use
* Portable
* Extensible

# The _rust-keylock_ library

This library executes the logic of the _rust-keylock_.

It can be viewed as the executor of the _rust-keylock_ logic. `Editor` references are used to interact with the _rust-keylock_ users.