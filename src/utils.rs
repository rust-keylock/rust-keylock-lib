// Copyright 2017 astonbitecode
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

use j4rs::Jvm;
#[cfg(target_os = "android")]
use j4rs::JvmBuilder;

use crate::errors;

pub(crate) fn to_result<T>(opt: Option<T>) -> errors::Result<T> {
    opt.ok_or(errors::RustKeylockError::GeneralError("Value was not found".to_string()))
}

#[cfg(not(target_os = "android"))]
pub(crate) fn create_jvm() -> errors::Result<Jvm> {
    Ok(Jvm::new(&[], None)?)
}

#[cfg(target_os = "android")]
pub(crate) fn create_jvm() -> errors::Result<Jvm> {
    Ok(JvmBuilder::new()
        .detach_thread_on_drop(false)
        .with_no_implicit_classpath()
        .build()?)
}

#[cfg(test)]
mod utils_unit_tests {
    use super::*;

    #[test]
    fn test_to_result() {
        let none: Option<isize> = None;
        assert!(to_result(Some(1)).is_ok());
        assert!(to_result(Some("123".to_string())).is_ok());
        assert!(to_result(none).is_err());
    }
}
