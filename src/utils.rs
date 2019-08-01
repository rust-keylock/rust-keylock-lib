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

use serde_json::map::Map as SerdeMap;
use serde_json::value::Value as SerdeValue;

use crate::errors;

pub(crate) fn to_result<T>(opt: Option<T>) -> errors::Result<T> {
    opt.ok_or(errors::RustKeylockError::GeneralError("Value was not found".to_string()))
}

#[allow(dead_code)]
pub(crate) fn retrieve_value(path: &str, map: &SerdeMap<String, SerdeValue>) -> Option<String> {
    let paths: Vec<String> = path
        .rsplit("/")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    do_retrieve_value(paths, map)
}

fn do_retrieve_value(paths: Vec<String>, map: &SerdeMap<String, SerdeValue>) -> Option<String> {
    let mut paths = paths;
    match paths.pop() {
        None => None,
        Some(path) => {
            match map.get(&path) {
                None => None,
                Some(v) => {
                    match v {
                        SerdeValue::Object(inner_map) => do_retrieve_value(paths, inner_map),
                        SerdeValue::Array(arr) => {
                            let index = paths.pop()
                                .unwrap_or("-1".to_string())
                                .parse::<i32>()
                                .unwrap_or(-1);
                            if index >= 0 {
                                arr.get(index as usize)
                                    .and_then(|v| v.as_object()
                                        .and_then(|inner_map| do_retrieve_value(paths, inner_map)))
                            } else {
                                None
                            }
                        }
                        SerdeValue::String(s) => Some(s.to_owned()),
                        other => Some(other.to_string()),
                    }
                }
            }
        }
    }
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

    #[test]
    fn retrieve_value_from_inside_list() {
        let json = r#"{
          "is_deleted" : false,
          "entries" : [ {
            "name" : ".version",
            "path_lower" : "/.version",
            "path_display" : "/.version",
            "id" : "id:rYxtlrWJLTAAAAAAAAAAQg",
            "client_modified" : "2019-07-25T05:49:16Z",
            "server_modified" : "2019-07-25T05:49:16Z",
            "rev" : "0158e7afc77f4b1000000013338a710",
            "size" : 13,
            "is_downloadable" : true,
            "content_hash" : "19ccaf95189fe3af15e096f727d406c434d55dd87912bb5134655730d89dbc68"
          } ]
        }"#;
        let map: SerdeMap<String, SerdeValue> = serde_json::from_str(&json).unwrap();

        assert!(retrieve_value("/entries/0/rev", &map).unwrap() == "0158e7afc77f4b1000000013338a710")
    }

    #[test]
    fn retrieve_boolean_value() {
        let json = r#"{
          "is_deleted" : false,
          "entries" : [ {
            "name" : ".version",
            "path_lower" : "/.version",
            "path_display" : "/.version",
            "id" : "id:rYxtlrWJLTAAAAAAAAAAQg",
            "client_modified" : "2019-07-25T05:49:16Z",
            "server_modified" : "2019-07-25T05:49:16Z",
            "rev" : "0158e7afc77f4b1000000013338a710",
            "size" : 13,
            "is_downloadable" : true,
            "content_hash" : "19ccaf95189fe3af15e096f727d406c434d55dd87912bb5134655730d89dbc68"
          } ]
        }"#;
        let map: SerdeMap<String, SerdeValue> = serde_json::from_str(&json).unwrap();

        assert!(retrieve_value("is_deleted", &map).unwrap() == "false")
    }

    #[test]
    fn retrieve_number_value() {
        let json = r#"{
          "is_deleted" : false,
          "entries" : [ {
            "name" : ".version",
            "path_lower" : "/.version",
            "path_display" : "/.version",
            "id" : "id:rYxtlrWJLTAAAAAAAAAAQg",
            "client_modified" : "2019-07-25T05:49:16Z",
            "server_modified" : "2019-07-25T05:49:16Z",
            "rev" : "0158e7afc77f4b1000000013338a710",
            "size" : 13,
            "is_downloadable" : true,
            "content_hash" : "19ccaf95189fe3af15e096f727d406c434d55dd87912bb5134655730d89dbc68"
          } ]
        }"#;
        let map: SerdeMap<String, SerdeValue> = serde_json::from_str(&json).unwrap();

        assert!(retrieve_value("/entries/0/size", &map).unwrap() == "13")
    }
}
