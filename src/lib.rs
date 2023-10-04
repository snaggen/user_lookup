// Copyright 2022 Mattias Eriksson
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! `user_lookup` provides an easy way to lookup Linux/Unix user and group information
//! from /etc/passwd and /etc/group. It will cache the information for a
//! duration specified by the user. If no caching is desired, a Duration of 0.0 can be used.
//!
//!```rust,ignore
//!use user_lookup::async_reader::PasswdReader;
//!use std::time::Duration;
//!
//!#[tokio::main]
//!async fn main() {
//!   let mut reader = PasswdReader::new(Duration::new(0,0));
//!
//!   println!("User with uid 1000 is: {}",
//!   reader.get_username_by_uid(1000).await.unwrap().unwrap());
//!}
//!
//!```
#[cfg(feature = "async")]
pub mod async_reader;
#[cfg(feature = "sync")]
pub mod sync_reader;

/// A passwd entry, representing one row in
/// `/etc/passwd`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// Username
    pub username: String,
    /// User password
    pub passwd: String,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// User full name or comment
    pub gecos: String,
    /// Home directory
    pub home_dir: String,
    /// Shell
    pub shell: String,
}

impl PasswdEntry {
    ///Create a PasswdEntry from &str.
    pub fn parse(s: &str) -> Option<PasswdEntry> {
        let mut entries = s.splitn(7, ':');
        Some(PasswdEntry {
            username: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
            passwd: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
            uid: match entries.next().and_then(|s| s.parse().ok()) {
                None => return None,
                Some(s) => s,
            },
            gid: match entries.next().and_then(|s| s.parse().ok()) {
                None => return None,
                Some(s) => s,
            },
            gecos: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
            home_dir: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
            shell: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
        })
    }
}

/// A group entry, representing one row in
/// ```/etc/group```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    //Username
    pub name: String,
    //Password
    pub passwd: String,
    //Group ID
    pub gid: u32,
    //List of users
    pub users: Vec<String>,
}

impl GroupEntry {
    ///Create a GroupEntry from &str.
    pub fn parse(s: &str) -> Option<GroupEntry> {
        let mut entries = s.splitn(4, ':');
        Some(GroupEntry {
            name: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
            passwd: match entries.next() {
                None => return None,
                Some(s) => s.to_string(),
            },
            gid: match entries.next().and_then(|s| s.parse().ok()) {
                None => return None,
                Some(s) => s,
            },
            users: match entries.next() {
                None => return None,
                Some(s) => s.split(',').map(|p| p.to_string()).collect(),
            },
        })
    }
}
