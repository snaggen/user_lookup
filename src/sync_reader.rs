// Copyright 2022 Mattias Eriksson
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! `sync_reader` provides readers for PasswdReader and GroupReader,
//! to read and process /etc/passwd and /etc/group
//!
//!```rust,ignore
//! use user_lookup::sync_reader::PasswdReader;
//! use std::time::Duration;
//!
//! fn main() {
//!    let mut reader = PasswdReader::new(Duration::new(0,0));
//!
//!    println!("User with uid 1000 is: {}",
//!    reader.get_username_by_uid(1000).unwrap().unwrap());
//! }
//!
//!```
use crate::GroupEntry;
use crate::PasswdEntry;

use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

///The main entity to reaad and lookup user information. It
///supports caching the information to avoid having to read
///the information from disk more than needed.
/// ```
/// use user_lookup::sync_reader::PasswdReader;
/// use std::time::Duration;
///
/// let mut reader = PasswdReader::from_file("test_files/passwd",Duration::new(0,0));
/// let entries = reader.get_entries().unwrap();
///
/// assert_eq!(3, entries.len());
/// assert_eq!(Some("user1".to_string()), reader.get_username_by_uid(1000).unwrap());
/// assert_eq!(Some("user2".to_string()), reader.get_username_by_uid(1001).unwrap());
/// ```
pub struct PasswdReader {
    file: Option<PathBuf>,
    cache_time: Duration,
    last_check: Instant,
    passwd: Vec<PasswdEntry>,
}

impl PasswdReader {
    ///Creates a new PasswdReader for `/etc/passwd` with a
    ///specified cache_time in seconds.
    ///
    ///Use cache_time with a Duration of 0 to disable caching.
    pub fn new(cache_time: Duration) -> Self {
        let last_check = Instant::now() - (cache_time);
        Self {
            file: None,
            cache_time,
            last_check,
            passwd: vec![],
        }
    }

    ///Creates a new PasswdReader with the
    /// passwd file at an specified alternative
    /// location. Uses the specified cache_time in seconds.
    ///
    ///Use cache_time with a Duration of 0 to disable caching.
    pub fn from_file<T: Into<PathBuf>>(file: T, cache_time: Duration) -> Self {
        let last_check = Instant::now() - (cache_time);
        Self {
            file: Some(file.into()),
            cache_time,
            last_check,
            passwd: vec![],
        }
    }

    fn refresh_if_needed(&mut self) -> Result<(), std::io::Error> {
        if Instant::now() < (self.last_check + self.cache_time) {
            return Ok(());
        }
        let contents =
            std::fs::read_to_string(self.file.as_ref().unwrap_or(&"/etc/passwd".into()))?;
        self.passwd = contents.lines().filter_map(PasswdEntry::parse).collect();
        Ok(())
    }

    ///Get all the entire list of passwd entries
    pub fn get_entries(&mut self) -> Result<&Vec<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(&self.passwd)
    }

    ///Will return an iterator over &PasswdEntry
    pub fn try_iter(&mut self) -> Result<std::slice::Iter<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self.passwd.iter())
    }

    ///Look up a PasswdEntry by username
    pub fn get_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.username == username)
            .map(|e| e.to_owned()))
    }

    ///Look up a PasswdEntry by uid
    pub fn get_by_uid(&mut self, uid: u32) -> Result<Option<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.uid == uid)
            .map(|e| e.to_owned()))
    }

    ///Look up a username by uid
    pub fn get_username_by_uid(&mut self, uid: u32) -> Result<Option<String>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.uid == uid)
            .map(|e| e.username.to_owned()))
    }

    ///Look up a user ID by username
    pub fn get_uid_by_username(&mut self, username: &str) -> Result<Option<u32>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.username == username)
            .map(|e| e.uid))
    }
}

///The main entity to reaad and lookup groups information. It
///supports caching the information to avoid having to read
///the information from disk more than needed.
///```
/// use user_lookup::sync_reader::GroupReader;
/// use std::time::Duration;
///
/// let mut reader = GroupReader::from_file("test_files/group",Duration::new(0,0));
/// let groups = reader.get_groups().unwrap();
///
/// assert_eq!(3, groups.len());
/// assert_eq!(Some("users".to_string()), reader.get_name_by_gid(100).unwrap());
/// ```
pub struct GroupReader {
    file: Option<PathBuf>,
    cache_time: Duration,
    last_check: Instant,
    groups: Vec<GroupEntry>,
}

impl GroupReader {
    ///Creates a new GroupReader for `/etc/group` with a
    ///specified cache_time in seconds.
    ///
    ///Use cache_time with a duration of 0 to disable caching.
    pub fn new(cache_time: Duration) -> Self {
        let last_check = Instant::now() - (cache_time);
        Self {
            file: None,
            cache_time,
            last_check,
            groups: vec![],
        }
    }

    ///Creates a new GroupReader which reads
    ///the group file at a specific path, and
    ///uses the specified cache_time in seconds.
    ///
    ///Use cache_time with a duration of 0 to disable caching.
    pub fn from_file<T: Into<PathBuf>>(file: T, cache_time: Duration) -> Self {
        let last_check = Instant::now() - (cache_time);
        Self {
            file: Some(file.into()),
            cache_time,
            last_check,
            groups: vec![],
        }
    }

    fn refresh_if_needed(&mut self) -> Result<(), std::io::Error> {
        if Instant::now() < (self.last_check + self.cache_time) {
            return Ok(());
        }
        let contents = std::fs::read_to_string(self.file.as_ref().unwrap_or(&"/etc/group".into()))?;
        self.groups = contents.lines().filter_map(GroupEntry::parse).collect();
        Ok(())
    }

    ///Get the entire list of group entries
    pub fn get_groups(&mut self) -> Result<&Vec<GroupEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(&self.groups)
    }

    ///Will return an iterator over &GroupEntry
    pub fn try_iter(&mut self) -> Result<std::slice::Iter<GroupEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self.groups.iter())
    }

    ///Look up a GroupEntry by the group name
    pub fn get_by_name(&mut self, name: &str) -> Result<Option<GroupEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .groups
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.to_owned()))
    }

    ///Look up a GroupEntry by gid
    pub fn get_by_gid(&mut self, gid: u32) -> Result<Option<GroupEntry>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .groups
            .iter()
            .find(|e| e.gid == gid)
            .map(|e| e.to_owned()))
    }

    ///Look up a group name by gid
    pub fn get_name_by_gid(&mut self, gid: u32) -> Result<Option<String>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self
            .groups
            .iter()
            .find(|e| e.gid == gid)
            .map(|e| e.name.to_owned()))
    }

    ///Look up a group ID by the group name
    pub fn get_gid_by_name(&mut self, name: &str) -> Result<Option<u32>, std::io::Error> {
        self.refresh_if_needed()?;
        Ok(self.groups.iter().find(|e| e.name == name).map(|e| e.gid))
    }
}
