// Copyright 2022 Mattias Eriksson
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! `async_user_lookup` provides an easy way to lookup Linux/Unix user and group information
//! from /etc/passwd and /etc/group. It uses tokio async and will cache the information for a
//! duration specified by the user. If no caching is desired, a Duration of 0.0 can be used.
//!
//!```rust
//!use async_user_lookup::PasswdReader;
//!use std::time::Duration;
//!
//!#[tokio::main]
//!async fn main() {
//!   let mut reader = PasswdReader::new(Duration::new(0,0));
//!   let entries = reader.get_entries().await.unwrap();
//!
//!   println!("User with uid 1000 is: {}", reader.get_username_by_uid(1000).await.unwrap());
//!}
//!
//!```
use std::time::Duration;

use tokio::time::Instant;

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

///The main entity to reaad and lookup user information. It
///supports caching the information to avoid having to read
///the information from disk more than needed.
/// ```
/// use async_user_lookup::PasswdReader;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///    let mut reader = PasswdReader::new_at("test_files/passwd",Duration::new(0,0));
///    let entries = reader.get_entries().await.unwrap();
///
///    assert_eq!(3, entries.len());
///    assert_eq!(Some("user1".to_string()), reader.get_username_by_uid(1000).await.unwrap());
///    assert_eq!(Some("user2".to_string()), reader.get_username_by_uid(1001).await.unwrap());
/// }
/// ```
pub struct PasswdReader {
    file: Option<String>,
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
    pub fn new_at(file: &str, cache_time: Duration) -> Self {
        let last_check = Instant::now() - (cache_time);
        Self {
            file: Some(file.to_string()),
            cache_time,
            last_check,
            passwd: vec![],
        }
    }

    async fn refresh_if_needed(&mut self) -> Result<(), std::io::Error> {
        if Instant::now() < (self.last_check + self.cache_time) {
            return Ok(());
        }
        let contents =
            tokio::fs::read_to_string(self.file.as_ref().unwrap_or(&"/etc/passwd".to_string()))
                .await?;
        self.passwd = contents.lines().filter_map(PasswdEntry::parse).collect();
        Ok(())
    }

    ///Get all the entire list of passwd entries
    pub async fn get_entries(&mut self) -> Result<&Vec<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(&self.passwd)
    }

    ///Will return an IntoIter to iterate over PasswdEntry
    pub async fn to_iter(mut self) -> Result<std::vec::IntoIter<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self.passwd.into_iter())
    }

    ///Look up a PasswdEntry by username
    pub async fn get_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.username == username)
            .map(|e| e.to_owned()))
    }

    ///Look up a PasswdEntry by uid
    pub async fn get_by_uid(&mut self, uid: u32) -> Result<Option<PasswdEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.uid == uid)
            .map(|e| e.to_owned()))
    }

    ///Look up a username by uid
    pub async fn get_username_by_uid(
        &mut self,
        uid: u32,
    ) -> Result<Option<String>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self
            .passwd
            .iter()
            .find(|e| e.uid == uid)
            .map(|e| e.username.to_owned()))
    }

    ///Look up a user ID by username
    pub async fn get_uid_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<u32>, std::io::Error> {
        self.refresh_if_needed().await?;
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
/// ```
/// use async_user_lookup::GroupReader;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///    let mut reader = GroupReader::new_at("test_files/group",Duration::new(0,0));
///    let groups = reader.get_groups().await.unwrap();
///
///    assert_eq!(3, groups.len());
///    assert_eq!(Some("users".to_string()), reader.get_name_by_gid(100).await.unwrap());
/// }
/// ```
pub struct GroupReader {
    file: Option<String>,
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
    pub fn new_at(file: &str, cache_time: Duration) -> Self {
        let last_check = Instant::now() - (cache_time);
        Self {
            file: Some(file.to_string()),
            cache_time,
            last_check,
            groups: vec![],
        }
    }

    async fn refresh_if_needed(&mut self) -> Result<(), std::io::Error> {
        if Instant::now() < (self.last_check + self.cache_time) {
            return Ok(());
        }
        let contents =
            tokio::fs::read_to_string(self.file.as_ref().unwrap_or(&"/etc/group".to_string()))
                .await?;
        self.groups = contents.lines().filter_map(GroupEntry::parse).collect();
        Ok(())
    }

    ///Get the entire list of group entries
    pub async fn get_groups(&mut self) -> Result<&Vec<GroupEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(&self.groups)
    }

    ///Will return an IntoIter to iterate over GroupEntry
    pub async fn to_iter(mut self) -> Result<std::vec::IntoIter<GroupEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self.groups.into_iter())
    }

    ///Look up a GroupEntry by the group name
    pub async fn get_by_name(&mut self, name: &str) -> Result<Option<GroupEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self
            .groups
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.to_owned()))
    }

    ///Look up a GroupEntry by gid
    pub async fn get_by_gid(&mut self, gid: u32) -> Result<Option<GroupEntry>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self
            .groups
            .iter()
            .find(|e| e.gid == gid)
            .map(|e| e.to_owned()))
    }

    ///Look up a group name by gid
    pub async fn get_name_by_gid(&mut self, gid: u32) -> Result<Option<String>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self
            .groups
            .iter()
            .find(|e| e.gid == gid)
            .map(|e| e.name.to_owned()))
    }

    ///Look up a group ID by the group name
    pub async fn get_gid_by_name(&mut self, name: &str) -> Result<Option<u32>, std::io::Error> {
        self.refresh_if_needed().await?;
        Ok(self.groups.iter().find(|e| e.name == name).map(|e| e.gid))
    }
}
