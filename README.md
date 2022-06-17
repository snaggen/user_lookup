# Async User Lookup

An easy way to lookup Linux/Unix user and group information from /etc/passwd and /etc/group. It uses tokio async and will cache the information for a duration specified by the user. 

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[crates-badge]: https://img.shields.io/crates/v/async_user_lookup
[crates-url]: https://crates.io/crates/async_user_lookup
[doc-badge]: https://img.shields.io/docsrs/async_user_lookup
[docs-url]: https://docs.rs/async_user_lookup/0.1.0/async_user_lookup

```rust
use async_user_lookup::PasswdReader;
use std::time::Duration;

#[tokio::main]
async fn main() {
   let mut reader = PasswdReader::new(Duration::new(0,0));

   println!("User with uid 1000 is: {}", reader.get_username_by_uid(1000).await.unwrap().unwrap());
}

```
