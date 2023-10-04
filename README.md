# User Lookup


[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]


[crates-badge]: https://img.shields.io/crates/v/user_lookup
[crates-url]: https://crates.io/crates/user_lookup
[docs-badge]: https://img.shields.io/docsrs/user_lookup
[docs-url]: https://docs.rs/user_lookup/0.2.0/user_lookup

An easy way to lookup Linux/Unix user and group information from /etc/passwd and /etc/group. It will cache the information for a duration specified by the user. 

```rust
use user_lookup::async_reader::PasswdReader;
use std::time::Duration;

#[tokio::main]
async fn main() {
   let mut reader = PasswdReader::new(Duration::new(0,0));

   println!("User with uid 1000 is: {}", reader.get_username_by_uid(1000).await.unwrap().unwrap());
}

```
