`async_user_lookup` provides an easy way to lookup Linux/Unix user and group information from /etc/passwd and /etc/group. It uses tokio async and will cache the information for a duration specified by the user. 

```rust
use async_user_lookup::PasswdReader;
use std::time::Duration;

#[tokio::main]
async fn main() {
   let mut reader = PasswdReader::new(Duration::new(0,0));
   let entries = reader.get_entries().await.unwrap();

   println!("User with uid 1000 is: {}", reader.get_username_by_uid(1000).await.unwrap());
}

```
