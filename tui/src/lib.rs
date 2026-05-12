//! Public library surface — used by the package's auxiliary binaries
//! (`frost-camouflage`, etc). The TUI itself (`sovereign-vault`) lives in
//! `main.rs` and owns its own modules privately. Only modules that need
//! to be shared with separate binaries live here.

pub mod stego;
