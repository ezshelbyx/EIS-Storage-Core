//! EIS Storage Core - Shared Rust storage and device engine.

pub mod crypto;
pub mod device;
pub mod error;
pub mod filesystem;
pub mod io;
pub mod partition;
pub mod safety;
pub mod storage;
pub mod verify;

pub use error::{Result, StorageError};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
