use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid device path: {0}")]
    InvalidDevicePath(String),
    #[error("device not found: {0}")]
    DeviceNotFound(String),
    #[error("device is not a removable USB device")]
    NotRemovable,
    #[error("device identity mismatch: expected {expected}, got {actual}")]
    IdentityMismatch { expected: String, actual: String },
    #[error("write operation not authorized")]
    WriteNotAuthorized,
    #[error("destructive operation blocked by safety policy")]
    DestructiveBlocked,
    #[error("invalid partition table: {0}")]
    InvalidPartitionTable(String),
    #[error("invalid MBR: {0}")]
    InvalidMbr(String),
    #[error("invalid GPT: {0}")]
    InvalidGpt(String),
    #[error("partition out of bounds: start={start}, end={end}, disk_size={disk_size}")]
    PartitionOutOfBounds {
        start: u64,
        end: u64,
        disk_size: u64,
    },
    #[error("filesystem not recognized")]
    UnknownFilesystem,
    #[error("hash mismatch: expected {expected}, computed {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("operation cancelled")]
    Cancelled,
    #[error("operation timed out")]
    Timeout,
    #[error("insufficient capacity: need {need} bytes, have {have} bytes")]
    InsufficientCapacity { need: u64, have: u64 },
    #[error("image too large: {size} bytes exceeds limit {limit} bytes")]
    ImageTooLarge { size: u64, limit: u64 },
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
