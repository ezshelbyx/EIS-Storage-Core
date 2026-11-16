#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveOp { Format, Wipe, Partition, WriteImage, Erase }

pub fn is_authorized(_op: DestructiveOp) -> bool { false }
