#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacitySource { StorageStats, StatFsVolume, StatFsAppDir, RootStat, Unknown }
