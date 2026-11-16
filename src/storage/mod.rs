#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacitySource {
    StorageStats,
    StatFsVolume,
    StatFsAppDir,
    RootStat,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StorageInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub source: CapacitySource,
}

impl StorageInfo {
    pub fn usage_percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f64 / self.total_bytes as f64) * 100.0
    }
}
