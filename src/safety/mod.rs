use crate::device::{BlockDevice, DeviceIdentity};
use crate::error::{Result, StorageError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveOp {
    Format,
    Wipe,
    Partition,
    WriteImage,
    Erase,
    Resize,
}

impl DestructiveOp {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Wipe => "wipe",
            Self::Partition => "partition",
            Self::WriteImage => "write image",
            Self::Erase => "erase",
            Self::Resize => "resize",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthToken {
    pub operation: DestructiveOp,
    pub device_fingerprint: String,
    pub confirmed: bool,
    pub timestamp: u64,
}

impl AuthToken {
    pub fn new(op: DestructiveOp, device: &DeviceIdentity) -> Self {
        Self {
            operation: op,
            device_fingerprint: device.fingerprint(),
            confirmed: false,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }
    pub fn is_valid(&self, device: &DeviceIdentity) -> bool {
        self.confirmed && self.device_fingerprint == device.fingerprint()
    }
}

#[derive(Debug, Clone)]
pub struct SafetyPolicy {
    pub allow_fixed_disk_write: bool,
    pub allow_system_partition_modify: bool,
    pub require_confirmation: bool,
    pub max_image_size_bytes: u64,
    pub blocked_device_patterns: Vec<String>,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            allow_fixed_disk_write: false,
            allow_system_partition_modify: false,
            require_confirmation: true,
            max_image_size_bytes: 64 * 1024 * 1024 * 1024,
            blocked_device_patterns: vec![
                "/dev/sda".into(),
                "/dev/nvme0".into(),
                "/dev/hda".into(),
                "/dev/vda".into(),
                "/dev/mmcblk0".into(),
            ],
        }
    }
}

pub struct SafetyGuard {
    policy: SafetyPolicy,
}

impl SafetyGuard {
    pub fn new(policy: SafetyPolicy) -> Self {
        Self { policy }
    }
    pub fn default_guard() -> Self {
        Self {
            policy: SafetyPolicy::default(),
        }
    }
    pub fn check_write_target(&self, dev: &BlockDevice) -> Result<()> {
        if !dev.removable && !self.policy.allow_fixed_disk_write {
            return Err(StorageError::DestructiveBlocked);
        }
        if dev.read_only {
            return Err(StorageError::DestructiveBlocked);
        }
        for pattern in &self.policy.blocked_device_patterns {
            if dev.path.starts_with(pattern) {
                return Err(StorageError::DestructiveBlocked);
            }
        }
        if !self.policy.allow_system_partition_modify {
            for mp in &dev.mount_points {
                if mp == "/" || mp.starts_with("/boot") || mp.starts_with("/usr") || mp == "/home" {
                    return Err(StorageError::DestructiveBlocked);
                }
            }
        }
        Ok(())
    }
    pub fn check_identity(&self, expected: &DeviceIdentity, actual: &DeviceIdentity) -> Result<()> {
        if !expected.matches(actual) {
            return Err(StorageError::IdentityMismatch {
                expected: expected.fingerprint(),
                actual: actual.fingerprint(),
            });
        }
        Ok(())
    }
    pub fn check_image_size(&self, size: u64) -> Result<()> {
        if size > self.policy.max_image_size_bytes {
            return Err(StorageError::ImageTooLarge {
                size,
                limit: self.policy.max_image_size_bytes,
            });
        }
        Ok(())
    }
    pub fn authorize(
        &self,
        op: DestructiveOp,
        dev: &BlockDevice,
        identity: &DeviceIdentity,
        actual_identity: &DeviceIdentity,
        auth_token: Option<&AuthToken>,
    ) -> Result<()> {
        self.check_write_target(dev)?;
        self.check_identity(identity, actual_identity)?;
        if self.policy.require_confirmation {
            match auth_token {
                Some(token) if token.is_valid(identity) && token.operation == op => {}
                _ => return Err(StorageError::WriteNotAuthorized),
            }
        }
        Ok(())
    }
    pub fn is_authorized(&self, _op: DestructiveOp) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteProtection {
    Enabled,
    Disabled,
    Unknown,
}

pub fn check_write_protection(dev: &BlockDevice) -> WriteProtection {
    if dev.read_only {
        WriteProtection::Enabled
    } else {
        WriteProtection::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{BlockDevice, DeviceClass, DeviceIdentity, DeviceType};
    fn make_removable_dev() -> BlockDevice {
        BlockDevice {
            path: "/dev/sdb".into(),
            name: "sdb".into(),
            size_bytes: 8_000_000_000,
            class: DeviceClass::Sata,
            device_type: DeviceType::Removable,
            vendor: None,
            model: None,
            serial: None,
            removable: true,
            read_only: false,
            mounted: false,
            mount_points: vec![],
            partitions: vec![],
        }
    }
    #[test]
    fn guard_allows_removable() {
        assert!(SafetyGuard::default_guard()
            .check_write_target(&make_removable_dev())
            .is_ok());
    }
    #[test]
    fn guard_blocks_fixed() {
        let mut dev = make_removable_dev();
        dev.removable = false;
        dev.device_type = DeviceType::Fixed;
        assert!(SafetyGuard::default_guard()
            .check_write_target(&dev)
            .is_err());
    }
    #[test]
    fn guard_blocks_readonly() {
        let mut dev = make_removable_dev();
        dev.read_only = true;
        assert!(SafetyGuard::default_guard()
            .check_write_target(&dev)
            .is_err());
    }
    #[test]
    fn guard_blocks_system_mount() {
        let mut dev = make_removable_dev();
        dev.mount_points = vec!["/".into()];
        dev.mounted = true;
        assert!(SafetyGuard::default_guard()
            .check_write_target(&dev)
            .is_err());
    }
    #[test]
    fn identity_check_ok() {
        let guard = SafetyGuard::default_guard();
        let id = DeviceIdentity {
            vendor_id: None,
            product_id: None,
            serial: Some("ABC".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sdb".into(),
        };
        assert!(guard.check_identity(&id, &id).is_ok());
    }
    #[test]
    fn identity_check_mismatch() {
        let guard = SafetyGuard::default_guard();
        let id1 = DeviceIdentity {
            vendor_id: None,
            product_id: None,
            serial: Some("ABC".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sdb".into(),
        };
        let id2 = DeviceIdentity {
            vendor_id: None,
            product_id: None,
            serial: Some("XYZ".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sdb".into(),
        };
        assert!(guard.check_identity(&id1, &id2).is_err());
    }
    #[test]
    fn auth_token_flow() {
        let id = DeviceIdentity {
            vendor_id: None,
            product_id: None,
            serial: Some("ABC".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sdb".into(),
        };
        let mut token = AuthToken::new(DestructiveOp::WriteImage, &id);
        assert!(!token.is_valid(&id));
        token.confirm();
        assert!(token.is_valid(&id));
    }
    #[test]
    fn image_size_check() {
        let guard = SafetyGuard::default_guard();
        assert!(guard.check_image_size(1000).is_ok());
        assert!(guard.check_image_size(100 * 1024 * 1024 * 1024).is_err());
    }
}
