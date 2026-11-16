use crate::error::{Result, StorageError};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    UsbMassStorage,
    Nvme,
    Sata,
    Scsi,
    Loopback,
    Virtual,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Removable,
    Fixed,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub name: String,
    pub path: String,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub filesystem: Option<String>,
    pub mount_point: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BlockDevice {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub class: DeviceClass,
    pub device_type: DeviceType,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub removable: bool,
    pub read_only: bool,
    pub mounted: bool,
    pub mount_points: Vec<String>,
    pub partitions: Vec<PartitionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub serial: Option<String>,
    pub bus_path: String,
    pub device_path: String,
}

impl DeviceIdentity {
    pub fn matches(&self, other: &DeviceIdentity) -> bool {
        if let (Some(s1), Some(s2)) = (&self.serial, &other.serial) {
            s1 == s2
        } else {
            self.bus_path == other.bus_path && self.device_path == other.device_path
        }
    }
    pub fn fingerprint(&self) -> String {
        format!(
            "vid={:?}:pid={:?}:serial={:?}:bus={}:dev={}",
            self.vendor_id, self.product_id, self.serial, self.bus_path, self.device_path
        )
    }
}

pub fn classify_device(path: &str) -> DeviceClass {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.starts_with("nvme") {
        DeviceClass::Nvme
    } else if name.starts_with("sd") || name.starts_with("hd") {
        DeviceClass::Sata
    } else if name.starts_with("sr") || name.starts_with("scd") {
        DeviceClass::Scsi
    } else if name.starts_with("loop") {
        DeviceClass::Loopback
    } else if name.starts_with("dm-") || name.starts_with("md") {
        DeviceClass::Virtual
    } else {
        DeviceClass::Unknown
    }
}

pub fn sectors_to_bytes(sectors: u64) -> u64 {
    sectors * 512
}

#[cfg(target_os = "linux")]
pub fn read_sysfs(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}
#[cfg(not(target_os = "linux"))]
pub fn read_sysfs(_path: &str) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
pub fn discover_block_devices() -> Result<Vec<BlockDevice>> {
    let mut devices = Vec::new();
    let sys_block = Path::new("/sys/block");
    if !sys_block.exists() {
        return Err(StorageError::Unsupported("not on Linux".into()));
    }
    let entries = std::fs::read_dir(sys_block)?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("ram") || name.starts_with("zram") {
            continue;
        }
        let dev_path = format!("/dev/{}", name);
        let size_sectors: u64 = read_sysfs(&format!("/sys/block/{}/size", name))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let removable_flag = read_sysfs(&format!("/sys/block/{}/removable", name))
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0)
            == 1;
        let mount_points = find_mount_points(&name);
        let read_only = read_sysfs(&format!("/sys/block/{}/ro", name))
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0)
            == 1;
        devices.push(BlockDevice {
            path: dev_path,
            name: name.clone(),
            size_bytes: sectors_to_bytes(size_sectors),
            class: classify_device(&format!("/dev/{}", name)),
            device_type: if removable_flag {
                DeviceType::Removable
            } else {
                DeviceType::Fixed
            },
            vendor: read_sysfs(&format!("/sys/block/{}/device/vendor", name)),
            model: read_sysfs(&format!("/sys/block/{}/device/model", name)),
            serial: read_sysfs(&format!("/sys/block/{}/device/serial", name)),
            removable: removable_flag,
            read_only,
            mounted: !mount_points.is_empty(),
            mount_points,
            partitions: Vec::new(),
        });
    }
    Ok(devices)
}
#[cfg(not(target_os = "linux"))]
pub fn discover_block_devices() -> Result<Vec<BlockDevice>> {
    Err(StorageError::Unsupported(
        "device discovery only on Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
fn find_mount_points(dev_name: &str) -> Vec<String> {
    let mut mounts = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0].contains(dev_name) {
                mounts.push(parts[1].to_string());
            }
        }
    }
    mounts
}
#[cfg(not(target_os = "linux"))]
fn find_mount_points(_dev_name: &str) -> Vec<String> {
    Vec::new()
}

pub fn filter_removable_usb(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    devices
        .iter()
        .filter(|d| d.removable && d.device_type == DeviceType::Removable)
        .collect()
}

pub fn is_safe_write_target(dev: &BlockDevice) -> bool {
    if !dev.removable {
        return false;
    }
    if dev.device_type != DeviceType::Removable {
        return false;
    }
    if dev.mounted
        && dev
            .mount_points
            .iter()
            .any(|m| m == "/" || m.starts_with("/boot"))
    {
        return false;
    }
    if dev.read_only {
        return false;
    }
    true
}

pub fn device_identity(dev: &BlockDevice) -> DeviceIdentity {
    DeviceIdentity {
        vendor_id: None,
        product_id: None,
        serial: dev.serial.clone(),
        bus_path: format!("/sys/block/{}", dev.name),
        device_path: dev.path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classify_nvme() {
        assert_eq!(classify_device("/dev/nvme0n1"), DeviceClass::Nvme);
    }
    #[test]
    fn classify_sata() {
        assert_eq!(classify_device("/dev/sda"), DeviceClass::Sata);
    }
    #[test]
    fn classify_loopback() {
        assert_eq!(classify_device("/dev/loop0"), DeviceClass::Loopback);
    }
    #[test]
    fn sectors_conversion() {
        assert_eq!(sectors_to_bytes(2048), 1048576);
    }
    #[test]
    fn identity_match_by_serial() {
        let id1 = DeviceIdentity {
            vendor_id: Some(0x1234),
            product_id: Some(0x5678),
            serial: Some("ABC123".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sda".into(),
        };
        let id2 = DeviceIdentity {
            vendor_id: Some(0x9999),
            product_id: Some(0x8888),
            serial: Some("ABC123".into()),
            bus_path: "/bus/2".into(),
            device_path: "/dev/sdb".into(),
        };
        assert!(id1.matches(&id2));
    }
    #[test]
    fn identity_mismatch() {
        let id1 = DeviceIdentity {
            vendor_id: None,
            product_id: None,
            serial: Some("ABC123".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sda".into(),
        };
        let id2 = DeviceIdentity {
            vendor_id: None,
            product_id: None,
            serial: Some("XYZ789".into()),
            bus_path: "/bus/1".into(),
            device_path: "/dev/sda".into(),
        };
        assert!(!id1.matches(&id2));
    }
    #[test]
    fn safe_write_target_removable() {
        let dev = BlockDevice {
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
        };
        assert!(is_safe_write_target(&dev));
    }
    #[test]
    fn safe_write_target_fixed_rejected() {
        let dev = BlockDevice {
            path: "/dev/sda".into(),
            name: "sda".into(),
            size_bytes: 500_000_000_000,
            class: DeviceClass::Sata,
            device_type: DeviceType::Fixed,
            vendor: None,
            model: None,
            serial: None,
            removable: false,
            read_only: false,
            mounted: false,
            mount_points: vec![],
            partitions: vec![],
        };
        assert!(!is_safe_write_target(&dev));
    }
    #[test]
    fn safe_write_target_system_mount_rejected() {
        let dev = BlockDevice {
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
            mounted: true,
            mount_points: vec!["/".into()],
            partitions: vec![],
        };
        assert!(!is_safe_write_target(&dev));
    }
}
