#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Ntfs,
    Ext2,
    Ext3,
    Ext4,
    Btrfs,
    Xfs,
    Iso9660,
    Squashfs,
    Swap,
    Unknown,
}

impl FilesystemType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fat12 => "FAT12",
            Self::Fat16 => "FAT16",
            Self::Fat32 => "FAT32",
            Self::ExFat => "exFAT",
            Self::Ntfs => "NTFS",
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Btrfs => "Btrfs",
            Self::Xfs => "XFS",
            Self::Iso9660 => "ISO 9660",
            Self::Squashfs => "SquashFS",
            Self::Swap => "Linux Swap",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemInfo {
    pub fs_type: FilesystemType,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub cluster_size: Option<u32>,
    pub total_size: Option<u64>,
    pub free_size: Option<u64>,
    pub block_size: Option<u32>,
}

pub fn detect_filesystem(data: &[u8]) -> FilesystemType {
    if data.len() >= 32774 && &data[32769..32774] == b"CD001" {
        return FilesystemType::Iso9660;
    }
    if data.len() >= 4 && (&data[0..4] == b"hsqs" || &data[0..4] == b"sqsh") {
        return FilesystemType::Squashfs;
    }
    if data.len() >= 11 && &data[3..11] == b"NTFS    " {
        return FilesystemType::Ntfs;
    }
    if data.len() >= 11 && &data[3..11] == b"EXFAT   " {
        return FilesystemType::ExFat;
    }
    if data.len() < 512 {
        // Only filesystems detectable in small buffers remain below
    }
    // FAT check (requires >= 40 bytes)
    if data.len() < 40 {
        // skip FAT; continue
    } else {
        let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
        let sectors_per_cluster = data[13];
        let num_fats = data[16];
        let fat_size_16 = u16::from_le_bytes([data[22], data[23]]);
        let fat_size_32 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        if bytes_per_sector > 0
            && (bytes_per_sector == 512
                || bytes_per_sector == 1024
                || bytes_per_sector == 2048
                || bytes_per_sector == 4096)
            && sectors_per_cluster > 0
            && num_fats >= 1
            && num_fats <= 2
        {
            if fat_size_16 == 0 && fat_size_32 > 0 {
                return FilesystemType::Fat32;
            }
            if fat_size_16 > 0 {
                let total_sectors = if u16::from_le_bytes([data[19], data[20]]) != 0 {
                    u16::from_le_bytes([data[19], data[20]]) as u32
                } else {
                    u32::from_le_bytes([data[32], data[33], data[34], data[35]])
                };
                let root_entries = u16::from_le_bytes([data[17], data[18]]);
                let reserved = u16::from_le_bytes([data[14], data[15]]) as u32;
                let data_sectors = total_sectors.saturating_sub(
                    reserved
                        + (num_fats as u32 * fat_size_16 as u32)
                        + ((root_entries as u32 * 32 + bytes_per_sector as u32 - 1)
                            / bytes_per_sector as u32),
                );
                let clusters = data_sectors / (sectors_per_cluster as u32);
                if clusters < 4085 {
                    return FilesystemType::Fat12;
                } else {
                    return FilesystemType::Fat16;
                }
            }
        }
    }
    // ext
    if data.len() >= 1082 {
        let magic = u16::from_le_bytes([data[1024 + 56], data[1024 + 57]]);
        if magic == 0xEF53 {
            let incompat = u32::from_le_bytes([
                data[1024 + 96],
                data[1024 + 97],
                data[1024 + 98],
                data[1024 + 99],
            ]);
            if incompat & 0x40 != 0 {
                return FilesystemType::Ext4;
            }
            let compat = u32::from_le_bytes([
                data[1024 + 92],
                data[1024 + 93],
                data[1024 + 94],
                data[1024 + 95],
            ]);
            if compat & 0x4 != 0 || incompat & 0x4 != 0 {
                return FilesystemType::Ext3;
            }
            return FilesystemType::Ext2;
        }
    }
    if data.len() >= 72 && &data[64..72] == b"_BHRfS_M" {
        return FilesystemType::Btrfs;
    }
    if data.len() >= 4 && &data[0..4] == b"XFSB" {
        return FilesystemType::Xfs;
    }
    if data.len() >= 4096 && &data[4086..4096] == b"SWAPSPACE2" {
        return FilesystemType::Swap;
    }
    FilesystemType::Unknown
}

pub fn detect_partition_filesystem(data: &[u8]) -> FilesystemType {
    detect_filesystem(data)
}

pub fn fat_volume_label(data: &[u8]) -> Option<String> {
    let fs = detect_filesystem(data);
    match fs {
        FilesystemType::Fat32 => {
            if data.len() >= 82 {
                let label = &data[71..82];
                let s = String::from_utf8_lossy(label).trim().to_string();
                if s.is_empty() || s.chars().all(|c| c == ' ' || c == '\0') {
                    None
                } else {
                    Some(s)
                }
            } else {
                None
            }
        }
        FilesystemType::Fat16 | FilesystemType::Fat12 => {
            if data.len() >= 54 {
                let label = &data[43..54];
                let s = String::from_utf8_lossy(label).trim().to_string();
                if s.is_empty() || s.chars().all(|c| c == ' ' || c == '\0') {
                    None
                } else {
                    Some(s)
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn ntfs_serial(data: &[u8]) -> Option<String> {
    if data.len() >= 80 && &data[3..11] == b"NTFS    " {
        let serial = u64::from_le_bytes(data[72..80].try_into().ok()?);
        Some(format!("{:016X}", serial))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_empty() {
        assert_eq!(detect_filesystem(&[]), FilesystemType::Unknown);
    }
    #[test]
    fn detect_iso9660() {
        let mut d = vec![0u8; 32774 + 5];
        d[32769..32774].copy_from_slice(b"CD001");
        assert_eq!(detect_filesystem(&d), FilesystemType::Iso9660);
    }
    #[test]
    fn detect_squashfs() {
        let mut d = vec![0u8; 512];
        d[0..4].copy_from_slice(b"hsqs");
        assert_eq!(detect_filesystem(&d), FilesystemType::Squashfs);
    }
    #[test]
    fn detect_ntfs() {
        let mut d = vec![0u8; 512];
        d[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(detect_filesystem(&d), FilesystemType::Ntfs);
    }
    #[test]
    fn detect_exfat() {
        let mut d = vec![0u8; 512];
        d[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(detect_filesystem(&d), FilesystemType::ExFat);
    }
    #[test]
    fn detect_fat32() {
        let mut d = vec![0u8; 512];
        d[11] = 0x00;
        d[12] = 0x02;
        d[13] = 8;
        d[16] = 2;
        d[36] = 0x01;
        assert_eq!(detect_filesystem(&d), FilesystemType::Fat32);
    }
    #[test]
    fn detect_ext4() {
        let mut d = vec![0u8; 2048];
        d[1024 + 56] = 0x53;
        d[1024 + 57] = 0xEF;
        d[1024 + 96] = 0x40;
        assert_eq!(detect_filesystem(&d), FilesystemType::Ext4);
    }
    #[test]
    fn detect_ext2() {
        let mut d = vec![0u8; 2048];
        d[1024 + 56] = 0x53;
        d[1024 + 57] = 0xEF;
        assert_eq!(detect_filesystem(&d), FilesystemType::Ext2);
    }
    #[test]
    fn detect_btrfs() {
        let mut d = vec![0u8; 128];
        d[64..72].copy_from_slice(b"_BHRfS_M");
        assert_eq!(detect_filesystem(&d), FilesystemType::Btrfs);
    }
    #[test]
    fn detect_xfs() {
        let mut d = vec![0u8; 512];
        d[0..4].copy_from_slice(b"XFSB");
        assert_eq!(detect_filesystem(&d), FilesystemType::Xfs);
    }
    #[test]
    fn detect_swap() {
        let mut d = vec![0u8; 4096];
        d[4086..4096].copy_from_slice(b"SWAPSPACE2");
        assert_eq!(detect_filesystem(&d), FilesystemType::Swap);
    }
    #[test]
    fn fs_type_name() {
        assert_eq!(FilesystemType::Fat32.name(), "FAT32");
        assert_eq!(FilesystemType::Ntfs.name(), "NTFS");
    }
}
