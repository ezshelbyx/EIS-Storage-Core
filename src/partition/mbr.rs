use crate::error::{Result, StorageError};
use crate::partition::Partition;

const PARTITION_TABLE_OFFSET: usize = 446;
const PARTITION_ENTRY_SIZE: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct MbrEntry {
    pub status: u8,
    pub partition_type: u8,
    pub start_lba: u32,
    pub num_sectors: u32,
}

impl MbrEntry {
    pub fn is_empty(&self) -> bool {
        self.partition_type == 0 && self.num_sectors == 0
    }
    pub fn is_bootable(&self) -> bool {
        self.status == 0x80
    }
    pub fn end_lba(&self) -> u64 {
        if self.num_sectors == 0 {
            0
        } else {
            self.start_lba as u64 + self.num_sectors as u64 - 1
        }
    }
}

pub fn parse_mbr_partitions(data: &[u8]) -> Result<Vec<Partition>> {
    if data.len() < 512 {
        return Err(StorageError::InvalidMbr("data too short".into()));
    }
    if data[510] != 0x55 || data[511] != 0xAA {
        return Err(StorageError::InvalidMbr("bad signature".into()));
    }
    let mut partitions = Vec::new();
    for i in 0..4 {
        let off = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE;
        let entry = parse_mbr_entry(&data[off..off + PARTITION_ENTRY_SIZE]);
        if entry.is_empty() {
            continue;
        }
        if entry.partition_type == 0x05
            || entry.partition_type == 0x0F
            || entry.partition_type == 0x85
        {
            continue; // extended - skip for simplicity
        }
        partitions.push(Partition {
            index: i as u32,
            start_lba: entry.start_lba as u64,
            end_lba: entry.end_lba(),
            size_bytes: entry.num_sectors as u64 * 512,
            partition_type: entry.partition_type,
            type_guid: None,
            unique_guid: None,
            name: None,
            bootable: entry.is_bootable(),
            filesystem_hint: mbr_type_to_fs(entry.partition_type),
        });
    }
    for (i, p) in partitions.iter_mut().enumerate() {
        p.index = i as u32;
    }
    Ok(partitions)
}

fn parse_mbr_entry(data: &[u8]) -> MbrEntry {
    MbrEntry {
        status: data[0],
        partition_type: data[4],
        start_lba: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        num_sectors: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
    }
}

fn mbr_type_to_fs(ptype: u8) -> Option<String> {
    match ptype {
        0x01 => Some("FAT12".into()),
        0x04 | 0x06 | 0x0E => Some("FAT16".into()),
        0x0B | 0x0C => Some("FAT32".into()),
        0x07 => Some("NTFS/exFAT".into()),
        0x83 => Some("Linux".into()),
        0x82 => Some("Linux Swap".into()),
        0xEE => Some("GPT Protective".into()),
        0xEF => Some("EFI System".into()),
        _ => None,
    }
}

pub fn validate_mbr(data: &[u8]) -> Result<()> {
    if data.len() < 512 {
        return Err(StorageError::InvalidMbr("too short".into()));
    }
    if data[510] != 0x55 || data[511] != 0xAA {
        return Err(StorageError::InvalidMbr("bad signature".into()));
    }
    let parts = parse_mbr_partitions(data)?;
    for i in 0..parts.len() {
        for j in (i + 1)..parts.len() {
            if parts[i].start_lba <= parts[j].end_lba && parts[j].start_lba <= parts[i].end_lba {
                return Err(StorageError::InvalidMbr(format!(
                    "partitions {} and {} overlap",
                    i, j
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_mbr() -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[510] = 0x55;
        data[511] = 0xAA;
        let off = 446;
        data[off + 4] = 0x07;
        data[off + 8..off + 12].copy_from_slice(&2048u32.to_le_bytes());
        data[off + 12..off + 16].copy_from_slice(&1000u32.to_le_bytes());
        let off2 = 446 + 16;
        data[off2 + 4] = 0x83;
        data[off2 + 8..off2 + 12].copy_from_slice(&4096u32.to_le_bytes());
        data[off2 + 12..off2 + 16].copy_from_slice(&2000u32.to_le_bytes());
        data
    }
    #[test]
    fn parse_mbr_basic() {
        let data = make_mbr();
        let parts = parse_mbr_partitions(&data).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].partition_type, 0x07);
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].size_bytes, 1000 * 512);
        assert_eq!(parts[1].partition_type, 0x83);
        assert_eq!(parts[1].start_lba, 4096);
    }
    #[test]
    fn parse_mbr_empty() {
        let mut data = vec![0u8; 512];
        data[510] = 0x55;
        data[511] = 0xAA;
        assert!(parse_mbr_partitions(&data).unwrap().is_empty());
    }
    #[test]
    fn parse_mbr_bad_signature() {
        assert!(parse_mbr_partitions(&vec![0u8; 512]).is_err());
    }
    #[test]
    fn parse_mbr_too_short() {
        assert!(parse_mbr_partitions(&vec![0u8; 256]).is_err());
    }
    #[test]
    fn validate_mbr_ok() {
        assert!(validate_mbr(&make_mbr()).is_ok());
    }
    #[test]
    fn mbr_bootable_flag() {
        let mut data = make_mbr();
        data[446] = 0x80;
        assert!(parse_mbr_partitions(&data).unwrap()[0].bootable);
    }
    #[test]
    fn mbr_filesystem_hint() {
        let data = make_mbr();
        let parts = parse_mbr_partitions(&data).unwrap();
        assert_eq!(parts[0].filesystem_hint.as_deref(), Some("NTFS/exFAT"));
        assert_eq!(parts[1].filesystem_hint.as_deref(), Some("Linux"));
    }
}
