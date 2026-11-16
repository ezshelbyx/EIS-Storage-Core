pub mod gpt;
pub mod mbr;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableType {
    Mbr,
    Gpt,
    Unknown,
    None,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub index: u32,
    pub start_lba: u64,
    pub end_lba: u64,
    pub size_bytes: u64,
    pub partition_type: u8,
    pub type_guid: Option<String>,
    pub unique_guid: Option<String>,
    pub name: Option<String>,
    pub bootable: bool,
    pub filesystem_hint: Option<String>,
}

impl Partition {
    pub fn size_sectors(&self) -> u64 {
        if self.end_lba >= self.start_lba {
            self.end_lba - self.start_lba + 1
        } else {
            0
        }
    }
}

pub fn detect_partition_table(data: &[u8]) -> PartitionTableType {
    if data.len() < 512 {
        return PartitionTableType::None;
    }
    if data.len() >= 1024 && &data[512..520] == b"EFI PART" {
        return PartitionTableType::Gpt;
    }
    if data[510] == 0x55 && data[511] == 0xAA {
        if data.len() >= 1024 && &data[512..520] == b"EFI PART" {
            return PartitionTableType::Gpt;
        }
        if data[446 + 4] == 0xEE {
            return PartitionTableType::Gpt;
        }
        return PartitionTableType::Mbr;
    }
    PartitionTableType::Unknown
}

pub fn parse_partitions(data: &[u8]) -> Result<(PartitionTableType, Vec<Partition>)> {
    let pt_type = detect_partition_table(data);
    match pt_type {
        PartitionTableType::Mbr => Ok((pt_type, mbr::parse_mbr_partitions(data)?)),
        PartitionTableType::Gpt => Ok((pt_type, gpt::parse_gpt_partitions(data)?)),
        _ => Ok((pt_type, Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_empty() {
        let data = vec![0u8; 1024];
        assert_eq!(detect_partition_table(&data), PartitionTableType::Unknown);
    }
    #[test]
    fn detect_mbr_signature() {
        let mut data = vec![0u8; 1024];
        data[510] = 0x55;
        data[511] = 0xAA;
        assert_eq!(detect_partition_table(&data), PartitionTableType::Mbr);
    }
    #[test]
    fn detect_gpt() {
        let mut data = vec![0u8; 1024];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[512..520].copy_from_slice(b"EFI PART");
        assert_eq!(detect_partition_table(&data), PartitionTableType::Gpt);
    }
    #[test]
    fn detect_protective_mbr() {
        let mut data = vec![0u8; 1024];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[446 + 4] = 0xEE;
        assert_eq!(detect_partition_table(&data), PartitionTableType::Gpt);
    }
}
