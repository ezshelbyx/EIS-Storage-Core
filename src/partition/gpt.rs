use crate::error::{Result, StorageError};
use crate::partition::Partition;

pub fn parse_gpt_header(data: &[u8]) -> Result<(u32, u32, u64, u64, u64, u64, u64, u32, u32)> {
    if data.len() < 1024 {
        return Err(StorageError::InvalidGpt("data too short".into()));
    }
    let hdr = &data[512..512 + 92];
    if &hdr[0..8] != b"EFI PART" {
        return Err(StorageError::InvalidGpt("bad signature".into()));
    }
    let revision = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let header_size = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
    let current_lba = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let backup_lba = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let first_usable_lba = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
    let last_usable_lba = u64::from_le_bytes(hdr[48..56].try_into().unwrap());
    let partition_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes([hdr[80], hdr[81], hdr[82], hdr[83]]);
    let entry_size = u32::from_le_bytes([hdr[84], hdr[85], hdr[86], hdr[87]]);
    Ok((
        revision,
        header_size,
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        partition_entry_lba,
        num_entries,
        entry_size,
    ))
}

pub fn parse_gpt_partitions(data: &[u8]) -> Result<Vec<Partition>> {
    let (_, _, _, _, _, _, entry_lba, num_entries, entry_size) = parse_gpt_header(data)?;
    let entry_size = entry_size as usize;
    if entry_size < 128 {
        return Err(StorageError::InvalidGpt("bad entry size".into()));
    }
    let num_entries = num_entries as usize;
    if num_entries == 0 || num_entries > 128 {
        return Err(StorageError::InvalidGpt("bad entry count".into()));
    }
    let entry_offset = entry_lba as usize * 512;
    let total = num_entries * entry_size;
    if entry_offset + total > data.len() {
        return Err(StorageError::InvalidGpt("entries beyond data".into()));
    }
    let mut partitions = Vec::new();
    for i in 0..num_entries {
        let off = entry_offset + i * entry_size;
        let entry = &data[off..off + entry_size];
        let type_guid = &entry[0..16];
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }
        let unique_guid = &entry[16..32];
        let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let name_bytes = &entry[56..128];
        let name = decode_utf16le(name_bytes);
        let type_guid_str = format_guid(type_guid);
        partitions.push(Partition {
            index: partitions.len() as u32,
            start_lba,
            end_lba,
            size_bytes: if end_lba >= start_lba {
                (end_lba - start_lba + 1) * 512
            } else {
                0
            },
            partition_type: 0,
            type_guid: Some(type_guid_str.clone()),
            unique_guid: Some(format_guid(unique_guid)),
            name: if name.is_empty() { None } else { Some(name) },
            bootable: false,
            filesystem_hint: gpt_type_to_fs(&type_guid_str),
        });
    }
    Ok(partitions)
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            break;
        }
        if let Some(c) = char::from_u32(code as u32) {
            chars.push(c);
        }
    }
    chars.into_iter().collect()
}

fn format_guid(bytes: &[u8]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])
}

fn gpt_type_to_fs(guid: &str) -> Option<String> {
    let g = guid.to_lowercase();
    if g.starts_with("c12a7328") {
        Some("EFI System".into())
    } else if g.starts_with("0fc63daf") {
        Some("Linux".into())
    } else if g.starts_with("ebd0a0a2") {
        Some("Microsoft Basic Data".into())
    } else if g.starts_with("0657fd6d") {
        Some("Windows Recovery".into())
    } else if g.starts_with("e3c9e316") {
        Some("Microsoft Reserved".into())
    } else {
        None
    }
}

pub fn validate_gpt(data: &[u8]) -> Result<()> {
    let (_, _, _, _, first_usable, last_usable, _, _num_entries, entry_size) =
        parse_gpt_header(data)?;
    if first_usable >= last_usable {
        return Err(StorageError::InvalidGpt("bad usable range".into()));
    }
    if entry_size < 128 {
        return Err(StorageError::InvalidGpt("entry size too small".into()));
    }
    let parts = parse_gpt_partitions(data)?;
    for p in &parts {
        if p.start_lba < first_usable || p.end_lba > last_usable {
            return Err(StorageError::PartitionOutOfBounds {
                start: p.start_lba,
                end: p.end_lba,
                disk_size: last_usable,
            });
        }
        if p.start_lba > p.end_lba {
            return Err(StorageError::InvalidGpt("start > end".into()));
        }
    }
    for i in 0..parts.len() {
        for j in (i + 1)..parts.len() {
            if parts[i].start_lba <= parts[j].end_lba && parts[j].start_lba <= parts[i].end_lba {
                return Err(StorageError::InvalidGpt(format!(
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
    #[test]
    fn parse_gpt_header_bad_sig() {
        assert!(parse_gpt_header(&vec![0u8; 1024]).is_err());
    }
    #[test]
    fn parse_gpt_partitions_short_data() {
        assert!(parse_gpt_header(&vec![0u8; 512]).is_err());
    }
    #[test]
    fn format_guid_works() {
        let bytes = [
            0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47,
            0x7D, 0xE4,
        ];
        assert_eq!(format_guid(&bytes), "0fc63daf-8483-4772-8e79-3d69d8477de4");
    }
    #[test]
    fn decode_utf16le_basic() {
        let bytes = [0x41, 0x00, 0x42, 0x00, 0x00, 0x00];
        assert_eq!(decode_utf16le(&bytes), "AB");
    }
}
