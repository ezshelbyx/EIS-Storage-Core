use crate::crypto::HashAlgorithm;
use crate::error::{Result, StorageError};
use crate::io::SafeReader;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub success: bool,
    pub bytes_verified: u64,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub mismatches: Vec<Mismatch>,
}

#[derive(Debug, Clone)]
pub struct Mismatch {
    pub offset: u64,
    pub expected_byte: u8,
    pub actual_byte: u8,
}

pub fn verify_image_hash(source_path: &str, target_path: &str) -> Result<VerificationResult> {
    let mut source_reader = SafeReader::open(source_path)?;
    let source_hash = source_reader.hash(HashAlgorithm::Sha256)?;
    let mut target_reader = SafeReader::open(target_path)?;
    let target_hash = target_reader.hash(HashAlgorithm::Sha256)?;
    let success = source_hash == target_hash;
    Ok(VerificationResult {
        success,
        bytes_verified: target_reader.size(),
        expected_hash: Some(source_hash),
        actual_hash: Some(target_hash),
        mismatches: Vec::new(),
    })
}

pub fn verify_byte_by_byte(
    source_path: &str,
    target_path: &str,
    on_progress: Option<Box<dyn Fn(u64, u64) + Send + Sync>>,
) -> Result<VerificationResult> {
    let mut source = SafeReader::open(source_path)?;
    let mut target = SafeReader::open(target_path)?;
    if source.size() != target.size() {
        return Err(StorageError::VerificationFailed(format!(
            "size mismatch: source={} target={}",
            source.size(),
            target.size()
        )));
    }
    let total = source.size();
    let progress = on_progress.unwrap_or_else(|| Box::new(|_, _| {}));
    let mut mismatches = Vec::new();
    let mut verified: u64 = 0;
    let mut buf_s = [0u8; 65536];
    let mut buf_t = [0u8; 65536];
    source.file_mut().seek(SeekFrom::Start(0))?;
    target.file_mut().seek(SeekFrom::Start(0))?;
    loop {
        let n_s = source.file_mut().read(&mut buf_s)?;
        let n_t = target.file_mut().read(&mut buf_t)?;
        if n_s == 0 && n_t == 0 {
            break;
        }
        let n = n_s.min(n_t);
        for i in 0..n {
            if buf_s[i] != buf_t[i] {
                mismatches.push(Mismatch {
                    offset: verified + i as u64,
                    expected_byte: buf_s[i],
                    actual_byte: buf_t[i],
                });
                if mismatches.len() > 1000 {
                    break;
                }
            }
        }
        if mismatches.len() > 1000 {
            break;
        }
        verified += n as u64;
        progress(verified, total);
        if n_s != n_t {
            return Err(StorageError::VerificationFailed(
                "read length mismatch".into(),
            ));
        }
    }
    Ok(VerificationResult {
        success: mismatches.is_empty(),
        bytes_verified: verified,
        expected_hash: None,
        actual_hash: None,
        mismatches,
    })
}

pub fn verify_write(source_hash: &str, target_path: &str) -> Result<bool> {
    let mut reader = SafeReader::open(target_path)?;
    let actual = reader.hash(HashAlgorithm::Sha256)?;
    Ok(actual == source_hash)
}

pub fn hash_file(path: &str, algo: HashAlgorithm) -> Result<String> {
    let mut reader = SafeReader::open(path)?;
    reader.hash(algo)
}

pub fn check_integrity(path: &str, expected_hash: &str, algo: HashAlgorithm) -> Result<bool> {
    let actual = hash_file(path, algo)?;
    Ok(actual.eq_ignore_ascii_case(expected_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn verify_identical_files() {
        let dir = std::env::temp_dir();
        let p1 = dir.join("eis_v_a.bin");
        let p2 = dir.join("eis_v_b.bin");
        std::fs::write(&p1, b"hello world test").unwrap();
        std::fs::write(&p2, b"hello world test").unwrap();
        let r = verify_byte_by_byte(p1.to_str().unwrap(), p2.to_str().unwrap(), None).unwrap();
        assert!(r.success);
        assert_eq!(r.bytes_verified, 16);
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }
    #[test]
    fn verify_different_files() {
        let dir = std::env::temp_dir();
        let p1 = dir.join("eis_v_c.bin");
        let p2 = dir.join("eis_v_d.bin");
        std::fs::write(&p1, b"hello world test").unwrap();
        std::fs::write(&p2, b"hello WORLD test").unwrap();
        let r = verify_byte_by_byte(p1.to_str().unwrap(), p2.to_str().unwrap(), None).unwrap();
        assert!(!r.success);
        assert!(!r.mismatches.is_empty());
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }
    #[test]
    fn verify_hash_match() {
        let dir = std::env::temp_dir();
        let p1 = dir.join("eis_v_e.bin");
        let p2 = dir.join("eis_v_f.bin");
        std::fs::write(&p1, b"hello").unwrap();
        std::fs::write(&p2, b"hello").unwrap();
        assert!(
            verify_image_hash(p1.to_str().unwrap(), p2.to_str().unwrap())
                .unwrap()
                .success
        );
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }
    #[test]
    fn verify_hash_mismatch() {
        let dir = std::env::temp_dir();
        let p1 = dir.join("eis_v_g.bin");
        let p2 = dir.join("eis_v_h.bin");
        std::fs::write(&p1, b"hello").unwrap();
        std::fs::write(&p2, b"world").unwrap();
        assert!(
            !verify_image_hash(p1.to_str().unwrap(), p2.to_str().unwrap())
                .unwrap()
                .success
        );
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }
    #[test]
    fn hash_file_works() {
        let dir = std::env::temp_dir();
        let p = dir.join("eis_v_i.bin");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            hash_file(p.to_str().unwrap(), HashAlgorithm::Sha256).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&p);
    }
    #[test]
    fn check_integrity_ok() {
        let dir = std::env::temp_dir();
        let p = dir.join("eis_v_j.bin");
        std::fs::write(&p, b"abc").unwrap();
        assert!(check_integrity(
            p.to_str().unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            HashAlgorithm::Sha256
        )
        .unwrap());
        let _ = std::fs::remove_file(&p);
    }
}
