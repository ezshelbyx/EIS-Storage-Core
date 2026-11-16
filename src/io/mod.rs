use crate::error::{Result, StorageError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const BUFFER_SIZE: usize = 65536;
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

#[derive(Clone)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(StorageError::Cancelled)
        } else {
            Ok(())
        }
    }
}
impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SafeReader {
    file: File,
    size: u64,
    position: u64,
}
impl SafeReader {
    pub fn open(path: &str) -> Result<Self> {
        validate_path(path)?;
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file,
            size,
            position: 0,
        })
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn position(&self) -> u64 {
        self.position
    }
    pub fn hash(&mut self, algo: crate::crypto::HashAlgorithm) -> Result<String> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut hasher = crate::crypto::StreamingHasher::new(algo);
        let mut buf = [0u8; BUFFER_SIZE];
        loop {
            let n = self.file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            self.position += n as u64;
        }
        Ok(hasher.finalize())
    }
    pub fn read_all_with_progress<F: FnMut(u64, u64)>(
        &mut self,
        mut on_progress: F,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut result = Vec::with_capacity(self.size as usize);
        let mut buf = [0u8; BUFFER_SIZE];
        let mut read_total: u64 = 0;
        loop {
            if let Some(ct) = &cancel {
                ct.check()?;
            }
            let n = self.file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
            read_total += n as u64;
            on_progress(read_total, self.size);
        }
        Ok(result)
    }
    pub fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset + len as u64 > self.size {
            return Err(StorageError::InvalidDevicePath("read beyond end".into()));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.file.read_exact(&mut buf)?;
        self.position = offset + len as u64;
        Ok(buf)
    }
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

pub struct SafeWriter {
    file: File,
    bytes_written: u64,
    verify_on_write: bool,
}
impl SafeWriter {
    pub fn create(path: &str) -> Result<Self> {
        validate_path(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file,
            bytes_written: 0,
            verify_on_write: false,
        })
    }
    pub fn open_device(path: &str) -> Result<Self> {
        validate_path(path)?;
        let file = OpenOptions::new().write(true).open(path)?;
        Ok(Self {
            file,
            bytes_written: 0,
            verify_on_write: false,
        })
    }
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
    pub fn set_verify_on_write(&mut self, v: bool) {
        self.verify_on_write = v;
    }
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        let n = self.file.write(data)?;
        self.bytes_written += n as u64;
        self.file.flush()?;
        Ok(n)
    }
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.file.write_all(data)?;
        self.bytes_written += data.len() as u64;
        self.file.flush()?;
        Ok(())
    }
    pub fn write_stream<R: Read, F: FnMut(u64, u64)>(
        &mut self,
        mut source: R,
        total: u64,
        mut on_progress: F,
        cancel: Option<CancellationToken>,
    ) -> Result<u64> {
        let mut buf = [0u8; BUFFER_SIZE];
        let mut written: u64 = 0;
        loop {
            if let Some(ct) = &cancel {
                ct.check()?;
            }
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.file.write_all(&buf[..n])?;
            written += n as u64;
            on_progress(written, total);
        }
        self.file.flush()?;
        self.bytes_written += written;
        Ok(written)
    }
    pub fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(StorageError::InvalidDevicePath("empty path".into()));
    }
    if !path.starts_with('/') && !path.starts_with('.') {
        return Err(StorageError::InvalidDevicePath(format!(
            "path must be absolute or relative: {}",
            path
        )));
    }
    let blocked = ["/dev/sda", "/dev/nvme0n1", "/dev/hda", "/dev/vda"];
    for b in &blocked {
        if path == *b || path.starts_with(&format!("{}/", b)) {
            return Err(StorageError::DestructiveBlocked);
        }
    }
    Ok(())
}

pub fn copy_image_to_device(
    source_path: &str,
    target_path: &str,
    on_progress: Option<Box<dyn Fn(u64, u64) + Send + Sync>>,
    cancel: Option<CancellationToken>,
) -> Result<u64> {
    validate_path(target_path)?;
    let source = File::open(source_path)?;
    let source_size = source.metadata()?.len();
    let mut writer = SafeWriter::open_device(target_path)?;
    let progress = on_progress.unwrap_or_else(|| Box::new(|_, _| {}));
    let written = writer.write_stream(source, source_size, progress, cancel.clone())?;
    writer.sync()?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn cancellation_token() {
        let ct = CancellationToken::new();
        assert!(!ct.is_cancelled());
        ct.cancel();
        assert!(ct.is_cancelled());
        assert!(ct.check().is_err());
    }
    #[test]
    fn safe_reader_open_temp() {
        let dir = std::env::temp_dir();
        let path = dir.join("eis_test_reader.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let reader = SafeReader::open(path.to_str().unwrap()).unwrap();
        assert_eq!(reader.size(), 11);
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn safe_writer_create_and_write() {
        let dir = std::env::temp_dir();
        let path = dir.join("eis_test_writer.bin");
        let mut writer = SafeWriter::create(path.to_str().unwrap()).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.sync().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn write_stream_with_progress() {
        let dir = std::env::temp_dir();
        let path = dir.join("eis_test_stream.bin");
        let mut writer = SafeWriter::create(path.to_str().unwrap()).unwrap();
        let data = b"hello world test data";
        let mut cursor = Cursor::new(data.to_vec());
        let pc = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let pc2 = pc.clone();
        let written = writer
            .write_stream(
                cursor,
                data.len() as u64,
                move |w, t| {
                    pc2.lock().unwrap().push((w, t));
                },
                None,
            )
            .unwrap();
        assert_eq!(written, data.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn write_stream_cancelled() {
        let dir = std::env::temp_dir();
        let path = dir.join("eis_test_cancel.bin");
        let mut writer = SafeWriter::create(path.to_str().unwrap()).unwrap();
        let data = vec![0u8; 100000];
        let mut cursor = Cursor::new(data.clone());
        let ct = CancellationToken::new();
        ct.cancel();
        assert!(writer
            .write_stream(cursor, data.len() as u64, |_, _| {}, Some(ct))
            .is_err());
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn validate_path_blocks_system() {
        assert!(validate_path("/dev/sda").is_err());
        assert!(validate_path("/dev/nvme0n1").is_err());
    }
    #[test]
    fn validate_path_allows_temp() {
        assert!(validate_path("/tmp/test.img").is_ok());
    }
    #[test]
    fn read_at_offset() {
        let dir = std::env::temp_dir();
        let path = dir.join("eis_test_readat.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let mut reader = SafeReader::open(path.to_str().unwrap()).unwrap();
        assert_eq!(reader.read_at(6, 5).unwrap(), b"world");
        let _ = std::fs::remove_file(&path);
    }
}
