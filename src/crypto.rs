use crate::error::Result;
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha512_hex(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_reader<R: Read>(reader: &mut R) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub fn crc64(data: &[u8]) -> u64 {
    let mut crc: u64 = 0;
    for &byte in data {
        crc ^= (byte as u64) << 56;
        for _ in 0..8 {
            if crc & 0x8000_0000_0000_0000 != 0 {
                crc = (crc << 1) ^ 0x42F0E1EBA9EA3693;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

pub fn md5_hex(data: &[u8]) -> String {
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xEFCDAB89;
    let mut c: u32 = 0x98BADCFE;
    let mut d: u32 = 0x10325476;
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);
        for i in 0..64usize {
            let (f, g) = if i < 16 {
                ((bb & cc) | (!bb & dd), i)
            } else if i < 32 {
                ((dd & bb) | (!dd & cc), (5 * i + 1) % 16)
            } else if i < 48 {
                (bb ^ cc ^ dd, (3 * i + 5) % 16)
            } else {
                (cc ^ (bb | !dd), (7 * i) % 16)
            };
            let temp = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(
                aa.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(x[g])
                    .rotate_left(S[i]),
            );
            aa = temp;
        }
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }
    let mut result = Vec::with_capacity(16);
    for &v in &[a, b, c, d] {
        result.extend_from_slice(&v.to_le_bytes());
    }
    hex::encode(result)
}

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Md5,
    Crc32,
    Crc64,
}

impl HashAlgorithm {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Md5 => "MD5",
            Self::Crc32 => "CRC32",
            Self::Crc64 => "CRC64",
        }
    }
    pub fn hash(&self, data: &[u8]) -> String {
        match self {
            Self::Sha256 => sha256_hex(data),
            Self::Sha512 => sha512_hex(data),
            Self::Md5 => md5_hex(data),
            Self::Crc32 => format!("{:08x}", crc32(data)),
            Self::Crc64 => format!("{:016x}", crc64(data)),
        }
    }
}

pub struct StreamingHasher {
    algo: HashAlgorithm,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
    crc32_state: u32,
    crc64_state: u64,
    bytes_processed: u64,
    md5_buf: Vec<u8>,
}

impl StreamingHasher {
    pub fn new(algo: HashAlgorithm) -> Self {
        Self {
            algo,
            sha256: if algo == HashAlgorithm::Sha256 {
                Some(Sha256::new())
            } else {
                None
            },
            sha512: if algo == HashAlgorithm::Sha512 {
                Some(Sha512::new())
            } else {
                None
            },
            crc32_state: 0xFFFFFFFF,
            crc64_state: 0,
            bytes_processed: 0,
            md5_buf: Vec::new(),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.bytes_processed += data.len() as u64;
        match self.algo {
            HashAlgorithm::Sha256 => {
                if let Some(h) = &mut self.sha256 {
                    h.update(data);
                }
            }
            HashAlgorithm::Sha512 => {
                if let Some(h) = &mut self.sha512 {
                    h.update(data);
                }
            }
            HashAlgorithm::Md5 => {
                self.md5_buf.extend_from_slice(data);
            }
            HashAlgorithm::Crc32 => {
                let mut crc = self.crc32_state;
                for &byte in data {
                    crc ^= byte as u32;
                    for _ in 0..8 {
                        if crc & 1 == 1 {
                            crc = (crc >> 1) ^ 0xEDB88320;
                        } else {
                            crc >>= 1;
                        }
                    }
                }
                self.crc32_state = crc;
            }
            HashAlgorithm::Crc64 => {
                let mut crc = self.crc64_state;
                for &byte in data {
                    crc ^= (byte as u64) << 56;
                    for _ in 0..8 {
                        if crc & 0x8000_0000_0000_0000 != 0 {
                            crc = (crc << 1) ^ 0x42F0E1EBA9EA3693;
                        } else {
                            crc <<= 1;
                        }
                    }
                }
                self.crc64_state = crc;
            }
        }
    }
    pub fn finalize(mut self) -> String {
        match self.algo {
            HashAlgorithm::Sha256 => {
                if let Some(h) = self.sha256.take() {
                    hex::encode(h.finalize())
                } else {
                    String::new()
                }
            }
            HashAlgorithm::Sha512 => {
                if let Some(h) = self.sha512.take() {
                    hex::encode(h.finalize())
                } else {
                    String::new()
                }
            }
            HashAlgorithm::Md5 => md5_hex(&self.md5_buf),
            HashAlgorithm::Crc32 => format!("{:08x}", !self.crc32_state),
            HashAlgorithm::Crc64 => format!("{:016x}", self.crc64_state),
        }
    }
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

pub fn hashes_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn sha256_eis() {
        assert_eq!(
            sha256_hex(b"EIS test"),
            "08fa24243c8dbdadfecc92e02c3247b3e952063f7cb6f84315eba8cf0ebe24f9"
        );
    }
    #[test]
    fn crc32_known() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }
    #[test]
    fn crc64_known() {
        assert_eq!(crc64(b"123456789"), 0x6C40DF5F0B497347);
    }
    #[test]
    fn md5_empty() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }
    #[test]
    fn md5_abc() {
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }
    #[test]
    fn streaming_sha256() {
        let mut h = StreamingHasher::new(HashAlgorithm::Sha256);
        h.update(b"ab");
        h.update(b"c");
        assert_eq!(
            h.finalize(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn streaming_reader() {
        use std::io::Cursor;
        let mut c = Cursor::new(b"abc".to_vec());
        assert_eq!(
            sha256_reader(&mut c).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn algo_name() {
        assert_eq!(HashAlgorithm::Sha256.name(), "SHA-256");
    }
}
