//! Finds well-known cryptographic and encoding constants (AES S-box, SHA-256 round constants, CRC tables, …)
//! in a program's bytes, the way IDA's FindCrypt plugin does. A hit says which algorithm the code probably uses.

use crate::loader::Binary;

pub struct Pattern {
    pub name: &'static str,
    pub algo: &'static str,
    pub bytes: &'static [u8],
}

pub const PATTERNS: &[Pattern] = &[
    Pattern { name: "AES_sbox", algo: "AES", bytes: &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76] },
    Pattern { name: "AES_inv_sbox", algo: "AES", bytes: &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb] },
    Pattern { name: "AES_te0", algo: "AES", bytes: &[0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8] },
    Pattern { name: "SHA256_K", algo: "SHA-256", bytes: &[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5] },
    Pattern { name: "SHA256_init", algo: "SHA-256", bytes: &[0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c] },
    Pattern { name: "SHA512_K", algo: "SHA-512", bytes: &[0x22, 0xae, 0x28, 0xd7, 0x98, 0x2f, 0x8a, 0x42, 0xcd, 0x65, 0xef, 0x23, 0x91, 0x44, 0x37, 0x71] },
    Pattern { name: "SHA1_K", algo: "SHA-1", bytes: &[0x99, 0x79, 0x82, 0x5a, 0xa1, 0xeb, 0xd9, 0x6e, 0xdc, 0xbc, 0x1b, 0x8f] },
    Pattern { name: "MD5_init", algo: "MD5/SHA-1", bytes: &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10] },
    Pattern { name: "MD5_K", algo: "MD5", bytes: &[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8, 0xdb, 0x70, 0x20, 0x24] },
    Pattern { name: "CRC32_table", algo: "CRC-32", bytes: &[0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee] },
    Pattern { name: "CRC32_table", algo: "CRC-32", bytes: &[0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96, 0xee, 0x0e, 0x61, 0x2c] },
    Pattern { name: "CRC32C_table", algo: "CRC-32C", bytes: &[0x00, 0x00, 0x00, 0x00, 0x03, 0x83, 0x13, 0xf2, 0x43, 0x4e, 0xe0, 0x6e] },
    Pattern { name: "Blowfish_P", algo: "Blowfish", bytes: &[0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85, 0x2e, 0x8a, 0x19, 0x13] },
    Pattern { name: "ChaCha_sigma", algo: "ChaCha20/Salsa20", bytes: b"expand 32-byte k" },
    Pattern { name: "ChaCha_tau", algo: "ChaCha20/Salsa20", bytes: b"expand 16-byte k" },
    Pattern { name: "Base64_alphabet", algo: "Base64", bytes: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" },
    Pattern { name: "Base32_alphabet", algo: "Base32", bytes: b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" },
    Pattern { name: "TEA_delta", algo: "TEA/XTEA", bytes: &[0xb9, 0x79, 0x37, 0x9e, ] },
    Pattern { name: "Poly1305_clamp", algo: "Poly1305", bytes: &[0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f] },
    Pattern { name: "Keccak_RC", algo: "SHA-3/Keccak", bytes: &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x80] },
    Pattern { name: "DES_sbox1", algo: "DES", bytes: &[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7] },
    Pattern { name: "RC5_RC6_magic", algo: "RC5/RC6", bytes: &[0x63, 0x51, 0xe1, 0xb7, 0x39, 0x79, 0x37, 0x9e] },
];

fn find_all(hay: &[u8], needle: &[u8], cap: usize) -> Vec<usize> {
    let mut out = vec![];
    if needle.is_empty() || hay.len() < needle.len() {
        return out;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        match hay[i..hay.len() - needle.len() + 1].iter().position(|b| *b == first) {
            None => break,
            Some(p) => {
                i += p;
                if &hay[i..i + needle.len()] == needle {
                    out.push(i);
                    if out.len() >= cap {
                        break;
                    }
                }
                i += 1;
            }
        }
    }
    out
}

/// (address, constant name, algorithm) for every hit, in address order.
pub fn scan(bin: &Binary) -> Vec<(u64, String, String)> {
    let mut out = vec![];
    for seg in &bin.segments {
        for p in PATTERNS {
            for off in find_all(&seg.data, p.bytes, 4) {
                // the four-byte TEA constant is too common in data; only trust it inside code
                if p.name == "TEA_delta" && !seg.exec {
                    continue;
                }
                out.push((seg.start + off as u64, p.name.to_string(), p.algo.to_string()));
            }
        }
    }
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_needles() {
        let mut h = vec![0u8; 100];
        h[40..44].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(find_all(&h, &[1, 2, 3, 4], 5), vec![40]);
        assert!(find_all(&h, &[9, 9], 5).is_empty());
    }

    #[test]
    fn finds_aes_sbox_in_a_segment() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(PATTERNS[0].bytes);
        let spec = crate::loader::RawSpec { path: "t".into(), name: "t".into(), arch: crate::loader::Arch::X64, big: false, segs: vec![(0x1000, data)], entry: None, format: "t".into() };
        let bin = crate::loader::raw_binary(&spec);
        let hits = scan(&bin);
        assert!(hits.iter().any(|h| h.1 == "AES_sbox" && h.0 == 0x1040), "{hits:?}");
    }
}
