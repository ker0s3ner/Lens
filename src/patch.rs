//! Byte patching: edit code in the open program, keep the edits as a list, and write a patched copy.

use crate::loader::{Arch, Binary};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Patch {
    pub addr: u64,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
}

/// Puts the patched bytes into the in-memory image (the file on disk is never touched).
pub fn apply(bin: &mut Binary, patches: &[Patch]) {
    for p in patches {
        for (i, b) in p.new.iter().enumerate() {
            let a = p.addr + i as u64;
            if let Some(seg) = bin.segments.iter_mut().find(|s| s.contains(a)) {
                let off = (a - seg.start) as usize;
                if off < seg.data.len() {
                    seg.data[off] = *b;
                }
            }
        }
    }
}

pub fn nop_bytes(arch: Arch, big: bool, len: usize) -> Option<Vec<u8>> {
    let unit: Vec<u8> = match arch {
        Arch::X16 | Arch::X86 | Arch::X64 => return Some(vec![0x90; len]),
        Arch::Arm64 => vec![0x1F, 0x20, 0x03, 0xD5],
        Arch::Arm32 => if big { vec![0xE3, 0x20, 0xF0, 0x00] } else { vec![0x00, 0xF0, 0x20, 0xE3] },
        Arch::Thumb => if big { vec![0xBF, 0x00] } else { vec![0x00, 0xBF] },
        Arch::RiscV32 | Arch::RiscV64 => if len % 4 == 0 { vec![0x13, 0x00, 0x00, 0x00] } else { vec![0x01, 0x00] },
        Arch::Mips32 | Arch::Mips64 => vec![0, 0, 0, 0],
        Arch::Ppc32 | Arch::Ppc64 => if big { vec![0x60, 0, 0, 0] } else { vec![0, 0, 0, 0x60] },
        Arch::M68k => vec![0x4E, 0x71],
        Arch::Other => return None,
    };
    if len % unit.len() != 0 {
        return None;
    }
    Some(unit.iter().cycle().take(len).copied().collect())
}

fn w32(b: &[u8], big: bool) -> Option<u32> {
    let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
    Some(if big { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) })
}
fn put32(v: u32, big: bool) -> Vec<u8> {
    if big { v.to_be_bytes().to_vec() } else { v.to_le_bytes().to_vec() }
}

/// The same instruction with its condition reversed (je <-> jne, cbz <-> cbnz, beq <-> bne …).
pub fn invert_branch(arch: Arch, big: bool, b: &[u8]) -> Option<Vec<u8>> {
    match arch {
        Arch::X16 | Arch::X86 | Arch::X64 => {
            let mut v = b.to_vec();
            if (0x70..=0x7F).contains(b.first()?) {
                v[0] ^= 1;
                return Some(v);
            }
            if *b.first()? == 0x0F && (0x80..=0x8F).contains(b.get(1)?) {
                v[1] ^= 1;
                return Some(v);
            }
            None
        }
        Arch::Arm64 => {
            let w = w32(b, big)?;
            if w & 0xFF00_0010 == 0x5400_0000 && (w & 0xF) < 0xE {
                return Some(put32(w ^ 1, big));
            }
            if matches!(w & 0x7F00_0000, 0x3400_0000 | 0x3500_0000 | 0x3600_0000 | 0x3700_0000) {
                return Some(put32(w ^ (1 << 24), big));
            }
            None
        }
        Arch::Arm32 => {
            let w = w32(b, big)?;
            let cond = w >> 28;
            if cond < 0xE && (w >> 25) & 7 == 0b101 {
                return Some(put32(w ^ (1 << 28), big));
            }
            None
        }
        Arch::RiscV32 | Arch::RiscV64 => {
            let w = w32(b, big)?;
            (w & 0x7F == 0x63).then(|| put32(w ^ (1 << 12), big))
        }
        Arch::Mips32 | Arch::Mips64 => {
            let w = w32(b, big)?;
            matches!(w >> 26, 4 | 5).then(|| put32(w ^ (1 << 26), big))
        }
        _ => None,
    }
}

/// Turn a conditional branch into an unconditional one. `ip` is the branch's address.
pub fn force_jump(arch: Arch, big: bool, b: &[u8]) -> Option<Vec<u8>> {
    match arch {
        Arch::X16 | Arch::X86 | Arch::X64 => {
            if (0x70..=0x7F).contains(b.first()?) {
                let mut v = b.to_vec();
                v[0] = 0xEB;
                return Some(v);
            }
            if *b.first()? == 0x0F && (0x80..=0x8F).contains(b.get(1)?) && b.len() == 6 {
                let rel = i32::from_le_bytes(b[2..6].try_into().ok()?).wrapping_add(1);
                let mut v = vec![0xE9];
                v.extend(rel.to_le_bytes());
                v.push(0x90);
                return Some(v);
            }
            None
        }
        Arch::Arm64 => {
            let w = w32(b, big)?;
            if w & 0xFF00_0010 == 0x5400_0000 {
                let imm19 = (w >> 5) & 0x7FFFF;
                let signed = ((imm19 << 13) as i32) >> 13;
                return Some(put32(0x1400_0000 | (signed as u32 & 0x03FF_FFFF), big));
            }
            None
        }
        _ => None,
    }
}

/// Write the patches into a copy of the original file. Returns how many bytes were changed.
pub fn save_patched(bin: &Binary, patches: &[Patch], dest: &std::path::Path) -> Result<usize, String> {
    let mut bytes = std::fs::read(&bin.path).map_err(|e| format!("Couldn't read the original file: {e}"))?;
    let mut n = 0;
    for p in patches {
        for (i, b) in p.new.iter().enumerate() {
            let a = p.addr + i as u64;
            let seg = bin.segments.iter().find(|s| s.contains(a) && s.file_offset.is_some()).ok_or(format!("{a:X} isn't backed by the file, so it can't be saved"))?;
            let off = (bin.file_base + seg.file_offset.unwrap() + (a - seg.start)) as usize;
            let slot = bytes.get_mut(off).ok_or("A patch points past the end of the file")?;
            *slot = *b;
            n += 1;
        }
    }
    std::fs::write(dest, &bytes).map_err(|e| format!("Couldn't write the file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(&bin.path) {
            let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(m.permissions().mode()));
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invert() {
        assert_eq!(invert_branch(Arch::X64, false, &[0x74, 0x05]), Some(vec![0x75, 0x05]));
        assert_eq!(invert_branch(Arch::X64, false, &[0x0F, 0x84, 1, 0, 0, 0]), Some(vec![0x0F, 0x85, 1, 0, 0, 0]));
        // b.eq +8  ->  b.ne +8
        assert_eq!(invert_branch(Arch::Arm64, false, &0x5400_0040u32.to_le_bytes()), Some(0x5400_0041u32.to_le_bytes().to_vec()));
        assert_eq!(nop_bytes(Arch::Arm64, false, 8).unwrap().len(), 8);
        assert!(nop_bytes(Arch::Arm64, false, 6).is_none());
    }
    #[test]
    fn force() {
        assert_eq!(force_jump(Arch::X64, false, &[0x74, 0x05]), Some(vec![0xEB, 0x05]));
        // b.eq +8 (imm19=2) -> b +8 (imm26=2)
        assert_eq!(force_jump(Arch::Arm64, false, &0x5400_0040u32.to_le_bytes()), Some(0x1400_0002u32.to_le_bytes().to_vec()));
    }
}
