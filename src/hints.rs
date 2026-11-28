//! Function starts found in the tables compilers leave behind (ELF .eh_frame, PE .pdata, Mach-O function-start and unwind indexes).
//! They let Lens find functions in stripped programs that no symbol or call points at.

use crate::loader::Binary;

fn uleb(d: &[u8], p: &mut usize) -> Option<u64> {
    let (mut r, mut s) = (0u64, 0u32);
    loop {
        let b = *d.get(*p)?;
        *p += 1;
        if s < 64 {
            r |= ((b & 0x7f) as u64) << s;
        }
        s += 7;
        if b & 0x80 == 0 {
            return Some(r);
        }
    }
}

fn sleb(d: &[u8], p: &mut usize) -> Option<i64> {
    let (mut r, mut s) = (0i64, 0u32);
    loop {
        let b = *d.get(*p)?;
        *p += 1;
        if s < 64 {
            r |= ((b & 0x7f) as i64) << s;
        }
        s += 7;
        if b & 0x80 == 0 {
            if s < 64 && b & 0x40 != 0 {
                r |= -1i64 << s;
            }
            return Some(r);
        }
    }
}

/// Mach-O LC_FUNCTION_STARTS blob: ULEB128 deltas starting at the __TEXT base.
pub fn macho_starts(blob: &[u8], text_base: u64) -> Vec<u64> {
    let mut out = vec![];
    let (mut p, mut a) = (0usize, text_base);
    while p < blob.len() {
        let Some(d) = uleb(blob, &mut p) else { break };
        if d == 0 {
            break;
        }
        a = a.wrapping_add(d);
        out.push(a);
    }
    out
}

/// Parse Mach-O `__unwind_info` first- and second-level indexes for function starts.
/// Both regular and compressed second-level pages are supported. All offsets and counts
/// are bounded before slicing so malformed metadata cannot panic the loader.
pub fn macho_unwind_info(blob: &[u8], text_base: u64, bin: &Binary) -> Vec<u64> {
    fn u16at(d: &[u8], p: usize) -> Option<u16> { Some(u16::from_le_bytes(d.get(p..p.checked_add(2)?)?.try_into().ok()?)) }
    fn u32at(d: &[u8], p: usize) -> Option<u32> { Some(u32::from_le_bytes(d.get(p..p.checked_add(4)?)?.try_into().ok()?)) }
    let Some(version) = u32at(blob, 0) else { return vec![] };
    let (Some(index_off), Some(index_count)) = (u32at(blob, 20), u32at(blob, 24)) else { return vec![] };
    if version != 1 || index_count < 2 || index_count > 1_000_000 { return vec![]; }
    let index_off = index_off as usize;
    let index_count = index_count as usize;
    let Some(index_bytes) = index_count.checked_mul(12).and_then(|n| index_off.checked_add(n)) else { return vec![] };
    if index_bytes > blob.len() { return vec![]; }
    let mut out = Vec::new();
    for i in 0..index_count - 1 {
        let p = index_off + i * 12;
        let Some(function_base) = u32at(blob, p) else { break };
        let Some(page_off) = u32at(blob, p + 4).map(|x| x as usize) else { break };
        let Some(kind) = u32at(blob, page_off) else { continue };
        let (Some(entry_off), Some(entry_count)) = (u16at(blob, page_off + 4).map(|x| x as usize), u16at(blob, page_off + 6).map(|x| x as usize)) else { continue };
        if entry_count == 0 || entry_count > 65_535 { continue; }
        match kind {
            2 => {
                let Some(start) = page_off.checked_add(entry_off) else { continue };
                for n in 0..entry_count {
                    let Some(ep) = n.checked_mul(8).and_then(|x| start.checked_add(x)) else { break };
                    let Some(off) = u32at(blob, ep) else { break };
                    if off == 0 { continue; }
                    let addr = text_base.saturating_add(off as u64);
                    if bin.is_exec(addr) { out.push(addr); }
                }
            }
            3 => {
                let (Some(enc_off), Some(enc_count)) = (u16at(blob, page_off + 8).map(|x| x as usize), u16at(blob, page_off + 10).map(|x| x as usize)) else { continue };
                let Some(start) = page_off.checked_add(entry_off) else { continue };
                let Some(enc_start) = page_off.checked_add(enc_off) else { continue };
                let Some(enc_end) = enc_count.checked_mul(4).and_then(|n| enc_start.checked_add(n)) else { continue };
                if enc_end > blob.len() { continue; }
                for n in 0..entry_count {
                    let Some(ep) = n.checked_mul(4).and_then(|x| start.checked_add(x)) else { break };
                    let Some(packed) = u32at(blob, ep) else { break };
                    let delta = packed & 0x00ff_ffff;
                    let enc_index = (packed >> 24) as usize;
                    if enc_index >= enc_count { continue; }
                    let off = (function_base as u64).saturating_add(delta as u64);
                    let addr = text_base.saturating_add(off);
                    if bin.is_exec(addr) { out.push(addr); }
                }
            }
            _ => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// PE x64 .pdata uses 12-byte records; ARM/ARM64 use 8-byte records with
/// packed unwind data. Function starts occupy the first word in both forms.
pub fn pe_pdata(bin: &Binary, base: u64) -> Vec<u64> {
    let mut out = vec![];
    let arm_unwind = matches!(bin.arch, crate::loader::Arch::Arm32 | crate::loader::Arch::Thumb | crate::loader::Arch::Arm64);
    let record_size = if arm_unwind { 8 } else { 12 };
    for s in bin.segments.iter().filter(|s| s.name.eq_ignore_ascii_case(".pdata")) {
        for c in s.data.chunks_exact(record_size) {
            let b = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64;
            let valid_record = if arm_unwind {
                b != 0
            } else {
                let e = u32::from_le_bytes([c[4], c[5], c[6], c[7]]) as u64;
                b != 0 && e > b
            };
            if valid_record {
                let Some(addr) = base.checked_add(b) else { continue };
                if bin.is_exec(addr) {
                    out.push(addr);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn read_enc(d: &[u8], p: &mut usize, enc: u8, field_addr: u64) -> Option<u64> {
    let v: i64 = match enc & 0x0f {
        0x00 => { let x = u64::from_le_bytes(d.get(*p..*p + 8)?.try_into().ok()?); *p += 8; x as i64 }
        0x02 => { let x = u16::from_le_bytes(d.get(*p..*p + 2)?.try_into().ok()?); *p += 2; x as i64 }
        0x03 => { let x = u32::from_le_bytes(d.get(*p..*p + 4)?.try_into().ok()?); *p += 4; x as i64 }
        0x04 => { let x = u64::from_le_bytes(d.get(*p..*p + 8)?.try_into().ok()?); *p += 8; x as i64 }
        0x0a => { let x = i16::from_le_bytes(d.get(*p..*p + 2)?.try_into().ok()?); *p += 2; x as i64 }
        0x0b => { let x = i32::from_le_bytes(d.get(*p..*p + 4)?.try_into().ok()?); *p += 4; x as i64 }
        0x0c => { let x = i64::from_le_bytes(d.get(*p..*p + 8)?.try_into().ok()?); *p += 8; x }
        _ => return None,
    };
    Some(match enc & 0x70 {
        0x10 => (field_addr as i64).wrapping_add(v) as u64,
        _ => v as u64,
    })
}

/// ELF .eh_frame: every FDE names the start of one function.
pub fn eh_frame(bin: &Binary) -> Vec<u64> {
    let Some(seg) = bin.segments.iter().find(|s| s.name == ".eh_frame") else { return vec![] };
    let d = &seg.data;
    let mut cies: std::collections::HashMap<usize, u8> = Default::default();
    let mut out = vec![];
    let mut pos = 0usize;
    while pos + 8 <= d.len() {
        let len = u32::from_le_bytes([d[pos], d[pos + 1], d[pos + 2], d[pos + 3]]) as usize;
        if len == 0 || len == 0xffff_ffff {
            break;
        }
        let body = pos + 4;
        let end = body + len;
        if end > d.len() || len < 4 {
            break;
        }
        let id = u32::from_le_bytes([d[body], d[body + 1], d[body + 2], d[body + 3]]) as usize;
        if id == 0 {
            // CIE
            let mut p = body + 4;
            let Some(&ver) = d.get(p).filter(|_| p < end) else { break };
            p += 1;
            let aug_start = p;
            while p < end && d[p] != 0 { p += 1; }
            if p >= end { break; }
            let aug: Vec<u8> = d[aug_start..p.min(end)].to_vec();
            p += 1;
            let mut enc = 0u8;
            let _ = uleb(d, &mut p);
            let _ = sleb(d, &mut p);
            if ver == 1 {
                if p >= end { break; }
                p += 1;
            } else {
                let _ = uleb_bounded(d, &mut p, end);
            }
            if aug.first() == Some(&b'z') {
                let _ = uleb_bounded(d, &mut p, end);
                for c in &aug[1..] {
                    match c {
                        b'R' => { enc = *d.get(p).filter(|_| p < end).unwrap_or(&0); if p >= end { break; } p += 1; }
                        b'L' => { if p >= end { break; } p += 1; }
                        b'P' => {
                            let Some(&e) = d.get(p).filter(|_| p < end) else { break };
                            p += 1;
                            let mut q = p;
                            if read_enc_bounded(d, &mut q, e & 0x7f, 0, end).is_some() { p = q; } else { break; }
                        }
                        _ => {}
                    }
                }
            }
            cies.insert(pos, enc);
        } else if let Some(cie) = (body).checked_sub(id).and_then(|c| cies.get(&c)).copied() {
            let mut p = body + 4;
            let field = seg.start + p as u64;
            if let Some(a) = read_enc(d, &mut p, cie, field) {
                if a != 0 && bin.is_exec(a) {
                    out.push(a);
                }
            }
        }
        pos = end;
    }
    out
}

fn uleb_bounded(d: &[u8], p: &mut usize, end: usize) -> Option<u64> {
    if *p > end { return None; }
    let start = *p;
    let v = uleb(&d[..end], p);
    if v.is_none() { *p = start; }
    v
}

fn read_enc_bounded(d: &[u8], p: &mut usize, enc: u8, field_addr: u64, end: usize) -> Option<u64> {
    if *p > end { return None; }
    let start = *p;
    let v = read_enc(&d[..end], p, enc, field_addr);
    if v.is_none() { *p = start; }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macho_function_starts_are_deltas() {
        // 0x100, +0x20 (one byte), +0x1000 (two bytes: 0x80 0x20), end
        let blob = [0x80, 0x02, 0x20, 0x80, 0x20, 0x00];
        assert_eq!(macho_starts(&blob, 0x1000), vec![0x1100, 0x1120, 0x2120]);
    }

    #[test]
    fn leb_decoding() {
        let mut p = 0;
        assert_eq!(uleb(&[0xe5, 0x8e, 0x26], &mut p), Some(624485));
        let mut p = 0;
        assert_eq!(sleb(&[0x7f], &mut p), Some(-1));
        let mut p = 0;
        assert_eq!(sleb(&[0x80, 0x7f], &mut p), Some(-128));
    }

    #[test]
    fn bounded_eh_frame_fields_do_not_cross_record_boundary() {
        let mut p = 0;
        assert_eq!(uleb_bounded(&[0x80, 0x01], &mut p, 1), None);
        assert_eq!(p, 0);

        let mut p = 0;
        assert_eq!(read_enc_bounded(&[0, 0, 0, 0], &mut p, 0x03, 0, 2), None);
        assert_eq!(p, 0);
    }

    #[test]
    fn pe_pdata_keeps_only_executable_function_starts() {
        let mut bin = crate::loader::raw_binary(&crate::loader::RawSpec {
            path: "test".into(),
            name: "test".into(),
            arch: crate::loader::Arch::Arm64,
            big: false,
            segs: vec![(0x1000, vec![0; 0x100]), (0x2000, vec![0; 16])],
            entry: Some(0x1000),
            format: "raw".into(),
        });
        bin.segments[1].name = ".pdata".into();
        bin.segments[1].data = std::sync::Arc::new(vec![
            0x10, 0, 0, 0, 1, 0, 0, 0,
            0x20, 0, 0, 0, 1, 0, 0, 0,
        ]);
        assert_eq!(pe_pdata(&bin, 0x1000), vec![0x1010, 0x1020]);
    }
}
