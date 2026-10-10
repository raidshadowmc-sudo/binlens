#[derive(Debug, Clone)]
pub struct RawSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

pub fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    if end <= buf.len() {
        Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
    } else {
        None
    }
}

pub fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    if end <= buf.len() {
        Some(u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]))
    } else {
        None
    }
}

pub fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    if end <= buf.len() {
        Some(u64::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]))
    } else {
        None
    }
}

pub fn read_cstring(buf: &[u8], offset: usize) -> Option<String> {
    read_cstring_bounded(buf, offset, 1024)
}

pub fn read_cstring_bounded(buf: &[u8], offset: usize, max_len: usize) -> Option<String> {
    if offset >= buf.len() {
        return None;
    }
    let limit = offset
        .checked_add(max_len)
        .unwrap_or(buf.len())
        .min(buf.len());
    let mut end = offset;
    while end < limit && buf[end] != 0 {
        end += 1;
    }
    if end < buf.len() && buf[end] == 0 {
        String::from_utf8(buf[offset..end].to_vec()).ok()
    } else {
        None
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn rva_to_offset(rva: u32, sections: &[RawSection]) -> Option<usize> {
    if sections.is_empty() {
        return Some(rva as usize);
    }
    let first_va = sections
        .iter()
        .map(|s| s.virtual_address)
        .min()
        .unwrap_or(0x1000);
    if rva < first_va {
        return Some(rva as usize);
    }

    for s in sections {
        if s.size_of_raw_data == 0 || s.pointer_to_raw_data == 0 {
            continue;
        }
        let va = s.virtual_address;
        if rva >= va {
            let delta = rva - va;
            if delta < s.size_of_raw_data {
                let offset = (s.pointer_to_raw_data as usize).checked_add(delta as usize)?;
                return Some(offset);
            }
        }
    }
    None
}
