use crate::entropy::calculate_entropy;
use crate::pe::hex_encode;
use crate::types::{BinaryFormat, BinaryReport, SectionInfo, SecurityMitigations};
use md5::Md5;
use sha2::{Digest, Sha256};

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= buf.len() {
        Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
    } else {
        None
    }
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 <= buf.len() {
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

fn read_u64_le(buf: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 <= buf.len() {
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

fn read_cstring(buf: &[u8], offset: usize) -> Option<String> {
    if offset >= buf.len() {
        return None;
    }
    let mut end = offset;
    while end < buf.len() && buf[end] != 0 {
        end += 1;
    }
    String::from_utf8(buf[offset..end].to_vec()).ok()
}

pub fn parse_elf(data: &[u8], file_name: &str) -> Option<BinaryReport> {
    if data.len() < 52 {
        return None;
    }
    if &data[0..4] != b"\x7fELF" {
        return None;
    }

    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let is_64 = class == 2;

    let e_type = read_u16_le(data, 16)?;
    let e_machine = read_u16_le(data, 18)?;

    let arch_str = match e_machine {
        0x03 => "x86 (32-bit)",
        0x3E => "x86_64 (64-bit)",
        0x28 => "ARM",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        _ => "Unknown",
    };

    let (entry_point, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if is_64 {
        let entry = read_u64_le(data, 24)?;
        let phoff = read_u64_le(data, 32)? as usize;
        let shoff = read_u64_le(data, 40)? as usize;
        let phentsize = read_u16_le(data, 54)? as usize;
        let phnum = read_u16_le(data, 56)? as usize;
        let shentsize = read_u16_le(data, 58)? as usize;
        let shnum = read_u16_le(data, 60)? as usize;
        let shstrndx = read_u16_le(data, 62)? as usize;
        (entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
    } else {
        let entry = read_u32_le(data, 24)? as u64;
        let phoff = read_u32_le(data, 28)? as usize;
        let shoff = read_u32_le(data, 32)? as usize;
        let phentsize = read_u16_le(data, 42)? as usize;
        let phnum = read_u16_le(data, 44)? as usize;
        let shentsize = read_u16_le(data, 46)? as usize;
        let shnum = read_u16_le(data, 48)? as usize;
        let shstrndx = read_u16_le(data, 50)? as usize;
        (entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
    };

    let mut nx_enabled = true;
    let mut relro = "None".to_string();

    for i in 0..phnum {
        let off = phoff + (i * phentsize);
        if off + phentsize <= data.len() {
            let p_type = read_u32_le(data, off).unwrap_or(0);
            if p_type == 0x6474e551 {
                let flags = if is_64 {
                    read_u32_le(data, off + 4).unwrap_or(0)
                } else {
                    read_u32_le(data, off + 24).unwrap_or(0)
                };
                if (flags & 1) != 0 {
                    nx_enabled = false;
                }
            } else if p_type == 0x6474e552 {
                relro = "Partial / Full".to_string();
            }
        }
    }

    let is_pie = e_type == 3;

    let shstrtab_offset = if shstrndx < shnum {
        let str_sh_off = shoff + (shstrndx * shentsize);
        if is_64 {
            read_u64_le(data, str_sh_off + 24).unwrap_or(0) as usize
        } else {
            read_u32_le(data, str_sh_off + 16).unwrap_or(0) as usize
        }
    } else {
        0
    };

    let mut sections = Vec::new();
    let mut has_rwx = false;

    for i in 0..shnum {
        let off = shoff + (i * shentsize);
        if off + shentsize > data.len() {
            break;
        }

        let sh_name_idx = read_u32_le(data, off).unwrap_or(0) as usize;
        let name = if shstrtab_offset > 0 {
            read_cstring(data, shstrtab_offset + sh_name_idx).unwrap_or_else(|| "unnamed".to_string())
        } else {
            format!("sec_{}", i)
        };

        let (addr, sec_offset, size, flags) = if is_64 {
            let flags = read_u64_le(data, off + 8).unwrap_or(0);
            let addr = read_u64_le(data, off + 16).unwrap_or(0);
            let offset = read_u64_le(data, off + 24).unwrap_or(0) as usize;
            let size = read_u64_le(data, off + 32).unwrap_or(0) as usize;
            (addr, offset, size, flags)
        } else {
            let flags = read_u32_le(data, off + 8).unwrap_or(0) as u64;
            let addr = read_u32_le(data, off + 12).unwrap_or(0) as u64;
            let offset = read_u32_le(data, off + 16).unwrap_or(0) as usize;
            let size = read_u32_le(data, off + 20).unwrap_or(0) as usize;
            (addr, offset, size, flags)
        };

        let writable = (flags & 1) != 0;
        let alloc = (flags & 2) != 0;
        let exec = (flags & 4) != 0;
        let is_rwx = writable && exec;
        if is_rwx {
            has_rwx = true;
        }

        let end = (sec_offset + size).min(data.len());
        let sec_data = if sec_offset < data.len() {
            &data[sec_offset..end]
        } else {
            &[]
        };
        let entropy = calculate_entropy(sec_data);

        sections.push(SectionInfo {
            name,
            virtual_address: addr,
            virtual_size: size as u64,
            raw_offset: sec_offset as u64,
            raw_size: size as u64,
            entropy,
            readable: alloc,
            writable,
            executable: exec,
            is_rwx,
        });
    }

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(data);
    let sha256 = hex_encode(&sha_hasher.finalize());

    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5 = hex_encode(&md5_hasher.finalize());

    let overall_entropy = calculate_entropy(data);

    Some(BinaryReport {
        file_name: file_name.to_string(),
        file_size: data.len() as u64,
        md5,
        sha256,
        format: if is_64 {
            BinaryFormat::ELF64
        } else {
            BinaryFormat::ELF32
        },
        architecture: arch_str.to_string(),
        subsystem: "Unix/Linux ELF".to_string(),
        entry_point,
        overall_entropy,
        is_likely_packed: overall_entropy >= 7.2,
        mitigations: SecurityMitigations {
            aslr: is_pie,
            high_entropy_va: is_64,
            dep_nx: nx_enabled,
            seh: false,
            cfg: false,
            authenticode_signed: false,
            has_rwx_sections: has_rwx,
            pie: is_pie,
            relro,
        },
        sections,
        imports: Vec::new(),
        exports: Vec::new(),
        imphash: None,
        interesting_strings: Vec::new(),
    })
}
