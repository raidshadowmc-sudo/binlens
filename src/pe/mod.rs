pub mod exports;
pub mod imports;
pub mod mitigations;
pub mod rich;
pub mod utils;

pub use exports::parse_exports;
pub use imports::parse_imports;
pub use mitigations::parse_mitigations;
pub use rich::{get_rich_tool_name, parse_rich_header};
pub use utils::{
    RawSection, hex_encode, read_cstring, read_cstring_bounded, read_u16, read_u32, read_u64,
    rva_to_offset,
};

use crate::entropy::calculate_entropy;
use crate::types::{BinaryFormat, BinaryReport, SectionInfo};
use md5::Md5;
use sha2::{Digest, Sha256};

pub fn parse_pe(data: &[u8], file_name: &str) -> Option<BinaryReport> {
    if data.len() < 64 {
        return None;
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew.checked_add(4).is_none_or(|end| end > data.len()) {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let rich_header = parse_rich_header(data, e_lfanew);

    let coff_offset = e_lfanew.checked_add(4)?;
    let machine = read_u16(data, coff_offset)?;
    let num_sections = coff_offset
        .checked_add(2)
        .and_then(|off| read_u16(data, off))? as usize;
    let size_of_opt_hdr = coff_offset
        .checked_add(16)
        .and_then(|off| read_u16(data, off))? as usize;

    let opt_hdr_offset = coff_offset.checked_add(20)?;
    if opt_hdr_offset
        .checked_add(size_of_opt_hdr)
        .is_none_or(|end| end > data.len())
    {
        return None;
    }

    let opt_magic = read_u16(data, opt_hdr_offset)?;
    let is_64 = match opt_magic {
        0x10b => false, // PE32
        0x20b => true,  // PE32+
        _ => return None,
    };

    let entry_point_rva = opt_hdr_offset
        .checked_add(16)
        .and_then(|off| read_u32(data, off))? as u64;
    let size_of_headers = opt_hdr_offset
        .checked_add(60)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0x400) as usize;

    let (image_base, subsystem_val, dll_chars, data_dirs_offset) = if is_64 {
        let base = opt_hdr_offset
            .checked_add(24)
            .and_then(|off| read_u64(data, off))
            .unwrap_or(0x140000000);
        let sub = opt_hdr_offset
            .checked_add(68)
            .and_then(|off| read_u16(data, off))?;
        let dll = opt_hdr_offset
            .checked_add(70)
            .and_then(|off| read_u16(data, off))?;
        let dd = opt_hdr_offset.checked_add(112)?;
        (base, sub, dll, dd)
    } else {
        let base = opt_hdr_offset
            .checked_add(28)
            .and_then(|off| read_u32(data, off))
            .unwrap_or(0x400000) as u64;
        let sub = opt_hdr_offset
            .checked_add(68)
            .and_then(|off| read_u16(data, off))?;
        let dll = opt_hdr_offset
            .checked_add(70)
            .and_then(|off| read_u16(data, off))?;
        let dd = opt_hdr_offset.checked_add(96)?;
        (base, sub, dll, dd)
    };

    let arch_str = match machine {
        0x014c => "x86 (32-bit)",
        0x8664 => "x86_64 / AMD64 (64-bit)",
        0xaa64 => "ARM64",
        0x01c0 => "ARM",
        _ => "Unknown",
    };

    let subsystem_str = match subsystem_val {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI (Console)",
        7 => "POSIX CUI",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        _ => "Unknown",
    };

    let export_dir_rva = read_u32(data, data_dirs_offset).unwrap_or(0);
    let import_dir_rva = data_dirs_offset
        .checked_add(8)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0);
    let cert_dir_offset = data_dirs_offset
        .checked_add(32)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0) as usize;
    let cert_dir_size = data_dirs_offset
        .checked_add(36)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0) as usize;

    let section_headers_offset = opt_hdr_offset.checked_add(size_of_opt_hdr)?;
    let mut raw_sections = Vec::new();
    let mut sections = Vec::new();
    let mut has_rwx_sections = false;

    for i in 0..num_sections {
        let sec_offset = match i
            .checked_mul(40)
            .and_then(|delta| section_headers_offset.checked_add(delta))
        {
            Some(off) => off,
            None => break,
        };
        if sec_offset
            .checked_add(40)
            .is_none_or(|end| end > data.len())
        {
            break;
        }
        let name_bytes = &data[sec_offset..sec_offset + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        let virt_size = sec_offset
            .checked_add(8)
            .and_then(|off| read_u32(data, off))
            .unwrap_or(0);
        let virt_addr = sec_offset
            .checked_add(12)
            .and_then(|off| read_u32(data, off))
            .unwrap_or(0);
        let raw_size = sec_offset
            .checked_add(16)
            .and_then(|off| read_u32(data, off))
            .unwrap_or(0);
        let raw_offset = sec_offset
            .checked_add(20)
            .and_then(|off| read_u32(data, off))
            .unwrap_or(0);
        let characteristics = sec_offset
            .checked_add(36)
            .and_then(|off| read_u32(data, off))
            .unwrap_or(0);

        raw_sections.push(RawSection {
            virtual_address: virt_addr,
            virtual_size: virt_size,
            pointer_to_raw_data: raw_offset,
            size_of_raw_data: raw_size,
        });

        let readable = (characteristics & 0x4000_0000) != 0;
        let writable = (characteristics & 0x8000_0000) != 0;
        let executable = (characteristics & 0x2000_0000) != 0;
        let is_rwx = writable && executable;

        if is_rwx {
            has_rwx_sections = true;
        }

        let raw_off = raw_offset as usize;
        let raw_sz = raw_size as usize;
        let raw_end = raw_off
            .checked_add(raw_sz)
            .unwrap_or(data.len())
            .min(data.len());
        let sec_data = if raw_off < data.len() {
            &data[raw_off..raw_end]
        } else {
            &[]
        };
        let entropy = calculate_entropy(sec_data);

        sections.push(SectionInfo {
            name,
            virtual_address: virt_addr as u64,
            virtual_size: virt_size as u64,
            raw_offset: raw_offset as u64,
            raw_size: raw_size as u64,
            entropy,
            readable,
            writable,
            executable,
            is_rwx,
        });
    }

    let mut mitigations = parse_mitigations(
        data,
        is_64,
        dll_chars,
        data_dirs_offset,
        &raw_sections,
        has_rwx_sections,
    );

    let (imports, imphash) = parse_imports(data, import_dir_rva, &raw_sections, is_64);
    let exports = parse_exports(data, export_dir_rva, &raw_sections);

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(data);
    let sha256 = hex_encode(&sha_hasher.finalize());

    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5 = hex_encode(&md5_hasher.finalize());

    let overall_entropy = calculate_entropy(data);
    let is_likely_packed = overall_entropy >= 7.2;

    let entry_point_preview = crate::disasm::disassemble_pe_entry_point(
        data,
        entry_point_rva as u32,
        image_base,
        is_64,
        &raw_sections,
        16,
    );

    let authenticode_report = crate::authenticode::verify_pe_authenticode(
        data,
        e_lfanew,
        is_64,
        cert_dir_offset,
        cert_dir_size,
        size_of_headers,
        &raw_sections,
    );

    if let Some(ref auth) = authenticode_report {
        mitigations.authenticode_signed = auth.is_signed;
    }

    Some(BinaryReport {
        file_name: file_name.to_string(),
        file_size: data.len() as u64,
        md5,
        sha256,
        format: if is_64 {
            BinaryFormat::PE64
        } else {
            BinaryFormat::PE32
        },
        architecture: arch_str.to_string(),
        subsystem: subsystem_str.to_string(),
        entry_point: entry_point_rva,
        overall_entropy,
        is_likely_packed,
        mitigations,
        sections,
        imports,
        exports,
        rich_header,
        imphash,
        interesting_strings: Vec::new(),
        entry_point_preview,
        authenticode: authenticode_report,
        yara: None,
    })
}
