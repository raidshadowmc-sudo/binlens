use crate::entropy::calculate_entropy;
use crate::types::{BinaryFormat, BinaryReport, ExportInfo, ImportInfo, SectionInfo, SecurityMitigations};
use md5::Md5;
use sha2::{Digest, Sha256};

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= buf.len() {
        Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
    } else {
        None
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
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

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
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

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct RawSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

fn rva_to_offset(rva: u32, sections: &[RawSection]) -> Option<usize> {
    for s in sections {
        let va = s.virtual_address;
        let sz = s.virtual_size.max(s.size_of_raw_data);
        if rva >= va && rva < va + sz {
            let delta = rva - va;
            let offset = s.pointer_to_raw_data as usize + delta as usize;
            return Some(offset);
        }
    }
    None
}

pub fn parse_pe(data: &[u8], file_name: &str) -> Option<BinaryReport> {
    if data.len() < 64 {
        return None;
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let coff_offset = e_lfanew + 4;
    let machine = read_u16(data, coff_offset)?;
    let num_sections = read_u16(data, coff_offset + 2)? as usize;
    let size_of_opt_hdr = read_u16(data, coff_offset + 16)? as usize;

    let opt_hdr_offset = coff_offset + 20;
    if opt_hdr_offset + size_of_opt_hdr > data.len() {
        return None;
    }

    let opt_magic = read_u16(data, opt_hdr_offset)?;
    let is_64 = match opt_magic {
        0x10b => false, // PE32
        0x20b => true,  // PE32+
        _ => return None,
    };

    let entry_point_rva = read_u32(data, opt_hdr_offset + 16)? as u64;

    let (subsystem_val, dll_chars, data_dirs_offset) = if is_64 {
        let sub = read_u16(data, opt_hdr_offset + 68)?;
        let dll = read_u16(data, opt_hdr_offset + 70)?;
        (sub, dll, opt_hdr_offset + 112)
    } else {
        let sub = read_u16(data, opt_hdr_offset + 68)?;
        let dll = read_u16(data, opt_hdr_offset + 70)?;
        (sub, dll, opt_hdr_offset + 96)
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

    let mut mitigations = SecurityMitigations {
        high_entropy_va: (dll_chars & 0x0020) != 0,
        aslr: (dll_chars & 0x0040) != 0,
        dep_nx: (dll_chars & 0x0100) != 0,
        seh: (dll_chars & 0x0400) == 0,
        cfg: (dll_chars & 0x4000) != 0,
        authenticode_signed: false,
        has_rwx_sections: false,
        pie: (dll_chars & 0x0040) != 0,
        relro: "N/A (Windows)".to_string(),
    };

    let export_dir_rva = read_u32(data, data_dirs_offset).unwrap_or(0);
    let import_dir_rva = read_u32(data, data_dirs_offset + 8).unwrap_or(0);
    let cert_dir_size = read_u32(data, data_dirs_offset + 32 + 4).unwrap_or(0);

    if cert_dir_size > 0 {
        mitigations.authenticode_signed = true;
    }

    let section_headers_offset = opt_hdr_offset + size_of_opt_hdr;
    let mut raw_sections = Vec::new();
    let mut sections = Vec::new();

    for i in 0..num_sections {
        let sec_offset = section_headers_offset + (i * 40);
        if sec_offset + 40 > data.len() {
            break;
        }
        let name_bytes = &data[sec_offset..sec_offset + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        let virt_size = read_u32(data, sec_offset + 8).unwrap_or(0);
        let virt_addr = read_u32(data, sec_offset + 12).unwrap_or(0);
        let raw_size = read_u32(data, sec_offset + 16).unwrap_or(0);
        let raw_offset = read_u32(data, sec_offset + 20).unwrap_or(0);
        let characteristics = read_u32(data, sec_offset + 36).unwrap_or(0);

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
            mitigations.has_rwx_sections = true;
        }

        let raw_end = (raw_offset as usize + raw_size as usize).min(data.len());
        let sec_data = if (raw_offset as usize) < data.len() {
            &data[raw_offset as usize..raw_end]
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

    let mut imports = Vec::new();
    let mut imphash_items = Vec::new();

    if import_dir_rva > 0 {
        if let Some(mut imp_offset) = rva_to_offset(import_dir_rva, &raw_sections) {
            while imp_offset + 20 <= data.len() {
                let orig_first_thunk = read_u32(data, imp_offset).unwrap_or(0);
                let name_rva = read_u32(data, imp_offset + 12).unwrap_or(0);
                let first_thunk = read_u32(data, imp_offset + 16).unwrap_or(0);

                if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                    break;
                }

                if let Some(name_offset) = rva_to_offset(name_rva, &raw_sections) {
                    if let Some(dll_name) = read_cstring(data, name_offset) {
                        let thunk_rva = if orig_first_thunk != 0 {
                            orig_first_thunk
                        } else {
                            first_thunk
                        };
                        let mut funcs = Vec::new();

                        if let Some(mut thunk_offset) = rva_to_offset(thunk_rva, &raw_sections) {
                            let step = if is_64 { 8 } else { 4 };
                            while thunk_offset + step <= data.len() {
                                let val = if is_64 {
                                    read_u64(data, thunk_offset).unwrap_or(0)
                                } else {
                                    read_u32(data, thunk_offset).unwrap_or(0) as u64
                                };

                                if val == 0 {
                                    break;
                                }

                                let is_ordinal = if is_64 {
                                    (val & 0x8000_0000_0000_0000) != 0
                                } else {
                                    (val & 0x8000_0000) != 0
                                };

                                let func_name = if is_ordinal {
                                    let ord = (val & 0xFFFF) as u32;
                                    format!("Ordinal#{}", ord)
                                } else {
                                    let func_rva = (val & 0x7FFF_FFFF) as u32;
                                    if let Some(func_offset) = rva_to_offset(func_rva, &raw_sections) {
                                        read_cstring(data, func_offset + 2).unwrap_or_else(|| "Unknown".to_string())
                                    } else {
                                        "Unknown".to_string()
                                    }
                                };

                                let dll_stem = dll_name
                                    .to_lowercase()
                                    .trim_end_matches(".dll")
                                    .trim_end_matches(".ocx")
                                    .trim_end_matches(".sys")
                                    .to_string();
                                imphash_items.push(format!("{}.{}", dll_stem, func_name.to_lowercase()));
                                funcs.push(func_name);

                                thunk_offset += step;
                            }
                        }

                        imports.push(ImportInfo {
                            dll: dll_name,
                            functions: funcs,
                        });
                    }
                }

                imp_offset += 20;
            }
        }
    }

    let imphash = if !imphash_items.is_empty() {
        let joined = imphash_items.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined.as_bytes());
        Some(hex_encode(&hasher.finalize()))
    } else {
        None
    };

    let mut exports = Vec::new();
    if export_dir_rva > 0 {
        if let Some(exp_offset) = rva_to_offset(export_dir_rva, &raw_sections) {
            if exp_offset + 40 <= data.len() {
                let num_names = read_u32(data, exp_offset + 24).unwrap_or(0) as usize;
                let addr_names = read_u32(data, exp_offset + 32).unwrap_or(0);
                let addr_ords = read_u32(data, exp_offset + 36).unwrap_or(0);

                if let (Some(names_off), Some(ords_off)) = (
                    rva_to_offset(addr_names, &raw_sections),
                    rva_to_offset(addr_ords, &raw_sections),
                ) {
                    for i in 0..num_names.min(256) {
                        if names_off + (i * 4) + 4 <= data.len() && ords_off + (i * 2) + 2 <= data.len() {
                            let name_rva = read_u32(data, names_off + (i * 4)).unwrap_or(0);
                            let ordinal = read_u16(data, ords_off + (i * 2)).unwrap_or(0) as u32;
                            if let Some(no) = rva_to_offset(name_rva, &raw_sections) {
                                if let Some(exp_name) = read_cstring(data, no) {
                                    exports.push(ExportInfo {
                                        name: exp_name,
                                        ordinal,
                                        rva: 0,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(data);
    let sha256 = hex_encode(&sha_hasher.finalize());

    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5 = hex_encode(&md5_hasher.finalize());

    let overall_entropy = calculate_entropy(data);
    let is_likely_packed = overall_entropy >= 7.2;

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
        imphash,
        interesting_strings: Vec::new(),
    })
}
