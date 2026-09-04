use crate::entropy::calculate_entropy;
use crate::types::{BinaryFormat, BinaryReport, ExportInfo, ImportInfo, SectionInfo, SecurityMitigations};
use md5::Md5;
use sha2::{Digest, Sha256};

pub fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= buf.len() {
        Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
    } else {
        None
    }
}

pub fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
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

pub fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
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

pub fn read_cstring(buf: &[u8], offset: usize) -> Option<String> {
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

#[derive(Debug, Clone)]
pub struct RawSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

pub fn rva_to_offset(rva: u32, sections: &[RawSection]) -> Option<usize> {
    if sections.is_empty() {
        return Some(rva as usize);
    }
    let first_va = sections.iter().map(|s| s.virtual_address).min().unwrap_or(0x1000);
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
                let offset = s.pointer_to_raw_data as usize + delta as usize;
                return Some(offset);
            }
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

    // CFG and SafeSEH start as false and require verification from IMAGE_LOAD_CONFIG_DIRECTORY
    let mut mitigations = SecurityMitigations {
        high_entropy_va: is_64 && (dll_chars & 0x0020) != 0,
        aslr: (dll_chars & 0x0040) != 0,
        dep_nx: (dll_chars & 0x0100) != 0,
        seh: is_64 && (dll_chars & 0x0400) == 0, // on x64 SEH is table-based in .pdata (unless NO_SEH); on 32-bit requires SafeSEH table in Load Config
        cfg: false,  // requires both GUARD_CF flag and valid Load Config function pointer
        authenticode_signed: false,
        has_rwx_sections: false,
        pie: (dll_chars & 0x0040) != 0,
        relro: "N/A (Windows)".to_string(),
    };

    let export_dir_rva = read_u32(data, data_dirs_offset).unwrap_or(0);
    let import_dir_rva = read_u32(data, data_dirs_offset + 8).unwrap_or(0);
    let cert_dir_offset = read_u32(data, data_dirs_offset + 32).unwrap_or(0) as usize;
    let cert_dir_size = read_u32(data, data_dirs_offset + 32 + 4).unwrap_or(0) as usize;
    let load_config_rva = read_u32(data, data_dirs_offset + 80).unwrap_or(0);

    // Authenticode Certificate Table check (validates WIN_CERTIFICATE structure presence)
    if cert_dir_offset > 0 && cert_dir_size >= 8 && cert_dir_offset + cert_dir_size <= data.len() {
        let dw_len = read_u32(data, cert_dir_offset).unwrap_or(0) as usize;
        let w_cert_type = read_u16(data, cert_dir_offset + 6).unwrap_or(0);
        if w_cert_type == 0x0002 && dw_len <= cert_dir_size {
            // WIN_CERT_TYPE_PKCS_SIGNED_DATA certificate table present
            mitigations.authenticode_signed = true;
        }
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

    // Verify SafeSEH and CFG from IMAGE_LOAD_CONFIG_DIRECTORY
    if load_config_rva > 0 {
        if let Some(lc_offset) = rva_to_offset(load_config_rva, &raw_sections) {
            let lc_size = read_u32(data, lc_offset).unwrap_or(0) as usize;
            if is_64 {
                // In 64-bit load config: GuardCFCheckFunctionPointer is at offset 112 (size >= 120)
                // (offset 88 is SecurityCookie, offset 96 is SEHandlerTable, offset 104 is SEHandlerCount)
                if (dll_chars & 0x4000) != 0 && lc_size >= 120 && lc_offset + 120 <= data.len() {
                    let guard_check = read_u64(data, lc_offset + 112).unwrap_or(0);
                    if guard_check != 0 {
                        mitigations.cfg = true;
                    }
                }
            } else {
                // In 32-bit load config:
                // SafeSEH: SEHandlerTable at offset 64, SEHandlerCount at offset 68 (size >= 72)
                if lc_size >= 72 && lc_offset + 72 <= data.len() {
                    let se_table = read_u32(data, lc_offset + 64).unwrap_or(0);
                    let se_count = read_u32(data, lc_offset + 68).unwrap_or(0);
                    if (dll_chars & 0x0400) == 0 && se_table != 0 && se_count > 0 {
                        mitigations.seh = true;
                    }
                }
                // CFG in 32-bit: GuardCFCheckFunctionPointer at offset 72 (size >= 76)
                if (dll_chars & 0x4000) != 0 && lc_size >= 76 && lc_offset + 76 <= data.len() {
                    let guard_check = read_u32(data, lc_offset + 72).unwrap_or(0);
                    if guard_check != 0 {
                        mitigations.cfg = true;
                    }
                }
            }
        }
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

                                let (func_name, imphash_name) = if is_ordinal {
                                    let ord = (val & 0xFFFF) as u32;
                                    (format!("Ordinal#{}", ord), format!("ord{}", ord))
                                } else {
                                    let func_rva = (val & 0x7FFF_FFFF) as u32;
                                    if let Some(func_offset) = rva_to_offset(func_rva, &raw_sections) {
                                        let name = read_cstring(data, func_offset + 2).unwrap_or_else(|| "Unknown".to_string());
                                        (name.clone(), name.to_lowercase())
                                    } else {
                                        ("Unknown".to_string(), "unknown".to_string())
                                    }
                                };

                                let dll_lower = dll_name.to_lowercase();
                                let dll_stem = dll_lower
                                    .strip_suffix(".dll")
                                    .or_else(|| dll_lower.strip_suffix(".sys"))
                                    .or_else(|| dll_lower.strip_suffix(".ocx"))
                                    .unwrap_or(&dll_lower);
                                imphash_items.push(format!("{}.{}", dll_stem, imphash_name));
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
                let base = read_u32(data, exp_offset + 16).unwrap_or(0);
                let num_names = read_u32(data, exp_offset + 24).unwrap_or(0) as usize;
                let addr_funcs = read_u32(data, exp_offset + 28).unwrap_or(0);
                let addr_names = read_u32(data, exp_offset + 32).unwrap_or(0);
                let addr_ords = read_u32(data, exp_offset + 36).unwrap_or(0);

                if let (Some(names_off), Some(ords_off), Some(funcs_off)) = (
                    rva_to_offset(addr_names, &raw_sections),
                    rva_to_offset(addr_ords, &raw_sections),
                    rva_to_offset(addr_funcs, &raw_sections),
                ) {
                    for i in 0..num_names.min(256) {
                        if names_off + (i * 4) + 4 <= data.len() && ords_off + (i * 2) + 2 <= data.len() {
                            let name_rva = read_u32(data, names_off + (i * 4)).unwrap_or(0);
                            let ordinal_idx = read_u16(data, ords_off + (i * 2)).unwrap_or(0) as u32;
                            let ordinal = base + ordinal_idx;

                            let func_rva = if funcs_off + (ordinal_idx as usize * 4) + 4 <= data.len() {
                                read_u32(data, funcs_off + (ordinal_idx as usize * 4)).unwrap_or(0)
                            } else {
                                0
                            };

                            if let Some(no) = rva_to_offset(name_rva, &raw_sections) {
                                if let Some(exp_name) = read_cstring(data, no) {
                                    exports.push(ExportInfo {
                                        name: exp_name,
                                        ordinal,
                                        rva: func_rva,
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
