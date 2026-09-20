use crate::entropy::calculate_entropy;
use crate::pe::hex_encode;
use crate::types::{
    BinaryFormat, BinaryReport, ExportInfo, ImportInfo, SectionInfo, SecurityMitigations,
};
use md5::Md5;
use sha2::{Digest, Sha256};

pub fn read_u16(buf: &[u8], offset: usize, be: bool) -> Option<u16> {
    if offset + 2 <= buf.len() {
        if be {
            Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
        } else {
            Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
        }
    } else {
        None
    }
}

pub fn read_u32(buf: &[u8], offset: usize, be: bool) -> Option<u32> {
    if offset + 4 <= buf.len() {
        if be {
            Some(u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]))
        } else {
            Some(u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]))
        }
    } else {
        None
    }
}

pub fn read_u64(buf: &[u8], offset: usize, be: bool) -> Option<u64> {
    if offset + 8 <= buf.len() {
        if be {
            Some(u64::from_be_bytes([
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
        }
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
    let limit = (offset + max_len).min(buf.len());
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

pub fn parse_elf(data: &[u8], file_name: &str) -> Option<BinaryReport> {
    if data.len() < 52 {
        return None;
    }
    if &data[0..4] != b"\x7fELF" {
        return None;
    }

    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let is_64 = class == 2;
    let be = data[5] == 2; // 1 = Little Endian, 2 = Big Endian

    let e_type = read_u16(data, 16, be)?;
    let e_machine = read_u16(data, 18, be)?;

    let arch_str = match e_machine {
        0x02 => "SPARC",
        0x03 => "x86 (32-bit)",
        0x08 => "MIPS",
        0x14 => "PowerPC (32-bit)",
        0x15 => "PowerPC (64-bit)",
        0x28 => "ARM",
        0x3E => "x86_64 (64-bit)",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        _ => "Unknown",
    };

    let (entry_point, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if is_64 {
        let entry = read_u64(data, 24, be)?;
        let phoff = read_u64(data, 32, be)? as usize;
        let shoff = read_u64(data, 40, be)? as usize;
        let phentsize = read_u16(data, 54, be)? as usize;
        let phnum = read_u16(data, 56, be)? as usize;
        let shentsize = read_u16(data, 58, be)? as usize;
        let shnum = read_u16(data, 60, be)? as usize;
        let shstrndx = read_u16(data, 62, be)? as usize;
        (
            entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx,
        )
    } else {
        let entry = read_u32(data, 24, be)? as u64;
        let phoff = read_u32(data, 28, be)? as usize;
        let shoff = read_u32(data, 32, be)? as usize;
        let phentsize = read_u16(data, 42, be)? as usize;
        let phnum = read_u16(data, 44, be)? as usize;
        let shentsize = read_u16(data, 46, be)? as usize;
        let shnum = read_u16(data, 48, be)? as usize;
        let shstrndx = read_u16(data, 50, be)? as usize;
        (
            entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx,
        )
    };

    let mut has_gnu_stack = false;
    let mut nx_enabled = false;
    let mut has_relro_segment = false;
    let mut has_interp = false;
    let mut dynamic_offset: Option<usize> = None;
    let mut dynamic_size: usize = 0;

    for i in 0..phnum {
        let off = phoff + (i * phentsize);
        if off + phentsize <= data.len() {
            let p_type = read_u32(data, off, be).unwrap_or(0);
            if p_type == 3 {
                // PT_INTERP
                has_interp = true;
            } else if p_type == 0x6474e551 {
                // PT_GNU_STACK
                has_gnu_stack = true;
                let flags = if is_64 {
                    read_u32(data, off + 4, be).unwrap_or(0)
                } else {
                    read_u32(data, off + 24, be).unwrap_or(0)
                };
                if (flags & 1) == 0 {
                    // PF_X is NOT set -> NX is enabled!
                    nx_enabled = true;
                } else {
                    nx_enabled = false;
                }
            } else if p_type == 0x6474e552 {
                // PT_GNU_RELRO
                has_relro_segment = true;
            } else if p_type == 2 {
                // PT_DYNAMIC
                let (off_val, size_val) = if is_64 {
                    (
                        read_u64(data, off + 8, be).unwrap_or(0) as usize,
                        read_u64(data, off + 32, be).unwrap_or(0) as usize,
                    )
                } else {
                    (
                        read_u32(data, off + 4, be).unwrap_or(0) as usize,
                        read_u32(data, off + 16, be).unwrap_or(0) as usize,
                    )
                };
                dynamic_offset = Some(off_val);
                dynamic_size = size_val;
            }
        }
    }

    if !has_gnu_stack {
        nx_enabled = false; // Default for Linux when no PT_GNU_STACK is present
    }

    let shstrtab_offset = if shstrndx < shnum {
        let str_sh_off = shoff + (shstrndx * shentsize);
        if is_64 {
            read_u64(data, str_sh_off + 24, be).unwrap_or(0) as usize
        } else {
            read_u32(data, str_sh_off + 16, be).unwrap_or(0) as usize
        }
    } else {
        0
    };

    let mut sections = Vec::new();
    let mut has_rwx = false;
    let mut dynstr_offset: Option<usize> = None;
    let mut dynsym_offset: Option<usize> = None;
    let mut dynsym_size: usize = 0;
    let mut dynsym_entsize: usize = if is_64 { 24 } else { 16 };
    let mut strtab_offset: Option<usize> = None;
    let mut symtab_offset: Option<usize> = None;
    let mut symtab_size: usize = 0;
    let mut symtab_entsize: usize = if is_64 { 24 } else { 16 };

    for i in 0..shnum {
        let off = shoff + (i * shentsize);
        if off + shentsize > data.len() {
            break;
        }

        let sh_name_idx = read_u32(data, off, be).unwrap_or(0) as usize;
        let sh_type = read_u32(data, off + 4, be).unwrap_or(0);
        let name = if shstrtab_offset > 0 {
            read_cstring(data, shstrtab_offset + sh_name_idx)
                .unwrap_or_else(|| "unnamed".to_string())
        } else {
            format!("sec_{}", i)
        };

        let (addr, sec_offset, size, flags, link, entsize) = if is_64 {
            let flags = read_u64(data, off + 8, be).unwrap_or(0);
            let addr = read_u64(data, off + 16, be).unwrap_or(0);
            let offset = read_u64(data, off + 24, be).unwrap_or(0) as usize;
            let size = read_u64(data, off + 32, be).unwrap_or(0) as usize;
            let link = read_u32(data, off + 40, be).unwrap_or(0) as usize;
            let entsize = read_u64(data, off + 56, be).unwrap_or(0) as usize;
            (addr, offset, size, flags, link, entsize)
        } else {
            let flags = read_u32(data, off + 8, be).unwrap_or(0) as u64;
            let addr = read_u32(data, off + 12, be).unwrap_or(0) as u64;
            let offset = read_u32(data, off + 16, be).unwrap_or(0) as usize;
            let size = read_u32(data, off + 20, be).unwrap_or(0) as usize;
            let link = read_u32(data, off + 24, be).unwrap_or(0) as usize;
            let entsize = read_u32(data, off + 36, be).unwrap_or(0) as usize;
            (addr, offset, size, flags, link, entsize)
        };

        if name == ".dynstr"
            || (sh_type == 3
                && dynstr_offset.is_none()
                && (name.contains("dynstr") || shstrtab_offset == 0))
        {
            dynstr_offset = Some(sec_offset);
        }
        if name == ".strtab" {
            strtab_offset = Some(sec_offset);
        }
        if sh_type == 2 || name == ".symtab" {
            symtab_offset = Some(sec_offset);
            symtab_size = size;
            if entsize > 0 {
                symtab_entsize = entsize;
            }
            if link < shnum && strtab_offset.is_none() {
                let link_sh_off = shoff + (link * shentsize);
                let link_off = if is_64 {
                    read_u64(data, link_sh_off + 24, be).unwrap_or(0) as usize
                } else {
                    read_u32(data, link_sh_off + 16, be).unwrap_or(0) as usize
                };
                strtab_offset = Some(link_off);
            }
        }
        if sh_type == 11 || name == ".dynsym" {
            // SHT_DYNSYM
            dynsym_offset = Some(sec_offset);
            dynsym_size = size;
            if entsize > 0 {
                dynsym_entsize = entsize;
            }
            // link points to associated string table
            if link < shnum && dynstr_offset.is_none() {
                let link_sh_off = shoff + (link * shentsize);
                let link_off = if is_64 {
                    read_u64(data, link_sh_off + 24, be).unwrap_or(0) as usize
                } else {
                    read_u32(data, link_sh_off + 16, be).unwrap_or(0) as usize
                };
                dynstr_offset = Some(link_off);
            }
        }

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

    // Extract dynamic library dependencies (DT_NEEDED), search paths (DT_RPATH, DT_RUNPATH), and flags
    let mut needed_indices = Vec::new();
    let mut bind_now = false;
    let mut has_df_1_pie = false;
    let mut rpath_idx: Option<usize> = None;
    let mut runpath_idx: Option<usize> = None;

    if let Some(dyn_off) = dynamic_offset {
        let entry_size = if is_64 { 16 } else { 8 };
        let mut curr = dyn_off;
        while curr + entry_size <= data.len() && (curr - dyn_off) < dynamic_size {
            let (tag, val) = if is_64 {
                (
                    read_u64(data, curr, be).unwrap_or(0),
                    read_u64(data, curr + 8, be).unwrap_or(0) as usize,
                )
            } else {
                (
                    read_u32(data, curr, be).unwrap_or(0) as u64,
                    read_u32(data, curr + 4, be).unwrap_or(0) as usize,
                )
            };
            if tag == 0 {
                // DT_NULL
                break;
            }
            if tag == 1 {
                // DT_NEEDED
                needed_indices.push(val);
            } else if tag == 5 && dynstr_offset.is_none() {
                // DT_STRTAB
                dynstr_offset = Some(val);
            } else if tag == 15 {
                // DT_RPATH
                rpath_idx = Some(val);
            } else if tag == 24 {
                // DT_BIND_NOW
                bind_now = true;
            } else if tag == 29 {
                // DT_RUNPATH
                runpath_idx = Some(val);
            } else if tag == 30 {
                // DT_FLAGS: DF_BIND_NOW = 0x01
                if (val & 0x01) != 0 {
                    bind_now = true;
                }
            } else if tag == 0x6ffffffb {
                // DT_FLAGS_1: DF_1_NOW = 0x01, DF_1_PIE = 0x08000000
                if (val & 0x01) != 0 {
                    bind_now = true;
                }
                if (val & 0x0800_0000) != 0 {
                    has_df_1_pie = true;
                }
            }
            curr += entry_size;
        }
    }

    let mut needed_libs = Vec::new();
    let mut rpath: Option<String> = None;
    let mut runpath: Option<String> = None;

    if let Some(str_off) = dynstr_offset {
        for idx in needed_indices {
            if let Some(lib_name) = read_cstring(data, str_off + idx) {
                needed_libs.push(lib_name);
            }
        }
        if let Some(idx) = rpath_idx {
            rpath = read_cstring(data, str_off + idx);
        }
        if let Some(idx) = runpath_idx {
            runpath = read_cstring(data, str_off + idx);
        }
    }

    let relro = if has_relro_segment {
        if bind_now {
            "Full".to_string()
        } else {
            "Partial".to_string()
        }
    } else {
        "None".to_string()
    };

    let is_pie = e_type == 3 && (has_df_1_pie || has_interp || needed_libs.is_empty());

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut has_stack_canary = false;
    let mut has_fortify = false;

    // Helper to check symbol for stack canary and fortify
    let check_sym = |name: &str, canary: &mut bool, fortify: &mut bool| {
        if name == "__stack_chk_fail"
            || name == "__stack_chk_fail_local"
            || name == "__stack_chk_guard"
            || name == "__intel_security_cookie"
        {
            *canary = true;
        }
        if name.starts_with("__") && name.ends_with("_chk") {
            *fortify = true;
        }
    };

    // Parse symbols from .dynsym
    if let (Some(sym_off), Some(str_off)) = (dynsym_offset, dynstr_offset) {
        let count = dynsym_size / dynsym_entsize;
        let mut imported_funcs = Vec::new();

        for i in 0..count.min(4096) {
            let s_off = sym_off + (i * dynsym_entsize);
            if s_off + dynsym_entsize > data.len() {
                break;
            }
            let (st_name, st_info, st_shndx, st_value) = if is_64 {
                let name_idx = read_u32(data, s_off, be).unwrap_or(0) as usize;
                let info = data[s_off + 4];
                let shndx = read_u16(data, s_off + 6, be).unwrap_or(0);
                let val = read_u64(data, s_off + 8, be).unwrap_or(0);
                (name_idx, info, shndx, val)
            } else {
                let name_idx = read_u32(data, s_off, be).unwrap_or(0) as usize;
                let val = read_u32(data, s_off + 4, be).unwrap_or(0) as u64;
                let info = data[s_off + 12];
                let shndx = read_u16(data, s_off + 14, be).unwrap_or(0);
                (name_idx, info, shndx, val)
            };

            if st_name > 0 {
                if let Some(sym_name) = read_cstring(data, str_off + st_name) {
                    check_sym(&sym_name, &mut has_stack_canary, &mut has_fortify);
                    let bind = st_info >> 4; // STB_GLOBAL=1, STB_WEAK=2
                    if st_shndx == 0 {
                        // SHN_UNDEF -> Imported symbol
                        imported_funcs.push(sym_name);
                    } else if bind == 1 || bind == 2 {
                        // Defined global/weak -> Exported symbol
                        exports.push(ExportInfo {
                            name: sym_name,
                            ordinal: i as u32,
                            rva: st_value as u32,
                        });
                    }
                }
            }
        }

        if !needed_libs.is_empty() {
            for (idx, lib) in needed_libs.iter().enumerate() {
                imports.push(ImportInfo {
                    dll: lib.clone(),
                    functions: if idx == 0 {
                        imported_funcs.clone()
                    } else {
                        vec![]
                    },
                });
            }
        } else if !imported_funcs.is_empty() {
            imports.push(ImportInfo {
                dll: "Dynamic / libc".to_string(),
                functions: imported_funcs,
            });
        }
    }

    // Also check .symtab if present (e.g. static binaries or unstripped binaries)
    if (!has_stack_canary || !has_fortify) && symtab_offset.is_some() && strtab_offset.is_some() {
        if let (Some(sym_off), Some(str_off)) = (symtab_offset, strtab_offset) {
            let count = symtab_size / symtab_entsize;
            for i in 0..count.min(8192) {
                let s_off = sym_off + (i * symtab_entsize);
                if s_off + symtab_entsize > data.len() {
                    break;
                }
                let name_idx = read_u32(data, s_off, be).unwrap_or(0) as usize;
                if name_idx > 0 {
                    if let Some(sym_name) = read_cstring(data, str_off + name_idx) {
                        check_sym(&sym_name, &mut has_stack_canary, &mut has_fortify);
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
            high_entropy_va: false,
            dep_nx: nx_enabled,
            seh: false,
            cfg: false,
            authenticode_signed: false,
            has_rwx_sections: has_rwx,
            pie: is_pie,
            relro,
            stack_canary: has_stack_canary,
            fortify: has_fortify,
            rpath,
            runpath,
        },
        sections,
        imports,
        exports,
        rich_header: None,
        imphash: None,
        interesting_strings: Vec::new(),
    })
}
