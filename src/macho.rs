use crate::disasm::disassemble_bytes;
use crate::entropy::calculate_entropy;
use crate::pe::hex_encode;
use crate::types::{
    BinaryFormat, BinaryReport, ExportInfo, ImportInfo, SectionInfo, SecurityMitigations,
};
use md5::Md5;
use sha2::{Digest, Sha256};

// Mach-O Magic Numbers
pub const MH_MAGIC: u32 = 0xfeedface;
pub const MH_CIGAM: u32 = 0xcefaedfe;
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;

pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;
pub const FAT_MAGIC_64: u32 = 0xcafebabf;
pub const FAT_CIGAM_64: u32 = 0xbfbafeca;

// CPU Types
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = 0x01000007;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = 0x0100000c;
pub const CPU_TYPE_ARM64_32: u32 = 0x0200000c;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = 0x01000012;

// Mach-O File Types
pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const MH_DYLINKER: u32 = 7;
pub const MH_BUNDLE: u32 = 8;
pub const MH_DSYM: u32 = 10;

// Mach-O Flags
pub const MH_PIE: u32 = 0x200000;
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;

// Load Commands
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x80000018;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_RPATH: u32 = 0x8000001c;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000001f;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_MAIN: u32 = 0x80000028;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

// Symbol types
pub const N_EXT: u8 = 0x01;
pub const N_TYPE: u8 = 0x0e;
pub const N_UNDF: u8 = 0x00;
pub const N_SECT: u8 = 0x0e;

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

pub fn read_cstring_bounded(buf: &[u8], offset: usize, max_len: usize) -> Option<String> {
    if offset >= buf.len() {
        return None;
    }
    let end = (offset + max_len).min(buf.len());
    let null_pos = buf[offset..end].iter().position(|&b| b == 0)?;
    let slice = &buf[offset..offset + null_pos];
    String::from_utf8(slice.to_vec()).ok()
}

pub fn cpu_type_to_str(cputype: u32) -> &'static str {
    match cputype {
        CPU_TYPE_X86 => "x86",
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM => "ARM",
        CPU_TYPE_ARM64 => "ARM64",
        CPU_TYPE_ARM64_32 => "ARM64_32",
        CPU_TYPE_POWERPC => "PowerPC",
        CPU_TYPE_POWERPC64 => "PowerPC64",
        _ => "Unknown",
    }
}

pub fn file_type_to_str(filetype: u32) -> &'static str {
    match filetype {
        MH_OBJECT => "Mach-O Object (MH_OBJECT)",
        MH_EXECUTE => "Mach-O Executable (MH_EXECUTE)",
        MH_DYLIB => "Mach-O Dynamic Library (MH_DYLIB)",
        MH_DYLINKER => "Mach-O Dynamic Linker (MH_DYLINKER)",
        MH_BUNDLE => "Mach-O Bundle (MH_BUNDLE)",
        MH_DSYM => "Mach-O dSYM (MH_DSYM)",
        _ => "Mach-O File",
    }
}

/// Main entry for parsing Mach-O binaries (handles both Fat/Universal and single-slice Mach-O).
pub fn parse_macho(data: &[u8], file_name: &str) -> Option<BinaryReport> {
    if data.len() < 4 {
        return None;
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // Check for Universal / Fat binary
    if magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64 {
        return parse_fat_binary(data, file_name, magic);
    }

    // Single-slice Mach-O
    parse_single_macho(data, file_name, 0, data.len(), None)
}

struct FatSlice {
    cputype: u32,
    offset: usize,
    size: usize,
}

fn parse_fat_binary(data: &[u8], file_name: &str, magic: u32) -> Option<BinaryReport> {
    let be = magic == FAT_MAGIC || magic == FAT_MAGIC_64;
    let is_64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;

    let nfat_arch = read_u32(data, 4, be)? as usize;
    if nfat_arch == 0 {
        return None;
    }

    let mut slices = Vec::new();
    let arch_header_size = if is_64 { 32 } else { 20 };

    for i in 0..nfat_arch.min(32) {
        let arch_off = 8 + i * arch_header_size;
        if arch_off + arch_header_size > data.len() {
            break;
        }

        let cputype = read_u32(data, arch_off, be)?;
        let offset = if is_64 {
            read_u64(data, arch_off + 8, be)? as usize
        } else {
            read_u32(data, arch_off + 8, be)? as usize
        };
        let size = if is_64 {
            read_u64(data, arch_off + 16, be)? as usize
        } else {
            read_u32(data, arch_off + 12, be)? as usize
        };

        if offset + size <= data.len() {
            slices.push(FatSlice {
                cputype,
                offset,
                size,
            });
        }
    }

    if slices.is_empty() {
        return None;
    }

    // Collect all architecture names in the fat binary
    let all_arch_names: Vec<&'static str> =
        slices.iter().map(|s| cpu_type_to_str(s.cputype)).collect();
    let universal_tag = format!("Universal Fat Binary [{}]", all_arch_names.join(", "));

    // Select preferred slice: ARM64 (Apple Silicon) -> x86_64 -> first
    let selected_idx = slices
        .iter()
        .position(|s| s.cputype == CPU_TYPE_ARM64)
        .or_else(|| slices.iter().position(|s| s.cputype == CPU_TYPE_X86_64))
        .unwrap_or(0);

    let selected = &slices[selected_idx];
    parse_single_macho(
        data,
        file_name,
        selected.offset,
        selected.size,
        Some(&universal_tag),
    )
}

fn parse_single_macho(
    data: &[u8],
    file_name: &str,
    slice_offset: usize,
    slice_size: usize,
    universal_info: Option<&str>,
) -> Option<BinaryReport> {
    if slice_offset + 28 > data.len() || slice_offset + slice_size > data.len() {
        return None;
    }

    let slice_data = &data[slice_offset..slice_offset + slice_size];
    let magic_le = read_u32(slice_data, 0, false)?;
    let magic_be = read_u32(slice_data, 0, true)?;

    let (is_64, be) = if magic_le == MH_MAGIC_64 {
        (true, false)
    } else if magic_be == MH_MAGIC_64 || magic_be == MH_CIGAM_64 {
        (true, true)
    } else if magic_le == MH_MAGIC {
        (false, false)
    } else if magic_be == MH_MAGIC || magic_be == MH_CIGAM {
        (false, true)
    } else {
        return None;
    };

    let header_size = if is_64 { 32 } else { 28 };
    if slice_data.len() < header_size {
        return None;
    }

    let cputype = read_u32(slice_data, 4, be)?;
    let _cpusubtype = read_u32(slice_data, 8, be)?;
    let filetype = read_u32(slice_data, 12, be)?;
    let ncmds = read_u32(slice_data, 16, be)? as usize;
    let _sizeofcmds = read_u32(slice_data, 20, be)? as usize;
    let flags = read_u32(slice_data, 24, be)?;

    let arch_base = cpu_type_to_str(cputype);
    let architecture = match universal_info {
        Some(univ) => format!("{} ({})", arch_base, univ),
        None => arch_base.to_string(),
    };

    let subsystem = file_type_to_str(filetype).to_string();

    let is_pie = (flags & MH_PIE) != 0;
    // By default in modern Mach-O, stack is non-executable unless MH_ALLOW_STACK_EXECUTION is set
    let stack_executable = (flags & MH_ALLOW_STACK_EXECUTION) != 0;
    let dep_nx = !stack_executable;

    let mut mitigations = SecurityMitigations {
        aslr: is_pie,
        pie: is_pie,
        high_entropy_va: is_64,
        dep_nx,
        seh: false,
        cfg: false,
        authenticode_signed: false, // will be set if LC_CODE_SIGNATURE is found
        has_rwx_sections: false,
        relro: "N/A (Mach-O)".to_string(),
        stack_canary: false,
        fortify: false,
        rpath: None,
        runpath: None,
    };

    let mut sections = Vec::new();
    let mut imported_libs = Vec::new();
    let mut imported_funcs = Vec::new();
    let mut exports = Vec::new();

    let mut entry_point_vaddr: u64 = 0;
    let mut entry_point_fileoff: u64 = 0;
    let mut text_vmaddr: u64 = 0;

    let mut symtab_info: Option<(usize, usize, usize, usize)> = None; // (symoff, nsyms, stroff, strsize)

    let mut cmd_offset = header_size;
    for _ in 0..ncmds.min(512) {
        if cmd_offset + 8 > slice_data.len() {
            break;
        }

        let cmd = read_u32(slice_data, cmd_offset, be)?;
        let cmdsize = read_u32(slice_data, cmd_offset + 4, be)? as usize;

        if cmdsize < 8 || cmd_offset + cmdsize > slice_data.len() {
            break;
        }

        match cmd {
            LC_SEGMENT_64 => {
                // 64-bit segment
                if cmd_offset + 72 <= slice_data.len() {
                    let segname_bytes = &slice_data[cmd_offset + 8..cmd_offset + 24];
                    let segname = String::from_utf8_lossy(segname_bytes)
                        .trim_matches('\0')
                        .to_string();
                    let vmaddr = read_u64(slice_data, cmd_offset + 24, be).unwrap_or(0);
                    let _vmsize = read_u64(slice_data, cmd_offset + 32, be).unwrap_or(0);
                    let _fileoff = read_u64(slice_data, cmd_offset + 40, be).unwrap_or(0);
                    let _filesize = read_u64(slice_data, cmd_offset + 48, be).unwrap_or(0);
                    let maxprot = read_u32(slice_data, cmd_offset + 56, be).unwrap_or(0);
                    let initprot = read_u32(slice_data, cmd_offset + 60, be).unwrap_or(0);
                    let nsects = read_u32(slice_data, cmd_offset + 64, be).unwrap_or(0) as usize;

                    if segname == "__TEXT" {
                        text_vmaddr = vmaddr;
                    }

                    // Check W^X on segment level: writable (2) and executable (4)
                    if (initprot & 2 != 0 && initprot & 4 != 0)
                        || (maxprot & 2 != 0 && maxprot & 4 != 0)
                    {
                        if segname != "__PAGEZERO" {
                            mitigations.has_rwx_sections = true;
                        }
                    }

                    let mut sect_off = cmd_offset + 72;
                    for _ in 0..nsects.min(256) {
                        if sect_off + 80 > slice_data.len() {
                            break;
                        }

                        let s_name = String::from_utf8_lossy(&slice_data[sect_off..sect_off + 16])
                            .trim_matches('\0')
                            .to_string();
                        let s_segname =
                            String::from_utf8_lossy(&slice_data[sect_off + 16..sect_off + 32])
                                .trim_matches('\0')
                                .to_string();
                        let s_addr = read_u64(slice_data, sect_off + 32, be).unwrap_or(0);
                        let s_size = read_u64(slice_data, sect_off + 40, be).unwrap_or(0);
                        let s_offset = read_u32(slice_data, sect_off + 48, be).unwrap_or(0);

                        let readable = (initprot & 1) != 0;
                        let writable = (initprot & 2) != 0;
                        let executable = (initprot & 4) != 0;
                        let is_rwx = writable && executable;
                        if is_rwx && segname != "__PAGEZERO" {
                            mitigations.has_rwx_sections = true;
                        }

                        let raw_start = s_offset as usize;
                        let raw_len = s_size as usize;
                        let sec_entropy = if raw_start + raw_len <= slice_data.len() && raw_len > 0
                        {
                            calculate_entropy(&slice_data[raw_start..raw_start + raw_len])
                        } else {
                            0.0
                        };

                        let full_name = format!("{}.{}", s_segname, s_name);
                        sections.push(SectionInfo {
                            name: full_name,
                            virtual_address: s_addr,
                            virtual_size: s_size,
                            raw_offset: s_offset as u64 + slice_offset as u64,
                            raw_size: s_size,
                            entropy: sec_entropy,
                            readable,
                            writable,
                            executable,
                            is_rwx,
                        });

                        sect_off += 80;
                    }
                }
            }
            LC_SEGMENT => {
                // 32-bit segment
                if cmd_offset + 56 <= slice_data.len() {
                    let segname =
                        String::from_utf8_lossy(&slice_data[cmd_offset + 8..cmd_offset + 24])
                            .trim_matches('\0')
                            .to_string();
                    let vmaddr = read_u32(slice_data, cmd_offset + 24, be).unwrap_or(0) as u64;
                    let _vmsize = read_u32(slice_data, cmd_offset + 28, be).unwrap_or(0) as u64;
                    let _fileoff = read_u32(slice_data, cmd_offset + 32, be).unwrap_or(0) as u64;
                    let _filesize = read_u32(slice_data, cmd_offset + 36, be).unwrap_or(0) as u64;
                    let maxprot = read_u32(slice_data, cmd_offset + 40, be).unwrap_or(0);
                    let initprot = read_u32(slice_data, cmd_offset + 44, be).unwrap_or(0);
                    let nsects = read_u32(slice_data, cmd_offset + 48, be).unwrap_or(0) as usize;

                    if segname == "__TEXT" {
                        text_vmaddr = vmaddr;
                    }

                    if (initprot & 2 != 0 && initprot & 4 != 0)
                        || (maxprot & 2 != 0 && maxprot & 4 != 0)
                    {
                        if segname != "__PAGEZERO" {
                            mitigations.has_rwx_sections = true;
                        }
                    }

                    let mut sect_off = cmd_offset + 56;
                    for _ in 0..nsects.min(256) {
                        if sect_off + 68 > slice_data.len() {
                            break;
                        }

                        let s_name = String::from_utf8_lossy(&slice_data[sect_off..sect_off + 16])
                            .trim_matches('\0')
                            .to_string();
                        let s_segname =
                            String::from_utf8_lossy(&slice_data[sect_off + 16..sect_off + 32])
                                .trim_matches('\0')
                                .to_string();
                        let s_addr = read_u32(slice_data, sect_off + 32, be).unwrap_or(0) as u64;
                        let s_size = read_u32(slice_data, sect_off + 36, be).unwrap_or(0) as u64;
                        let s_offset = read_u32(slice_data, sect_off + 40, be).unwrap_or(0);

                        let readable = (initprot & 1) != 0;
                        let writable = (initprot & 2) != 0;
                        let executable = (initprot & 4) != 0;
                        let is_rwx = writable && executable;
                        if is_rwx && segname != "__PAGEZERO" {
                            mitigations.has_rwx_sections = true;
                        }

                        let raw_start = s_offset as usize;
                        let raw_len = s_size as usize;
                        let sec_entropy = if raw_start + raw_len <= slice_data.len() && raw_len > 0
                        {
                            calculate_entropy(&slice_data[raw_start..raw_start + raw_len])
                        } else {
                            0.0
                        };

                        let full_name = format!("{}.{}", s_segname, s_name);
                        sections.push(SectionInfo {
                            name: full_name,
                            virtual_address: s_addr,
                            virtual_size: s_size,
                            raw_offset: s_offset as u64 + slice_offset as u64,
                            raw_size: s_size,
                            entropy: sec_entropy,
                            readable,
                            writable,
                            executable,
                            is_rwx,
                        });

                        sect_off += 68;
                    }
                }
            }
            LC_MAIN => {
                // Modern entry point: entryoff at offset 8 (u64)
                if cmd_offset + 16 <= slice_data.len() {
                    let entryoff = read_u64(slice_data, cmd_offset + 8, be).unwrap_or(0);
                    entry_point_fileoff = entryoff;
                    entry_point_vaddr = text_vmaddr.wrapping_add(entryoff);
                }
            }
            LC_UNIXTHREAD | LC_THREAD => {
                // Legacy thread entry point: rip/eip located in thread state registers
                if entry_point_vaddr == 0 && cmd_offset + 16 <= slice_data.len() {
                    let flavor = read_u32(slice_data, cmd_offset + 8, be).unwrap_or(0);
                    // x86_THREAD_STATE64 (flavor 4), RIP is at reg offset 16*8 = 128 from state start
                    if flavor == 4 && cmd_offset + 16 + 144 <= slice_data.len() {
                        let rip = read_u64(slice_data, cmd_offset + 16 + 128, be).unwrap_or(0);
                        if rip > 0 {
                            entry_point_vaddr = rip;
                            if rip >= text_vmaddr {
                                entry_point_fileoff = rip - text_vmaddr;
                            }
                        }
                    } else if cmd_offset + 16 + 48 <= slice_data.len() {
                        // 32-bit x86_THREAD_STATE (flavor 1), EIP is at reg offset 10*4 = 40 from state start
                        let eip =
                            read_u32(slice_data, cmd_offset + 16 + 40, be).unwrap_or(0) as u64;
                        if eip > 0 {
                            entry_point_vaddr = eip;
                            if eip >= text_vmaddr {
                                entry_point_fileoff = eip - text_vmaddr;
                            }
                        }
                    }
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                if cmd_offset + 16 <= slice_data.len() {
                    let name_offset =
                        read_u32(slice_data, cmd_offset + 8, be).unwrap_or(0) as usize;
                    if name_offset < cmdsize && cmd_offset + name_offset < slice_data.len() {
                        let max_len = cmdsize.saturating_sub(name_offset);
                        if let Some(dylib_path) =
                            read_cstring_bounded(slice_data, cmd_offset + name_offset, max_len)
                        {
                            imported_libs.push(dylib_path);
                        }
                    }
                }
            }
            LC_RPATH => {
                if cmd_offset + 16 <= slice_data.len() {
                    let path_offset =
                        read_u32(slice_data, cmd_offset + 8, be).unwrap_or(0) as usize;
                    if path_offset < cmdsize && cmd_offset + path_offset < slice_data.len() {
                        let max_len = cmdsize.saturating_sub(path_offset);
                        if let Some(rpath_str) =
                            read_cstring_bounded(slice_data, cmd_offset + path_offset, max_len)
                        {
                            match &mut mitigations.rpath {
                                Some(existing) => {
                                    existing.push(':');
                                    existing.push_str(&rpath_str);
                                }
                                None => {
                                    mitigations.rpath = Some(rpath_str);
                                }
                            }
                        }
                    }
                }
            }
            LC_CODE_SIGNATURE => {
                // Embedded code signature present in binary
                mitigations.authenticode_signed = true;
            }
            LC_SYMTAB if cmd_offset + 24 <= slice_data.len() => {
                let symoff = read_u32(slice_data, cmd_offset + 8, be).unwrap_or(0) as usize;
                let nsyms = read_u32(slice_data, cmd_offset + 12, be).unwrap_or(0) as usize;
                let stroff = read_u32(slice_data, cmd_offset + 16, be).unwrap_or(0) as usize;
                let strsize = read_u32(slice_data, cmd_offset + 20, be).unwrap_or(0) as usize;
                symtab_info = Some((symoff, nsyms, stroff, strsize));
            }
            _ => {}
        }

        cmd_offset += cmdsize;
    }

    // Process symbol table for Canary, FORTIFY, and Imported/Exported symbols
    if let Some((symoff, nsyms, stroff, strsize)) = symtab_info {
        let nlist_size = if is_64 { 16 } else { 12 };
        let str_end = (stroff + strsize).min(slice_data.len());

        for i in 0..nsyms.min(16384) {
            let ent_off = symoff + i * nlist_size;
            if ent_off + nlist_size > slice_data.len() {
                break;
            }

            let n_strx = read_u32(slice_data, ent_off, be).unwrap_or(0) as usize;
            let n_type = slice_data[ent_off + 4];
            let _n_sect = slice_data[ent_off + 5];
            let _n_desc = read_u16(slice_data, ent_off + 6, be).unwrap_or(0);
            let n_value = if is_64 {
                read_u64(slice_data, ent_off + 8, be).unwrap_or(0)
            } else {
                read_u32(slice_data, ent_off + 8, be).unwrap_or(0) as u64
            };

            let str_abs = stroff + n_strx;
            if n_strx > 0 && str_abs < str_end {
                let max_len = str_end.saturating_sub(str_abs);
                if let Some(sym_name) = read_cstring_bounded(slice_data, str_abs, max_len) {
                    // Check for Stack Canary
                    if sym_name.contains("stack_chk_fail") || sym_name.contains("stack_chk_guard") {
                        mitigations.stack_canary = true;
                    }

                    // Check for FORTIFY_SOURCE
                    if sym_name.contains("_chk")
                        && (sym_name.contains("memcpy")
                            || sym_name.contains("printf")
                            || sym_name.contains("sprintf")
                            || sym_name.contains("strcpy")
                            || sym_name.contains("memset"))
                    {
                        mitigations.fortify = true;
                    }

                    // Classification: N_EXT means external/global
                    if (n_type & N_EXT) != 0 {
                        let type_bits = n_type & N_TYPE;
                        if type_bits == N_UNDF {
                            // Undefined / imported symbol
                            imported_funcs.push(sym_name);
                        } else if type_bits == N_SECT {
                            // Defined in section / exported symbol
                            exports.push(ExportInfo {
                                name: sym_name,
                                ordinal: i as u32,
                                rva: n_value as u32,
                            });
                        }
                    }
                }
            }
        }
    }

    // Assemble ImportInfo
    let mut imports = Vec::new();
    if !imported_libs.is_empty() {
        for (idx, lib) in imported_libs.iter().enumerate() {
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
            dll: "Dynamic / libSystem".to_string(),
            functions: imported_funcs,
        });
    }

    // Disassemble Entry Point preview (for x86 and x86_64 Mach-O)
    let mut entry_point_preview = Vec::new();
    if entry_point_fileoff > 0 && (cputype == CPU_TYPE_X86 || cputype == CPU_TYPE_X86_64) {
        let ep_file = entry_point_fileoff as usize;
        if ep_file < slice_data.len() {
            let bitness = if is_64 { 64 } else { 32 };
            entry_point_preview =
                disassemble_bytes(&slice_data[ep_file..], entry_point_vaddr, bitness, 16);
        }
    }

    let overall_entropy = calculate_entropy(data);
    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5 = hex_encode(&md5_hasher.finalize());

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(data);
    let sha256 = hex_encode(&sha_hasher.finalize());

    Some(BinaryReport {
        file_name: file_name.to_string(),
        file_size: data.len() as u64,
        md5,
        sha256,
        format: BinaryFormat::MachO,
        architecture,
        subsystem,
        entry_point: entry_point_vaddr,
        overall_entropy,
        is_likely_packed: overall_entropy >= 7.20,
        mitigations,
        sections,
        imports,
        exports,
        rich_header: None,
        imphash: None,
        interesting_strings: Vec::new(),
        entry_point_preview,
        authenticode: None,
    })
}
