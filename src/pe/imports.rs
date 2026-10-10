use super::utils::{RawSection, hex_encode, read_cstring, read_u32, read_u64, rva_to_offset};
use crate::types::ImportInfo;
use md5::Md5;
use sha2::Digest;

pub fn parse_imports(
    data: &[u8],
    import_dir_rva: u32,
    raw_sections: &[RawSection],
    is_64: bool,
) -> (Vec<ImportInfo>, Option<String>) {
    let mut imports = Vec::new();
    let mut imphash_items = Vec::new();

    if import_dir_rva > 0 {
        if let Some(mut imp_offset) = rva_to_offset(import_dir_rva, raw_sections) {
            while imp_offset
                .checked_add(20)
                .is_some_and(|end| end <= data.len())
                && imports.len() < 4096
            {
                let orig_first_thunk = read_u32(data, imp_offset).unwrap_or(0);
                let name_rva = imp_offset
                    .checked_add(12)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0);
                let first_thunk = imp_offset
                    .checked_add(16)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0);

                if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                    break;
                }

                if let Some(name_offset) = rva_to_offset(name_rva, raw_sections) {
                    if let Some(dll_name) = read_cstring(data, name_offset) {
                        let thunk_rva = if orig_first_thunk != 0 {
                            orig_first_thunk
                        } else {
                            first_thunk
                        };
                        let mut funcs = Vec::new();

                        if let Some(mut thunk_offset) = rva_to_offset(thunk_rva, raw_sections) {
                            let step = if is_64 { 8 } else { 4 };
                            while thunk_offset
                                .checked_add(step)
                                .is_some_and(|end| end <= data.len())
                                && funcs.len() < 65536
                            {
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
                                    if let Some(func_offset) = rva_to_offset(func_rva, raw_sections)
                                    {
                                        let name = func_offset
                                            .checked_add(2)
                                            .and_then(|off| read_cstring(data, off))
                                            .unwrap_or_else(|| "Unknown".to_string());
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

                                match thunk_offset.checked_add(step) {
                                    Some(next) => thunk_offset = next,
                                    None => break,
                                }
                            }
                        }

                        imports.push(ImportInfo {
                            dll: dll_name,
                            functions: funcs,
                        });
                    }
                }

                match imp_offset.checked_add(20) {
                    Some(next) => imp_offset = next,
                    None => break,
                }
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

    (imports, imphash)
}
