use super::utils::{RawSection, read_cstring, read_u16, read_u32, rva_to_offset};
use crate::types::ExportInfo;

pub fn parse_exports(
    data: &[u8],
    export_dir_rva: u32,
    raw_sections: &[RawSection],
) -> Vec<ExportInfo> {
    let mut exports = Vec::new();
    if export_dir_rva > 0 {
        if let Some(exp_offset) = rva_to_offset(export_dir_rva, raw_sections) {
            if exp_offset
                .checked_add(40)
                .is_some_and(|end| end <= data.len())
            {
                let base = exp_offset
                    .checked_add(16)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0);
                let num_names = exp_offset
                    .checked_add(24)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0) as usize;
                let addr_funcs = exp_offset
                    .checked_add(28)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0);
                let addr_names = exp_offset
                    .checked_add(32)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0);
                let addr_ords = exp_offset
                    .checked_add(36)
                    .and_then(|off| read_u32(data, off))
                    .unwrap_or(0);

                if let (Some(names_off), Some(ords_off), Some(funcs_off)) = (
                    rva_to_offset(addr_names, raw_sections),
                    rva_to_offset(addr_ords, raw_sections),
                    rva_to_offset(addr_funcs, raw_sections),
                ) {
                    for i in 0..num_names.min(65536) {
                        let name_entry_off =
                            match i.checked_mul(4).and_then(|d| names_off.checked_add(d)) {
                                Some(off) => off,
                                None => break,
                            };
                        let ord_entry_off =
                            match i.checked_mul(2).and_then(|d| ords_off.checked_add(d)) {
                                Some(off) => off,
                                None => break,
                            };

                        if name_entry_off
                            .checked_add(4)
                            .is_some_and(|end| end <= data.len())
                            && ord_entry_off
                                .checked_add(2)
                                .is_some_and(|end| end <= data.len())
                        {
                            let name_rva = read_u32(data, name_entry_off).unwrap_or(0);
                            let ordinal_idx = read_u16(data, ord_entry_off).unwrap_or(0) as u32;
                            let ordinal = base.checked_add(ordinal_idx).unwrap_or(ordinal_idx);

                            let func_entry_off = (ordinal_idx as usize)
                                .checked_mul(4)
                                .and_then(|d| funcs_off.checked_add(d));

                            let func_rva = if let Some(fo) = func_entry_off {
                                if fo.checked_add(4).is_some_and(|end| end <= data.len()) {
                                    read_u32(data, fo).unwrap_or(0)
                                } else {
                                    0
                                }
                            } else {
                                0
                            };

                            if let Some(no) = rva_to_offset(name_rva, raw_sections) {
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
    exports
}
