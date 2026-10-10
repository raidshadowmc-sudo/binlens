use super::utils::{RawSection, read_u16, read_u32, read_u64, rva_to_offset};
use crate::types::SecurityMitigations;

pub fn parse_mitigations(
    data: &[u8],
    is_64: bool,
    dll_chars: u16,
    data_dirs_offset: usize,
    raw_sections: &[RawSection],
    has_rwx_sections: bool,
) -> SecurityMitigations {
    let mut mitigations = SecurityMitigations {
        high_entropy_va: is_64 && (dll_chars & 0x0020) != 0,
        aslr: (dll_chars & 0x0040) != 0,
        dep_nx: (dll_chars & 0x0100) != 0,
        seh: is_64 && (dll_chars & 0x0400) == 0, // on x64 SEH is table-based in .pdata (unless NO_SEH); on 32-bit requires SafeSEH table in Load Config
        cfg: false, // requires both GUARD_CF flag and valid Load Config function pointer
        authenticode_signed: false,
        has_rwx_sections,
        pie: (dll_chars & 0x0040) != 0,
        relro: "N/A (Windows)".to_string(),
        stack_canary: false,
        fortify: false,
        rpath: None,
        runpath: None,
    };

    let cert_dir_offset = data_dirs_offset
        .checked_add(32)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0) as usize;
    let cert_dir_size = data_dirs_offset
        .checked_add(36)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0) as usize;
    let load_config_rva = data_dirs_offset
        .checked_add(80)
        .and_then(|off| read_u32(data, off))
        .unwrap_or(0);

    // Authenticode Certificate Table check (validates WIN_CERTIFICATE structure presence)
    if cert_dir_offset > 0
        && cert_dir_size >= 8
        && cert_dir_offset
            .checked_add(cert_dir_size)
            .is_some_and(|end| end <= data.len())
    {
        let dw_len = read_u32(data, cert_dir_offset).unwrap_or(0) as usize;
        let w_cert_type = cert_dir_offset
            .checked_add(6)
            .and_then(|off| read_u16(data, off))
            .unwrap_or(0);
        if w_cert_type == 0x0002 && dw_len <= cert_dir_size {
            // WIN_CERT_TYPE_PKCS_SIGNED_DATA certificate table present
            mitigations.authenticode_signed = true;
        }
    }

    // Verify SafeSEH, CFG, and Stack Cookie (/GS) from IMAGE_LOAD_CONFIG_DIRECTORY
    if load_config_rva > 0 {
        if let Some(lc_offset) = rva_to_offset(load_config_rva, raw_sections) {
            let lc_size = read_u32(data, lc_offset).unwrap_or(0) as usize;
            if is_64 {
                // In 64-bit load config:
                // SecurityCookie is at offset 88 (size >= 96)
                if lc_size >= 96
                    && lc_offset
                        .checked_add(96)
                        .is_some_and(|end| end <= data.len())
                {
                    let cookie = lc_offset
                        .checked_add(88)
                        .and_then(|off| read_u64(data, off))
                        .unwrap_or(0);
                    if cookie != 0 {
                        mitigations.stack_canary = true;
                    }
                }
                // GuardCFCheckFunctionPointer is at offset 112 (size >= 120)
                if (dll_chars & 0x4000) != 0
                    && lc_size >= 120
                    && lc_offset
                        .checked_add(120)
                        .is_some_and(|end| end <= data.len())
                {
                    let guard_check = lc_offset
                        .checked_add(112)
                        .and_then(|off| read_u64(data, off))
                        .unwrap_or(0);
                    if guard_check != 0 {
                        mitigations.cfg = true;
                    }
                }
            } else {
                // In 32-bit load config:
                // SecurityCookie is at offset 60 (size >= 64)
                if lc_size >= 64
                    && lc_offset
                        .checked_add(64)
                        .is_some_and(|end| end <= data.len())
                {
                    let cookie = lc_offset
                        .checked_add(60)
                        .and_then(|off| read_u32(data, off))
                        .unwrap_or(0);
                    if cookie != 0 {
                        mitigations.stack_canary = true;
                    }
                }
                // SafeSEH: SEHandlerTable at offset 64, SEHandlerCount at offset 68 (size >= 72)
                if lc_size >= 72
                    && lc_offset
                        .checked_add(72)
                        .is_some_and(|end| end <= data.len())
                {
                    let se_table = lc_offset
                        .checked_add(64)
                        .and_then(|off| read_u32(data, off))
                        .unwrap_or(0);
                    let se_count = lc_offset
                        .checked_add(68)
                        .and_then(|off| read_u32(data, off))
                        .unwrap_or(0);
                    if (dll_chars & 0x0400) == 0 && se_table != 0 && se_count > 0 {
                        mitigations.seh = true;
                    }
                }
                // CFG in 32-bit: GuardCFCheckFunctionPointer at offset 72 (size >= 76)
                if (dll_chars & 0x4000) != 0
                    && lc_size >= 76
                    && lc_offset
                        .checked_add(76)
                        .is_some_and(|end| end <= data.len())
                {
                    let guard_check = lc_offset
                        .checked_add(72)
                        .and_then(|off| read_u32(data, off))
                        .unwrap_or(0);
                    if guard_check != 0 {
                        mitigations.cfg = true;
                    }
                }
            }
        }
    }

    mitigations
}
