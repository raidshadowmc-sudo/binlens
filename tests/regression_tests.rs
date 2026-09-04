use binlens::elf::parse_elf;
use binlens::pe::{parse_pe, rva_to_offset, RawSection};
use binlens::diff::compare_binaries;
use binlens::types::{BinaryReport, BinaryFormat, SecurityMitigations};
use binlens::strings::extract_strings;

#[test]
fn test_rva_to_offset_bounds_and_zero_raw_data() {
    let sections = vec![
        RawSection {
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            pointer_to_raw_data: 0x400,
            size_of_raw_data: 0x200,
        },
        RawSection {
            virtual_address: 0x2000,
            virtual_size: 0x1000,
            pointer_to_raw_data: 0,
            size_of_raw_data: 0, // BSS section
        },
    ];

    // 1) RVA 0x1100 -> delta = 0x100 < raw_size (0x200) -> Valid offset: 0x400 + 0x100 = 0x500
    assert_eq!(rva_to_offset(0x1100, &sections), Some(0x500));

    // 2) RVA 0x1300 -> delta = 0x300 >= raw_size (0x200) -> In memory padding, NOT in raw file!
    assert_eq!(rva_to_offset(0x1300, &sections), None, "RVA in virtual padding beyond raw size must return None");

    // 3) RVA 0x2050 -> in .bss section with size_of_raw_data == 0 -> Must return None!
    assert_eq!(rva_to_offset(0x2050, &sections), None, "RVA in uninitialized BSS section must return None");

    // 4) RVA 0x0080 -> in PE header before sections -> Must map 1:1 to offset 0x80
    assert_eq!(rva_to_offset(0x0080, &sections), Some(0x80), "Header RVA before first section must map 1:1");
}

#[test]
fn test_elf_nx_default_when_no_pt_gnu_stack() {
    let mut elf = vec![0u8; 128];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[6] = 1; // Version
    elf[16] = 2; // ET_EXEC
    elf[18] = 0x3E; // x86_64
    elf[20] = 1;
    elf[32] = 64; // e_phoff
    elf[54] = 56; // e_phentsize
    elf[56] = 1;  // e_phnum = 1 (A single PT_LOAD segment, NO PT_GNU_STACK)
    elf[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD

    let report = parse_elf(&elf, "test_no_nx.elf").expect("Failed to parse minimal ELF");
    assert_eq!(
        report.mitigations.dep_nx, false,
        "ELF without PT_GNU_STACK must NOT report NX as enabled (Linux kernel defaults to executable stack!)"
    );
}

#[test]
fn test_elf_big_endian_parsing() {
    // Construct a minimal Big Endian 32-bit ELF (e.g. MIPS or PPC)
    let mut elf = vec![0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 1; // 32-bit
    elf[5] = 2; // Big-endian (ELFDATA2MSB)
    elf[6] = 1; // EV_CURRENT
    // e_type = ET_EXEC (2) in BE: 0x0002
    elf[16] = 0;
    elf[17] = 2;
    // e_machine = MIPS (8) or PPC (20 = 0x0014) in BE
    elf[18] = 0;
    elf[19] = 0x14; // PowerPC
    // e_entry = 0x1000_0000 in BE
    elf[24..28].copy_from_slice(&[0x10, 0x00, 0x00, 0x00]);

    let report = parse_elf(&elf, "test_be.elf").expect("Failed to parse Big Endian ELF");
    assert_eq!(report.entry_point, 0x1000_0000, "Entry point must be parsed using big-endian ordering");
    assert!(report.architecture.contains("PowerPC") || report.architecture.contains("PPC") || !report.architecture.contains("Unknown"));
}

#[test]
fn test_pe_imphash_standard_format_with_ordinals() {
    // In Mandiant/VirusTotal standard imphash, an ordinal import for ws2_32.dll ordinal 12
    // must be formatted as "ws2_32.ord12".
    // MD5 of "ws2_32.ord12" is e73ef5e0e0e090f9be3eece6007e059a
    use md5::Md5;
    use sha2::Digest;
    let mut hasher = Md5::new();
    hasher.update(b"ws2_32.ord12");
    let expected_hash = binlens::pe::hex_encode(&hasher.finalize());

    // Build a minimal PE with import of ws2_32.dll by ordinal 12
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes()); // e_lfanew = 64
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr+2..file_hdr+4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes()); // opt hdr size

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // Import Directory RVA at opt_hdr + 112 + 8
    let import_dir_entry = opt_hdr + 112 + 8;
    pe[import_dir_entry..import_dir_entry+4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[import_dir_entry+4..import_dir_entry+8].copy_from_slice(&40u32.to_le_bytes());

    // Section header: .rdata at offset opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr+8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr+8..sec_hdr+12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtSize
    pe[sec_hdr+12..sec_hdr+16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtAddr = 0x200
    pe[sec_hdr+16..sec_hdr+20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize = 0x400
    pe[sec_hdr+20..sec_hdr+24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr+36..sec_hdr+40].copy_from_slice(&0x40000040u32.to_le_bytes()); // R

    // Import Directory at offset 0x200 (RVA 0x200)
    let imp_desc = 0x200;
    let ilt_rva = 0x250u32;
    let name_rva = 0x280u32;
    pe[imp_desc..imp_desc+4].copy_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
    pe[imp_desc+12..imp_desc+16].copy_from_slice(&name_rva.to_le_bytes()); // Name
    pe[imp_desc+16..imp_desc+20].copy_from_slice(&ilt_rva.to_le_bytes()); // FirstThunk

    // Name at offset 0x280 (RVA 0x280)
    pe[0x280..0x280+12].copy_from_slice(b"WS2_32.dll\0\0");

    // ILT at offset 0x250 (RVA 0x250): import by ordinal 12 (high bit set for 64-bit)
    let ord_entry = 0x8000_0000_0000_000C_u64;
    pe[0x250..0x250+8].copy_from_slice(&ord_entry.to_le_bytes());

    let report = parse_pe(&pe, "test_imphash.exe").expect("Failed to parse PE with ordinal import");
    assert_eq!(report.imphash, Some(expected_hash), "Imphash must match Mandiant/pefile standard (ws2_32.ord12)");
}

#[test]
fn test_pe_export_ordinal_base_and_function_rva() {
    // Build a minimal PE with export directory: Base = 50, Export Function RVA = 0x1050
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr+2..file_hdr+4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // Export Directory RVA at opt_hdr + 112 (Data Directory 0)
    let export_dir_entry = opt_hdr + 112;
    pe[export_dir_entry..export_dir_entry+4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[export_dir_entry+4..export_dir_entry+8].copy_from_slice(&100u32.to_le_bytes());

    // Section header: .edata at offset opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr+8].copy_from_slice(b".edata\0\0");
    pe[sec_hdr+8..sec_hdr+12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr+12..sec_hdr+16].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[sec_hdr+16..sec_hdr+20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize
    pe[sec_hdr+20..sec_hdr+24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr+36..sec_hdr+40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Export Directory at offset 0x200 (RVA 0x200)
    let exp = 0x200;
    pe[exp+16..exp+20].copy_from_slice(&50u32.to_le_bytes()); // Base = 50
    pe[exp+20..exp+24].copy_from_slice(&1u32.to_le_bytes());  // NumberOfFunctions = 1
    pe[exp+24..exp+28].copy_from_slice(&1u32.to_le_bytes());  // NumberOfNames = 1
    let func_rva_table = 0x250u32;
    let name_rva_table = 0x260u32;
    let ord_table = 0x270u32;
    pe[exp+28..exp+32].copy_from_slice(&func_rva_table.to_le_bytes()); // AddressOfFunctions
    pe[exp+32..exp+36].copy_from_slice(&name_rva_table.to_le_bytes()); // AddressOfNames
    pe[exp+36..exp+40].copy_from_slice(&ord_table.to_le_bytes());      // AddressOfNameOrdinals

    // Function RVA at 0x250: 0x1050
    pe[0x250..0x250+4].copy_from_slice(&0x1050u32.to_le_bytes());
    // Name RVA at 0x260: 0x280 ("ExportedApi")
    pe[0x260..0x260+4].copy_from_slice(&0x280u32.to_le_bytes());
    // Ordinal index at 0x270: index 0 (u16)
    pe[0x270..0x270+2].copy_from_slice(&0u16.to_le_bytes());
    // Name string at 0x280
    pe[0x280..0x280+12].copy_from_slice(b"ExportedApi\0");

    let report = parse_pe(&pe, "test_export.dll").expect("Failed to parse PE with exports");
    assert_eq!(report.exports.len(), 1);
    let exp_info = &report.exports[0];
    assert_eq!(exp_info.name, "ExportedApi");
    assert_eq!(exp_info.ordinal, 50, "Ordinal must include Base (Base 50 + index 0 = 50)");
    assert_eq!(exp_info.rva, 0x1050, "Export RVA must be read from AddressOfFunctions (expected 0x1050, got 0)");
}
#[test]
fn test_elf_imports_and_exports_parsing() {
    // Construct a minimal 64-bit ELF with PT_DYNAMIC, DT_NEEDED, .dynsym and .dynstr
    let mut elf = vec![0u8; 1024];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[6] = 1;
    elf[16] = 3; // ET_DYN
    elf[18] = 0x3E; // x86_64
    elf[20] = 1;
    elf[32] = 64; // e_phoff = 64
    elf[54] = 56; // e_phentsize
    elf[56] = 1;  // e_phnum = 1 (PT_DYNAMIC)
    
    // PT_DYNAMIC at offset 64
    let ph_off = 64;
    elf[ph_off..ph_off+4].copy_from_slice(&2u32.to_le_bytes()); // p_type = PT_DYNAMIC (2)
    elf[ph_off+8..ph_off+16].copy_from_slice(&200u64.to_le_bytes()); // p_offset = 200
    elf[ph_off+32..ph_off+40].copy_from_slice(&64u64.to_le_bytes());  // p_filesz = 64

    // Section headers: 3 sections: [0] null, [1] .dynstr at 400, [2] .dynsym at 600
    let sh_off = 800;
    elf[40] = (sh_off & 0xFF) as u8; // e_shoff = 800
    elf[41] = ((sh_off >> 8) & 0xFF) as u8;
    elf[58] = 64; // e_shentsize = 64
    elf[60] = 3;  // e_shnum = 3

    // Section 1: .dynstr at offset 400
    let s1 = sh_off + 64;
    elf[s1+4..s1+8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB = 3
    elf[s1+24..s1+32].copy_from_slice(&400u64.to_le_bytes()); // sh_offset = 400
    elf[s1+32..s1+40].copy_from_slice(&100u64.to_le_bytes()); // sh_size = 100

    // Section 2: .dynsym at offset 600
    let s2 = sh_off + 128;
    elf[s2+4..s2+8].copy_from_slice(&11u32.to_le_bytes()); // SHT_DYNSYM = 11
    elf[s2+24..s2+32].copy_from_slice(&600u64.to_le_bytes()); // sh_offset = 600
    elf[s2+32..s2+40].copy_from_slice(&48u64.to_le_bytes());  // sh_size = 48 (2 symbols: null + 1 export)
    elf[s2+40..s2+44].copy_from_slice(&1u32.to_le_bytes());   // sh_link = 1 (.dynstr)
    elf[s2+56..s2+64].copy_from_slice(&24u64.to_le_bytes());  // sh_entsize = 24

    // Strings at 400: "\0libc.so.6\0my_exported_func\0"
    elf[401..411].copy_from_slice(b"libc.so.6\0");
    elf[411..428].copy_from_slice(b"my_exported_func\0");

    // Dynamic section at 200:
    // Entry 1: DT_NEEDED (1), d_val = 1 ("libc.so.6")
    elf[200..208].copy_from_slice(&1u64.to_le_bytes());
    elf[208..216].copy_from_slice(&1u64.to_le_bytes());
    // Entry 2: DT_NULL (0)
    elf[216..224].copy_from_slice(&0u64.to_le_bytes());

    // Dynsym entry 1 at 600 + 24 = 624:
    // st_name = 11 ("my_exported_func")
    elf[624..628].copy_from_slice(&11u32.to_le_bytes());
    // st_info = (STB_GLOBAL << 4) = 0x10
    elf[628] = 0x10;
    // st_shndx = 1 (defined)
    elf[630..632].copy_from_slice(&1u16.to_le_bytes());
    // st_value = 0x2000
    elf[632..640].copy_from_slice(&0x2000u64.to_le_bytes());

    let report = parse_elf(&elf, "test_dynamic.so").expect("Failed to parse dynamic ELF");
    assert!(!report.imports.is_empty(), "Must extract DT_NEEDED library dependencies");
    assert_eq!(report.imports[0].dll, "libc.so.6");
    assert!(!report.exports.is_empty(), "Must extract exported symbols from .dynsym");
    assert_eq!(report.exports[0].name, "my_exported_func");
}

#[test]
fn test_strings_no_runaway_concatenation() {
    // Emulate adjacent string literals in rodata without null byte
    let data = b"virtualalloc\0https://example.com/api\0HKEY_LOCAL_MACHINE\\Software\0";
    let categorized = extract_strings(data, 4);

    let api_items: Vec<_> = categorized.iter().filter(|c| c.category == "Suspicious API/Command").collect();
    assert_eq!(api_items.len(), 1);
    assert_eq!(api_items[0].value, "virtualalloc");

    let url_items: Vec<_> = categorized.iter().filter(|c| c.category == "URL").collect();
    assert_eq!(url_items.len(), 1);
    assert_eq!(url_items[0].value, "https://example.com/api");
}

#[test]
fn test_diff_headers_distinguish_identical_basenames() {
    let report_a = BinaryReport {
        file_name: "target/debug/app.exe".to_string(),
        file_size: 1000,
        md5: "aaa".to_string(),
        sha256: "aaa".to_string(),
        format: BinaryFormat::PE64,
        architecture: "x86_64".to_string(),
        subsystem: "Console".to_string(),
        entry_point: 0x1000,
        overall_entropy: 5.0,
        is_likely_packed: false,
        mitigations: SecurityMitigations::default(),
        sections: vec![],
        imports: vec![],
        exports: vec![],
        imphash: None,
        interesting_strings: vec![],
    };
    let mut report_b = report_a.clone();
    report_b.file_name = "target/release/app.exe".to_string();
    report_b.file_size = 2000;

    let diff_lines = compare_binaries(&report_a, &report_b);
    let header_line = diff_lines.iter().find(|l| l.contains("METRIC")).expect("Header not found");
    assert!(header_line.contains("[A]") || header_line.contains("target/debug/app.exe"));
}
#[test]
fn test_cfg_false_positive_without_load_config() {
    // PE with GUARD_CF flag (0x4000), but NO Load Config Directory (RVA 0)
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes());
    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // DllCharacteristics with GUARD_CF (0x4000)
    pe[opt_hdr+70..opt_hdr+72].copy_from_slice(&0x4000u16.to_le_bytes());
    // Data Directory 10 (Load Config) is at opt_hdr + 112 + (10 * 8) = opt_hdr + 192 -> leaves as 0!

    let report = binlens::pe::parse_pe(&pe, "test_cfg_fake.exe").expect("Parse failed");
    assert_eq!(
        report.mitigations.cfg, false,
        "CFG must be false if Load Config is missing even if GUARD_CF flag is set"
    );
}

#[test]
fn test_safeseh_false_positive_without_load_config() {
    // 32-bit PE without NO_SEH flag, but NO Load Config Directory
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x014cu16.to_le_bytes()); // x86 32-bit
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&224u16.to_le_bytes());
    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
    // DllCharacteristics = 0 (NO_SEH is NOT set)
    pe[opt_hdr+70..opt_hdr+72].copy_from_slice(&0u16.to_le_bytes());
    // Load Config Directory (index 10) is 0

    let report = binlens::pe::parse_pe(&pe, "test_safeseh_fake.exe").expect("Parse failed");
    assert_eq!(
        report.mitigations.seh, false,
        "SafeSEH must be false if Load Config is missing in 32-bit PE"
    );
}

#[test]
fn test_cfg_x64_offset_cookie_vs_guard_check() {
    // x64 PE with GUARD_CF flag (0x4000), Load Config present (size 128),
    // SecurityCookie (offset 88) is non-zero, but GuardCFCheckFunctionPointer (offset 112) is 0.
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr+2..file_hdr+4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes()); // opt hdr size

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // DllCharacteristics with GUARD_CF (0x4000)
    pe[opt_hdr+70..opt_hdr+72].copy_from_slice(&0x4000u16.to_le_bytes());

    // Load Config Directory entry (Data Directory 10 at opt_hdr + 112 + 10 * 8 = opt_hdr + 192)
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry+4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[lc_entry+4..lc_entry+8].copy_from_slice(&128u32.to_le_bytes()); // Size 128

    // Section header: .rdata at opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr+8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr+8..sec_hdr+12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtSize
    pe[sec_hdr+12..sec_hdr+16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtAddr = 0x200
    pe[sec_hdr+16..sec_hdr+20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize = 0x400
    pe[sec_hdr+20..sec_hdr+24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr+36..sec_hdr+40].copy_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics

    // Load Config at offset 0x200:
    let lc_offset = 0x200;
    pe[lc_offset..lc_offset+4].copy_from_slice(&128u32.to_le_bytes()); // Size = 128 (0x80)
    // Offset 88: SecurityCookie != 0
    pe[lc_offset+88..lc_offset+96].copy_from_slice(&0x1234_5678_9ABC_DEF0_u64.to_le_bytes());
    // Offset 112: GuardCFCheckFunctionPointer == 0
    pe[lc_offset+112..lc_offset+120].copy_from_slice(&0_u64.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_cfg_cookie.exe").expect("Parse failed");
    assert_eq!(
        report.mitigations.cfg, false,
        "CFG must be FALSE when GuardCFCheckFunctionPointer (offset 112) is 0, even if SecurityCookie (offset 88) is non-zero"
    );
}

#[test]
fn test_cfg_x64_valid_guard_check_passes() {
    // x64 PE with GUARD_CF flag (0x4000), Load Config present (size 128),
    // and valid GuardCFCheckFunctionPointer (offset 112) != 0.
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr+2..file_hdr+4].copy_from_slice(&1u16.to_le_bytes());
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    pe[opt_hdr+70..opt_hdr+72].copy_from_slice(&0x4000u16.to_le_bytes()); // GUARD_CF

    // Load Config Directory entry
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry+4].copy_from_slice(&0x200u32.to_le_bytes());
    pe[lc_entry+4..lc_entry+8].copy_from_slice(&128u32.to_le_bytes());

    // Section header: .rdata
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr+8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr+8..sec_hdr+12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr+12..sec_hdr+16].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr+16..sec_hdr+20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr+20..sec_hdr+24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr+36..sec_hdr+40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Load Config at offset 0x200:
    let lc_offset = 0x200;
    pe[lc_offset..lc_offset+4].copy_from_slice(&128u32.to_le_bytes()); // Size = 128
    // Offset 112: GuardCFCheckFunctionPointer != 0
    pe[lc_offset+112..lc_offset+120].copy_from_slice(&0x0000_0001_4000_1000_u64.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_cfg_valid.exe").expect("Parse failed");
    assert_eq!(report.mitigations.cfg, true, "CFG must be TRUE when GuardCFCheckFunctionPointer is non-zero");
}

#[test]
fn test_cfg_x64_truncated_load_config_fails() {
    // x64 PE with GUARD_CF flag (0x4000), but Load Config size is only 96 bytes (does not cover offset 112)
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr+2..file_hdr+4].copy_from_slice(&1u16.to_le_bytes());
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    pe[opt_hdr+70..opt_hdr+72].copy_from_slice(&0x4000u16.to_le_bytes()); // GUARD_CF

    // Load Config Directory entry: size 96
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry+4].copy_from_slice(&0x200u32.to_le_bytes());
    pe[lc_entry+4..lc_entry+8].copy_from_slice(&96u32.to_le_bytes());

    // Section header: .rdata
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr+8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr+8..sec_hdr+12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr+12..sec_hdr+16].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr+16..sec_hdr+20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr+20..sec_hdr+24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr+36..sec_hdr+40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Load Config at offset 0x200: Size = 96
    let lc_offset = 0x200;
    pe[lc_offset..lc_offset+4].copy_from_slice(&96u32.to_le_bytes());
    // Even if memory at 112 has bytes, struct size 96 doesn't reach it
    pe[lc_offset+112..lc_offset+120].copy_from_slice(&0x0000_0001_4000_1000_u64.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_cfg_trunc.exe").expect("Parse failed");
    assert_eq!(report.mitigations.cfg, false, "CFG must be FALSE when Load Config size < 120");
}

#[test]
fn test_seh_x64_no_seh_flag() {
    // x64 PE with IMAGE_DLLCHARACTERISTICS_NO_SEH (0x0400)
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt+4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr+2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr+16..file_hdr+18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr+2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // DllCharacteristics: NO_SEH (0x0400)
    pe[opt_hdr+70..opt_hdr+72].copy_from_slice(&0x0400u16.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_no_seh.exe").expect("Parse failed");
    assert_eq!(report.mitigations.seh, false, "SEH must be false on x64 if NO_SEH flag is set");
}
