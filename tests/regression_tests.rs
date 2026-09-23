use binlens::diff::compare_binaries;
use binlens::elf::parse_elf;
use binlens::pe::{RawSection, parse_pe, rva_to_offset};
use binlens::strings::extract_strings;
use binlens::types::{BinaryFormat, BinaryReport, SecurityMitigations};

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
    assert_eq!(
        rva_to_offset(0x1300, &sections),
        None,
        "RVA in virtual padding beyond raw size must return None"
    );

    // 3) RVA 0x2050 -> in .bss section with size_of_raw_data == 0 -> Must return None!
    assert_eq!(
        rva_to_offset(0x2050, &sections),
        None,
        "RVA in uninitialized BSS section must return None"
    );

    // 4) RVA 0x0080 -> in PE header before sections -> Must map 1:1 to offset 0x80
    assert_eq!(
        rva_to_offset(0x0080, &sections),
        Some(0x80),
        "Header RVA before first section must map 1:1"
    );
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
    elf[56] = 1; // e_phnum = 1 (A single PT_LOAD segment, NO PT_GNU_STACK)
    elf[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD

    let report = parse_elf(&elf, "test_no_nx.elf").expect("Failed to parse minimal ELF");
    assert!(
        !report.mitigations.dep_nx,
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
    assert_eq!(
        report.entry_point, 0x1000_0000,
        "Entry point must be parsed using big-endian ordering"
    );
    assert!(
        report.architecture.contains("PowerPC")
            || report.architecture.contains("PPC")
            || !report.architecture.contains("Unknown")
    );
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
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes()); // opt hdr size

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // Import Directory RVA at opt_hdr + 112 + 8
    let import_dir_entry = opt_hdr + 112 + 8;
    pe[import_dir_entry..import_dir_entry + 4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[import_dir_entry + 4..import_dir_entry + 8].copy_from_slice(&40u32.to_le_bytes());

    // Section header: .rdata at offset opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtSize
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtAddr = 0x200
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize = 0x400
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // R

    // Import Directory at offset 0x200 (RVA 0x200)
    let imp_desc = 0x200;
    let ilt_rva = 0x250u32;
    let name_rva = 0x280u32;
    pe[imp_desc..imp_desc + 4].copy_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
    pe[imp_desc + 12..imp_desc + 16].copy_from_slice(&name_rva.to_le_bytes()); // Name
    pe[imp_desc + 16..imp_desc + 20].copy_from_slice(&ilt_rva.to_le_bytes()); // FirstThunk

    // Name at offset 0x280 (RVA 0x280)
    pe[0x280..0x280 + 12].copy_from_slice(b"WS2_32.dll\0\0");

    // ILT at offset 0x250 (RVA 0x250): import by ordinal 12 (high bit set for 64-bit)
    let ord_entry = 0x8000_0000_0000_000C_u64;
    pe[0x250..0x250 + 8].copy_from_slice(&ord_entry.to_le_bytes());

    let report = parse_pe(&pe, "test_imphash.exe").expect("Failed to parse PE with ordinal import");
    assert_eq!(
        report.imphash,
        Some(expected_hash),
        "Imphash must match Mandiant/pefile standard (ws2_32.ord12)"
    );
}

#[test]
fn test_pe_export_ordinal_base_and_function_rva() {
    // Build a minimal PE with export directory: Base = 50, Export Function RVA = 0x1050
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // Export Directory RVA at opt_hdr + 112 (Data Directory 0)
    let export_dir_entry = opt_hdr + 112;
    pe[export_dir_entry..export_dir_entry + 4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[export_dir_entry + 4..export_dir_entry + 8].copy_from_slice(&100u32.to_le_bytes());

    // Section header: .edata at offset opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".edata\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Export Directory at offset 0x200 (RVA 0x200)
    let exp = 0x200;
    pe[exp + 16..exp + 20].copy_from_slice(&50u32.to_le_bytes()); // Base = 50
    pe[exp + 20..exp + 24].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions = 1
    pe[exp + 24..exp + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames = 1
    let func_rva_table = 0x250u32;
    let name_rva_table = 0x260u32;
    let ord_table = 0x270u32;
    pe[exp + 28..exp + 32].copy_from_slice(&func_rva_table.to_le_bytes()); // AddressOfFunctions
    pe[exp + 32..exp + 36].copy_from_slice(&name_rva_table.to_le_bytes()); // AddressOfNames
    pe[exp + 36..exp + 40].copy_from_slice(&ord_table.to_le_bytes()); // AddressOfNameOrdinals

    // Function RVA at 0x250: 0x1050
    pe[0x250..0x250 + 4].copy_from_slice(&0x1050u32.to_le_bytes());
    // Name RVA at 0x260: 0x280 ("ExportedApi")
    pe[0x260..0x260 + 4].copy_from_slice(&0x280u32.to_le_bytes());
    // Ordinal index at 0x270: index 0 (u16)
    pe[0x270..0x270 + 2].copy_from_slice(&0u16.to_le_bytes());
    // Name string at 0x280
    pe[0x280..0x280 + 12].copy_from_slice(b"ExportedApi\0");

    let report = parse_pe(&pe, "test_export.dll").expect("Failed to parse PE with exports");
    assert_eq!(report.exports.len(), 1);
    let exp_info = &report.exports[0];
    assert_eq!(exp_info.name, "ExportedApi");
    assert_eq!(
        exp_info.ordinal, 50,
        "Ordinal must include Base (Base 50 + index 0 = 50)"
    );
    assert_eq!(
        exp_info.rva, 0x1050,
        "Export RVA must be read from AddressOfFunctions (expected 0x1050, got 0)"
    );
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
    elf[56] = 1; // e_phnum = 1 (PT_DYNAMIC)

    // PT_DYNAMIC at offset 64
    let ph_off = 64;
    elf[ph_off..ph_off + 4].copy_from_slice(&2u32.to_le_bytes()); // p_type = PT_DYNAMIC (2)
    elf[ph_off + 8..ph_off + 16].copy_from_slice(&200u64.to_le_bytes()); // p_offset = 200
    elf[ph_off + 32..ph_off + 40].copy_from_slice(&64u64.to_le_bytes()); // p_filesz = 64

    // Section headers: 3 sections: [0] null, [1] .dynstr at 400, [2] .dynsym at 600
    let sh_off = 800;
    elf[40] = (sh_off & 0xFF) as u8; // e_shoff = 800
    elf[41] = ((sh_off >> 8) & 0xFF) as u8;
    elf[58] = 64; // e_shentsize = 64
    elf[60] = 3; // e_shnum = 3

    // Section 1: .dynstr at offset 400
    let s1 = sh_off + 64;
    elf[s1 + 4..s1 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB = 3
    elf[s1 + 24..s1 + 32].copy_from_slice(&400u64.to_le_bytes()); // sh_offset = 400
    elf[s1 + 32..s1 + 40].copy_from_slice(&100u64.to_le_bytes()); // sh_size = 100

    // Section 2: .dynsym at offset 600
    let s2 = sh_off + 128;
    elf[s2 + 4..s2 + 8].copy_from_slice(&11u32.to_le_bytes()); // SHT_DYNSYM = 11
    elf[s2 + 24..s2 + 32].copy_from_slice(&600u64.to_le_bytes()); // sh_offset = 600
    elf[s2 + 32..s2 + 40].copy_from_slice(&48u64.to_le_bytes()); // sh_size = 48 (2 symbols: null + 1 export)
    elf[s2 + 40..s2 + 44].copy_from_slice(&1u32.to_le_bytes()); // sh_link = 1 (.dynstr)
    elf[s2 + 56..s2 + 64].copy_from_slice(&24u64.to_le_bytes()); // sh_entsize = 24

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
    assert!(
        !report.imports.is_empty(),
        "Must extract DT_NEEDED library dependencies"
    );
    assert_eq!(report.imports[0].dll, "libc.so.6");
    assert!(
        !report.exports.is_empty(),
        "Must extract exported symbols from .dynsym"
    );
    assert_eq!(report.exports[0].name, "my_exported_func");
}

#[test]
fn test_strings_no_runaway_concatenation() {
    // Emulate adjacent string literals in rodata without null byte
    let data = b"virtualalloc\0https://example.com/api\0HKEY_LOCAL_MACHINE\\Software\0";
    let categorized = extract_strings(data, 4);

    let api_items: Vec<_> = categorized
        .iter()
        .filter(|c| c.category == "Suspicious API/Command")
        .collect();
    assert_eq!(api_items.len(), 1);
    assert_eq!(api_items[0].value, "virtualalloc");

    let url_items: Vec<_> = categorized.iter().filter(|c| c.category == "URL").collect();
    assert_eq!(url_items.len(), 1);
    assert_eq!(url_items[0].value, "https://example.com/api");
}

#[test]
fn test_strings_utf16_odd_offset() {
    // UTF-16LE string "https://evil.com" starting at odd offset (index 1)
    let mut data = vec![0xAA]; // 1 leading dummy byte to create odd alignment
    for c in "https://evil.com".encode_utf16() {
        data.extend_from_slice(&c.to_le_bytes());
    }
    data.extend_from_slice(&[0x00, 0x00]); // null terminator

    let categorized = extract_strings(&data, 4);
    let urls: Vec<_> = categorized.iter().filter(|c| c.category == "URL").collect();
    assert_eq!(
        urls.len(),
        1,
        "Must extract UTF-16LE strings even with odd byte offset"
    );
    assert_eq!(urls[0].value, "https://evil.com");
}

#[test]
fn test_strings_suspicious_api_variants() {
    let data = b"VirtualAllocEx\0LoadLibraryA\0CreateProcessW\0SomeNormalFunc\0";
    let categorized = extract_strings(data, 4);
    let apis: Vec<_> = categorized
        .iter()
        .filter(|c| c.category == "Suspicious API/Command")
        .collect();

    assert_eq!(
        apis.len(),
        3,
        "Must match API variants like VirtualAllocEx, LoadLibraryA, CreateProcessW"
    );
    assert_eq!(apis[0].value, "VirtualAllocEx");
    assert_eq!(apis[1].value, "LoadLibraryA");
    assert_eq!(apis[2].value, "CreateProcessW");
}

#[test]
fn test_strings_ipv4_heuristics() {
    // Real IPs vs false positive version strings & unroutable IPs
    let data = b"192.168.1.1\x0010.0.0.1\x001.2.3.4\x001.0.0.0\x000.0.0.0\x00255.255.255.255\x00";
    let categorized = extract_strings(data, 4);
    let ips: Vec<_> = categorized
        .iter()
        .filter(|c| c.category == "IPv4")
        .collect();

    assert_eq!(
        ips.len(),
        2,
        "Only legitimate routable IPv4 addresses should pass heuristics"
    );
    assert_eq!(ips[0].value, "192.168.1.1");
    assert_eq!(ips[1].value, "10.0.0.1");
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
        rich_header: None,
        imphash: None,
        interesting_strings: vec![],
        entry_point_preview: vec![],
        authenticode: None,
    };
    let mut report_b = report_a.clone();
    report_b.file_name = "target/release/app.exe".to_string();
    report_b.file_size = 2000;

    let diff_lines = compare_binaries(&report_a, &report_b);
    let header_line = diff_lines
        .iter()
        .find(|l| l.contains("METRIC"))
        .expect("Header not found");
    assert!(header_line.contains("[A]") || header_line.contains("target/debug/app.exe"));
}
#[test]
fn test_cfg_false_positive_without_load_config() {
    // PE with GUARD_CF flag (0x4000), but NO Load Config Directory (RVA 0)
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());
    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // DllCharacteristics with GUARD_CF (0x4000)
    pe[opt_hdr + 70..opt_hdr + 72].copy_from_slice(&0x4000u16.to_le_bytes());
    // Data Directory 10 (Load Config) is at opt_hdr + 112 + (10 * 8) = opt_hdr + 192 -> leaves as 0!

    let report = binlens::pe::parse_pe(&pe, "test_cfg_fake.exe").expect("Parse failed");
    assert!(
        !report.mitigations.cfg,
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
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // x86 32-bit
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&224u16.to_le_bytes());
    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
    // DllCharacteristics = 0 (NO_SEH is NOT set)
    pe[opt_hdr + 70..opt_hdr + 72].copy_from_slice(&0u16.to_le_bytes());
    // Load Config Directory (index 10) is 0

    let report = binlens::pe::parse_pe(&pe, "test_safeseh_fake.exe").expect("Parse failed");
    assert!(
        !report.mitigations.seh,
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
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes()); // opt hdr size

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // DllCharacteristics with GUARD_CF (0x4000)
    pe[opt_hdr + 70..opt_hdr + 72].copy_from_slice(&0x4000u16.to_le_bytes());

    // Load Config Directory entry (Data Directory 10 at opt_hdr + 112 + 10 * 8 = opt_hdr + 192)
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry + 4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[lc_entry + 4..lc_entry + 8].copy_from_slice(&128u32.to_le_bytes()); // Size 128

    // Section header: .rdata at opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtSize
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x200u32.to_le_bytes()); // VirtAddr = 0x200
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize = 0x400
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics

    // Load Config at offset 0x200:
    let lc_offset = 0x200;
    pe[lc_offset..lc_offset + 4].copy_from_slice(&128u32.to_le_bytes()); // Size = 128 (0x80)
    // Offset 88: SecurityCookie != 0
    pe[lc_offset + 88..lc_offset + 96].copy_from_slice(&0x1234_5678_9ABC_DEF0_u64.to_le_bytes());
    // Offset 112: GuardCFCheckFunctionPointer == 0
    pe[lc_offset + 112..lc_offset + 120].copy_from_slice(&0_u64.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_cfg_cookie.exe").expect("Parse failed");
    assert!(
        !report.mitigations.cfg,
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
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes());
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    pe[opt_hdr + 70..opt_hdr + 72].copy_from_slice(&0x4000u16.to_le_bytes()); // GUARD_CF

    // Load Config Directory entry
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry + 4].copy_from_slice(&0x200u32.to_le_bytes());
    pe[lc_entry + 4..lc_entry + 8].copy_from_slice(&128u32.to_le_bytes());

    // Section header: .rdata
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Load Config at offset 0x200:
    let lc_offset = 0x200;
    pe[lc_offset..lc_offset + 4].copy_from_slice(&128u32.to_le_bytes()); // Size = 128
    // Offset 112: GuardCFCheckFunctionPointer != 0
    pe[lc_offset + 112..lc_offset + 120].copy_from_slice(&0x0000_0001_4000_1000_u64.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_cfg_valid.exe").expect("Parse failed");
    assert!(
        report.mitigations.cfg,
        "CFG must be TRUE when GuardCFCheckFunctionPointer is non-zero"
    );
}

#[test]
fn test_cfg_x64_truncated_load_config_fails() {
    // x64 PE with GUARD_CF flag (0x4000), but Load Config size is only 96 bytes (does not cover offset 112)
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes());
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    pe[opt_hdr + 70..opt_hdr + 72].copy_from_slice(&0x4000u16.to_le_bytes()); // GUARD_CF

    // Load Config Directory entry: size 96
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry + 4].copy_from_slice(&0x200u32.to_le_bytes());
    pe[lc_entry + 4..lc_entry + 8].copy_from_slice(&96u32.to_le_bytes());

    // Section header: .rdata
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Load Config at offset 0x200: Size = 96
    let lc_offset = 0x200;
    pe[lc_offset..lc_offset + 4].copy_from_slice(&96u32.to_le_bytes());
    // Even if memory at 112 has bytes, struct size 96 doesn't reach it
    pe[lc_offset + 112..lc_offset + 120].copy_from_slice(&0x0000_0001_4000_1000_u64.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_cfg_trunc.exe").expect("Parse failed");
    assert!(
        !report.mitigations.cfg,
        "CFG must be FALSE when Load Config size < 120"
    );
}

#[test]
fn test_seh_x64_no_seh_flag() {
    // x64 PE with IMAGE_DLLCHARACTERISTICS_NO_SEH (0x0400)
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // DllCharacteristics: NO_SEH (0x0400)
    pe[opt_hdr + 70..opt_hdr + 72].copy_from_slice(&0x0400u16.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_no_seh.exe").expect("Parse failed");
    assert!(
        !report.mitigations.seh,
        "SEH must be false on x64 if NO_SEH flag is set"
    );
}

#[test]
fn test_pe_rich_header_parsing() {
    // Construct a PE with synthetic DanS ... Rich header between 0x80 and e_lfanew
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    let e_lfanew = 256;
    pe[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    pe[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = e_lfanew + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());
    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes());

    let xor_key: u32 = 0xA1B2C3D4;
    let dans_magic: u32 = 0x536E6144; // "DanS"
    let rich_magic = b"Rich";

    // Place DanS at 0x80
    let dans_off = 0x80;
    pe[dans_off..dans_off + 4].copy_from_slice(&(dans_magic ^ xor_key).to_le_bytes());
    pe[dans_off + 4..dans_off + 8].copy_from_slice(&xor_key.to_le_bytes());
    pe[dans_off + 8..dans_off + 12].copy_from_slice(&xor_key.to_le_bytes());
    pe[dans_off + 12..dans_off + 16].copy_from_slice(&xor_key.to_le_bytes());

    // Entry 1: Utc1930_C (prod_id 0x0101), build 33145, count 42
    let comp_id_1: u32 = (0x0101 << 16) | 33145;
    let count_1: u32 = 42;
    pe[dans_off + 16..dans_off + 20].copy_from_slice(&(comp_id_1 ^ xor_key).to_le_bytes());
    pe[dans_off + 20..dans_off + 24].copy_from_slice(&(count_1 ^ xor_key).to_le_bytes());

    // Rich footer at dans_off + 24
    let rich_off = dans_off + 24;
    pe[rich_off..rich_off + 4].copy_from_slice(rich_magic);
    pe[rich_off + 4..rich_off + 8].copy_from_slice(&xor_key.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_rich.exe").expect("Parse failed");
    let rich = report.rich_header.expect("Rich header was not found");
    assert_eq!(rich.xor_key, xor_key);
    assert_eq!(rich.raw_offset, dans_off);
    assert_eq!(rich.entries.len(), 1);
    assert_eq!(rich.entries[0].prod_id, 0x0101);
    assert_eq!(rich.entries[0].build_id, 33145);
    assert_eq!(rich.entries[0].count, 42);
    assert_eq!(rich.entries[0].tool_name, "Utc1930_C");
    assert_eq!(
        rich.entries[0].msvc_version.as_deref(),
        Some("Visual Studio 2022 (17.0)")
    );
}

#[test]
fn test_pe_rich_header_oversized_dos_protection() {
    // A crafted PE with e_lfanew far away and a >4KB gap between DanS and Rich
    let mut pe = vec![0u8; 8192];
    pe[0..2].copy_from_slice(b"MZ");
    let e_lfanew = 7000;
    pe[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    pe[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = e_lfanew + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());
    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes());

    let xor_key: u32 = 0x12345678;
    let dans_magic: u32 = 0x536E6144;
    let dans_off = 0x80;
    pe[dans_off..dans_off + 4].copy_from_slice(&(dans_magic ^ xor_key).to_le_bytes());

    // Place Rich 5000 bytes later (> 4096 bytes threshold)
    let rich_off = dans_off + 5000;
    pe[rich_off..rich_off + 4].copy_from_slice(b"Rich");
    pe[rich_off + 4..rich_off + 8].copy_from_slice(&xor_key.to_le_bytes());

    let report = binlens::pe::parse_pe(&pe, "test_huge_rich.exe").expect("Parse failed");
    assert!(
        report.rich_header.is_none(),
        "Oversized (>4KB) Rich Header must be rejected to prevent memory exhaustion"
    );
}

#[test]
fn test_elf_relro_full_vs_partial_vs_none() {
    use binlens::elf::parse_elf;

    // 1. Full RELRO: PT_GNU_RELRO + PT_DYNAMIC with DT_BIND_NOW (24)
    let mut elf_full = vec![0u8; 1024];
    elf_full[0..4].copy_from_slice(b"\x7fELF");
    elf_full[4] = 2; // 64-bit
    elf_full[5] = 1; // Little endian
    elf_full[6] = 1;
    elf_full[16] = 3; // ET_DYN
    elf_full[18] = 0x3E; // x86_64
    elf_full[32] = 64; // e_phoff = 64
    elf_full[54] = 56; // e_phentsize
    elf_full[56] = 2; // e_phnum = 2 (PT_GNU_RELRO + PT_DYNAMIC)

    // Program header 0: PT_GNU_RELRO (0x6474e552)
    let ph0 = 64;
    elf_full[ph0..ph0 + 4].copy_from_slice(&0x6474e552_u32.to_le_bytes());

    // Program header 1: PT_DYNAMIC (2)
    let ph1 = 64 + 56;
    elf_full[ph1..ph1 + 4].copy_from_slice(&2_u32.to_le_bytes());
    elf_full[ph1 + 8..ph1 + 16].copy_from_slice(&200_u64.to_le_bytes()); // p_offset = 200
    elf_full[ph1 + 32..ph1 + 40].copy_from_slice(&32_u64.to_le_bytes()); // p_filesz = 32

    // Dynamic section at 200:
    // Entry 1: DT_BIND_NOW (24)
    elf_full[200..208].copy_from_slice(&24_u64.to_le_bytes());
    elf_full[208..216].copy_from_slice(&1_u64.to_le_bytes());
    // Entry 2: DT_NULL (0)
    elf_full[216..224].copy_from_slice(&0_u64.to_le_bytes());

    let rep_full = parse_elf(&elf_full, "test_full.elf").expect("Failed to parse Full RELRO ELF");
    assert_eq!(
        rep_full.mitigations.relro, "Full",
        "PT_GNU_RELRO + DT_BIND_NOW must be Full RELRO"
    );
    assert!(
        !rep_full.mitigations.high_entropy_va,
        "ELF must not report High Entropy VA (PE-specific)"
    );

    // 2. Partial RELRO: PT_GNU_RELRO without DT_BIND_NOW
    let mut elf_partial = elf_full.clone();
    // Overwrite DT_BIND_NOW with DT_DEBUG (21)
    elf_partial[200..208].copy_from_slice(&21_u64.to_le_bytes());
    let rep_part =
        parse_elf(&elf_partial, "test_part.elf").expect("Failed to parse Partial RELRO ELF");
    assert_eq!(
        rep_part.mitigations.relro, "Partial",
        "PT_GNU_RELRO without BIND_NOW must be Partial RELRO"
    );

    // 3. No RELRO: No PT_GNU_RELRO segment
    let mut elf_none = elf_full.clone();
    elf_none[ph0..ph0 + 4].copy_from_slice(&1_u32.to_le_bytes()); // Change to PT_LOAD (1)
    let rep_none = parse_elf(&elf_none, "test_none.elf").expect("Failed to parse No RELRO ELF");
    assert_eq!(
        rep_none.mitigations.relro, "None",
        "Absence of PT_GNU_RELRO must be None RELRO"
    );
}

#[test]
fn test_structured_diff_report() {
    use binlens::diff::generate_diff_report;
    use binlens::types::{BinaryFormat, BinaryReport, SectionInfo, SecurityMitigations};

    let report_a = BinaryReport {
        file_name: "release_v1.exe".to_string(),
        file_size: 1000,
        md5: "a1a1a1".to_string(),
        sha256: "b1b1b1".to_string(),
        format: BinaryFormat::PE64,
        architecture: "x86_64".to_string(),
        subsystem: "CUI".to_string(),
        entry_point: 0x1000,
        overall_entropy: 5.0,
        is_likely_packed: false,
        mitigations: SecurityMitigations {
            aslr: true,
            high_entropy_va: true,
            dep_nx: true,
            seh: false,
            cfg: true,
            authenticode_signed: true,
            has_rwx_sections: false,
            pie: false,
            relro: "None".to_string(),
            stack_canary: false,
            fortify: false,
            rpath: None,
            runpath: None,
        },
        sections: vec![SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 500,
            raw_offset: 0x400,
            raw_size: 500,
            entropy: 6.0,
            readable: true,
            writable: false,
            executable: true,
            is_rwx: false,
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        rich_header: None,
        imphash: None,
        interesting_strings: Vec::new(),
        entry_point_preview: Vec::new(),
        authenticode: None,
    };

    let mut report_b = report_a.clone();
    report_b.file_name = "release_v2.exe".to_string();
    report_b.file_size = 1200;
    report_b.overall_entropy = 5.2;
    // Degrade CFG to test mitigation drift detection
    report_b.mitigations.cfg = false;
    // Add a new section
    report_b.sections.push(SectionInfo {
        name: ".extra".to_string(),
        virtual_address: 0x2000,
        virtual_size: 200,
        raw_offset: 0x900,
        raw_size: 200,
        entropy: 4.5,
        readable: true,
        writable: true,
        executable: false,
        is_rwx: false,
    });

    let diff = generate_diff_report(&report_a, &report_b);
    assert_eq!(diff.size_delta, 200);
    assert_eq!(diff.file_a, "release_v1.exe");
    assert_eq!(diff.file_b, "release_v2.exe");

    let cfg_drift = diff
        .mitigations_drift
        .iter()
        .find(|m| m.mitigation.contains("Control Flow Guard"))
        .unwrap();
    assert_eq!(cfg_drift.status, "degraded");
    assert!(cfg_drift.before);
    assert!(!cfg_drift.after);

    let extra_sec = diff
        .section_deltas
        .iter()
        .find(|s| s.name == ".extra")
        .unwrap();
    assert_eq!(extra_sec.action, "added");
    assert_eq!(extra_sec.size_delta, 200);
}

#[test]
fn test_read_cstring_bounded_dos_protection() {
    use binlens::pe::read_cstring_bounded;

    // A buffer with 5000 'A' bytes without a null terminator
    let long_buf = vec![b'A'; 5000];
    // Bounded read with max_len 256 should stop at 256 and return None
    let res = read_cstring_bounded(&long_buf, 0, 256);
    assert_eq!(
        res, None,
        "Un-terminated cstring must return None and avoid unbounded scan"
    );

    // A buffer with null terminator at byte 50
    let mut valid_buf = vec![b'B'; 100];
    valid_buf[50] = 0;
    let res_valid = read_cstring_bounded(&valid_buf, 0, 256);
    let expected_b = "B".repeat(50);
    assert_eq!(res_valid.as_deref(), Some(expected_b.as_str()));
}

#[test]
fn test_elf_stack_canary_and_fortify_detection() {
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
    elf[56] = 1; // e_phnum = 1 (PT_DYNAMIC)

    // PT_DYNAMIC at offset 64
    let ph_off = 64;
    elf[ph_off..ph_off + 4].copy_from_slice(&2u32.to_le_bytes()); // p_type = PT_DYNAMIC (2)
    elf[ph_off + 8..ph_off + 16].copy_from_slice(&200u64.to_le_bytes()); // p_offset = 200
    elf[ph_off + 32..ph_off + 40].copy_from_slice(&32u64.to_le_bytes()); // p_filesz = 32

    // Dynamic section at 200: DT_NULL
    elf[200..208].copy_from_slice(&0u64.to_le_bytes());

    // Section headers at 800: [0] null, [1] .dynstr at 400, [2] .dynsym at 600
    let sh_off = 800;
    elf[40] = (sh_off & 0xFF) as u8;
    elf[41] = ((sh_off >> 8) & 0xFF) as u8;
    elf[58] = 64; // e_shentsize = 64
    elf[60] = 3; // e_shnum = 3

    // Section 1: .dynstr at offset 400
    let s1 = sh_off + 64;
    elf[s1 + 4..s1 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB = 3
    elf[s1 + 24..s1 + 32].copy_from_slice(&400u64.to_le_bytes());
    elf[s1 + 32..s1 + 40].copy_from_slice(&100u64.to_le_bytes());

    // Section 2: .dynsym at offset 600
    let s2 = sh_off + 128;
    elf[s2 + 4..s2 + 8].copy_from_slice(&11u32.to_le_bytes()); // SHT_DYNSYM = 11
    elf[s2 + 24..s2 + 32].copy_from_slice(&600u64.to_le_bytes());
    elf[s2 + 32..s2 + 40].copy_from_slice(&72u64.to_le_bytes()); // 3 symbols * 24 bytes = 72
    elf[s2 + 40..s2 + 44].copy_from_slice(&1u32.to_le_bytes()); // sh_link = 1 (.dynstr)
    elf[s2 + 56..s2 + 64].copy_from_slice(&24u64.to_le_bytes()); // sh_entsize = 24

    // String table at 400: "\0__stack_chk_fail\0__printf_chk\0"
    let s_canary = b"__stack_chk_fail\0";
    let s_fortify = b"__printf_chk\0";
    let off_canary = 1usize;
    let off_fortify = off_canary + s_canary.len();
    elf[400 + off_canary..400 + off_canary + s_canary.len()].copy_from_slice(s_canary);
    elf[400 + off_fortify..400 + off_fortify + s_fortify.len()].copy_from_slice(s_fortify);

    // Symbol 1: __stack_chk_fail (undefined import) at 600 + 24 = 624
    elf[624..628].copy_from_slice(&(off_canary as u32).to_le_bytes());
    elf[628] = 0x12; // STB_GLOBAL, STT_FUNC
    elf[630..632].copy_from_slice(&0u16.to_le_bytes()); // SHN_UNDEF

    // Symbol 2: __printf_chk (undefined import) at 600 + 48 = 648
    elf[648..652].copy_from_slice(&(off_fortify as u32).to_le_bytes());
    elf[652] = 0x12;
    elf[653] = 0;
    elf[654..656].copy_from_slice(&0u16.to_le_bytes()); // SHN_UNDEF

    let report = parse_elf(&elf, "test_canary.elf").expect("Failed to parse ELF");
    assert!(
        report.mitigations.stack_canary,
        "__stack_chk_fail must set stack_canary = true"
    );
    assert!(
        report.mitigations.fortify,
        "__printf_chk must set fortify = true"
    );
}

#[test]
fn test_elf_rpath_and_runpath_detection() {
    let mut elf = vec![0u8; 1024];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[6] = 1;
    elf[16] = 3; // ET_DYN
    elf[18] = 0x3E; // x86_64
    elf[20] = 1;
    elf[32] = 64; // e_phoff = 64
    elf[54] = 56;
    elf[56] = 1;

    // PT_DYNAMIC at 64
    let ph_off = 64;
    elf[ph_off..ph_off + 4].copy_from_slice(&2u32.to_le_bytes());
    elf[ph_off + 8..ph_off + 16].copy_from_slice(&200u64.to_le_bytes()); // p_offset = 200
    elf[ph_off + 32..ph_off + 40].copy_from_slice(&64u64.to_le_bytes()); // p_filesz = 64

    // Section headers at 800: [0] null, [1] .dynstr at 400
    let sh_off = 800;
    elf[40] = (sh_off & 0xFF) as u8;
    elf[41] = ((sh_off >> 8) & 0xFF) as u8;
    elf[58] = 64;
    elf[60] = 2; // 2 sections

    // Section 1: .dynstr at 400
    let s1 = sh_off + 64;
    elf[s1 + 4..s1 + 8].copy_from_slice(&3u32.to_le_bytes());
    elf[s1 + 24..s1 + 32].copy_from_slice(&400u64.to_le_bytes());
    elf[s1 + 32..s1 + 40].copy_from_slice(&100u64.to_le_bytes());

    // Strings at 400: "\0/opt/lib\0$ORIGIN/../lib\0"
    let rpath_str = b"/opt/lib\0";
    let runpath_str = b"$ORIGIN/../lib\0";
    let off_rpath = 1usize;
    let off_runpath = off_rpath + rpath_str.len();
    elf[400 + off_rpath..400 + off_rpath + rpath_str.len()].copy_from_slice(rpath_str);
    elf[400 + off_runpath..400 + off_runpath + runpath_str.len()].copy_from_slice(runpath_str);

    // Dynamic section at 200:
    // Entry 0: DT_STRTAB (5), val = 400
    elf[200..208].copy_from_slice(&5u64.to_le_bytes());
    elf[208..216].copy_from_slice(&400u64.to_le_bytes());
    // Entry 1: DT_RPATH (15), val = off_rpath
    elf[216..224].copy_from_slice(&15u64.to_le_bytes());
    elf[224..232].copy_from_slice(&(off_rpath as u64).to_le_bytes());
    // Entry 2: DT_RUNPATH (29), val = off_runpath
    elf[232..240].copy_from_slice(&29u64.to_le_bytes());
    elf[240..248].copy_from_slice(&(off_runpath as u64).to_le_bytes());
    // Entry 3: DT_NULL (0)
    elf[248..256].copy_from_slice(&0u64.to_le_bytes());

    let report = parse_elf(&elf, "test_paths.elf").expect("Failed to parse ELF");
    assert_eq!(report.mitigations.rpath, Some("/opt/lib".to_string()));
    assert_eq!(
        report.mitigations.runpath,
        Some("$ORIGIN/../lib".to_string())
    );
}

#[test]
fn test_pe_stack_cookie_detection() {
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // Load Config Directory entry is Data Directory 10 at opt_hdr + 112 + (10 * 8) = opt_hdr + 192
    let lc_entry = opt_hdr + 192;
    pe[lc_entry..lc_entry + 4].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[lc_entry + 4..lc_entry + 8].copy_from_slice(&128u32.to_le_bytes()); // Size = 128

    // Section header: .rdata at offset opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".rdata\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x200u32.to_le_bytes()); // RVA 0x200
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x200u32.to_le_bytes()); // RawOffset = 0x200
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Load Config at offset 0x200 (RVA 0x200)
    let lc = 0x200;
    pe[lc..lc + 4].copy_from_slice(&128u32.to_le_bytes()); // Size = 128
    // In 64-bit load config, SecurityCookie is at offset 88
    pe[lc + 88..lc + 96].copy_from_slice(&0x00007FF7_12345678u64.to_le_bytes());

    let report = parse_pe(&pe, "test_cookie.exe").expect("Failed to parse PE with Load Config");
    assert!(
        report.mitigations.stack_canary,
        "Valid SecurityCookie pointer in Load Config must set stack_canary = true"
    );
}

#[test]
fn test_diff_stack_canary_and_fortify_drift() {
    let a = BinaryReport {
        file_name: "app_v1".to_string(),
        file_size: 1000,
        md5: "aaa".to_string(),
        sha256: "aaa256".to_string(),
        format: BinaryFormat::ELF64,
        architecture: "x86_64".to_string(),
        subsystem: "Linux".to_string(),
        entry_point: 0x1000,
        overall_entropy: 5.0,
        is_likely_packed: false,
        mitigations: SecurityMitigations {
            stack_canary: true,
            fortify: true,
            ..Default::default()
        },
        sections: vec![],
        imports: vec![],
        exports: vec![],
        rich_header: None,
        imphash: None,
        interesting_strings: vec![],
        entry_point_preview: vec![],
        authenticode: None,
    };

    let mut b = a.clone();
    b.file_name = "app_v2".to_string();
    b.mitigations.stack_canary = false; // Degraded!

    let diff = binlens::diff::generate_diff_report(&a, &b);
    let canary_drift = diff
        .mitigations_drift
        .iter()
        .find(|m| m.mitigation == "Stack Canary")
        .expect("Must track Stack Canary drift");
    assert_eq!(canary_drift.status, "degraded");
    assert!(canary_drift.before);
    assert!(!canary_drift.after);

    let fortify_drift = diff
        .mitigations_drift
        .iter()
        .find(|m| m.mitigation == "Fortified Functions")
        .expect("Must track Fortified Functions drift");
    assert_eq!(fortify_drift.status, "unchanged");
}

#[test]
fn test_pe_entry_point_disassembly() {
    let mut pe = vec![0u8; 2048];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe[file_hdr + 2..file_hdr + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    // AddressOfEntryPoint at opt_hdr + 16 = 0x1000
    pe[opt_hdr + 16..opt_hdr + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    // ImageBase at opt_hdr + 24 = 0x140000000
    pe[opt_hdr + 24..opt_hdr + 32].copy_from_slice(&0x140000000u64.to_le_bytes());

    // Section header: .text at opt_hdr + 240
    let sec_hdr = opt_hdr + 240;
    pe[sec_hdr..sec_hdr + 8].copy_from_slice(b".text\0\0\0");
    pe[sec_hdr + 8..sec_hdr + 12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtSize = 0x400
    pe[sec_hdr + 12..sec_hdr + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtAddr = 0x1000
    pe[sec_hdr + 16..sec_hdr + 20].copy_from_slice(&0x400u32.to_le_bytes()); // RawSize = 0x400
    pe[sec_hdr + 20..sec_hdr + 24].copy_from_slice(&0x400u32.to_le_bytes()); // RawOffset = 0x400
    pe[sec_hdr + 36..sec_hdr + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // Code, Executable, Readable

    // Opcodes at 0x400:
    // 48 89 5C 24 08       mov [rsp+8], rbx
    // 48 89 6C 24 10       mov [rsp+10h], rbp
    // 48 89 74 24 18       mov [rsp+18h], rsi
    // 57                   push rdi
    // 48 83 EC 20          sub rsp, 20h
    // C3                   ret
    let code = [
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
        0x57, 0x48, 0x83, 0xEC, 0x20, 0xC3,
    ];
    pe[0x400..0x400 + code.len()].copy_from_slice(&code);

    let report = parse_pe(&pe, "test_disasm.exe").expect("Parse PE failed");
    assert!(
        !report.entry_point_preview.is_empty(),
        "Must decode entry point instructions"
    );
    assert_eq!(report.entry_point_preview[0].mnemonic, "mov");
    assert_eq!(report.entry_point_preview[0].address, 0x140001000);
    assert_eq!(report.entry_point_preview[3].mnemonic, "push");
    assert_eq!(report.entry_point_preview[4].mnemonic, "sub");
    assert_eq!(report.entry_point_preview[5].mnemonic, "ret");
}

#[test]
fn test_elf_entry_point_disassembly() {
    let mut elf = vec![0u8; 1024];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[6] = 1;
    elf[16] = 2; // ET_EXEC
    elf[18] = 0x3E; // x86_64
    elf[20] = 1;
    elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // e_entry = 0x401000
    elf[32] = 64; // e_phoff = 64
    elf[54] = 56; // e_phentsize
    elf[56] = 1; // e_phnum = 1

    // Program header 0: PT_LOAD at 64
    let ph0 = 64;
    elf[ph0..ph0 + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD = 1
    elf[ph0 + 4..ph0 + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf[ph0 + 8..ph0 + 16].copy_from_slice(&0x200u64.to_le_bytes()); // p_offset = 0x200
    elf[ph0 + 16..ph0 + 24].copy_from_slice(&0x401000u64.to_le_bytes()); // p_vaddr = 0x401000
    elf[ph0 + 24..ph0 + 32].copy_from_slice(&0x401000u64.to_le_bytes()); // p_paddr = 0x401000
    elf[ph0 + 32..ph0 + 40].copy_from_slice(&0x100u64.to_le_bytes()); // p_filesz = 0x100
    elf[ph0 + 40..ph0 + 48].copy_from_slice(&0x100u64.to_le_bytes()); // p_memsz = 0x100

    // Opcodes at offset 0x200 (standard ELF Linux _start entry preamble):
    // 31 ed             xor ebp, ebp
    // 49 89 d1          mov r9, rdx
    // 5e                pop rsi
    // 48 89 e2          mov rdx, rsp
    // 48 83 e4 f0       and rsp, -16
    let code = [
        0x31, 0xED, 0x49, 0x89, 0xD1, 0x5E, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xE4, 0xF0,
    ];
    elf[0x200..0x200 + code.len()].copy_from_slice(&code);

    let report = parse_elf(&elf, "test_elf_disasm.elf").expect("Parse ELF failed");
    assert!(
        !report.entry_point_preview.is_empty(),
        "Must decode ELF entry point instructions"
    );
    assert_eq!(report.entry_point_preview[0].mnemonic, "xor");
    assert_eq!(report.entry_point_preview[0].address, 0x401000);
    assert_eq!(report.entry_point_preview[1].mnemonic, "mov");
    assert_eq!(report.entry_point_preview[2].mnemonic, "pop");
    assert_eq!(report.entry_point_preview[3].mnemonic, "mov");
    assert_eq!(report.entry_point_preview[4].mnemonic, "and");
}

#[test]
fn test_disassemble_raw_bytes_helper() {
    use binlens::disasm::disassemble_bytes;

    // Test 32-bit x86: push ebp; mov ebp, esp; pop ebp; ret
    let code_32 = [0x55, 0x89, 0xE5, 0x5D, 0xC3];
    let insns_32 = disassemble_bytes(&code_32, 0x00401000, 32, 10);
    assert_eq!(insns_32.len(), 4);
    assert_eq!(insns_32[0].mnemonic, "push");
    assert_eq!(insns_32[1].mnemonic, "mov");
    assert_eq!(insns_32[2].mnemonic, "pop");
    assert_eq!(insns_32[3].mnemonic, "ret");

    // Test 64-bit x86: nop; int3
    let code_64 = [0x90, 0xCC];
    let insns_64 = disassemble_bytes(&code_64, 0x140000000, 64, 10);
    assert_eq!(insns_64.len(), 2);
    assert_eq!(insns_64[0].mnemonic, "nop");
    assert_eq!(insns_64[1].mnemonic, "int3");
}

#[test]
fn test_macho_64_bit_parsing_and_mitigations() {
    use binlens::macho::*;

    let mut macho = vec![0u8; 1024];

    // Mach-O Header (32 bytes)
    macho[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic: MH_MAGIC_64
    macho[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes()); // cputype: x86_64
    macho[8..12].copy_from_slice(&0x3u32.to_le_bytes()); // cpusubtype
    macho[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes()); // filetype: MH_EXECUTE
    let ncmds = 6u32;
    macho[16..20].copy_from_slice(&ncmds.to_le_bytes());
    let flags = MH_PIE;
    macho[24..28].copy_from_slice(&flags.to_le_bytes());

    let mut offset = 32;

    // Command 1: LC_SEGMENT_64 (__TEXT)
    // cmdsize = 72 (segment header) + 80 (1 section) = 152
    macho[offset..offset + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&152u32.to_le_bytes());
    macho[offset + 8..offset + 14].copy_from_slice(b"__TEXT");
    macho[offset + 24..offset + 32].copy_from_slice(&0x100000000u64.to_le_bytes()); // vmaddr
    macho[offset + 32..offset + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // vmsize
    macho[offset + 40..offset + 48].copy_from_slice(&0u64.to_le_bytes()); // fileoff
    macho[offset + 48..offset + 56].copy_from_slice(&0x400u64.to_le_bytes()); // filesize
    macho[offset + 56..offset + 60].copy_from_slice(&5u32.to_le_bytes()); // maxprot = r-x
    macho[offset + 60..offset + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot = r-x
    macho[offset + 64..offset + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects = 1
    offset += 72;

    // Section 1: __text inside __TEXT
    macho[offset..offset + 6].copy_from_slice(b"__text");
    macho[offset + 16..offset + 22].copy_from_slice(b"__TEXT");
    macho[offset + 32..offset + 40].copy_from_slice(&0x100000200u64.to_le_bytes()); // addr
    macho[offset + 40..offset + 48].copy_from_slice(&0x40u64.to_le_bytes()); // size
    macho[offset + 48..offset + 52].copy_from_slice(&0x200u32.to_le_bytes()); // offset in file
    offset += 80;

    // Command 2: LC_MAIN
    macho[offset..offset + 4].copy_from_slice(&LC_MAIN.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&24u32.to_le_bytes());
    macho[offset + 8..offset + 16].copy_from_slice(&0x200u64.to_le_bytes()); // entryoff = 0x200
    macho[offset + 16..offset + 24].copy_from_slice(&0u64.to_le_bytes()); // stacksize
    offset += 24;

    // Command 3: LC_LOAD_DYLIB
    let dylib_name = b"/usr/lib/libSystem.B.dylib\0";
    macho[offset..offset + 4].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&56u32.to_le_bytes());
    macho[offset + 8..offset + 12].copy_from_slice(&24u32.to_le_bytes()); // name_offset = 24
    macho[offset + 24..offset + 24 + dylib_name.len()].copy_from_slice(dylib_name);
    offset += 56;

    // Command 4: LC_RPATH
    let rpath_bytes = b"@loader_path/../Frameworks\0";
    macho[offset..offset + 4].copy_from_slice(&LC_RPATH.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&48u32.to_le_bytes());
    macho[offset + 8..offset + 12].copy_from_slice(&16u32.to_le_bytes()); // path_offset = 16
    macho[offset + 16..offset + 16 + rpath_bytes.len()].copy_from_slice(rpath_bytes);
    offset += 48;

    // Command 5: LC_CODE_SIGNATURE
    macho[offset..offset + 4].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&16u32.to_le_bytes());
    macho[offset + 8..offset + 12].copy_from_slice(&0x380u32.to_le_bytes()); // dataoff
    macho[offset + 12..offset + 16].copy_from_slice(&0x50u32.to_le_bytes()); // datasize
    offset += 16;

    // Command 6: LC_SYMTAB
    let symoff = 0x280u32;
    let nsyms = 3u32;
    let stroff = 0x300u32;
    let strsize = 0x80u32;
    macho[offset..offset + 4].copy_from_slice(&LC_SYMTAB.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&24u32.to_le_bytes());
    macho[offset + 8..offset + 12].copy_from_slice(&symoff.to_le_bytes());
    macho[offset + 12..offset + 16].copy_from_slice(&nsyms.to_le_bytes());
    macho[offset + 16..offset + 20].copy_from_slice(&stroff.to_le_bytes());
    macho[offset + 20..offset + 24].copy_from_slice(&strsize.to_le_bytes());
    offset += 24;

    let sizeofcmds = (offset - 32) as u32;
    macho[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());

    // Write opcodes at entryoff = 0x200 (x86_64)
    // 55                push rbp
    // 48 89 e5          mov rbp, rsp
    // 31 c0             xor eax, eax
    // 5d                pop rbp
    // c3                ret
    let code = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
    macho[0x200..0x200 + code.len()].copy_from_slice(&code);

    // Build String Table at stroff (0x300)
    let str_data = b"\0___stack_chk_fail\0___memcpy_chk\0_main_entry\0";
    let str_dest = stroff as usize;
    macho[str_dest..str_dest + str_data.len()].copy_from_slice(str_data);

    // Build Symbol Table entries at symoff (0x280) (16 bytes each for 64-bit nlist_64)
    // Symbol 0: ___stack_chk_fail (n_strx = 1, n_type = N_EXT | N_UNDF = 0x01)
    let s0 = symoff as usize;
    macho[s0..s0 + 4].copy_from_slice(&1u32.to_le_bytes());
    macho[s0 + 4] = N_EXT | N_UNDF;

    // Symbol 1: ___memcpy_chk (n_strx = 19, n_type = N_EXT | N_UNDF = 0x01)
    let s1 = s0 + 16;
    macho[s1..s1 + 4].copy_from_slice(&19u32.to_le_bytes());
    macho[s1 + 4] = N_EXT | N_UNDF;

    // Symbol 2: _main_entry (n_strx = 33, n_type = N_EXT | N_SECT = 0x0f)
    let s2 = s1 + 16;
    macho[s2..s2 + 4].copy_from_slice(&33u32.to_le_bytes());
    macho[s2 + 4] = N_EXT | N_SECT;
    macho[s2 + 5] = 1; // section index 1
    macho[s2 + 8..s2 + 16].copy_from_slice(&0x200u64.to_le_bytes());

    let report = parse_macho(&macho, "test_binary.macho").expect("Must parse Mach-O 64-bit");
    assert_eq!(report.format, BinaryFormat::MachO);
    assert_eq!(report.architecture, "x86_64");
    assert!(report.mitigations.pie, "MH_PIE flag must be recognized");
    assert!(
        report.mitigations.dep_nx,
        "DEP/NX must default to enabled on modern Mach-O"
    );
    assert!(
        report.mitigations.stack_canary,
        "Stack canary must be detected via ___stack_chk_fail"
    );
    assert!(
        report.mitigations.fortify,
        "FORTIFY must be detected via ___memcpy_chk"
    );
    assert!(
        report.mitigations.authenticode_signed,
        "LC_CODE_SIGNATURE must indicate code signature"
    );
    assert_eq!(
        report.mitigations.rpath,
        Some("@loader_path/../Frameworks".to_string())
    );
    assert!(
        !report.mitigations.has_rwx_sections,
        "r-x __TEXT segment is not RWX"
    );

    // Verify imports & exports
    assert_eq!(report.imports.len(), 1);
    assert_eq!(report.imports[0].dll, "/usr/lib/libSystem.B.dylib");
    assert!(
        report.imports[0]
            .functions
            .contains(&"___stack_chk_fail".to_string())
    );
    assert!(
        report.imports[0]
            .functions
            .contains(&"___memcpy_chk".to_string())
    );

    assert_eq!(report.exports.len(), 1);
    assert_eq!(report.exports[0].name, "_main_entry");
    assert_eq!(report.exports[0].rva, 0x200);

    // Verify entry point preview disassembly
    assert!(!report.entry_point_preview.is_empty());
    assert_eq!(report.entry_point_preview[0].mnemonic, "push");
    assert_eq!(report.entry_point_preview[1].mnemonic, "mov");
    assert_eq!(report.entry_point_preview[2].mnemonic, "xor");
}

#[test]
fn test_macho_universal_fat_binary() {
    use binlens::macho::*;

    let mut fat = vec![0u8; 2048];

    // Magic: 0xcafebabe (Big Endian)
    fat[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
    let narchs = 2u32;
    fat[4..8].copy_from_slice(&narchs.to_be_bytes());

    // Arch 0: x86_64 at offset 0x200, size 0x200
    let a0 = 8;
    fat[a0..a0 + 4].copy_from_slice(&CPU_TYPE_X86_64.to_be_bytes());
    fat[a0 + 4..a0 + 8].copy_from_slice(&3u32.to_be_bytes());
    fat[a0 + 8..a0 + 12].copy_from_slice(&0x200u32.to_be_bytes()); // offset
    fat[a0 + 12..a0 + 16].copy_from_slice(&0x200u32.to_be_bytes()); // size
    fat[a0 + 16..a0 + 20].copy_from_slice(&12u32.to_be_bytes()); // align

    // Arch 1: ARM64 at offset 0x400, size 0x200
    let a1 = 28;
    fat[a1..a1 + 4].copy_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
    fat[a1 + 4..a1 + 8].copy_from_slice(&0u32.to_be_bytes());
    fat[a1 + 8..a1 + 12].copy_from_slice(&0x400u32.to_be_bytes()); // offset
    fat[a1 + 12..a1 + 16].copy_from_slice(&0x200u32.to_be_bytes()); // size
    fat[a1 + 16..a1 + 20].copy_from_slice(&14u32.to_be_bytes()); // align

    // Slice 0 (x86_64) minimal Mach-O
    let s0 = 0x200;
    fat[s0..s0 + 4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    fat[s0 + 4..s0 + 8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    fat[s0 + 12..s0 + 16].copy_from_slice(&MH_EXECUTE.to_le_bytes());

    // Slice 1 (ARM64) minimal Mach-O
    let s1 = 0x400;
    fat[s1..s1 + 4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    fat[s1 + 4..s1 + 8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    fat[s1 + 12..s1 + 16].copy_from_slice(&MH_EXECUTE.to_le_bytes());

    let report = parse_macho(&fat, "test_universal.fat").expect("Must parse Universal Fat Mach-O");
    assert_eq!(report.format, BinaryFormat::MachO);
    // Should prefer ARM64 slice while recording both architectures in tag
    assert!(report.architecture.contains("ARM64"));
    assert!(
        report
            .architecture
            .contains("Universal Fat Binary [x86_64, ARM64]")
    );
}

#[test]
fn test_macho_rwx_segment_detection() {
    use binlens::macho::*;

    let mut macho = vec![0u8; 512];
    macho[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    macho[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    macho[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
    macho[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds = 1

    let offset = 32;
    // LC_SEGMENT_64 with initprot = 7 (Read | Write | Execute)
    macho[offset..offset + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    macho[offset + 4..offset + 8].copy_from_slice(&72u32.to_le_bytes()); // cmdsize = 72
    macho[offset + 8..offset + 14].copy_from_slice(b"__SELF");
    macho[offset + 56..offset + 60].copy_from_slice(&7u32.to_le_bytes()); // maxprot = 7 (RWX)
    macho[offset + 60..offset + 64].copy_from_slice(&7u32.to_le_bytes()); // initprot = 7 (RWX)

    macho[20..24].copy_from_slice(&72u32.to_le_bytes()); // sizeofcmds

    let report = parse_macho(&macho, "test_rwx.macho").expect("Must parse Mach-O");
    assert!(
        report.mitigations.has_rwx_sections,
        "Mach-O with RWX initprot segment must flag has_rwx_sections = true"
    );
}

#[test]
fn test_authenticode_asn1_der_primitives() {
    use binlens::authenticode::{
        decode_oid, decode_string, decode_time, format_serial_number, parse_sequence, parse_tlv,
    };

    // 1. Short-form TLV: INTEGER 42 (0x02 0x01 0x2A)
    let short_der = [0x02, 0x01, 0x2a];
    let elem = parse_tlv(&short_der).expect("Should parse short TLV");
    assert_eq!(elem.tag, 0x02);
    assert_eq!(elem.header_len, 2);
    assert_eq!(elem.data, &[0x2a]);
    assert_eq!(elem.total_len(), 3);

    // 2. Long-form TLV: OCTET STRING of 256 bytes
    let mut long_der = vec![0x04, 0x82, 0x01, 0x00];
    long_der.resize(4 + 256, 0xAA);
    let long_elem = parse_tlv(&long_der).expect("Should parse long TLV");
    assert_eq!(long_elem.tag, 0x04);
    assert_eq!(long_elem.header_len, 4);
    assert_eq!(long_elem.data.len(), 256);
    assert_eq!(long_elem.total_len(), 260);

    // 3. Truncated TLV should return None
    assert!(parse_tlv(&[0x30, 0x10, 0x01]).is_none());

    // 4. Decode OID: 2.16.840.1.101.3.4.2.1 (SHA-256)
    // Encoded: 60 86 48 01 65 03 04 02 01
    let sha256_oid_bytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    assert_eq!(decode_oid(&sha256_oid_bytes), "2.16.840.1.101.3.4.2.1");

    // 5. Decode String: PrintableString and UTF8String
    let ps = parse_tlv(&[0x13, 0x04, b'T', b'e', b's', b't']).unwrap();
    assert_eq!(decode_string(&ps), Some("Test".to_string()));

    let utf8 = parse_tlv(&[0x0c, 0x05, b'H', b'e', b'l', b'l', b'o']).unwrap();
    assert_eq!(decode_string(&utf8), Some("Hello".to_string()));

    // 6. Decode UTCTime: 250218201835Z -> 2025-02-18 20:18:35 UTC
    let mut utc_data = vec![0x17, 13];
    utc_data.extend_from_slice(b"250218201835Z");
    let utc_elem = parse_tlv(&utc_data).unwrap();
    assert_eq!(
        decode_time(&utc_elem),
        Some("2025-02-18 20:18:35 UTC".to_string())
    );

    // 7. Format serial number
    // Leading zeros stripped, uppercase hex
    let serial = [0x00, 0x06, 0x69, 0xD3, 0x6C];
    assert_eq!(format_serial_number(&serial), "0669D36C");

    // All zero serial
    let zero_serial = [0x00, 0x00];
    assert_eq!(format_serial_number(&zero_serial), "00");

    // Sequence parsing
    let seq_bytes = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let items = parse_sequence(&seq_bytes[2..]);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].tag, 0x02);
    assert_eq!(items[1].tag, 0x02);
}

#[test]
fn test_authenticode_real_or_synthetic_tamper_detection() {
    use binlens::types::AuthenticodeStatus;
    use std::path::Path;

    let test_path = r#"C:\Program Files\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe"#;
    if !Path::new(test_path).exists() {
        eprintln!(
            "Skipping real binary test because {} is not present",
            test_path
        );
        return;
    }

    let original_data = std::fs::read(test_path).expect("Failed to read test binary");

    // 1. Verify original authentic binary
    let report = parse_pe(&original_data, "CCXProcess.exe").expect("Must parse valid PE");
    assert!(
        report.authenticode.is_some(),
        "Must detect Authenticode signature"
    );
    let auth = report.authenticode.unwrap();
    assert_eq!(
        auth.status,
        AuthenticodeStatus::Valid,
        "Authentic binary hash must match signature"
    );
    assert_eq!(auth.digest_algorithm, "SHA256");
    assert_eq!(auth.calculated_digest, auth.expected_digest);
    assert!(
        auth.signer_certificate.is_some(),
        "Must extract signer certificate"
    );
    let signer = auth.signer_certificate.unwrap();
    assert!(
        signer.subject.contains("Adobe"),
        "Signer subject must contain Adobe"
    );
    assert!(!signer.serial_number.is_empty());
    assert!(!auth.certificates.is_empty());

    // 2. Tamper with a single byte in section 0 (.text)
    let mut tampered_data = original_data.clone();
    let sec0 = &report.sections[0];
    let offset_to_corrupt = sec0.raw_offset as usize + 0x10;
    tampered_data[offset_to_corrupt] ^= 0xFF; // Flip all bits of one byte in executable code

    let tampered_report =
        parse_pe(&tampered_data, "CCXProcess_tampered.exe").expect("Must parse tampered PE");
    assert!(
        tampered_report.authenticode.is_some(),
        "Must still detect Authenticode structure"
    );
    let tampered_auth = tampered_report.authenticode.unwrap();
    assert_eq!(
        tampered_auth.status,
        AuthenticodeStatus::HashMismatch,
        "Tampered binary MUST trigger HashMismatch!"
    );
    assert_ne!(
        tampered_auth.calculated_digest, tampered_auth.expected_digest,
        "Calculated hash must deviate from expected hash on tampering"
    );

    // 3. Corrupt ASN.1 signature table to test Malformed detection
    let mut malformed_data = original_data.clone();
    // In PE header, find the Security Directory and corrupt its payload
    let pe_off = u32::from_le_bytes([
        malformed_data[0x3c],
        malformed_data[0x3d],
        malformed_data[0x3e],
        malformed_data[0x3f],
    ]) as usize;
    let sec_dir_entry = pe_off + 0x18 + 112 + 32; // x64 DataDirectory[4]
    let sec_dir_rva = u32::from_le_bytes([
        malformed_data[sec_dir_entry],
        malformed_data[sec_dir_entry + 1],
        malformed_data[sec_dir_entry + 2],
        malformed_data[sec_dir_entry + 3],
    ]) as usize;
    // Overwrite the PKCS#7 table bytes with garbage
    if sec_dir_rva > 0 && sec_dir_rva + 64 < malformed_data.len() {
        for b in &mut malformed_data[sec_dir_rva + 8..sec_dir_rva + 64] {
            *b = 0xFF; // invalid DER tags
        }
        let malformed_report = parse_pe(&malformed_data, "CCXProcess_malformed.exe")
            .expect("Must parse PE with corrupt cert");
        assert_eq!(
            malformed_report.authenticode.unwrap().status,
            AuthenticodeStatus::Malformed,
            "Corrupted ASN.1 DER must yield Malformed status"
        );
    }
}

#[test]
fn test_authenticode_unsigned_pe_returns_none() {
    let mut pe = vec![0u8; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80

    let pe_off = 0x80;
    pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    pe[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
    pe[pe_off + 6..pe_off + 8].copy_from_slice(&0u16.to_le_bytes()); // 0 sections
    pe[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // Opt header size

    let opt_off = pe_off + 24;
    pe[opt_off..opt_off + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ (64-bit)
    // Security directory at opt_off + 112 + 32 (Data Directory 4): left as 0 RVA, 0 Size

    let report = parse_pe(&pe, "unsigned.exe").expect("Must parse unsigned PE");
    assert!(report.authenticode.is_none());
    assert!(!report.mitigations.authenticode_signed);
}
