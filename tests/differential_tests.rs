use binlens::pe::parse_pe;
use std::process::Command;

#[test]
fn test_differential_with_pefile_on_system32_cmd() {
    let target = r"C:\Windows\System32\cmd.exe";
    if !std::path::Path::new(target).exists() {
        eprintln!("Skipping test: {} does not exist", target);
        return;
    }

    let data = std::fs::read(target).expect("Failed to read cmd.exe");
    let report = parse_pe(&data, "cmd.exe").expect("binlens failed to parse cmd.exe");

    // Query pefile for ground truth
    let py_script = r#"
import pefile
import json
import sys

pe = pefile.PE(sys.argv[1])
result = {
    "imphash": pe.get_imphash(),
    "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    "sections_count": len(pe.sections),
    "sections": [{"name": s.Name.decode('utf-8', errors='ignore').rstrip('\x00'), "raw_size": s.SizeOfRawData} for s in pe.sections]
}
print(json.dumps(result))
"#;

    let output = Command::new("python")
        .args(["-c", py_script, target])
        .output()
        .expect("Failed to execute python with pefile");

    assert!(
        output.status.success(),
        "Python pefile execution failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pefile_data: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse JSON from pefile");

    // Compare Imphash
    let pefile_imphash = pefile_data["imphash"].as_str().unwrap();
    assert_eq!(
        report.imphash.as_deref(),
        Some(pefile_imphash),
        "Imphash differential mismatch on cmd.exe!"
    );

    // Compare EntryPoint
    let pefile_entry = pefile_data["entry_point"].as_u64().unwrap();
    assert_eq!(
        report.entry_point, pefile_entry,
        "Entry point mismatch on cmd.exe!"
    );

    // Compare Section Count
    let pefile_sec_count = pefile_data["sections_count"].as_u64().unwrap() as usize;
    assert_eq!(
        report.sections.len(),
        pefile_sec_count,
        "Section count mismatch on cmd.exe!"
    );

    // Compare Section Names & Sizes
    let pefile_sections = pefile_data["sections"].as_array().unwrap();
    for (i, s) in pefile_sections.iter().enumerate() {
        let expected_name = s["name"].as_str().unwrap();
        let expected_size = s["raw_size"].as_u64().unwrap();
        assert_eq!(report.sections[i].name, expected_name);
        assert_eq!(report.sections[i].raw_size, expected_size);
    }
}

#[test]
fn test_differential_exports_with_pefile_on_kernel32() {
    let target = r"C:\Windows\System32\kernel32.dll";
    if !std::path::Path::new(target).exists() {
        eprintln!("Skipping test: {} does not exist", target);
        return;
    }

    let data = std::fs::read(target).expect("Failed to read kernel32.dll");
    let report = parse_pe(&data, "kernel32.dll").expect("binlens failed to parse kernel32.dll");

    let py_script = r#"
import pefile
import json
import sys

pe = pefile.PE(sys.argv[1])
exports = []
total_count = 0
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    total_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:50]:
        name = exp.name.decode('utf-8') if exp.name else f"Ordinal#{exp.ordinal}"
        exports.append({"name": name, "ordinal": exp.ordinal, "rva": exp.address})
print(json.dumps({"total": total_count, "sample": exports}))
"#;

    let output = Command::new("python")
        .args(["-c", py_script, target])
        .output()
        .expect("Failed to execute python with pefile");

    assert!(output.status.success(), "Python pefile execution failed");
    let pefile_data: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse JSON");
    let total_exports = pefile_data["total"].as_u64().unwrap() as usize;
    let pefile_exports = pefile_data["sample"].as_array().unwrap();

    assert!(
        total_exports > 1000,
        "kernel32 should have over 1000 exports, got {}",
        total_exports
    );
    assert_eq!(
        report.exports.len(),
        total_exports,
        "All exports should be parsed without artificial 256 truncation"
    );

    for (i, exp) in pefile_exports.iter().enumerate() {
        let expected_name = exp["name"].as_str().unwrap();
        let expected_ord = exp["ordinal"].as_u64().unwrap() as u32;
        let expected_rva = exp["rva"].as_u64().unwrap() as u32;

        let bl_exp = &report.exports[i];
        assert_eq!(
            bl_exp.name, expected_name,
            "Export name mismatch at index {}",
            i
        );
        assert_eq!(
            bl_exp.ordinal, expected_ord,
            "Export ordinal mismatch at index {}",
            i
        );
        assert_eq!(
            bl_exp.rva, expected_rva,
            "Export RVA mismatch at index {}",
            i
        );
    }
}

#[test]
fn test_differential_cfg_with_pefile() {
    let targets = [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\FileHistory.exe",
        r"C:\Windows\System32\kernel32.dll",
    ];

    let py_script = r#"
import pefile
import json
import sys

results = {}
for path in sys.argv[1:]:
    try:
        pe = pefile.PE(path)
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        has_guard_flag = bool(dll_chars & 0x4000)
        has_lc = hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG')
        guard_ptr = getattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'GuardCFCheckFunctionPointer', 0) if has_lc else 0
        cfg_active = has_guard_flag and (guard_ptr != 0)
        results[path] = {
            "guard_flag": has_guard_flag,
            "has_load_config": has_lc,
            "guard_check_ptr": guard_ptr,
            "cfg": cfg_active
        }
    except Exception as e:
        results[path] = {"error": str(e)}

print(json.dumps(results))
"#;

    let existing_targets: Vec<&str> = targets
        .iter()
        .copied()
        .filter(|t| std::path::Path::new(t).exists())
        .collect();

    if existing_targets.is_empty() {
        eprintln!("Skipping test: no Windows target binaries found");
        return;
    }

    let mut cmd_args = vec!["-c", py_script];
    cmd_args.extend(existing_targets.iter());

    let output = Command::new("python")
        .args(&cmd_args)
        .output()
        .expect("Failed to execute python with pefile");

    assert!(
        output.status.success(),
        "Python execution failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ground_truth: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse JSON");

    for target in &existing_targets {
        let data = std::fs::read(target).expect("Failed to read binary");
        let file_name = std::path::Path::new(target)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let report = parse_pe(&data, file_name).expect("Failed to parse PE with binlens");

        let expected_cfg = ground_truth[*target]["cfg"]
            .as_bool()
            .expect("Missing cfg in python output");
        assert_eq!(
            report.mitigations.cfg, expected_cfg,
            "Differential CFG mismatch for {}: binlens reported {}, pefile reported {}",
            target, report.mitigations.cfg, expected_cfg
        );
    }
}

#[test]
fn test_differential_rich_header_with_pefile() {
    let target = r"C:\Windows\System32\cmd.exe";
    if !std::path::Path::new(target).exists() {
        return;
    }

    let py_script = r#"
import pefile
import json
import sys

pe = pefile.PE(sys.argv[1])
result = {}
if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
    result = {
        "has_rich": True,
        "checksum": pe.RICH_HEADER.checksum,
        "num_values": len(pe.RICH_HEADER.values) // 2
    }
else:
    result = {"has_rich": False}

print(json.dumps(result))
"#;

    let output = Command::new("python")
        .args(["-c", py_script, target])
        .output()
        .expect("Failed to execute python with pefile");

    assert!(output.status.success());
    let ground_truth: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse JSON");

    let data = std::fs::read(target).expect("Failed to read binary");
    let report = parse_pe(&data, "cmd.exe").expect("Failed to parse PE with binlens");

    if ground_truth["has_rich"].as_bool().unwrap() {
        let rich = report
            .rich_header
            .expect("binlens should detect Rich Header on cmd.exe");
        let expected_key = ground_truth["checksum"].as_u64().unwrap() as u32;
        let expected_count = ground_truth["num_values"].as_u64().unwrap() as usize;

        assert_eq!(
            rich.xor_key, expected_key,
            "Rich XOR key mismatch with pefile"
        );
        assert_eq!(
            rich.entries.len(),
            expected_count,
            "Rich entry count mismatch with pefile"
        );
    }
}

#[test]
fn test_differential_synthetic_pe_cross_platform() {
    // Generate a valid 64-bit PE image in memory
    let mut pe_data = vec![0u8; 0x1000];
    pe_data[0..2].copy_from_slice(b"MZ");
    pe_data[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    let nt = 64;
    pe_data[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let file_hdr = nt + 4;
    pe_data[file_hdr..file_hdr + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    pe_data[file_hdr + 2..file_hdr + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    pe_data[file_hdr + 16..file_hdr + 18].copy_from_slice(&240u16.to_le_bytes());

    let opt_hdr = file_hdr + 20;
    pe_data[opt_hdr..opt_hdr + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    pe_data[opt_hdr + 16..opt_hdr + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint = 0x1000
    pe_data[opt_hdr + 24..opt_hdr + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase = 0x140000000

    // Section 1: .text at 0x1000
    let sec1 = opt_hdr + 240;
    pe_data[sec1..sec1 + 8].copy_from_slice(b".text\0\0\0");
    pe_data[sec1 + 8..sec1 + 12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtualSize = 0x400
    pe_data[sec1 + 12..sec1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress = 0x1000
    pe_data[sec1 + 16..sec1 + 20].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData = 0x400
    pe_data[sec1 + 20..sec1 + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData = 0x400
    pe_data[sec1 + 36..sec1 + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    // Section 2: .data at 0x2000
    let sec2 = sec1 + 40;
    pe_data[sec2..sec2 + 8].copy_from_slice(b".data\0\0\0");
    pe_data[sec2 + 8..sec2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    pe_data[sec2 + 12..sec2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    pe_data[sec2 + 16..sec2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    pe_data[sec2 + 20..sec2 + 24].copy_from_slice(&0x800u32.to_le_bytes());
    pe_data[sec2 + 36..sec2 + 40].copy_from_slice(&0xC0000040u32.to_le_bytes());

    // Write temp file to pass to python pefile (works on Windows, Linux, and macOS)
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("binlens_synthetic_test.exe");
    std::fs::write(&temp_file, &pe_data).expect("Failed to write temporary test PE binary");

    let report = parse_pe(&pe_data, "binlens_synthetic_test.exe")
        .expect("binlens should successfully parse synthetic PE");

    let py_script = r#"
import pefile
import json
import sys

pe = pefile.PE(sys.argv[1])
result = {
    "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    "sections_count": len(pe.sections),
    "sections": [{"name": s.Name.decode('utf-8', errors='ignore').rstrip('\x00'), "raw_size": s.SizeOfRawData, "va": s.VirtualAddress} for s in pe.sections]
}
print(json.dumps(result))
"#;

    let output = Command::new("python")
        .args(["-c", py_script, temp_file.to_str().unwrap()])
        .output();

    let _ = std::fs::remove_file(&temp_file);

    let output = match output {
        Ok(out) if out.status.success() => out,
        _ => {
            eprintln!("Python or pefile not available, skipping cross-platform test");
            return;
        }
    };

    let pefile_data: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse JSON from pefile");

    // Differential asserts
    assert_eq!(
        report.entry_point,
        pefile_data["entry_point"].as_u64().unwrap(),
        "Cross-platform differential entry point mismatch!"
    );
    assert_eq!(
        report.sections.len(),
        pefile_data["sections_count"].as_u64().unwrap() as usize,
        "Cross-platform differential section count mismatch!"
    );

    let pe_secs = pefile_data["sections"].as_array().unwrap();
    assert_eq!(pe_secs.len(), 2);
    assert_eq!(
        report.sections[0].name,
        pe_secs[0]["name"].as_str().unwrap()
    );
    assert_eq!(
        report.sections[0].raw_size,
        pe_secs[0]["raw_size"].as_u64().unwrap()
    );
    assert_eq!(
        report.sections[0].virtual_address,
        pe_secs[0]["va"].as_u64().unwrap()
    );

    assert_eq!(
        report.sections[1].name,
        pe_secs[1]["name"].as_str().unwrap()
    );
    assert_eq!(
        report.sections[1].raw_size,
        pe_secs[1]["raw_size"].as_u64().unwrap()
    );
    assert_eq!(
        report.sections[1].virtual_address,
        pe_secs[1]["va"].as_u64().unwrap()
    );
}
