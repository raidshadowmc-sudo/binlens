use crate::entropy::{entropy_badge, render_entropy_bar, render_entropy_histogram};
use crate::types::{AuthenticodeStatus, BinaryFormat, BinaryReport};
use colored::*;

pub fn print_banner() {
    println!(
        "{}",
        r#"
 ██████╗ ██╗███╗   ██╗██╗     ███████╗███╗   ██╗███████╗
 ██╔══██╗██║████╗  ██║██║     ██╔════╝████╗  ██║██╔════╝
 ██████╔╝██║██╔██╗ ██║██║     █████╗  ██╔██╗ ██║███████╗
 ██╔══██╗██║██║╚██╗██║██║     ██╔══╝  ██║╚██╗██║╚════██║
 ██████╔╝██║██║ ╚████║███████╗███████╗██║ ╚████║███████║
 ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
 Modern Binary Inspector, Entropy Heatmapper & Security Auditor
"#
        .cyan()
        .bold()
    );
}

pub fn print_report(report: &BinaryReport, blocks: &[f64], show_all: bool) {
    print_banner();

    // 1. File Info Card
    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│ {:<76} │", format!("FILE: {}", report.file_name).bold());
    println!("├──────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ Format:        {:<61} │",
        report.format.to_string().cyan()
    );
    println!("│ Architecture:  {:<61} │", report.architecture);
    println!("│ Subsystem:     {:<61} │", report.subsystem);
    println!(
        "│ File Size:     {:<61} │",
        format!(
            "{} bytes ({:.2} KB)",
            report.file_size,
            report.file_size as f64 / 1024.0
        )
    );
    println!(
        "│ Entry Point:   {:<61} │",
        format!("0x{:X}", report.entry_point).yellow()
    );
    println!("│ MD5:           {:<61} │", report.md5);
    println!("│ SHA256:        {:<61} │", report.sha256);
    if let Some(ref imp) = report.imphash {
        println!("│ Imphash:       {:<61} │", imp.as_str().magenta());
    }
    println!("└──────────────────────────────────────────────────────────────────────────────┘");

    // 2. Entropy Analysis & Heatmap
    println!(
        "\n{}",
        "─── [ ENTROPY ANALYSIS & PACKING HEURISTICS ] ────────────────────────────────".bold()
    );
    println!(
        "  Overall Shannon Entropy: {:0.3} / 8.000  [{}]",
        report.overall_entropy,
        entropy_badge(report.overall_entropy)
    );

    if !blocks.is_empty() {
        println!("\n  Block Entropy Heatmap (Distribution across file offset):");
        let bar = render_entropy_bar(blocks, 64);
        println!("  [{}]", bar);
        println!(
            "  {:^66}",
            "0% ───────────────────────── 50% ──────────────────────── 100%"
        );
        println!(
            "  Legend: {} Zeroes  {} Text/Sparse  {} Code  {} Dense  {} Packed/Encrypted",
            "░".blue().dimmed(),
            "▒".cyan(),
            "█".green(),
            "█".yellow(),
            "█".red().bold()
        );

        println!("\n  Entropy Histogram:");
        for line in render_entropy_histogram(blocks) {
            println!("{}", line);
        }
    }

    // 3. Security Mitigations Audit (Checksec)
    println!(
        "\n{}",
        "─── [ SECURITY MITIGATIONS (CHECKSEC) ] ──────────────────────────────────────".bold()
    );
    print_checksec_table(report);

    // 4. Section Table
    if !report.sections.is_empty() {
        println!(
            "\n{}",
            "─── [ SECTION HEADERS & INTEGRITY ] ──────────────────────────────────────────".bold()
        );
        println!(
            "  ┌────────────┬─────────────┬─────────────┬──────────┬─────────┬──────────────┐"
        );
        println!(
            "  │ Name       │ Virt Size   │ Raw Size    │ Flags    │ Entropy │ Status       │"
        );
        println!(
            "  ├────────────┼─────────────┼─────────────┼──────────┼─────────┼──────────────┤"
        );
        for sec in &report.sections {
            let flags = format!(
                "{}{}{}",
                if sec.readable { "R" } else { "-" },
                if sec.writable { "W" } else { "-" },
                if sec.executable { "X" } else { "-" }
            );
            let status = if sec.is_rwx {
                "RWX HAZARD".red().bold()
            } else if sec.entropy >= 7.2 {
                "HIGH/PACKED".red()
            } else if sec.entropy >= 6.5 {
                "COMPRESSED".yellow()
            } else {
                "NORMAL".green()
            };
            println!(
                "  │ {:<10} │ 0x{:<9X} │ 0x{:<9X} │ {:<8} │ {:>5.2}   │ {:<12} │",
                sec.name.bold(),
                sec.virtual_size,
                sec.raw_size,
                flags,
                sec.entropy,
                status
            );
        }
        println!(
            "  └────────────┴─────────────┴─────────────┴──────────┴─────────┴──────────────┘"
        );
    }

    // 5. Imports summary
    if !report.imports.is_empty() {
        println!(
            "\n{}",
            "─── [ IMPORTS & DEPENDENCIES ] ───────────────────────────────────────────────".bold()
        );
        let total_apis: usize = report.imports.iter().map(|i| i.functions.len()).sum();
        println!(
            "  Total: {} Library/DLL(s), {} Symbol/API(s) resolved",
            report.imports.len(),
            total_apis
        );
        let imp_limit = if show_all { report.imports.len() } else { 8 };
        for imp in report.imports.iter().take(imp_limit) {
            let func_limit = if show_all { imp.functions.len() } else { 3 };
            let sample_funcs = if !imp.functions.is_empty() {
                format!(
                    " : {}",
                    imp.functions
                        .iter()
                        .take(func_limit)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                        + if !show_all && imp.functions.len() > 3 {
                            " ..."
                        } else {
                            ""
                        }
                )
            } else {
                String::new()
            };
            println!(
                "  • {:<25} ({} symbols){}",
                imp.dll.cyan().bold(),
                imp.functions.len(),
                sample_funcs
            );
        }
        if !show_all && report.imports.len() > 8 {
            println!(
                "  ... and {} more dependencies (use --all to dump full import table)",
                report.imports.len() - 8
            );
        }
    }

    // 6. Exports summary
    if !report.exports.is_empty() {
        println!(
            "\n{}",
            "─── [ EXPORTED SYMBOLS ] ─────────────────────────────────────────────────────".bold()
        );
        println!(
            "  Total: {} exported function(s)/symbol(s)",
            report.exports.len()
        );
        let exp_limit = if show_all { report.exports.len() } else { 8 };
        for exp in report.exports.iter().take(exp_limit) {
            println!(
                "  • [Ord {:>3}] 0x{:<8X} : {}",
                exp.ordinal,
                exp.rva,
                exp.name.green().bold()
            );
        }
        if !show_all && report.exports.len() > 8 {
            println!(
                "  ... and {} more exported symbols (use --all to dump full export table)",
                report.exports.len() - 8
            );
        }
    }

    // 7. MSVC Rich Header (Compiler Telemetry)
    if let Some(ref rich) = report.rich_header {
        println!(
            "\n{}",
            "─── [ MSVC RICH HEADER (COMPILER TELEMETRY) ] ───────────────────────────────".bold()
        );
        println!(
            "  Offset: 0x{:X} | XOR Key: 0x{:08X} | Records: {}",
            rich.raw_offset,
            rich.xor_key,
            rich.entries.len()
        );
        println!("  ┌──────────────────────┬─────────────┬───────────┬─────────────────────────┐");
        println!("  │ Tool / Component     │ Build ID    │ Count     │ Identified Version      │");
        println!("  ├──────────────────────┼─────────────┼───────────┼─────────────────────────┤");
        for entry in &rich.entries {
            let msvc_str = entry.msvc_version.as_deref().unwrap_or("-");
            println!(
                "  │ {:<20} │ {:<11} │ {:<9} │ {:<23} │",
                entry.tool_name.cyan(),
                entry.build_id,
                entry.count,
                msvc_str
            );
        }
        println!("  └──────────────────────┴─────────────┴───────────┴─────────────────────────┘");
    }

    // 8. Authenticode Digital Signature & Certificate Chain (PE)
    if report.authenticode.is_some() {
        print_authenticode_section(report);
    }

    // 9. Entry Point Disassembly Preview
    if !report.entry_point_preview.is_empty() {
        println!(
            "\n{}",
            "─── [ ENTRY POINT DISASSEMBLY PREVIEW ] ─────────────────────────────────────".bold()
        );
        println!(
            "  Entry Point: 0x{:X} ({} instructions decoded)",
            report.entry_point,
            report.entry_point_preview.len()
        );
        print_disassembly_table(&report.entry_point_preview);
    }

    // 10. Interesting Indicators & Strings
    if !report.interesting_strings.is_empty() {
        println!(
            "\n{}",
            "─── [ DETECTED SUSPICIOUS INDICATORS & PATTERNS ] ───────────────────────────".bold()
        );
        for item in report.interesting_strings.iter().take(15) {
            let cat_badge = match item.category.as_str() {
                "URL" => "[URL]".green().bold(),
                "IPv4" => "[IPv4]".yellow().bold(),
                "Registry" => "[REG]".cyan().bold(),
                "Path" => "[PATH]".blue().bold(),
                "Suspicious API/Command" => "[ALERT]".red().bold(),
                _ => "[INFO]".normal(),
            };
            println!("  {} {:<22} : {}", cat_badge, item.category, item.value);
        }
        if report.interesting_strings.len() > 15 {
            println!(
                "  ... and {} more matches found",
                report.interesting_strings.len() - 15
            );
        }
    }

    // 11. YARA Rule Matches
    if let Some(ref yara) = report.yara {
        print_yara_section(yara, show_all);
    }

    println!(
        "\n{}",
        "════════════════════════════════════════════════════════════════════════════════".cyan()
    );
}

pub fn print_disassembly_table(entries: &[crate::types::DisassemblyEntry]) {
    println!(
        "  ┌────────────────────┬─────────────────────────┬────────┬──────────────────────────┐"
    );
    println!(
        "  │ Virtual Address    │ Opcode Bytes            │ Mnem   │ Operands                 │"
    );
    println!(
        "  ├────────────────────┼─────────────────────────┼────────┼──────────────────────────┤"
    );
    for insn in entries {
        let op_fmt = if insn.op_str.len() > 24 {
            format!("{}...", &insn.op_str[..21])
        } else {
            insn.op_str.clone()
        };
        let mnem_colored = match insn.mnemonic.as_str() {
            "jmp" | "call" | "ret" => insn.mnemonic.yellow().bold(),
            "push" | "pop" | "mov" | "lea" => insn.mnemonic.cyan(),
            "xor" | "sub" | "add" | "cmp" | "test" => insn.mnemonic.green(),
            "nop" | "int3" => insn.mnemonic.normal().dimmed(),
            _ => insn.mnemonic.normal(),
        };
        println!(
            "  │ 0x{:<16X} │ {:<23} │ {:<6} │ {:<24} │",
            insn.address, insn.bytes, mnem_colored, op_fmt
        );
    }
    println!(
        "  └────────────────────┴─────────────────────────┴────────┴──────────────────────────┘"
    );
}

fn print_checksec_status_row(name: &str, status_str: ColoredString, desc: &str) {
    let formatted_desc = if desc.len() > 35 {
        format!("{}...", &desc[..32])
    } else {
        desc.to_string()
    };
    println!(
        "  │ {:<22} │ {} │ {:<35} │",
        name, status_str, formatted_desc
    );
}

fn print_checksec_row(name: &str, passed: bool, desc: &str) {
    let status_str = if passed {
        "  PASS ".green().bold()
    } else {
        "  FAIL ".red().bold()
    };
    print_checksec_status_row(name, status_str, desc);
}

fn print_checksec_table(report: &BinaryReport) {
    println!("  ┌────────────────────────┬───────────┬─────────────────────────────────────┐");
    println!("  │ Mitigation             │ Status    │ Details                             │");
    println!("  ├────────────────────────┼───────────┼─────────────────────────────────────┤");
    print_checksec_row(
        "ASLR / PIE",
        report.mitigations.aslr,
        "Address Space Layout Randomization",
    );
    if report.format == BinaryFormat::PE64 {
        print_checksec_row(
            "High Entropy VA",
            report.mitigations.high_entropy_va,
            "64-bit ASLR address pool expansion",
        );
    }
    print_checksec_row(
        "DEP / NX",
        report.mitigations.dep_nx,
        "Data Execution Prevention / No-Execute",
    );
    if report.format == BinaryFormat::PE32 {
        print_checksec_row(
            "SafeSEH",
            report.mitigations.seh,
            "Structured Exception Handler table",
        );
    }
    if report.format == BinaryFormat::ELF32 || report.format == BinaryFormat::ELF64 {
        let relro_full = report.mitigations.relro == "Full";
        let relro_desc = format!("RELRO: {}", report.mitigations.relro);
        print_checksec_row("RELRO", relro_full, &relro_desc);
        print_checksec_row(
            "Stack Canary",
            report.mitigations.stack_canary,
            "Stack smash protector (__stack_chk)",
        );
        print_checksec_row(
            "FORTIFY_SOURCE",
            report.mitigations.fortify,
            "Fortified glibc functions (__*_chk)",
        );
        let rpath_desc = match (&report.mitigations.rpath, &report.mitigations.runpath) {
            (Some(rp), Some(run)) => format!("RPATH={}, RUNPATH={}", rp, run),
            (Some(rp), None) => format!("RPATH={}", rp),
            (None, Some(run)) => format!("RUNPATH={}", run),
            (None, None) => "No insecure runpaths configured".to_string(),
        };
        let rpath_safe = report.mitigations.rpath.is_none();
        print_checksec_row("RPATH / RUNPATH", rpath_safe, &rpath_desc);
    } else if report.format == BinaryFormat::MachO {
        print_checksec_row(
            "Stack Canary",
            report.mitigations.stack_canary,
            "Stack smash protector (___stack_chk)",
        );
        print_checksec_row(
            "FORTIFY_SOURCE",
            report.mitigations.fortify,
            "Fortified libc functions (___*_chk)",
        );
        let rpath_desc = match &report.mitigations.rpath {
            Some(rp) => format!("RPATH={}", rp),
            None => "No runtime search paths configured".to_string(),
        };
        print_checksec_row("RPATH", true, &rpath_desc);
        print_checksec_row(
            "Code Signature",
            report.mitigations.authenticode_signed,
            "Apple LC_CODE_SIGNATURE slice",
        );
    } else {
        print_checksec_row(
            "Stack Cookie (/GS)",
            report.mitigations.stack_canary,
            "Buffer security check cookie",
        );
        print_checksec_row(
            "Control Flow Guard (CFG)",
            report.mitigations.cfg,
            "Indirect call target validation",
        );
        if let Some(ref auth) = report.authenticode {
            match auth.status {
                AuthenticodeStatus::Valid => {
                    print_checksec_status_row(
                        "Authenticode",
                        "  PASS ".green().bold(),
                        "Valid (Hash Verified)",
                    );
                }
                AuthenticodeStatus::HashMismatch => {
                    print_checksec_status_row(
                        "Authenticode",
                        "  FAIL ".red().bold(),
                        "TAMPERED (Hash Mismatch!)",
                    );
                }
                AuthenticodeStatus::Malformed => {
                    print_checksec_status_row(
                        "Authenticode",
                        "  WARN ".yellow().bold(),
                        "Malformed PKCS#7 Table",
                    );
                }
                AuthenticodeStatus::NotSigned => {
                    print_checksec_status_row("Authenticode", "  FAIL ".red().bold(), "Not Signed");
                }
            }
        } else {
            print_checksec_row(
                "Authenticode",
                report.mitigations.authenticode_signed,
                if report.mitigations.authenticode_signed {
                    "Embedded PKCS#7 table"
                } else {
                    "No digital signature found"
                },
            );
        }
    }
    print_checksec_row(
        "W^X (No RWX Sections)",
        !report.mitigations.has_rwx_sections,
        "Prevents writable and executable pages",
    );
    println!("  └────────────────────────┴───────────┴─────────────────────────────────────┘");
}

pub fn print_authenticode_section(report: &BinaryReport) {
    let Some(ref auth) = report.authenticode else {
        return;
    };
    if !auth.is_signed && auth.status == AuthenticodeStatus::NotSigned {
        return;
    }

    println!(
        "\n{}",
        "─── [ AUTHENTICODE SIGNATURE & CERTIFICATES ] ────────────────────────────────".bold()
    );

    let status_badge = match auth.status {
        AuthenticodeStatus::Valid => "[✔ VALID] Image hash verified against signature"
            .green()
            .bold(),
        AuthenticodeStatus::HashMismatch => {
            "[✖ TAMPERED] Binary image hash does NOT match signature digest!"
                .red()
                .bold()
        }
        AuthenticodeStatus::Malformed => {
            "[⚠ MALFORMED] Security directory contains invalid or corrupt ASN.1 DER"
                .yellow()
                .bold()
        }
        AuthenticodeStatus::NotSigned => "[-] Unsigned".normal(),
    };
    println!("  Status:          {}", status_badge);

    if !auth.digest_algorithm.is_empty() {
        println!("  Algorithm:       {}", auth.digest_algorithm.cyan().bold());
    }
    if !auth.expected_digest.is_empty() {
        println!("  Expected Digest: {}", auth.expected_digest.cyan());
    }
    if !auth.calculated_digest.is_empty() {
        let calc_str = if auth.status == AuthenticodeStatus::Valid {
            auth.calculated_digest.green()
        } else if auth.status == AuthenticodeStatus::HashMismatch {
            auth.calculated_digest.red().bold()
        } else {
            auth.calculated_digest.normal()
        };
        println!("  Calculated Hash: {}", calc_str);
    }
    if let Some(ref prog) = auth.program_name {
        println!("  Program Name:    {}", prog.white().bold());
    }

    // Signer Certificate
    if let Some(ref signer) = auth.signer_certificate {
        println!("\n  Signer Certificate:");
        println!("    • Subject:       {}", signer.subject.bold());
        if !signer.issuer.is_empty() && signer.issuer != signer.subject {
            println!("    • Issuer:        {}", signer.issuer);
        }
        println!("    • Serial Number: {}", signer.serial_number);
        if let (Some(from), Some(to)) = (&signer.valid_from, &signer.valid_to) {
            println!("    • Validity:      {} to {}", from, to);
        }
    }

    // Timestamp Info
    if auth.timestamp_time.is_some() || auth.timestamp_signer.is_some() {
        println!("\n  Countersignature / Timestamp (RFC 3161):");
        if let Some(ref time) = auth.timestamp_time {
            println!("    • Timestamp:     {}", time.yellow().bold());
        }
        if let Some(ref ts_signer) = auth.timestamp_signer {
            println!("    • TSA Signer:    {}", ts_signer.subject);
            if !ts_signer.issuer.is_empty() {
                println!("    • TSA Issuer:    {}", ts_signer.issuer);
            }
        }
    }

    // Additional Certificates in Chain
    if auth.certificates.len() > 1 {
        let signer_ser = auth
            .signer_certificate
            .as_ref()
            .map(|s| s.serial_number.as_str());
        let chain: Vec<_> = auth
            .certificates
            .iter()
            .filter(|c| signer_ser != Some(&c.serial_number))
            .collect();
        if !chain.is_empty() {
            println!(
                "\n  Certificate Chain ({} intermediate/root CA(s)):",
                chain.len()
            );
            for (idx, cert) in chain.iter().enumerate() {
                println!("    [{}] {}", idx + 1, cert.subject.dimmed());
                if !cert.issuer.is_empty() && cert.issuer != cert.subject {
                    println!("        Issuer: {}", cert.issuer.dimmed());
                }
            }
        }
    }
}

pub fn print_checksec_only(report: &BinaryReport) {
    println!(
        "\n{}",
        format!("Checksec Audit for: {}", report.file_name).bold()
    );
    print_checksec_table(report);
    if let Some(ref auth) = report.authenticode {
        if auth.is_signed {
            print_authenticode_section(report);
        }
    }
}

pub fn print_disasm_only(report: &BinaryReport) {
    println!(
        "\n{}",
        format!("Entry Point Disassembly for: {}", report.file_name).bold()
    );
    println!(
        "  Target Architecture: {} | Entry Point: 0x{:X}",
        report.architecture.cyan(),
        report.entry_point
    );
    if report.entry_point_preview.is_empty() {
        println!("  (No instructions decoded at entry point or unsupported architecture)");
    } else {
        print_disassembly_table(&report.entry_point_preview);
    }
}

pub fn print_yara_section(report: &crate::types::YaraMatchReport, show_all: bool) {
    println!(
        "\n{}",
        "─── [ YARA RULE MATCHES ] ────────────────────────────────────────────────────".bold()
    );
    if report.rules_matched.is_empty() {
        println!("  {}", "No YARA rules matched.".dimmed());
        return;
    }

    println!(
        "  Matched {} rule(s) (out of {} evaluated):",
        report.rules_matched.len().to_string().red().bold(),
        report.total_rules_evaluated
    );

    let rule_limit = if show_all {
        report.rules_matched.len()
    } else {
        10
    };
    for rule in report.rules_matched.iter().take(rule_limit) {
        let tag_str = if rule.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", rule.tags.join(", ").yellow())
        };
        let ns_str = if let Some(ref ns) = rule.namespace {
            format!(" (namespace: {})", ns.cyan())
        } else {
            String::new()
        };

        println!(
            "\n  {} {}{}{}",
            "▶ [MATCH]".red().bold(),
            rule.name.bold(),
            tag_str,
            ns_str
        );

        if !rule.metadatas.is_empty() {
            println!("    Metadata:");
            for (k, v) in &rule.metadatas {
                println!("      • {:<16} : {}", k.dimmed(), v);
            }
        }

        if !rule.matches.is_empty() {
            println!("    String Matches ({} hit(s)):", rule.matches.len());
            let match_limit = if show_all { rule.matches.len() } else { 5 };
            for m in rule.matches.iter().take(match_limit) {
                println!(
                    "      • 0x{:<8X} ({:>3} B) {:<12} : {}",
                    m.offset,
                    m.length,
                    m.name.cyan(),
                    m.data_preview
                );
            }
            if !show_all && rule.matches.len() > 5 {
                println!(
                    "        ... and {} more string occurrences (use --all to dump all)",
                    rule.matches.len() - 5
                );
            }
        }
    }

    if !show_all && report.rules_matched.len() > 10 {
        println!(
            "\n  ... and {} more matched rules (use --all to dump all matches)",
            report.rules_matched.len() - 10
        );
    }
}

pub fn print_yara_standalone(
    target_file: &str,
    report: &crate::types::YaraMatchReport,
    show_all: bool,
) {
    print_banner();
    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│ {:<76} │", format!("YARA SCAN: {}", target_file).bold());
    println!("├──────────────────────────────────────────────────────────────────────────────┤");
    println!("│ Rules Evaluated: {:<59} │", report.total_rules_evaluated);
    let match_summary = if report.rules_matched.is_empty() {
        "0 matches (clean)".green().bold()
    } else {
        format!("{} rule(s) triggered alert", report.rules_matched.len())
            .red()
            .bold()
    };
    println!("│ Scan Verdict:    {:<59} │", match_summary);
    println!("└──────────────────────────────────────────────────────────────────────────────┘");

    print_yara_section(report, show_all);

    println!(
        "\n{}",
        "════════════════════════════════════════════════════════════════════════════════".cyan()
    );
}
