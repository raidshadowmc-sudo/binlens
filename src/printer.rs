use crate::entropy::{entropy_badge, render_entropy_bar, render_entropy_histogram};
use crate::types::{BinaryFormat, BinaryReport};
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

    // 7. Interesting Indicators & Strings
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

    println!(
        "\n{}",
        "════════════════════════════════════════════════════════════════════════════════".cyan()
    );
}

fn print_checksec_row(name: &str, passed: bool, desc: &str) {
    let status_str = if passed {
        "  PASS ".green().bold()
    } else {
        "  FAIL ".red().bold()
    };
    println!("  │ {:<22} │ {} │ {:<35} │", name, status_str, desc);
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
    print_checksec_row(
        "Control Flow Guard (CFG)",
        report.mitigations.cfg,
        "Indirect call target validation",
    );
    print_checksec_row(
        "Authenticode (Embedded)",
        report.mitigations.authenticode_signed,
        "Embedded PKCS#7 table (absent if catalog-signed)",
    );
    print_checksec_row(
        "W^X (No RWX Sections)",
        !report.mitigations.has_rwx_sections,
        "Prevents writable and executable pages",
    );
    println!("  └────────────────────────┴───────────┴─────────────────────────────────────┘");
}

pub fn print_checksec_only(report: &BinaryReport) {
    println!(
        "\n{}",
        format!("Checksec Audit for: {}", report.file_name).bold()
    );
    print_checksec_table(report);
}
