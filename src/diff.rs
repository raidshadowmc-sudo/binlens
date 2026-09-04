use crate::types::BinaryReport;
use colored::*;

pub fn compare_binaries(a: &BinaryReport, b: &BinaryReport) -> Vec<String> {
    let mut out = Vec::new();

    out.push("================================================================================".normal().to_string());
    out.push(format!("  BINARY DIFFERENTIAL ANALYSIS: {} vs {}", a.file_name.bold(), b.file_name.bold()));
    out.push("================================================================================".normal().to_string());

    // Basic Metrics Diff
    out.push(format!("  {:20} | {:<25} | {:<25}", "METRIC", &a.file_name, &b.file_name).bold().to_string());
    out.push("  ---------------------+---------------------------+---------------------------".normal().to_string());
    
    let size_diff = b.file_size as i64 - a.file_size as i64;
    let size_diff_str = if size_diff > 0 {
        format!(" (+{} bytes)", size_diff).green()
    } else if size_diff < 0 {
        format!(" ({} bytes)", size_diff).red()
    } else {
        " (unchanged)".normal()
    };
    out.push(format!(
        "  {:20} | {:<25} | {:<25}{}",
        "File Size",
        format!("{} bytes", a.file_size),
        format!("{} bytes", b.file_size),
        size_diff_str
    ));

    out.push(format!(
        "  {:20} | {:<25} | {:<25}",
        "Format",
        a.format.to_string(),
        b.format.to_string()
    ));

    out.push(format!(
        "  {:20} | {:<25} | {:<25}",
        "Architecture",
        &a.architecture,
        &b.architecture
    ));

    let ent_diff = b.overall_entropy - a.overall_entropy;
    let ent_diff_str = if ent_diff.abs() > 0.05 {
        if ent_diff > 0.0 {
            format!(" (+{:.3})", ent_diff).yellow()
        } else {
            format!(" ({:.3})", ent_diff).cyan()
        }
    } else {
        " (stable)".normal()
    };
    out.push(format!(
        "  {:20} | {:<25.3} | {:<25.3}{}",
        "Entropy",
        a.overall_entropy,
        b.overall_entropy,
        ent_diff_str
    ));

    // Hashes
    out.push("".normal().to_string());
    out.push("  CRYPTOGRAPHIC HASHES:".bold().to_string());
    if a.md5 == b.md5 {
        out.push(format!("  MD5:    {} (IDENTICAL)", a.md5).green().to_string());
    } else {
        out.push(format!("  MD5 A:  {}", a.md5).red().to_string());
        out.push(format!("  MD5 B:  {}", b.md5).green().to_string());
    }

    if a.sha256 == b.sha256 {
        out.push(format!("  SHA256: {} (IDENTICAL)", a.sha256).green().to_string());
    } else {
        out.push(format!("  SHA256 A: {}", a.sha256).red().to_string());
        out.push(format!("  SHA256 B: {}", b.sha256).green().to_string());
    }

    // Security Mitigations Diff
    out.push("".normal().to_string());
    out.push("  SECURITY MITIGATIONS DELTA:".bold().to_string());
    diff_bool(&mut out, "ASLR", a.mitigations.aslr, b.mitigations.aslr);
    diff_bool(&mut out, "DEP / NX", a.mitigations.dep_nx, b.mitigations.dep_nx);
    diff_bool(&mut out, "Control Flow Guard", a.mitigations.cfg, b.mitigations.cfg);
    diff_bool(&mut out, "Authenticode Signed", a.mitigations.authenticode_signed, b.mitigations.authenticode_signed);
    diff_bool(&mut out, "No RWX Sections", !a.mitigations.has_rwx_sections, !b.mitigations.has_rwx_sections);

    // Section Diff
    out.push("".normal().to_string());
    out.push("  SECTION CHANGES:".bold().to_string());
    for s_b in &b.sections {
        if !a.sections.iter().any(|s_a| s_a.name == s_b.name) {
            out.push(format!("  [+] Added section:   {:<10} (Raw Size: {}, Entropy: {:.2})", s_b.name.green().bold(), s_b.raw_size, s_b.entropy));
        }
    }
    for s_a in &a.sections {
        if !b.sections.iter().any(|s_b| s_b.name == s_a.name) {
            out.push(format!("  [-] Removed section: {:<10} (Raw Size: {}, Entropy: {:.2})", s_a.name.red().bold(), s_a.raw_size, s_a.entropy));
        }
    }
    for s_a in &a.sections {
        if let Some(s_b) = b.sections.iter().find(|s| s.name == s_a.name) {
            let size_delta = s_b.raw_size as i64 - s_a.raw_size as i64;
            let ent_delta = s_b.entropy - s_a.entropy;
            if size_delta != 0 || ent_delta.abs() > 0.1 {
                out.push(format!(
                    "  [~] Modified section: {:<10} | Size delta: {:+8} | Entropy: {:.2} -> {:.2} ({:+0.2})",
                    s_a.name.yellow().bold(),
                    size_delta,
                    s_a.entropy,
                    s_b.entropy,
                    ent_delta
                ));
            }
        }
    }

    // Imports Diff
    out.push("".normal().to_string());
    out.push("  IMPORT / DEPENDENCY DELTA:".bold().to_string());
    for imp_b in &b.imports {
        if !a.imports.iter().any(|imp_a| imp_a.dll.eq_ignore_ascii_case(&imp_b.dll)) {
            out.push(format!("  [+] Added DLL:   {} ({} APIs)", imp_b.dll.green().bold(), imp_b.functions.len()));
        }
    }
    for imp_a in &a.imports {
        if !b.imports.iter().any(|imp_b| imp_b.dll.eq_ignore_ascii_case(&imp_a.dll)) {
            out.push(format!("  [-] Removed DLL: {} ({} APIs)", imp_a.dll.red().bold(), imp_a.functions.len()));
        }
    }

    out.push("================================================================================".normal().to_string());
    out
}

fn diff_bool(out: &mut Vec<String>, name: &str, val_a: bool, val_b: bool) {
    if val_a == val_b {
        let badge = if val_b { "PASSED".green() } else { "DISABLED".dimmed() };
        out.push(format!("  {:<24} : {} in both", name, badge));
    } else if val_b {
        out.push(format!("  {:<24} : {} -> {} (Hardened!)", name, "DISABLED".red(), "ENABLED".green().bold()));
    } else {
        out.push(format!("  {:<24} : {} -> {} (Degraded!)", name, "ENABLED".green(), "DISABLED".red().bold()));
    }
}
