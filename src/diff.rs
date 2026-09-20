use crate::types::{BinaryReport, DiffReport, ImportDelta, MitigationDrift, SectionDelta};
use colored::*;

pub fn generate_diff_report(a: &BinaryReport, b: &BinaryReport) -> DiffReport {
    let size_delta = b.file_size as i64 - a.file_size as i64;
    let entropy_delta = b.overall_entropy - a.overall_entropy;
    let md5_match = a.md5 == b.md5;
    let sha256_match = a.sha256 == b.sha256;

    let mut mitigations_drift = Vec::new();
    let checks = [
        ("ASLR", a.mitigations.aslr, b.mitigations.aslr),
        ("DEP / NX", a.mitigations.dep_nx, b.mitigations.dep_nx),
        (
            "Stack Canary",
            a.mitigations.stack_canary,
            b.mitigations.stack_canary,
        ),
        (
            "Fortified Functions",
            a.mitigations.fortify,
            b.mitigations.fortify,
        ),
        ("Control Flow Guard", a.mitigations.cfg, b.mitigations.cfg),
        (
            "Authenticode Signed",
            a.mitigations.authenticode_signed,
            b.mitigations.authenticode_signed,
        ),
        (
            "No RWX Sections",
            !a.mitigations.has_rwx_sections,
            !b.mitigations.has_rwx_sections,
        ),
    ];
    for (name, before, after) in checks {
        let status = if before == after {
            "unchanged".to_string()
        } else if after {
            "hardened".to_string()
        } else {
            "degraded".to_string()
        };
        mitigations_drift.push(MitigationDrift {
            mitigation: name.to_string(),
            before,
            after,
            status,
        });
    }

    let mut section_deltas = Vec::new();
    for s_b in &b.sections {
        if !a.sections.iter().any(|s_a| s_a.name == s_b.name) {
            section_deltas.push(SectionDelta {
                name: s_b.name.clone(),
                action: "added".to_string(),
                size_delta: s_b.raw_size as i64,
                entropy_before: None,
                entropy_after: Some(s_b.entropy),
            });
        }
    }
    for s_a in &a.sections {
        if !b.sections.iter().any(|s_b| s_b.name == s_a.name) {
            section_deltas.push(SectionDelta {
                name: s_a.name.clone(),
                action: "removed".to_string(),
                size_delta: -(s_a.raw_size as i64),
                entropy_before: Some(s_a.entropy),
                entropy_after: None,
            });
        }
    }
    for s_a in &a.sections {
        if let Some(s_b) = b.sections.iter().find(|s| s.name == s_a.name) {
            let s_delta = s_b.raw_size as i64 - s_a.raw_size as i64;
            let ent_delta = s_b.entropy - s_a.entropy;
            if s_delta != 0 || ent_delta.abs() > 0.1 {
                section_deltas.push(SectionDelta {
                    name: s_a.name.clone(),
                    action: "modified".to_string(),
                    size_delta: s_delta,
                    entropy_before: Some(s_a.entropy),
                    entropy_after: Some(s_b.entropy),
                });
            }
        }
    }

    let mut import_deltas = Vec::new();
    for imp_b in &b.imports {
        if !a
            .imports
            .iter()
            .any(|imp_a| imp_a.dll.eq_ignore_ascii_case(&imp_b.dll))
        {
            import_deltas.push(ImportDelta {
                dll: imp_b.dll.clone(),
                action: "added".to_string(),
                api_count: imp_b.functions.len(),
            });
        }
    }
    for imp_a in &a.imports {
        if !b
            .imports
            .iter()
            .any(|imp_b| imp_b.dll.eq_ignore_ascii_case(&imp_a.dll))
        {
            import_deltas.push(ImportDelta {
                dll: imp_a.dll.clone(),
                action: "removed".to_string(),
                api_count: imp_a.functions.len(),
            });
        }
    }

    DiffReport {
        file_a: a.file_name.clone(),
        file_b: b.file_name.clone(),
        size_delta,
        entropy_delta,
        md5_match,
        sha256_match,
        mitigations_drift,
        section_deltas,
        import_deltas,
    }
}

pub fn compare_binaries(a: &BinaryReport, b: &BinaryReport) -> Vec<String> {
    let mut out = Vec::new();

    let name_a = format!("[A] {}", a.file_name);
    let name_b = format!("[B] {}", b.file_name);

    out.push(
        "================================================================================"
            .normal()
            .to_string(),
    );
    out.push(format!(
        "  BINARY DIFFERENTIAL ANALYSIS: {} vs {}",
        name_a.bold(),
        name_b.bold()
    ));
    out.push(
        "================================================================================"
            .normal()
            .to_string(),
    );

    // Basic Metrics Diff
    out.push(
        format!("  {:20} | {:<25} | {:<25}", "METRIC", &name_a, &name_b)
            .bold()
            .to_string(),
    );
    out.push(
        "  ---------------------+---------------------------+---------------------------"
            .normal()
            .to_string(),
    );

    let size_diff = b.file_size as i64 - a.file_size as i64;
    let size_diff_str = match size_diff.cmp(&0) {
        std::cmp::Ordering::Greater => format!(" (+{} bytes)", size_diff).green(),
        std::cmp::Ordering::Less => format!(" ({} bytes)", size_diff).red(),
        std::cmp::Ordering::Equal => " (unchanged)".normal(),
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
        "Architecture", &a.architecture, &b.architecture
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
        "Entropy", a.overall_entropy, b.overall_entropy, ent_diff_str
    ));

    // Hashes
    out.push("".normal().to_string());
    out.push("  CRYPTOGRAPHIC HASHES:".bold().to_string());
    if a.md5 == b.md5 {
        out.push(
            format!("  MD5:    {} (IDENTICAL)", a.md5)
                .green()
                .to_string(),
        );
    } else {
        out.push(format!("  MD5 A:  {}", a.md5).red().to_string());
        out.push(format!("  MD5 B:  {}", b.md5).green().to_string());
    }

    if a.sha256 == b.sha256 {
        out.push(
            format!("  SHA256: {} (IDENTICAL)", a.sha256)
                .green()
                .to_string(),
        );
    } else {
        out.push(format!("  SHA256 A: {}", a.sha256).red().to_string());
        out.push(format!("  SHA256 B: {}", b.sha256).green().to_string());
    }

    // Security Mitigations Diff
    out.push("".normal().to_string());
    out.push("  SECURITY MITIGATIONS DELTA:".bold().to_string());
    diff_bool(&mut out, "ASLR", a.mitigations.aslr, b.mitigations.aslr);
    diff_bool(
        &mut out,
        "DEP / NX",
        a.mitigations.dep_nx,
        b.mitigations.dep_nx,
    );
    diff_bool(
        &mut out,
        "Stack Canary",
        a.mitigations.stack_canary,
        b.mitigations.stack_canary,
    );
    diff_bool(
        &mut out,
        "Fortified Functions",
        a.mitigations.fortify,
        b.mitigations.fortify,
    );
    diff_bool(
        &mut out,
        "Control Flow Guard",
        a.mitigations.cfg,
        b.mitigations.cfg,
    );
    diff_bool(
        &mut out,
        "Authenticode Signed",
        a.mitigations.authenticode_signed,
        b.mitigations.authenticode_signed,
    );
    diff_bool(
        &mut out,
        "No RWX Sections",
        !a.mitigations.has_rwx_sections,
        !b.mitigations.has_rwx_sections,
    );

    // Section Diff
    out.push("".normal().to_string());
    out.push("  SECTION CHANGES:".bold().to_string());
    for s_b in &b.sections {
        if !a.sections.iter().any(|s_a| s_a.name == s_b.name) {
            out.push(format!(
                "  [+] Added section:   {:<10} (Raw Size: {}, Entropy: {:.2})",
                s_b.name.green().bold(),
                s_b.raw_size,
                s_b.entropy
            ));
        }
    }
    for s_a in &a.sections {
        if !b.sections.iter().any(|s_b| s_b.name == s_a.name) {
            out.push(format!(
                "  [-] Removed section: {:<10} (Raw Size: {}, Entropy: {:.2})",
                s_a.name.red().bold(),
                s_a.raw_size,
                s_a.entropy
            ));
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
        if !a
            .imports
            .iter()
            .any(|imp_a| imp_a.dll.eq_ignore_ascii_case(&imp_b.dll))
        {
            out.push(format!(
                "  [+] Added DLL:   {} ({} APIs)",
                imp_b.dll.green().bold(),
                imp_b.functions.len()
            ));
        }
    }
    for imp_a in &a.imports {
        if !b
            .imports
            .iter()
            .any(|imp_b| imp_b.dll.eq_ignore_ascii_case(&imp_a.dll))
        {
            out.push(format!(
                "  [-] Removed DLL: {} ({} APIs)",
                imp_a.dll.red().bold(),
                imp_a.functions.len()
            ));
        }
    }

    out.push(
        "================================================================================"
            .normal()
            .to_string(),
    );
    out
}

fn diff_bool(out: &mut Vec<String>, name: &str, val_a: bool, val_b: bool) {
    if val_a == val_b {
        let badge = if val_b {
            "PASSED".green()
        } else {
            "DISABLED".dimmed()
        };
        out.push(format!("  {:<24} : {} in both", name, badge));
    } else if val_b {
        out.push(format!(
            "  {:<24} : {} -> {} (Hardened!)",
            name,
            "DISABLED".red(),
            "ENABLED".green().bold()
        ));
    } else {
        out.push(format!(
            "  {:<24} : {} -> {} (Degraded!)",
            name,
            "ENABLED".green(),
            "DISABLED".red().bold()
        ));
    }
}
