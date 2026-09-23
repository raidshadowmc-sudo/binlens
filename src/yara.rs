use crate::types::{YaraMatchReport, YaraRuleMatch, YaraStringMatch};
use boreal::{Compiler, MetadataValue};
use std::fs;
use std::path::Path;

pub fn compile_rules_from_str(rule_str: &str) -> Result<boreal::Scanner, String> {
    let mut compiler = Compiler::new();
    compiler
        .add_rules_str(rule_str)
        .map_err(|e| format!("Failed to compile YARA rules: {}", e))?;
    Ok(compiler.finalize())
}

pub fn compile_rules_from_path(path: &Path) -> Result<boreal::Scanner, String> {
    if !path.exists() {
        return Err(format!("YARA rules path not found: {}", path.display()));
    }

    let mut compiler = Compiler::new();

    if path.is_file() {
        compiler.add_rules_file(path).map_err(|e| {
            format!(
                "Failed to compile YARA rules from {}: {}",
                path.display(),
                e
            )
        })?;
    } else if path.is_dir() {
        let mut count = 0;
        add_rules_from_dir_recursive(&mut compiler, path, &mut count, 0)?;
        if count == 0 {
            return Err(format!(
                "No .yar or .yara rule files found in directory: {}",
                path.display()
            ));
        }
    } else {
        return Err(format!("Invalid path: {}", path.display()));
    }

    Ok(compiler.finalize())
}

fn add_rules_from_dir_recursive(
    compiler: &mut Compiler,
    dir: &Path,
    count: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > 16 || *count >= 1024 {
        return Ok(());
    }

    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

    for entry in entries {
        if *count >= 1024 {
            break;
        }
        let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            add_rules_from_dir_recursive(compiler, &entry_path, count, depth + 1)?;
        } else if entry_path.is_file() {
            if let Some(ext) = entry_path.extension() {
                if ext == "yar" || ext == "yara" {
                    compiler.add_rules_file(&entry_path).map_err(|e| {
                        format!("Error in YARA rule {}: {}", entry_path.display(), e)
                    })?;
                    *count += 1;
                }
            }
        }
    }
    Ok(())
}

pub fn scan_bytes_with_scanner(
    data: &[u8],
    scanner: &boreal::Scanner,
) -> Result<YaraMatchReport, String> {
    let scan_res = match scanner.scan_mem(data) {
        Ok(res) => res,
        Err((err, res)) => {
            eprintln!("Warning: YARA scan completed with error: {}", err);
            res
        }
    };

    let total_evaluated = scanner.rules().count();
    let mut rules_matched = Vec::new();

    for rule in scan_res.rules {
        if !rule.matched {
            continue;
        }

        let mut string_matches = Vec::new();
        for sm in rule.matches {
            for m in sm.matches {
                let preview_len = m.length.min(32);
                let preview_bytes = &m.data[..preview_len];
                let preview = if let Ok(s) = std::str::from_utf8(preview_bytes) {
                    if s.chars().all(|c| !c.is_control() || c == ' ') {
                        format!("\"{}\"", s)
                    } else {
                        hex_preview(preview_bytes)
                    }
                } else {
                    hex_preview(preview_bytes)
                };

                let name = if sm.name.starts_with('$') {
                    sm.name.to_string()
                } else {
                    format!("${}", sm.name)
                };

                string_matches.push(YaraStringMatch {
                    name,
                    offset: m.base + m.offset,
                    length: m.length,
                    data_preview: preview,
                });
            }
        }

        let metadatas = rule
            .metadatas
            .iter()
            .map(|meta| {
                let name = scanner.get_string_symbol(meta.name).to_string();
                let val_str = match meta.value {
                    MetadataValue::Integer(i) => i.to_string(),
                    MetadataValue::Boolean(b) => b.to_string(),
                    MetadataValue::Bytes(sym) => {
                        String::from_utf8_lossy(scanner.get_bytes_symbol(sym)).to_string()
                    }
                };
                (name, val_str)
            })
            .collect();

        let tags = rule
            .tags
            .iter()
            .map(|t| scanner.get_string_symbol(*t).to_string())
            .collect();

        rules_matched.push(YaraRuleMatch {
            name: rule.name.to_string(),
            namespace: if rule.namespace.is_empty() || rule.namespace == "default" {
                None
            } else {
                Some(rule.namespace.to_string())
            },
            tags,
            metadatas,
            matches: string_matches,
        });
    }

    Ok(YaraMatchReport {
        rules_matched,
        total_rules_evaluated: total_evaluated,
    })
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
