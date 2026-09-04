mod diff;
mod elf;
mod entropy;
mod pe;
mod printer;
mod strings;
mod types;

use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "binlens")]
#[command(author = "ENI & LO <community@github.com>")]
#[command(version = "0.1.0")]
#[command(about = "Modern binary inspector, Shannon entropy visualizer & security mitigations auditor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output raw JSON instead of formatted terminal UI (ideal for CI/CD and scripts)
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Comprehensive inspection of a binary (PE, ELF) with headers, entropy, checksec, imports
    Scan {
        /// Target binary file path
        file: String,

        /// Block size for entropy heatmap calculation (default: 512 bytes)
        #[arg(short, long, default_value_t = 512)]
        block_size: usize,

        /// Minimum string length for pattern scanning (default: 4)
        #[arg(short, long, default_value_t = 4)]
        min_string: usize,
    },

    /// Dedicated entropy visualization with block-by-block ASCII terminal heatmap & histogram
    Entropy {
        /// Target binary file path
        file: String,

        /// Chunk block size in bytes (default: 512)
        #[arg(short, long, default_value_t = 512)]
        block_size: usize,

        /// Heatmap rendering width (columns)
        #[arg(short, long, default_value_t = 64)]
        width: usize,
    },

    /// Run security mitigations audit (ASLR, DEP/NX, CFG, Authenticode, W^X)
    Checksec {
        /// Target binary file path
        file: String,
    },

    /// Compare two binaries side-by-side (size delta, entropy shift, section diff, import delta)
    Diff {
        /// First binary (baseline)
        file_a: String,

        /// Second binary (comparison)
        file_b: String,
    },

    /// Extract strings and tag suspicious indicators (URLs, IPs, Paths, Registry, APIs)
    Strings {
        /// Target binary file path
        file: String,

        /// Minimum string length (default: 4)
        #[arg(short, long, default_value_t = 4)]
        min_len: usize,

        /// Dump all strings (otherwise only categorized patterns are shown)
        #[arg(short, long)]
        all: bool,
    },
}

fn analyze_binary(path_str: &str, min_string_len: usize) -> Result<types::BinaryReport, String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("File '{}' not found.", path_str));
    }

    let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();

    let mut report = if let Some(pe_report) = pe::parse_pe(&data, &file_name) {
        pe_report
    } else if let Some(elf_report) = elf::parse_elf(&data, &file_name) {
        elf_report
    } else {
        let overall_entropy = entropy::calculate_entropy(&data);
        use md5::Md5;
        use sha2::{Digest, Sha256};
        let mut sha_hasher = Sha256::new();
        sha_hasher.update(&data);
        let mut md5_hasher = Md5::new();
        md5_hasher.update(&data);

        types::BinaryReport {
            file_name: file_name.to_string(),
            file_size: data.len() as u64,
            md5: pe::hex_encode(&md5_hasher.finalize()),
            sha256: pe::hex_encode(&sha_hasher.finalize()),
            format: types::BinaryFormat::Unknown("Raw binary / Unsupported".to_string()),
            architecture: "Unknown".to_string(),
            subsystem: "Unknown".to_string(),
            entry_point: 0,
            overall_entropy,
            is_likely_packed: overall_entropy >= 7.2,
            mitigations: types::SecurityMitigations::default(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            imphash: None,
            interesting_strings: Vec::new(),
        }
    };

    report.interesting_strings = strings::extract_strings(&data, min_string_len);
    Ok(report)
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { file, block_size, min_string } => {
            match analyze_binary(&file, min_string) {
                Ok(report) => {
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        let data = fs::read(&file).unwrap_or_default();
                        let blocks = entropy::calculate_block_entropy(&data, block_size);
                        printer::print_report(&report, &blocks);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Entropy { file, block_size, width } => {
            let data = match fs::read(&file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} Failed to read '{}': {}", "Error:".red().bold(), file, e);
                    std::process::exit(1);
                }
            };
            let overall = entropy::calculate_entropy(&data);
            let blocks = entropy::calculate_block_entropy(&data, block_size);

            if cli.json {
                let json_data = serde_json::json!({
                    "file": file,
                    "file_size": data.len(),
                    "block_size": block_size,
                    "overall_entropy": overall,
                    "blocks_count": blocks.len(),
                    "blocks": blocks,
                });
                println!("{}", serde_json::to_string_pretty(&json_data).unwrap());
            } else {
                printer::print_banner();
                println!("  Target File: {}", file.bold());
                println!("  File Size:   {} bytes", data.len());
                println!("  Block Size:  {} bytes ({} sample blocks)", block_size, blocks.len());
                println!("  Entropy:     {:.4} / 8.000  [{}]\n", overall, entropy::entropy_badge(overall));

                println!("  Entropy Heatmap ({} columns):", width);
                println!("  [{}]", entropy::render_entropy_bar(&blocks, width));
                println!("  {:^66}\n", "0% ───────────────────────── 50% ──────────────────────── 100%");

                println!("  Distribution Histogram:");
                for line in entropy::render_entropy_histogram(&blocks) {
                    println!("{}", line);
                }
            }
        }

        Commands::Checksec { file } => {
            match analyze_binary(&file, 4) {
                Ok(report) => {
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&report.mitigations).unwrap());
                    } else {
                        printer::print_banner();
                        printer::print_checksec_only(&report);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Diff { file_a, file_b } => {
            let report_a = match analyze_binary(&file_a, 4) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };
            let report_b = match analyze_binary(&file_b, 4) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if cli.json {
                let diff_json = serde_json::json!({
                    "file_a": report_a,
                    "file_b": report_b,
                });
                println!("{}", serde_json::to_string_pretty(&diff_json).unwrap());
            } else {
                let diff_lines = diff::compare_binaries(&report_a, &report_b);
                for line in diff_lines {
                    println!("{}", line);
                }
            }
        }

        Commands::Strings { file, min_len, all } => {
            let data = match fs::read(&file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} Failed to read '{}': {}", "Error:".red().bold(), file, e);
                    std::process::exit(1);
                }
            };

            let categorized = strings::extract_strings(&data, min_len);

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&categorized).unwrap());
            } else {
                printer::print_banner();
                println!("  Extracted Indicators from: {} (min length: {})\n", file.bold(), min_len);
                if all {
                    let mut current = Vec::new();
                    for &b in &data {
                        if (0x20..=0x7E).contains(&b) {
                            current.push(b);
                        } else {
                            if current.len() >= min_len {
                                if let Ok(s) = String::from_utf8(current.clone()) {
                                    println!("  {}", s);
                                }
                            }
                            current.clear();
                        }
                    }
                } else {
                    println!("  ┌────────────┬─────────────────────────────┬──────────────────────────────────────────┐");
                    println!("  │ Tag        │ Offset                      │ Value                                    │");
                    println!("  ├────────────┼─────────────────────────────┼──────────────────────────────────────────┤");
                    for item in &categorized {
                        println!("  │ {:<10} │ 0x{:<25X} │ {:<40} │", item.category.cyan(), item.offset, item.value);
                    }
                    println!("  └────────────┴─────────────────────────────┴──────────────────────────────────────────┘");
                    println!("\n  Found {} tagged indicator(s). Pass --all to dump raw strings.", categorized.len());
                }
            }
        }
    }
}
