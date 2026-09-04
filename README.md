<p align="center">
  <h1 align="center">🔍 binlens</h1>
  <p align="center">
    <strong>Blazingly fast binary inspector, Shannon entropy heatmapper & security mitigations auditor for hackers and reverse engineers.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/language-Rust%202024-orange.svg" alt="Rust">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
    <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  </p>
</p>

---

## ⚡ Overview

**`binlens`** is a modern, single-binary CLI utility built in pure Rust designed for reverse engineers, malware analysts, and systems programmers. It allows you to rapidly inspect PE (Windows) and ELF (Linux) binaries directly from your terminal, without needing heavy external tools or disassemblers.

### ✨ Key Features

- **🌈 Shannon Entropy Heatmap**: Computes entropy across configurable file chunks (default: 512 bytes) and renders an intuitive ASCII gradient bar (`░` zero padding, `▒` text, `█` code, `█` compressed, `█` packed/encrypted) alongside a distribution histogram.
- **🛡️ Security Mitigations Audit (`checksec`)**: Instant audit of binary hardening flags:
  - **ASLR** / High-Entropy 64-bit VA
  - **DEP / NX** (Data Execution Prevention)
  - **CFG** (Control Flow Guard)
  - **SafeSEH** / Exception handling
  - **Authenticode Signature** presence
  - **W^X Enforcement**: Automatic detection of hazardous `RWX` (Readable + Writable + Executable) sections.
- **📊 Deep PE & ELF Parsing**:
  - Full section headers breakdown (Virtual / Raw sizes, Characteristics, Section Entropy).
  - Import Directory Table resolution & **Imphash** (MD5 of normalized imported APIs) computation.
  - Exported symbols extraction.
- **🔎 Smart Indicator & Strings Extraction**: Identifies and tags interesting strings by pattern:
  - URLs (`http://`, `https://`, `ftp://`)
  - IPv4 addresses
  - Registry keys (`HKEY_`, `SOFTWARE\...`)
  - File paths (Windows drive letters, Unix system dirs)
  - High-interest / suspicious APIs (`VirtualAlloc`, `CreateRemoteThread`, `cmd.exe`, `powershell`)
- **⚖️ Side-by-Side Binary Diffing**: Compare two builds or variants with `binlens diff file_a file_b`:
  - Size and entropy shifts
  - Added / removed sections
  - Added / removed imported DLLs and functions
  - Hardening flags delta (e.g. detect dropped ASLR)
- **🤖 CI/CD Ready**: Every command supports `--json` for seamless integration into automated security gates and pipelines.

---

## 🚀 Terminal Showcase

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ FILE: binlens.exe                                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│ Format:        PE32+ (64-bit Windows)                                        │
│ Architecture:  x86_64 / AMD64 (64-bit)                                       │
│ Subsystem:     Windows CUI (Console)                                         │
│ File Size:     1080320 bytes (1055.00 KB)                                    │
│ Entry Point:   0x15AC0                                                       │
│ MD5:           9f8879ae7d99847b987eadf408fdfb93                              │
│ SHA256:        21c1b5c08d7875130d5f86335142d731615d39b19c1b9ce733992e2ac9e9a1df │
└──────────────────────────────────────────────────────────────────────────────┘

─── [ ENTROPY ANALYSIS & PACKING HEURISTICS ] ────────────────────────────────
  Overall Shannon Entropy: 6.215 / 8.000  [NORMAL CODE / DATA]

  Block Entropy Heatmap (Distribution across file offset):
  [████████████████████████████████████████████████▒▒█▒▒▒▒▒▒███▒▒██]
    0% ───────────────────────── 50% ──────────────────────── 100%  
  Legend: ░ Zeroes  ▒ Text/Sparse  █ Code  █ Dense  █ Packed/Encrypted

─── [ SECURITY MITIGATIONS (CHECKSEC) ] ──────────────────────────────────────
  ┌────────────────────────┬───────────┬─────────────────────────────────────┐
  │ Mitigation             │ Status    │ Details                             │
  ├────────────────────────┼───────────┼─────────────────────────────────────┤
  │ ASLR / PIE             │   PASS    │ Address Space Layout Randomization  │
  │ High Entropy VA        │   PASS    │ 64-bit ASLR address pool expansion  │
  │ DEP / NX               │   PASS    │ Data Execution Prevention / No-Exec │
  │ Control Flow Guard     │   FAIL    │ Indirect call target validation     │
  │ Authenticode Signature │   FAIL    │ Valid digital certificate table     │
  │ W^X (No RWX Sections)  │   PASS    │ Prevents writable & executable pages│
  └────────────────────────┴───────────┴─────────────────────────────────────┘
```

---

## 📦 Installation

### From Source

Ensure you have a recent Rust toolchain installed (1.80+):

```bash
git clone https://github.com/your-username/binlens.git
cd binlens
cargo build --release
```

The compiled binary will be located at:
- `target/release/binlens` (Linux / macOS)
- `target/release/binlens.exe` (Windows)

To install globally to your `~/.cargo/bin`:

```bash
cargo install --path .
```

---

## 🛠️ Usage

### 1. Full Scan

Analyze file headers, sections, entropy, mitigations, imports, and strings:

```bash
binlens scan target_app.exe
```

Tune block size for entropy or string scanning threshold:

```bash
binlens scan target_app.exe --block-size 256 --min-string 6
```

### 2. Shannon Entropy Heatmap

Visualize packed/encrypted areas across the binary file layout:

```bash
binlens entropy target_app.exe --width 80
```

### 3. Security Mitigations Audit (`checksec`)

Quickly check if a binary has ASLR, DEP, CFG, or dangerous RWX sections:

```bash
binlens checksec target_app.exe
```

### 4. Binary Differential Analysis (`diff`)

Compare two versions of an application or binary payload:

```bash
binlens diff build_v1.exe build_v2.exe
```

### 5. Suspicious String Extraction

Scan for URLs, IPv4 addresses, file paths, and known sensitive APIs:

```bash
binlens strings target_app.exe --min-len 6
```

Dump all printable strings:

```bash
binlens strings target_app.exe --all
```

### 6. Machine-Readable Output (JSON)

Use `--json` on any command for scripting or CI/CD pipelines:

```bash
binlens --json checksec app.exe | jq .aslr
```

---

## 🏗️ Architecture

- Pure, memory-safe Rust with zero unsafe blocks in header parsing.
- Zero heavyweight C library dependencies.
- Streaming zero-copy slicing for minimal memory overhead even on large binaries.

---

## 📜 License

Licensed under the [MIT License](LICENSE).
