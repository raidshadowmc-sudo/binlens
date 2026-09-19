<p align="center">
  <h1 align="center">🔍 binlens</h1>
  <p align="center">
    <strong>Blazingly fast binary inspector, Shannon entropy heatmapper & security mitigations auditor for hackers and reverse engineers.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/language-Rust%202024-orange.svg" alt="Rust">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
    <img src="https://img.shields.io/badge/version-0.1.0--alpha-blueviolet.svg" alt="Version">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg" alt="Platform">
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

## 🏗️ Architecture & Philosophy

- **Pure, memory-safe Rust**: Minimal external dependencies, zero unsafe blocks in header decoding.
- **Memory-mapped I/O (`memmap2`)**: Low memory footprint; parses gigabyte-scale binaries without loading entire files into heap RAM.
- **Rigorously Tested**: Verified with unit tests, 14 targeted regression tests, and differential testing against Python `pefile` on genuine Windows system binaries (`cmd.exe`, `notepad.exe`, `kernel32.dll`, `FileHistory.exe`).

---

## 📌 Project Status & Current Scope (v0.1.0-alpha)

This tool is currently in **early active development (`v0.1.0-alpha`)**. Here is the transparent breakdown of what is supported today and known scope boundaries:

- **Supported Formats**: 
  - Windows Portable Executable: `PE32` (x86) and `PE32+` (x64).
  - Linux Executable and Linkable Format: `ELF32` and `ELF64` (Little-Endian and Big-Endian).
- **Security Mitigations**:
  - `ASLR / PIE`: Verified via PE `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` and ELF `ET_DYN` / `DF_1_PIE`.
  - `DEP / NX`: Verified via PE `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` and ELF `PT_GNU_STACK` flags (defaults to NX enabled if GNU stack header is omitted).
  - `CFG (Control Flow Guard)`: Verified via PE `IMAGE_DLLCHARACTERISTICS_GUARD_CF` alongside `IMAGE_LOAD_CONFIG_DIRECTORY` function pointer checks (`GuardCFCheckFunctionPointer` at offset 112 on x64, offset 72 on x86).
  - `SafeSEH`: On x86, verifies Load Config table presence and handler counts (`SEHandlerTable` / `SEHandlerCount`). On x64, verifies table-based `.pdata` exception handling unless `IMAGE_DLLCHARACTERISTICS_NO_SEH` is flagged.
  - `Authenticode`: Currently verifies the existence and header format of the `WIN_CERTIFICATE` / PKCS#7 table in the Security Directory (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`). *Cryptographic hash validation of the file digest and root certificate chain traversal are planned for v0.2.0.*
- **Strings Extraction**: Fast byte scanning for printable ASCII/UTF-8 strings with heuristic pattern classification (IPs, URLs, registry keys, filesystem paths, sensitive process APIs).

---

## 🗺️ Roadmap & Planned Work

- [ ] **Mach-O Support**: Parsing 64-bit Mach-O headers, universal binaries (fat binaries), and macOS code signature blobs.
- [ ] **Cryptographic Authenticode Verification**: Full PKCS#7 / X.509 signature verification against Windows Root CA store and digest integrity checks.
- [ ] **Rich Header Parser**: Decrypting and parsing the undocumented MSVC `@comp.id` compiler and build telemetry records.
- [ ] **YARA Integration**: Ability to run external YARA rule files against target binaries alongside entropy & mitigation audits.
- [ ] **Entry Point Disassembly Preview**: Lightweight disassembly (first 16-32 instructions) via `iced-x86` for rapid triage of packers or shellcode stubs.
- [ ] **Prebuilt Release Binaries**: Automated multi-platform GitHub Actions release artifacts.

---

## 📜 License

Licensed under the [MIT License](LICENSE).
