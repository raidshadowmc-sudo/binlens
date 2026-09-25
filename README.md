# binlens

checksec, Shannon entropy heatmap, Authenticode digest, Rich Header, and YARA — one CLI, PE / ELF / Mach-O.

[![Crates.io](https://img.shields.io/crates/v/binlens.svg)](https://crates.io/crates/binlens)
[![CI](https://github.com/raidshadowmc-sudo/binlens/actions/workflows/ci.yml/badge.svg)](https://github.com/raidshadowmc-sudo/binlens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

```bash
cargo install binlens
binlens scan ./sample.exe
```

---

## Overview

`binlens` is a standalone, single-binary command-line utility built for security engineers, incident responders, malware analysts, and DevSecOps pipelines. It performs static analysis on executable headers, computes continuous block-level entropy distributions, evaluates operating system exploit mitigations, extracts API import/export tables, decodes undocumented compiler telemetry (MSVC Rich Header), verifies Authenticode PE image hashes, and evaluates YARA rules against mapped binary memory without requiring runtime execution, emulators, or heavy disassembler frameworks.

File parsing is backed by memory-mapped I/O (`memmap2`) with strict offset and bounds validation, avoiding whole-file heap allocations and enabling instant triage and metadata extraction even on multi-gigabyte files.

---

## Why binlens?

Security auditing and binary triage are frequently fragmented across disparate scripts and platform-dependent tools:

| Feature / Capability | `binlens` | Python `pefile` / scripts | `checksec.sh` |
| :--- | :--- | :--- | :--- |
| **Runtime Dependencies** | None (Single static binary) | Python 3 + `pip` packages | Bash, readelf, objdump |
| **Cross-Platform Support** | Windows, Linux & macOS (PE, ELF, Mach-O) | PE only (ELF/Mach-O require extra libs) | Linux / ELF only |
| **Throughput & Memory** | Zero-copy `memmap2` (minimal heap) | Interpreted overhead (~50–200 ms) | Process spawning overhead |
| **Shannon Entropy Visualizer** | In-terminal heatmap + histogram | Raw float values only | None |
| **MSVC Rich Header Decoding**| Built-in with VS toolset mapping | Raw tuples / requires custom parser| None |
| **Authenticode Integrity** | 5-phase PE image hash vs PKCS#7 | Requires `wintrust` / custom script | None |
| **YARA Rule Engine** | Built-in (pure Rust / `boreal`) | Requires `yara-python` / C libyara | None |
| **Differential Analysis (`diff`)**| Built-in structured delta engine | Manual script required | None |
| **Automated Pipeline Output**| Unified `--json` schema | Custom JSON serializer | Script-dependent JSON |

> **Scope Note**: `binlens` is designed as a fast, zero-dependency static triage and verification tool. It is not an interactive disassembler or emulator, and is not a replacement for heavyweight reverse engineering frameworks like `radare2` / `rabin2`, `LIEF`, or `capa`.

---

## Terminal Showcase

Executing `binlens scan C:\Windows\System32\cmd.exe` provides a comprehensive, unified terminal report card:

```text
 ██████╗ ██╗███╗   ██╗██╗     ███████╗███╗   ██╗███████╗
 ██╔══██╗██║████╗  ██║██║     ██╔════╝████╗  ██║██╔════╝
 ██████╔╝██║██╔██╗ ██║██║     █████╗  ██╔██╗ ██║███████╗
 ██╔══██╗██║██║╚██╗██║██║     ██╔══╝  ██║╚██╗██║╚════██║
 ██████╔╝██║██║ ╚████║███████╗███████╗██║ ╚████║███████║
 ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
 Modern Binary Inspector, Entropy Heatmapper & Security Auditor

┌──────────────────────────────────────────────────────────────────────────────┐
│ FILE: C:\Windows\System32\cmd.exe                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│ Format:        PE32+ (64-bit Windows)                                        │
│ Architecture:  x86_64 / AMD64 (64-bit)                                       │
│ Subsystem:     Windows CUI (Console)                                         │
│ File Size:     344064 bytes (336.00 KB)                                      │
│ Entry Point:   0x27B80                                                       │
│ MD5:           ce396564392fafaad5c07a5e2dade4e6                              │
│ SHA256:        97ac98b1a92c286054cce55239cfccdfc23a5517bd07fe693072c9ca96c7dabb │
│ Imphash:       010b165e4c37f484601d3dbd700c9423                              │
└──────────────────────────────────────────────────────────────────────────────┘

─── [ ENTROPY ANALYSIS & PACKING HEURISTICS ] ────────────────────────────────
  Overall Shannon Entropy: 5.880 / 8.000  [NORMAL CODE / DATA]

  Block Entropy Heatmap (Distribution across file offset):
  [░██████████████████████████████████████████▒░▒▒▒██▒█▒▒█░▒░▒█▒▒▒░]
    0% ───────────────────────── 50% ──────────────────────── 100%  
  Legend: ░ Zeroes  ▒ Text/Sparse  █ Code  █ Dense  █ Packed/Encrypted

  Entropy Histogram:
  0.0 - 1.0 (Zeroes/Null)  [███                     ]    67 ( 10.0%)
  1.0 - 2.0 (Low Padding)  [█                       ]    22 (  3.3%)
  2.0 - 3.0 (Sparse Data)  [█                       ]    31 (  4.6%)
  3.0 - 4.0 (ASCII/Text)   [█                       ]    23 (  3.4%)
  4.0 - 5.0 (Dense Text)   [███                     ]    67 ( 10.0%)
  5.0 - 6.0 (Exec Code)    [████████████████████████]   423 ( 62.9%)
  6.0 - 7.0 (Mixed/Dense)  [█                       ]    30 (  4.5%)
  7.0 - 8.0 (Packed/Crypt) [                        ]     9 (  1.3%)

─── [ SECURITY MITIGATIONS (CHECKSEC) ] ──────────────────────────────────────
  ┌────────────────────────┬───────────┬─────────────────────────────────────┐
  │ Mitigation             │ Status    │ Details                             │
  ├────────────────────────┼───────────┼─────────────────────────────────────┤
  │ ASLR / PIE             │   PASS    │ Address Space Layout Randomization  │
  │ High Entropy VA        │   PASS    │ 64-bit ASLR address pool expansion  │
  │ DEP / NX               │   PASS    │ Data Execution Prevention / No-Execute │
  │ Control Flow Guard (CFG) │   PASS  │ Indirect call target validation     │
  │ Authenticode (Embedded) │   FAIL   │ Embedded PKCS#7 table (absent if catalog-signed) │
  │ W^X (No RWX Sections)  │   PASS    │ Prevents writable and executable pages │
  └────────────────────────┴───────────┴─────────────────────────────────────┘
```

> **Note**: A full `binlens scan` output also prints the section integrity table with per-section entropy, MSVC Rich Header toolset build telemetry, import/export tables, entry point disassembly preview, and classified strings/IoCs.
>
> *(Note on Authenticode in `cmd.exe`: Core Windows system binaries are signed via external catalog files (`.cat`) rather than embedded PKCS#7 certificate tables inside the PE header).*

---

## Practical Workflows & Use Cases

### 1. Malware Triage & Incident Response (DFIR)
* **Instant Packing Detection**: Determine whether an unknown sample is packed, encrypted, or compressed by inspecting the Shannon entropy score and block gradient. Payloads with entropy $\ge 7.20$ or sections with `Virtual Size >> Raw Size` indicate runtime unpacking or process hollowing stubs.
* **API Capability Profiling**: Extract imported APIs to identify process injection primitives (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`), anti-debugging checks (`IsDebuggerPresent`, `NtQueryInformationProcess`), and dynamic resolution routines (`GetProcAddress`, `LoadLibraryA`).
* **Imphash IoC Clustering**: Compute Mandiant-standard Import Hashes (`imphash`) to cluster malware variants belonging to the same actor or campaign, even when payloads are recompiled with altered string tables or code layout.

### 2. CI/CD Security Gates & DevSecOps
Enforce binary hardening compliance in your build pipelines. Prevent compilation regressions before artifacts are released:

```bash
# Verify security mitigations on release binary
binlens --json checksec ./build/release/app.exe > checksec.json

# Assert ASLR, DEP/NX, and CFG pass without RWX sections
jq -e '.aslr and .dep_nx and .cfg and (.has_rwx_sections | not)' checksec.json
```

```bash
# Differential regression gate: ensure no mitigations were degraded between builds
binlens --json diff ./build/baseline/app.exe ./build/release/app.exe > diff.json

# Fail if any mitigation transitioned from enabled to disabled
jq -e '[.mitigations_drift[] | select(.status == "degraded")] | length == 0' diff.json
```

### 3. Software Supply-Chain & Build Telemetry Auditing
* **MSVC Rich Header Decoding**: Audit third-party Windows binaries and COTS products to reconstruct their compiler build toolset. The decoded Rich Header identifies exact MSVC compiler builds (e.g. Visual Studio 2013 vs 2022), MASM assembler versions, and linker build IDs.
* **Detecting Tampering & Stolen Headers**: Inconsistencies between the Rich Header toolset records and PE timestamp or compiler characteristics serve as a strong indicator of header spoofing or weaponized binary tampering.

### 4. Binary Differential Auditing (`diff`)
Audit changes between two consecutive software releases (`v1.0.0` vs `v1.0.1`):
* Detect unexpected section additions or deletions.
* Identify newly introduced third-party library imports or dangerous system calls.
* Catch silent security mitigation regressions (e.g. ASLR, DEP, or CFG dropped during refactoring).

### 5. YARA Rule Scanning & Threat Hunting
Scan unknown binaries against signature rules or entire rule directories:
```bash
# Scan a sample against a single rule or recursive directory
binlens yara ./sample.exe ./rules/packers.yar

# Full multi-engine audit + YARA matches in one scan
binlens scan ./sample.exe -r ./rules/
```


---

## Core Capabilities

### 1. Security Mitigation Verification (`checksec`)
Evaluates compilation and linker hardening mechanisms across executable formats:

* **Address Space Layout Randomization (ASLR / PIE)**:
  * **PE**: Evaluates `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` and 64-bit High-Entropy Virtual Address space (`IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`).
  * **ELF**: Evaluates `ET_DYN` object type, `PT_INTERP`, and dynamic flags (`DF_1_PIE`).
* **Data Execution Prevention (DEP / NX)**:
  * **PE**: Verifies `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.
  * **ELF**: Evaluates `PT_GNU_STACK` segment permissions. In accordance with Linux kernel loader semantics, if `PT_GNU_STACK` is absent, the stack defaults to executable (`dep_nx = false`).
* **RELRO (Relocation Read-Only)**:
  * **ELF**: Inspects `PT_GNU_RELRO` and dynamic tags (`DT_BIND_NOW`, `DF_BIND_NOW`, `DF_1_NOW`) to distinguish **Full RELRO** from **Partial RELRO**.
* **Stack Canary & Buffer Security Check**:
  * **ELF**: Detects stack smash protector symbols (`__stack_chk_fail`, `__stack_chk_guard`, `__intel_security_cookie`) across `.dynsym` and `.symtab`.
  * **PE**: Inspects `IMAGE_LOAD_CONFIG_DIRECTORY` for registered MSVC `/GS` buffer security cookies (`SecurityCookie`).
* **FORTIFY_SOURCE**:
  * **ELF**: Identifies fortified glibc runtime functions (`__*_chk`, such as `__printf_chk`, `__memcpy_chk`, `__snprintf_chk`).
* **Runpath & Library Search Security (RPATH / RUNPATH)**:
  * **ELF**: Decodes `DT_RPATH` (tag 15) and `DT_RUNPATH` (tag 29) from dynamic string tables to highlight insecure library hijacking vectors.
* **Control Flow Guard (CFG)**:
  * **PE**: Cross-references `IMAGE_DLLCHARACTERISTICS_GUARD_CF` with `IMAGE_LOAD_CONFIG_DIRECTORY`. Validates registered `GuardCFCheckFunctionPointer` (offset 112 for PE32+, offset 72 for PE32) to prevent flag-only false positives.
* **Structured Exception Handling (SafeSEH / SEH)**:
  * **PE32**: Validates registered exception handlers in Load Configuration (`SEHandlerTable` and `SEHandlerCount`).
  * **PE32+**: Audits table-based structured exception handling (verifying that `IMAGE_DLLCHARACTERISTICS_NO_SEH` is not set).
* **W^X Enforcement (No RWX Sections)**:
  * Scans section headers for concurrently writable and executable characteristics (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` on PE; `SHF_WRITE | SHF_EXECINSTR` on ELF).
* **Authenticode Presence**:
  * Authenticode: Inspects PE Security Data Directory for `WIN_CERTIFICATE` / PKCS#7 SignedData structures (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`), extracts signer certificates and metadata, and computes the 5-phase Authenticode PE image hash (SHA-256, SHA-1, SHA-384, SHA-512) to verify binary integrity against the embedded `SpcIndirectDataContent` digest. (Note: verifies PE image integrity and detects tampering; full external root CA trust-chain / CRL verification is not included).

### 2. Shannon Entropy Heatmap & Packing Detection
* Computes chunked Shannon entropy across configurable intervals (default: 512 bytes).
* Renders an in-terminal distribution bar alongside an 8-bucket frequency histogram, identifying regions of null padding, structured code, text data, and high-entropy packed or encrypted payloads.

### 3. MSVC Rich Header Analysis (Compiler Telemetry)
* Locates and extracts undocumented `@comp.id` records between the DOS stub and NT headers.
* Extracts the 32-bit XOR mask and decodes compiler build IDs, linker versions, and translation unit counts.
* Automatically maps internal build IDs to user-facing Microsoft Visual Studio product names (e.g. Visual Studio 2003 through Visual Studio 2022+).
* Hardened against DoS: encloses parsing within a 4096-byte search boundary and caps parsed records at 256 to defeat cyclic or crafted malformed headers.

### 4. Header, Import, and Export Inspection
* Resolves section headers with virtual addresses, raw offsets, sizes, permissions, and section-specific entropy metrics.
* Resolves Import Address Tables (IAT) across PE and ELF dynamic symbol tables with loop caps against corrupted structures.
* Computes normalized Import Hash (**Imphash**) compliant with the Mandiant standard, including ordinal import notation (`.ord<number>`).
* Extracts and indexes exported symbols with ordinal numbers and relative virtual addresses (RVA) without artificial 256 truncation.

### 5. Binary Differential Analysis (`diff`)
Compares two executable binaries side-by-side:
* Tracks file size and overall entropy variance.
* Detects section additions, deletions, and layout modifications.
* Highlights differences in imported dependencies and symbols.
* Reports drift in mitigation configurations (`hardened`, `degraded`, `unchanged`).
* Emits a structured `DiffReport` JSON schema when run with `--json`.

### 6. String Extraction with Pattern Classification
* Extracts ASCII and UTF-16LE strings from binary images using length thresholding.
* Employs heuristics to detect and classify:
  * IPv4 addresses and network endpoints.
  * HTTP / HTTPS URLs.
  * Windows Registry keys (`HKLM`, `HKCU`, `Software\...`).
  * Filesystem paths (`C:\...`, `/etc/...`).
  * High-risk system APIs and command execution strings (`cmd.exe`, `powershell.exe`, `VirtualAlloc`).

### 7. Entry Point Disassembly Preview (`disasm`)
* Built on `iced-x86` for robust, high-performance x86 and x86_64 instruction decoding. (Supported for x86/x86_64 PE, ELF, and Mach-O binaries; ARM64 Mach-O binaries display headers, load commands, sections, and mitigations).
* Automatically resolves the binary's Entry Point address to raw file offset across PE (RVA $\to$ Section Raw Data), ELF (VMA $\to$ PT_LOAD segment), and Mach-O (`LC_MAIN` / `LC_UNIXTHREAD`).
* Decodes the initial basic-block execution preamble, formatting addresses, opcode byte streams, and disassembly mnemonics.
* Assists reverse engineers in immediately identifying compiler calling conventions, function frames, packing stubs (`call $+5; pop reg`), and hook trampolines (`jmp`).

---

## Command Reference

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **`scan`** | `binlens scan <FILE> [-a, --all] [-r, --rules <PATH>]` | Full binary report: metadata, entropy heatmap, checksec, sections, imports, Rich Header, entry point disassembly, indicators, and optional YARA rule scanning. Use `--all` to dump full symbol tables. |
| **`yara`** | `binlens yara <FILE> <RULE_PATH> [-a, --all]` | Evaluates target binary against YARA rule file (`.yar`, `.yara`) or recursive directory of rules with match offsets, tags, and metadata. |
| **`disasm`** | `binlens disasm <FILE> [--count <N>]` | Decodes Entry Point instructions for immediate preamble, unpacker, or hook triage (default: 16 instructions). |
| **`checksec`** | `binlens checksec <FILE>` | Security mitigation audit (ASLR, DEP, CFG, SafeSEH, W^X, Authenticode, Stack Canary, FORTIFY, RPATH). |
| **`entropy`** | `binlens entropy <FILE> [--width <N>] [--block-size <BYTES>]` | Computes continuous Shannon entropy distribution and histogram. |
| **`diff`** | `binlens diff <FILE_A> <FILE_B>` | Compares two binaries for mitigation drift, section changes, and import variances. |
| **`strings`** | `binlens strings <FILE> [--min-len <N>] [--all]` | Extracts strings and highlights classified indicators (APIs, registry, paths, URLs). |
| **`--json`** | `binlens --json <SUBCOMMAND> <FILE>` | Emits structured JSON output for CI/CD pipelines and programmatic consumption. |

---

## Installation

### 1. From crates.io (Recommended)
```bash
cargo install binlens
```

### 2. Prebuilt Binaries (GitHub Releases)
Pre-compiled standalone binaries and `SHA256SUMS.txt` checksums for Windows (`x86_64`), Linux (`x86_64`), and macOS (`x86_64`, Apple Silicon `aarch64`) are available on [GitHub Releases](https://github.com/raidshadowmc-sudo/binlens/releases).

```bash
# Verify checksums on Linux / macOS
sha256sum -c SHA256SUMS.txt

# Or PowerShell on Windows
Get-FileHash binlens-windows-x86_64.exe -Algorithm SHA256
```

### 3. Build from Source
Requires Rust 1.85+ (Edition 2024):
```bash
git clone https://github.com/raidshadowmc-sudo/binlens.git
cd binlens
cargo build --release
```
The compiled binary will be located at `target/release/binlens` (or `binlens.exe` on Windows).

---

## Limitations

* **Authenticode Scope**: Validates PE image integrity against embedded `SpcIndirectDataContent` to detect file tampering. Does not evaluate external Windows Catalog (`.cat`) files, full X.509 root CA certificate trust chains, or online CRL/OCSP revocation.
* **Disassembly Architecture**: Entry point disassembly is powered by `iced-x86` and is available for x86/x86_64 binaries. ARM64 Mach-O binaries display headers, load commands, sections, and mitigations without instruction decoding.
* **Dynamic Import Scoping**: ELF and Mach-O dynamic symbol imports are currently mapped in aggregate rather than attributed per individual shared library / dylib.

---

## Architecture & Quality Assurance

* **Memory-Mapped Processing**: Built on `memmap2` to avoid loading complete file contents into heap memory, keeping memory consumption near zero.
* **Memory Safety**: Written entirely in safe Rust with zero `unsafe` blocks in format parsers.
* **Bounds & DoS Hardening**: Strict bounds checking on all RVA and section offset calculations, bounded string parsing (`read_cstring_bounded`), and bounded descriptor/thunk loops to guard against malformed headers, integer overflows, and parser exploitation.
* **Differential Verification**: Validated against industry-standard tooling, including Python `pefile` on genuine Windows system binaries (`cmd.exe`, `notepad.exe`, `kernel32.dll`, `FileHistory.exe`), ensuring parity in imphash calculation, full export resolution, section parsing, Load Config verification, and Rich Header extraction.
* **Automated Test Suite**: Includes 50 automated unit, regression, and cross-platform differential tests:
  ```bash
  cargo test
  ```

---

## Roadmap

- [ ] Windows Catalog (`.cat`) Authenticode validation for system binaries without embedded signatures.
- [ ] Complete X.509 root CA trust-chain and CRL/OCSP revocation verification.
- [ ] ARM64 entry point instruction decoding for Mach-O / Linux ELF binaries.
- [ ] Per-library import symbol attribution for ELF (`DT_NEEDED`) and Mach-O (`LC_LOAD_DYLIB`).
- [ ] Configurable Cargo feature flags (`--no-default-features` for minimal footprint builds without YARA/disasm).

---

## License

This project is licensed under the [MIT License](LICENSE).

