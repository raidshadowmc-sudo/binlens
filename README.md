# binlens

A memory-mapped binary inspection, Shannon entropy analysis, and security mitigation auditor for Windows Portable Executable (PE) and Linux Executable and Linkable Format (ELF) binaries.

---

## Overview

`binlens` is a command-line utility implemented in pure Rust designed for security auditing, binary triage, and software supply-chain verification. It performs static analysis on executable headers, computes continuous block-level entropy distributions, evaluates operating system exploit mitigations, extracts API import/export tables, and computes standard import hashes without requiring runtime execution or external disassembler dependencies.

All file parsing is backed by memory-mapped I/O (`memmap2`) and strict offset validation, ensuring zero-copy performance and minimal memory footprint on multi-gigabyte binaries.

---

## Capabilities

### 1. Security Mitigation Verification (`checksec`)
Evaluates compilation and linker hardening mechanisms across executable formats:

* **Address Space Layout Randomization (ASLR / PIE)**:
  * PE: Evaluates `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` and 64-bit High-Entropy Virtual Address space (`IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`).
  * ELF: Evaluates `ET_DYN` object type and dynamic flags (`DF_1_PIE`).
* **Data Execution Prevention (DEP / NX)**:
  * PE: Verifies `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.
  * ELF: Verifies `PT_GNU_STACK` segment permissions (defaults to non-executable stack if segment is absent).
* **Control Flow Guard (CFG)**:
  * PE: Cross-references `IMAGE_DLLCHARACTERISTICS_GUARD_CF` with `IMAGE_LOAD_CONFIG_DIRECTORY`. Verifies valid registration of `GuardCFCheckFunctionPointer` (offset 112 for PE32+, offset 72 for PE32) to prevent flag-only false positives.
* **Structured Exception Handling (SafeSEH / SEH)**:
  * PE32: Validates registered exception handlers in Load Configuration (`SEHandlerTable` and `SEHandlerCount`).
  * PE32+: Validates `.pdata` table-based exception handling unless explicitly disabled by `IMAGE_DLLCHARACTERISTICS_NO_SEH`.
* **W^X Enforcement (No RWX Sections)**:
  * Scans section headers for concurrently writable and executable characteristics (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` on PE; `SHF_WRITE | SHF_EXECINSTR` on ELF).
* **Authenticode Signature Presence**:
  * Inspects PE Security Data Directory for `WIN_CERTIFICATE` / PKCS#7 signed data structures (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`).

### 2. Shannon Entropy Heatmap & Packing Detection
* Computes chunked Shannon entropy across configurable intervals (default: 512 bytes).
* Renders an in-terminal distribution bar alongside an 8-bucket frequency histogram, identifying regions of null padding, structured code, text data, and high-entropy packed or encrypted payloads.

### 3. Header, Import, and Export Inspection
* Resolves section headers with virtual addresses, raw offsets, sizes, permissions, and section-specific entropy metrics.
* Resolves Import Address Tables (IAT) across PE and ELF dynamic symbol tables.
* Computes normalized Import Hash (**Imphash**) compliant with the Mandiant standard, including ordinal import notation (`.ord<number>`).
* Extracts and indexes exported symbols with ordinal numbers and relative virtual addresses (RVA).

### 4. Binary Differential Analysis (`diff`)
Compares two executable binaries side-by-side:
* Tracks file size and overall entropy variance.
* Detects section additions, deletions, and layout modifications.
* Highlights differences in imported dependencies and symbols.
* Reports drift in mitigation configurations (e.g., regressions where ASLR or DEP was dropped in a release build).

### 5. Automated Pipelines (`--json`)
All commands support standardized JSON output for integration into CI/CD security gates, vulnerability scanners, and automated triage workflows.

---

## Current Status and Scope (v0.1.0-alpha)

This project is in active development (`v0.1.0-alpha`). The current implementation provides verified, tested parsing and auditing capabilities with the following scope boundaries:

* **Supported Formats**:
  * Windows PE: `PE32` (x86) and `PE32+` (x64).
  * Linux ELF: `ELF32` and `ELF64`, Little-Endian and Big-Endian architectures.
* **Mitigation Scope**:
  * Authenticode: Verifies existence and header validity of the PKCS#7 certificate table in the Security Directory. Full cryptographic validation of the file digest and root certificate chain traversal is scheduled for v0.2.0.
  * Exception Handling: SafeSEH validates Load Config table presence and handler counts.
* **Strings Extraction**:
  * Utilizes byte scanning with pattern-based heuristics (IPv4, URLs, Windows registry keys, common filesystem paths, and sensitive system APIs).

---

## Installation

### Prerequisites
* Rust toolchain (version 1.80 or later)
* Cargo package manager

### Build from Source
```bash
git clone https://github.com/raidshadowmc-sudo/binlens.git
cd binlens
cargo build --release
```

The compiled binary will be located at:
* Windows: `target/release/binlens.exe`
* Linux: `target/release/binlens`

To install system-wide via Cargo:
```bash
cargo install --path .
```

---

## Usage Examples

### Full Binary Inspection
```bash
binlens scan target_binary.exe
```

### Security Mitigations Audit
```bash
binlens checksec target_binary
```

### Shannon Entropy Analysis
```bash
binlens entropy target_binary --width 80 --block-size 512
```

### Differential Analysis Between Builds
```bash
binlens diff release_v1.exe release_v2.exe
```

### String Extraction with Pattern Classification
```bash
binlens strings target_binary --min-len 6
```

### Machine-Readable Output for Automated Tooling
```bash
binlens --json checksec target_binary.exe
```

---

## Architecture and Quality Assurance

* **Memory-Mapped Processing**: Built on `memmap2` to avoid loading complete file contents into heap memory.
* **Memory Safety**: Written entirely in safe Rust with zero `unsafe` blocks in format parsers.
* **Bounds Verification**: Strict bounds checking on all RVA and section offset calculations to guard against malformed headers and parser exploitation.
* **Differential Verification**: Validated against industry-standard tooling, including Python `pefile` on genuine Windows system binaries (`cmd.exe`, `notepad.exe`, `kernel32.dll`, `FileHistory.exe`), ensuring parity in imphash calculation, section parsing, and Load Config verification.
* **Automated Test Suite**: Includes 14 targeted regression tests covering edge cases in RVA resolution, ordinal formatting, Big-Endian ELF structures, and Load Config layout variations.

---

## Roadmap

> * [x] MSVC Rich Header Analysis: Parsing and decoding undocumented `@comp.id` compiler and toolset build telemetry.
> * [ ] Mach-O Format Support: 64-bit Mach-O and Universal (Fat) binary parsing for macOS and iOS binaries.
> * [ ] Cryptographic Authenticode Validation: Full X.509 certificate chain validation against system trust stores and PE image hash verification.
> * [ ] YARA Rule Integration: Native rule compilation and matching against mapped binary memory.
> * [ ] Entry Point Disassembly Preview: Integration of lightweight instruction decoding (`iced-x86`) for initial basic-block triage.

---

## License

This project is licensed under the [MIT License](LICENSE).
