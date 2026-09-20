# binlens

A memory-mapped binary inspection, Shannon entropy analyzer, compiler telemetry decoder, and exploit mitigation auditor for Windows Portable Executable (PE) and Linux Executable and Linkable Format (ELF) binaries. Written in safe, dependency-light Rust.

---

## Overview

`binlens` is a standalone, single-binary command-line utility built for security engineers, incident responders, malware analysts, and DevSecOps pipelines. It performs static analysis on executable headers, computes continuous block-level entropy distributions, evaluates operating system exploit mitigations, extracts API import/export tables, decodes undocumented compiler telemetry (MSVC Rich Header), and computes standard import hashes without requiring runtime execution, emulators, or heavy disassembler frameworks.

File parsing is backed by memory-mapped I/O (`memmap2`) with strict offset and bounds validation, avoiding whole-file heap allocations and enabling instant header, checksec, and metadata extraction even on multi-gigabyte files.

---

## Why binlens?

Security auditing and binary triage are frequently fragmented across disparate scripts and platform-dependent tools:

| Feature / Capability | `binlens` | Python `pefile` / scripts | `checksec.sh` |
| :--- | :--- | :--- | :--- |
| **Runtime Dependencies** | None (Single static binary) | Python 3 + `pip` packages | Bash, readelf, objdump |
| **Cross-Platform Support** | Windows & Linux (PE + ELF) | PE only (ELF requires `pyelftools`) | Linux / ELF only |
| **Throughput & Memory** | Zero-copy `memmap2` (minimal heap) | Interpreted overhead (~50–200 ms) | Process spawning overhead |
| **Shannon Entropy Visualizer** | In-terminal heatmap + histogram | Raw float values only | None |
| **MSVC Rich Header Decoding**| Built-in with VS toolset mapping | Raw tuples / requires custom parser| None |
| **Differential Analysis (`diff`)**| Built-in structured delta engine | Manual script required | None |
| **Automated Pipeline Output**| Unified `--json` schema | Custom JSON serializer | Script-dependent JSON |

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

─── [ SECTION HEADERS & INTEGRITY ] ──────────────────────────────────────────
  ┌────────────┬─────────────┬─────────────┬──────────┬─────────┬──────────────┐
  │ Name       │ Virt Size   │ Raw Size    │ Flags    │ Entropy │ Status       │
  ├────────────┼─────────────┼─────────────┼──────────┼─────────┼──────────────┤
  │ .text      │ 0x38066     │ 0x39000     │ R-X      │  6.26   │ NORMAL       │
  │ fothk      │ 0x1000      │ 0x1000      │ R-X      │  0.02   │ NORMAL       │
  │ .rdata     │ 0x9C20      │ 0xA000      │ R--      │  4.93   │ NORMAL       │
  │ .data      │ 0x1C1E0     │ 0x1000      │ RW-      │  0.55   │ NORMAL       │
  │ .pdata     │ 0x234C      │ 0x3000      │ R--      │  4.43   │ NORMAL       │
  │ .didat     │ 0xC0        │ 0x1000      │ RW-      │  0.24   │ NORMAL       │
  │ .rsrc      │ 0x84F8      │ 0x9000      │ R--      │  4.12   │ NORMAL       │
  │ .reloc     │ 0x248       │ 0x1000      │ R--      │  1.13   │ NORMAL       │
  └────────────┴─────────────┴─────────────┴──────────┴─────────┴──────────────┘

─── [ MSVC RICH HEADER (COMPILER TELEMETRY) ] ───────────────────────────────
  Offset: 0x80 | XOR Key: 0xD7965A3A | Records: 11
  ┌──────────────────────┬─────────────┬───────────┬─────────────────────────┐
  │ Tool / Component     │ Build ID    │ Count     │ Identified Version      │
  ├──────────────────────┼─────────────┼───────────┼─────────────────────────┤
  │ Utc1930_C            │ 33145       │ 2         │ Visual Studio 2022 (17.0) │
  │ Utc1800_C            │ 30729       │ 85        │ Visual Studio 2013 (12.0) │
  │ Import0              │ 0           │ 1313      │ -                       │
  │ Unknown              │ 0           │ 1         │ -                       │
  │ Utc1930_LINK         │ 33145       │ 13        │ Visual Studio 2022 (17.0) │
  │ Utc1930_CVTRES       │ 33145       │ 5         │ Visual Studio 2022 (17.0) │
  │ Utc1930_EXPORT       │ 33145       │ 31        │ Visual Studio 2022 (17.0) │
  │ Utc1930_MASM         │ 33145       │ 41        │ Visual Studio 2022 (17.0) │
  │ Utc1920_C            │ 33145       │ 2         │ Visual Studio 2019 (16.0) │
  │ Utc1920_CVTRES       │ 33145       │ 1         │ Visual Studio 2019 (16.0) │
  │ Utc1930_CPP          │ 33145       │ 1         │ Visual Studio 2022 (17.0) │
  └──────────────────────┴─────────────┴───────────┴─────────────────────────┘

─── [ DETECTED SUSPICIOUS INDICATORS & PATTERNS ] ───────────────────────────
  [ALERT] Suspicious API/Command : NtQueryInformationProcess
  [ALERT] Suspicious API/Command : IsDebuggerPresent
  [ALERT] Suspicious API/Command : GetProcAddress
  [ALERT] Suspicious API/Command : VirtualAlloc
  [PATH] Path                   :  :\*
  [REG] Registry               : Software\Microsoft\Windows NT\CurrentVersion
  [REG] Registry               : Software\Policies\Microsoft\Windows\System
  [REG] Registry               : SYSTEM\CurrentControlSet\Control\Session Manager\Environment
```

> **Note on Authenticode in `cmd.exe`**: Core Windows system binaries are signed via external catalog files (`.cat` in `%SystemRoot%\System32\CatRoot`) rather than embedded PKCS#7 certificate tables inside the PE header. `binlens checksec` inspects the PE Security Directory for embedded certificates; catalog-signed binaries accurately indicate that no embedded certificate structure is present.

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
  * **PE32+**: Validates `.pdata` table-based exception handling unless explicitly disabled by `IMAGE_DLLCHARACTERISTICS_NO_SEH`.
* **W^X Enforcement (No RWX Sections)**:
  * Scans section headers for concurrently writable and executable characteristics (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` on PE; `SHF_WRITE | SHF_EXECINSTR` on ELF).
* **Authenticode Presence**:
  * Inspects PE Security Data Directory for `WIN_CERTIFICATE` / PKCS#7 signed data structures (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`).

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
* Built on `iced-x86` for robust, high-performance x86 and x86_64 instruction decoding.
* Automatically resolves the binary's Entry Point address to raw file offset across both PE (RVA $\to$ Section Raw Data) and ELF (VMA $\to$ PT_LOAD segment).
* Decodes the initial basic-block execution preamble, formatting addresses, opcode byte streams, and disassembly mnemonics.
* Assists reverse engineers in immediately identifying compiler calling conventions, function frames, packing stubs (`call $+5; pop reg`), and hook trampolines (`jmp`).

---

## Command Reference

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **`scan`** | `binlens scan <FILE> [-a, --all]` | Full binary report: metadata, entropy heatmap, checksec, sections, imports, Rich Header, entry point disassembly, and indicators. Use `--all` to dump full symbol tables. |
| **`disasm`** | `binlens disasm <FILE> [--count <N>]` | Decodes Entry Point instructions for immediate preamble, unpacker, or hook triage (default: 16 instructions). |
| **`checksec`** | `binlens checksec <FILE>` | Security mitigation audit (ASLR, DEP, CFG, SafeSEH, W^X, Authenticode, Stack Canary, FORTIFY, RPATH). |
| **`entropy`** | `binlens entropy <FILE> [--width <N>] [--block-size <BYTES>]` | Computes continuous Shannon entropy distribution and histogram. |
| **`diff`** | `binlens diff <FILE_A> <FILE_B>` | Compares two binaries for mitigation drift, section changes, and import variances. |
| **`strings`** | `binlens strings <FILE> [--min-len <N>] [--all]` | Extracts strings and highlights classified indicators (APIs, registry, paths, URLs). |
| **`--json`** | `binlens --json <SUBCOMMAND> <FILE>` | Emits structured JSON output for CI/CD pipelines and programmatic consumption. |

---

## Installation

### Prerequisites
* Rust toolchain (version 1.85 or later, Edition 2024)
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

### Install to System PATH
```bash
cargo install --path .
```

---

## Architecture & Quality Assurance

* **Memory-Mapped Processing**: Built on `memmap2` to avoid loading complete file contents into heap memory, keeping memory consumption near zero.
* **Memory Safety**: Written entirely in safe Rust with zero `unsafe` blocks in format parsers.
* **Bounds & DoS Hardening**: Strict bounds checking on all RVA and section offset calculations, bounded string parsing (`read_cstring_bounded`), and bounded descriptor/thunk loops to guard against malformed headers, integer overflows, and parser exploitation.
* **Differential Verification**: Validated against industry-standard tooling, including Python `pefile` on genuine Windows system binaries (`cmd.exe`, `notepad.exe`, `kernel32.dll`, `FileHistory.exe`), ensuring parity in imphash calculation, full export resolution, section parsing, Load Config verification, and Rich Header extraction.
* **Automated Test Suite**: Includes 34 automated unit, regression, and differential tests:
  ```bash
  cargo test
  ```

---

## Roadmap

- [x] MSVC Rich Header Analysis: Parsing and decoding undocumented `@comp.id` compiler and toolset build telemetry.
- [x] Linux ELF Exploit Mitigations: Stack Canary, FORTIFY_SOURCE, and dynamic RPATH / RUNPATH search path auditing.
- [x] Entry Point Disassembly Preview: Integration of lightweight instruction decoding (`iced-x86`) for initial basic-block triage.
- [ ] Mach-O Format Support: 64-bit Mach-O and Universal (Fat) binary parsing for macOS and iOS binaries.
- [ ] Cryptographic Authenticode Validation: Full X.509 certificate chain validation against system trust stores and PE image hash verification.
- [ ] YARA Rule Integration: Native rule compilation and matching against mapped binary memory.

---

## License

This project is licensed under the [MIT License](LICENSE).
