# Changelog

All notable changes to `binlens` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-24

### Documentation & Usability
- Overhauled README with concise hero summary, crates.io/CI badges, and quick-start command.
- Streamlined terminal showcase to key visual hooks (file metadata, entropy heatmap, and checksec).
- Added explicit YARA rule scanning workflows and threat hunting examples.
- Documented explicit feature limitations (Authenticode `.cat` vs embedded, x86/x86_64 disasm, aggregate dynamic imports) and forward-looking roadmap.
- Reordered installation documentation to prioritize `cargo install binlens` from crates.io.

## [0.1.0] - 2026-09-24


### Added
- **Multi-Format Binary Inspection**:
  - Windows Portable Executable (PE32 and PE32+).
  - Linux Executable and Linkable Format (ELF32 and ELF64, Little/Big Endian).
  - macOS / iOS Mach-O (32-bit, 64-bit, and Universal Fat binaries).
- **Security Mitigations Auditor (`checksec`)**:
  - Windows PE: ASLR, High-Entropy VA (64-bit ASLR), DEP/NX, Control Flow Guard (CFG), SafeSEH, Stack Cookie (`/GS`), Authenticode, W^X enforcement.
  - Linux ELF: ASLR / PIE, NX (GNU_STACK), Full / Partial RELRO, Stack Canary, FORTIFY_SOURCE, dynamic RPATH / RUNPATH security audit.
  - macOS Mach-O: PIE, NX / DEP, W^X segment permissions.
- **Authenticode PE Hash & Integrity Verification**:
  - Safe, bounded ASN.1 DER parser for PKCS#7 / CMS `SignedData` structures (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`).
  - Microsoft Authenticode 5-phase PE image hash calculation (SHA-256, SHA-1, SHA-384, SHA-512) excluding checksum and security directory.
  - Verification of calculated image digest against embedded `SpcIndirectDataContent` expected digest with tamper detection (`DigestMatch` vs `DigestMismatch`).
  - X.509 certificate extraction (Subject, Issuer, Serial Number, Validity, Signature Algorithm).
  - RFC 3161 and Authenticode countersignature timestamp parsing.
- **MSVC Rich Header Analysis**:
  - Locates and decrypts `@comp.id` records between DOS stub and NT headers.
  - Extracts XOR mask, build numbers, tool IDs, and translation unit counts.
  - Maps tool IDs to Microsoft Visual Studio product releases (VS 2003 through VS 2022+).
- **Shannon Entropy Analysis & Visualization**:
  - Continuous block-level entropy calculation (configurable block size and terminal width).
  - High-resolution in-terminal heatmap bar and 8-bucket frequency histogram.
  - Packing heuristics detection based on entropy thresholds ($\ge 7.20$).
- **YARA Rule Integration**:
  - Pure-Rust rule compilation and scanning via `boreal`.
  - Supports individual `.yar` / `.yara` files and recursive rule directories with recursion depth and file count bounds.
  - Structured output with rule names, namespaces, tags, metadata, and matched string offsets.
- **Entry Point Disassembly (`disasm`)**:
  - Lightweight basic-block disassembly preview via `iced-x86`.
  - Automatic VMA/RVA to raw file offset resolution across PE, ELF, and Mach-O (`LC_MAIN` / `LC_UNIXTHREAD`).
- **Binary Differential Analysis (`diff`)**:
  - Side-by-side binary comparison detecting size, entropy variance, section changes, import drift, and mitigation hardening/degradation.
- **String Extraction & Classification**:
  - ASCII and UTF-16LE string search with pattern classification (IPv4, URLs, Windows Registry, filesystem paths, suspicious APIs).
- **Automation & Output Formats**:
  - Full support for `--json` flag producing structured schemas for CI/CD integration.
  - High-performance memory-mapped I/O (`memmap2`) with bounds and DoS hardening (capped loops, bounded string reading).
- **Test Suite & CI/CD**:
  - 50 unit, regression, and cross-platform differential tests.
  - GitHub Actions matrix testing across Windows, Ubuntu Linux, and macOS runners with `--locked` reproducible builds.
