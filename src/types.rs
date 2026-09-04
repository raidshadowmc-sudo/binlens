use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BinaryFormat {
    PE32,
    PE64,
    ELF32,
    ELF64,
    MachO,
    Unknown(String),
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::PE32 => write!(f, "PE32 (32-bit Windows)"),
            BinaryFormat::PE64 => write!(f, "PE32+ (64-bit Windows)"),
            BinaryFormat::ELF32 => write!(f, "ELF32 (32-bit Unix/Linux)"),
            BinaryFormat::ELF64 => write!(f, "ELF64 (64-bit Unix/Linux)"),
            BinaryFormat::MachO => write!(f, "Mach-O (macOS)"),
            BinaryFormat::Unknown(desc) => write!(f, "Unknown ({})", desc),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub is_rwx: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub name: String,
    pub ordinal: u32,
    pub rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SecurityMitigations {
    pub aslr: bool,
    pub high_entropy_va: bool,
    pub dep_nx: bool,
    pub seh: bool,
    pub cfg: bool,
    pub authenticode_signed: bool,
    pub has_rwx_sections: bool,
    pub pie: bool,
    pub relro: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedString {
    pub category: String,
    pub value: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryReport {
    pub file_name: String,
    pub file_size: u64,
    pub md5: String,
    pub sha256: String,
    pub format: BinaryFormat,
    pub architecture: String,
    pub subsystem: String,
    pub entry_point: u64,
    pub overall_entropy: f64,
    pub is_likely_packed: bool,
    pub mitigations: SecurityMitigations,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub imphash: Option<String>,
    pub interesting_strings: Vec<CategorizedString>,
}
