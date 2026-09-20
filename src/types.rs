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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichHeaderEntry {
    pub comp_id: u32,
    pub prod_id: u16,
    pub build_id: u16,
    pub count: u32,
    pub tool_name: String,
    pub msvc_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichHeaderInfo {
    pub xor_key: u32,
    pub raw_offset: usize,
    pub entries: Vec<RichHeaderEntry>,
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
    pub rich_header: Option<RichHeaderInfo>,
    pub imphash: Option<String>,
    pub interesting_strings: Vec<CategorizedString>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MitigationDrift {
    pub mitigation: String,
    pub before: bool,
    pub after: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SectionDelta {
    pub name: String,
    pub action: String,
    pub size_delta: i64,
    pub entropy_before: Option<f64>,
    pub entropy_after: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportDelta {
    pub dll: String,
    pub action: String,
    pub api_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffReport {
    pub file_a: String,
    pub file_b: String,
    pub size_delta: i64,
    pub entropy_delta: f64,
    pub md5_match: bool,
    pub sha256_match: bool,
    pub mitigations_drift: Vec<MitigationDrift>,
    pub section_deltas: Vec<SectionDelta>,
    pub import_deltas: Vec<ImportDelta>,
}
