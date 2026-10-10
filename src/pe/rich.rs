use super::utils::read_u32;
use crate::types::{RichHeaderEntry, RichHeaderInfo};

pub fn get_rich_tool_name(prod_id: u16) -> (&'static str, Option<&'static str>) {
    match prod_id {
        0x0000 => ("Unknown", None),
        0x0001 => ("Import0", None),
        0x0002 => ("Linker510", Some("Visual Studio 97 (5.0)")),
        0x0003 => ("Cvtomf510", Some("Visual Studio 97 (5.0)")),
        0x0004 => ("Linker600", Some("Visual Studio 6.0")),
        0x0005 => ("Cvtomf600", Some("Visual Studio 6.0")),
        0x0006 => ("Cvtres500", Some("Visual Studio 97 (5.0)")),
        0x0007 => ("Utc11_Basic", Some("Visual Studio 97 (5.0)")),
        0x0008 => ("Utc11_C", Some("Visual Studio 97 (5.0)")),
        0x0009 => ("Utc12_Basic", Some("Visual Studio 6.0")),
        0x000a => ("Utc12_C", Some("Visual Studio 6.0")),
        0x000b => ("Utc12_CPP", Some("Visual Studio 6.0")),
        0x000c => ("AliasObj60", Some("Visual Studio 6.0")),
        0x000d => ("VisualBasic60", Some("Visual Basic 6.0")),
        0x000e => ("Masm613", Some("MASM 6.13")),
        0x000f => ("Masm710", Some("MASM 7.10")),
        0x0010 => ("Linker511", Some("Visual Studio 97 SP1")),
        0x0011 => ("Cvtomf511", Some("Visual Studio 97 SP1")),
        0x0012 => ("Masm614", Some("MASM 6.14")),
        0x0013 => ("Linker512", Some("Visual Studio 97 SP2/3")),
        0x0014 => ("Cvtomf512", Some("Visual Studio 97 SP2/3")),
        0x001b => ("Utc13_Basic", Some("Visual Studio .NET 2002")),
        0x001c => ("Utc13_C", Some("Visual Studio .NET 2002")),
        0x001d => ("Utc13_CPP", Some("Visual Studio .NET 2002")),
        0x001e => ("Linker610", Some("Visual Studio 6.0 SP1")),
        0x001f => ("Cvtomf610", Some("Visual Studio 6.0 SP1")),
        0x0020 => ("Linker601", Some("Visual Studio 6.0 SP1")),
        0x0021 => ("Cvtomf601", Some("Visual Studio 6.0 SP1")),
        0x0025 => ("Linker620", Some("Visual Studio 6.0 SP2/3")),
        0x0026 => ("Cvtomf620", Some("Visual Studio 6.0 SP2/3")),
        0x0028 => ("Linker621", Some("Visual Studio 6.0 SP3")),
        0x0029 => ("Cvtomf621", Some("Visual Studio 6.0 SP3")),
        0x002a => ("Masm615", Some("MASM 6.15")),
        0x002b => ("Utc13_LTCG_C", Some("Visual Studio .NET 2002")),
        0x002c => ("Utc13_LTCG_CPP", Some("Visual Studio .NET 2002")),
        0x002d => ("Masm620", Some("MASM 6.20")),
        0x002e => ("ILAsm100", Some(".NET 1.0")),
        0x0036 => ("Implib710", Some("Visual Studio .NET 2003")),
        0x0037 => ("Cvtomf710", Some("Visual Studio .NET 2003")),
        0x0038 => ("Masm700", Some("MASM 7.00")),
        0x0039 => ("Utc1310_C", Some("Visual Studio .NET 2003")),
        0x003a => ("Utc1310_CPP", Some("Visual Studio .NET 2003")),
        0x003b => ("Utc1310_LTCG_C", Some("Visual Studio .NET 2003")),
        0x003c => ("Utc1310_LTCG_CPP", Some("Visual Studio .NET 2003")),
        0x003d => ("Linker622", Some("Visual Studio 6.0 SP4")),
        0x003e => ("Cvtomf622", Some("Visual Studio 6.0 SP4")),
        0x003f => ("Linker700", Some("Visual Studio .NET 2002")),
        0x0040 => ("Export600", Some("Visual Studio 6.0")),
        0x0041 => ("Export700", Some("Visual Studio .NET 2002")),
        0x0042 => ("Cvtres700", Some("Visual Studio .NET 2002")),
        0x0047 => ("Cvtres710", Some("Visual Studio .NET 2003")),
        0x0066 => ("Export710", Some("Visual Studio .NET 2003")),
        0x0067 => ("Linker710", Some("Visual Studio .NET 2003")),
        0x0068 => ("AliasObj710", Some("Visual Studio .NET 2003")),
        0x006d => ("Utc1400_C", Some("Visual Studio 2005 (8.0)")),
        0x006e => ("Utc1400_CPP", Some("Visual Studio 2005 (8.0)")),
        0x006f => ("Utc1400_CVTRES", Some("Visual Studio 2005 (8.0)")),
        0x0070 => ("Utc1400_LINK", Some("Visual Studio 2005 (8.0)")),
        0x007b => ("Utc1500_C", Some("Visual Studio 2008 (9.0)")),
        0x007c => ("Utc1500_CPP", Some("Visual Studio 2008 (9.0)")),
        0x007d => ("Utc1500_CVTRES", Some("Visual Studio 2008 (9.0)")),
        0x007e => ("Utc1500_LINK", Some("Visual Studio 2008 (9.0)")),
        0x0083 => ("Utc1600_C", Some("Visual Studio 2010 (10.0)")),
        0x0084 => ("Utc1600_CPP", Some("Visual Studio 2010 (10.0)")),
        0x0085 => ("Utc1600_CVTRES", Some("Visual Studio 2010 (10.0)")),
        0x0086 => ("Utc1600_LINK", Some("Visual Studio 2010 (10.0)")),
        0x008b => ("Utc1700_C", Some("Visual Studio 2012 (11.0)")),
        0x008c => ("Utc1700_CPP", Some("Visual Studio 2012 (11.0)")),
        0x008d => ("Utc1700_CVTRES", Some("Visual Studio 2012 (11.0)")),
        0x008e => ("Utc1700_LINK", Some("Visual Studio 2012 (11.0)")),
        0x0093 => ("Utc1800_C", Some("Visual Studio 2013 (12.0)")),
        0x0094 => ("Utc1800_CPP", Some("Visual Studio 2013 (12.0)")),
        0x0095 => ("Utc1800_CVTRES", Some("Visual Studio 2013 (12.0)")),
        0x0096 => ("Utc1800_LINK", Some("Visual Studio 2013 (12.0)")),
        0x00aa => ("Utc1900_C", Some("Visual Studio 2015 (14.0)")),
        0x00ab => ("Utc1900_CPP", Some("Visual Studio 2015 (14.0)")),
        0x00ac => ("Utc1900_CVTRES", Some("Visual Studio 2015 (14.0)")),
        0x00ad => ("Utc1900_LINK", Some("Visual Studio 2015 (14.0)")),
        0x00d5 => ("Utc1910_C", Some("Visual Studio 2017 (15.0)")),
        0x00d6 => ("Utc1910_CPP", Some("Visual Studio 2017 (15.0)")),
        0x00d7 => ("Utc1910_CVTRES", Some("Visual Studio 2017 (15.0)")),
        0x00d8 => ("Utc1910_LINK", Some("Visual Studio 2017 (15.0)")),
        0x00fd => ("Utc1920_C", Some("Visual Studio 2019 (16.0)")),
        0x00fe => ("Utc1920_CPP", Some("Visual Studio 2019 (16.0)")),
        0x00ff => ("Utc1920_CVTRES", Some("Visual Studio 2019 (16.0)")),
        0x0100 => ("Utc1920_LINK", Some("Visual Studio 2019 (16.0)")),
        0x0101 => ("Utc1930_C", Some("Visual Studio 2022 (17.0)")),
        0x0102 => ("Utc1930_CPP", Some("Visual Studio 2022 (17.0)")),
        0x0103 => ("Utc1930_CVTRES", Some("Visual Studio 2022 (17.0)")),
        0x0104 => ("Utc1930_LINK", Some("Visual Studio 2022 (17.0)")),
        0x0105 => ("Utc1930_EXPORT", Some("Visual Studio 2022 (17.0)")),
        0x0108 => ("Utc1930_MASM", Some("Visual Studio 2022 (17.0)")),
        _ => ("Unknown", None),
    }
}

pub fn parse_rich_header(data: &[u8], e_lfanew: usize) -> Option<RichHeaderInfo> {
    if e_lfanew < 0x80 || e_lfanew > data.len() {
        return None;
    }

    // Search for "Rich" marker between 0x80 and e_lfanew
    let search_slice = &data[0x80..e_lfanew];
    let rich_rel = search_slice.windows(4).position(|w| w == b"Rich")?;
    let rich_offset = 0x80usize.checked_add(rich_rel)?;

    // After "Rich" marker is the 4-byte XOR key (checksum)
    if rich_offset
        .checked_add(8)
        .is_none_or(|end| end > data.len())
    {
        return None;
    }
    let xor_key = read_u32(data, rich_offset.checked_add(4)?)?;

    // Scan backwards in 4-byte increments looking for "DanS" ^ xor_key
    let dans_magic = 0x536E6144_u32; // "DanS" in little endian
    let mut dans_offset = None;
    let mut curr = rich_offset;
    while curr >= 0x40 + 4 {
        curr -= 4;
        if let Some(val) = read_u32(data, curr) {
            if (val ^ xor_key) == dans_magic {
                dans_offset = Some(curr);
                break;
            }
        }
    }

    let dans_off = dans_offset?;

    // Safety / DoS Guard: Microsoft Rich headers are virtually always under 1-2 KiB (typically 10-40 records).
    // An adversary could craft an inflated DOS stub (e.g. e_lfanew at 16 MiB) with DanS at 0x80
    // and Rich at 16 MiB to trigger massive heap allocations.
    // Impose a strict maximum length (4 KiB) and record cap (256 entries).
    if rich_offset <= dans_off.saturating_add(16) || rich_offset.saturating_sub(dans_off) > 4096 {
        return None;
    }

    const MAX_RICH_RECORDS: usize = 256;

    // The header format:
    // [dans_off]: "DanS" ^ xor_key
    // [dans_off + 4]: 0 ^ xor_key (xor_key itself)
    // [dans_off + 8]: 0 ^ xor_key (xor_key itself)
    // [dans_off + 12]: 0 ^ xor_key (xor_key itself)
    // Followed by pairs of (comp_id ^ xor_key, count ^ xor_key) up to rich_offset
    let mut entries = Vec::new();
    let mut entry_off = dans_off.checked_add(16)?;
    while entry_off
        .checked_add(8)
        .is_some_and(|end| end <= rich_offset)
        && entries.len() < MAX_RICH_RECORDS
    {
        let enc_comp_id = read_u32(data, entry_off)?;
        let enc_count = read_u32(data, entry_off.checked_add(4)?)?;

        let comp_id = enc_comp_id ^ xor_key;
        let count = enc_count ^ xor_key;

        let prod_id = (comp_id >> 16) as u16;
        let build_id = (comp_id & 0xFFFF) as u16;

        let (tool_name, msvc_version) = get_rich_tool_name(prod_id);

        entries.push(RichHeaderEntry {
            comp_id,
            prod_id,
            build_id,
            count,
            tool_name: tool_name.to_string(),
            msvc_version: msvc_version.map(|s| s.to_string()),
        });

        entry_off = match entry_off.checked_add(8) {
            Some(next) => next,
            None => break,
        };
    }

    Some(RichHeaderInfo {
        xor_key,
        raw_offset: dans_off,
        entries,
    })
}
