use crate::pe::RawSection;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn compute_authenticode_hash<D: Digest>(
    data: &[u8],
    checksum_off: usize,
    sec_dir_entry_offset: usize,
    size_of_headers: usize,
    sorted_sections: &[RawSection],
    sec_dir_offset: usize,
) -> String {
    let mut hasher = D::new();

    // 1. From byte 0 up to CheckSum
    hasher.update(&data[..checksum_off]);

    // 2. From after CheckSum (4 bytes skipped) up to Security Directory entry
    let after_chk = checksum_off
        .checked_add(4)
        .unwrap_or(sec_dir_entry_offset)
        .min(sec_dir_entry_offset);
    hasher.update(&data[after_chk..sec_dir_entry_offset]);

    // 3. From after Security Directory entry (8 bytes skipped) up to size_of_headers
    let after_sec_dir = sec_dir_entry_offset
        .checked_add(8)
        .unwrap_or(size_of_headers)
        .min(size_of_headers);
    hasher.update(&data[after_sec_dir..size_of_headers]);

    // 4. Hash each section's raw data in sorted order
    let mut last_end = size_of_headers;
    for sec in sorted_sections {
        let start = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        if start > 0 && raw_size > 0 && start < data.len() {
            let end = start
                .checked_add(raw_size)
                .unwrap_or(data.len())
                .min(data.len());
            hasher.update(&data[start..end]);
            if end > last_end {
                last_end = end;
            }
        }
    }

    // 5. Hash trailing bytes before the certificate table (if any)
    let limit = if sec_dir_offset > 0 && sec_dir_offset <= data.len() {
        sec_dir_offset
    } else {
        data.len()
    };

    if limit > last_end {
        hasher.update(&data[last_end..limit]);
    }

    hex_encode(&hasher.finalize())
}

pub fn calculate_pe_authenticode_hash(
    data: &[u8],
    pe_offset: usize,
    is_64: bool,
    sec_dir_offset: usize,
    size_of_headers: usize,
    raw_sections: &[RawSection],
    algo: &str,
) -> Option<String> {
    let opt_hdr_off = pe_offset.checked_add(24)?;
    let checksum_off = opt_hdr_off.checked_add(64)?;
    let sec_dir_entry_offset = if is_64 {
        opt_hdr_off.checked_add(112 + 32)?
    } else {
        opt_hdr_off.checked_add(96 + 32)?
    };

    if checksum_off
        .checked_add(4)
        .is_none_or(|end| end > data.len())
        || sec_dir_entry_offset
            .checked_add(8)
            .is_none_or(|end| end > data.len())
    {
        return None;
    }

    let mut sorted_sections = raw_sections.to_vec();
    sorted_sections.sort_by_key(|s| s.pointer_to_raw_data);

    match algo.to_uppercase().as_str() {
        "SHA256" => Some(compute_authenticode_hash::<Sha256>(
            data,
            checksum_off,
            sec_dir_entry_offset,
            size_of_headers,
            &sorted_sections,
            sec_dir_offset,
        )),
        "SHA1" => Some(compute_authenticode_hash::<Sha1>(
            data,
            checksum_off,
            sec_dir_entry_offset,
            size_of_headers,
            &sorted_sections,
            sec_dir_offset,
        )),
        "SHA384" => Some(compute_authenticode_hash::<Sha384>(
            data,
            checksum_off,
            sec_dir_entry_offset,
            size_of_headers,
            &sorted_sections,
            sec_dir_offset,
        )),
        "SHA512" => Some(compute_authenticode_hash::<Sha512>(
            data,
            checksum_off,
            sec_dir_entry_offset,
            size_of_headers,
            &sorted_sections,
            sec_dir_offset,
        )),
        _ => None,
    }
}
