use crate::pe::RawSection;
use crate::types::{AuthenticodeReport, AuthenticodeStatus, CertificateInfo};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

// ASN.1 DER Tags
#[allow(dead_code)]
const TAG_BOOLEAN: u8 = 0x01;
#[allow(dead_code)]
const TAG_INTEGER: u8 = 0x02;
#[allow(dead_code)]
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
#[allow(dead_code)]
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_1: u8 = 0xa1;

// OID Constants
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_SHA1: &str = "1.3.14.3.2.26";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_MD5: &str = "1.2.840.113549.2.5";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_COUNTERSIGNATURE: &str = "1.2.840.113549.1.9.6";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

// RDN Attribute OIDs
const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ORGANIZATION: &str = "2.5.4.10";
const OID_ORG_UNIT: &str = "2.5.4.11";
const OID_COUNTRY: &str = "2.5.4.6";
const OID_STATE_PROVINCE: &str = "2.5.4.8";
const OID_LOCALITY: &str = "2.5.4.7";

#[derive(Debug, Clone)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub header_len: usize,
    pub data: &'a [u8],
}

impl DerElement<'_> {
    pub fn total_len(&self) -> usize {
        self.header_len + self.data.len()
    }
}

pub fn parse_tlv(slice: &[u8]) -> Option<DerElement<'_>> {
    if slice.len() < 2 {
        return None;
    }
    let tag = slice[0];
    let len_byte = slice[1];

    if (len_byte & 0x80) == 0 {
        // Short form length
        let len = len_byte as usize;
        let header_len = 2;
        if header_len + len <= slice.len() {
            Some(DerElement {
                tag,
                header_len,
                data: &slice[header_len..header_len + len],
            })
        } else {
            None
        }
    } else {
        // Long form length
        let num_len_bytes = (len_byte & 0x7f) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 || 2 + num_len_bytes > slice.len() {
            return None;
        }

        let mut len: usize = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (slice[2 + i] as usize);
        }

        let header_len = 2 + num_len_bytes;
        if header_len + len <= slice.len() {
            Some(DerElement {
                tag,
                header_len,
                data: &slice[header_len..header_len + len],
            })
        } else {
            None
        }
    }
}

pub fn parse_sequence(buf: &[u8]) -> Vec<DerElement<'_>> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if let Some(elem) = parse_tlv(&buf[offset..]) {
            let step = elem.total_len();
            if step == 0 {
                break;
            }
            elements.push(elem);
            offset += step;
        } else {
            break;
        }
    }
    elements
}

pub fn decode_oid(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();

    let first = data[0];
    parts.push((first / 40).to_string());
    parts.push((first % 40).to_string());

    let mut current: u64 = 0;
    for &b in &data[1..] {
        current = (current << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            parts.push(current.to_string());
            current = 0;
        }
    }
    parts.join(".")
}

pub fn decode_string(elem: &DerElement<'_>) -> Option<String> {
    match elem.tag {
        TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => {
            String::from_utf8(elem.data.to_vec()).ok()
        }
        // BMPString (tag 0x1e) is big-endian UTF-16
        0x1e => {
            if (elem.data.len() & 1) != 0 {
                return None;
            }
            let mut u16s = Vec::with_capacity(elem.data.len() / 2);
            let mut i = 0;
            while i + 1 < elem.data.len() {
                u16s.push(u16::from_be_bytes([elem.data[i], elem.data[i + 1]]));
                i += 2;
            }
            String::from_utf16(&u16s).ok()
        }
        _ => None,
    }
}

pub fn decode_time(elem: &DerElement<'_>) -> Option<String> {
    let raw = String::from_utf8_lossy(elem.data);
    let s = raw.trim();

    if elem.tag == TAG_UTC_TIME {
        // Format: YYMMDDHHMMSSZ
        if s.len() >= 12 {
            let year_prefix = if s[0..2].parse::<u32>().unwrap_or(0) >= 50 {
                "19"
            } else {
                "20"
            };
            return Some(format!(
                "{}{}-{}-{} {}:{}:{} UTC",
                year_prefix,
                &s[0..2],
                &s[2..4],
                &s[4..6],
                &s[6..8],
                &s[8..10],
                &s[10..12]
            ));
        }
    } else if elem.tag == TAG_GENERALIZED_TIME {
        // Format: YYYYMMDDHHMMSSZ
        if s.len() >= 14 {
            return Some(format!(
                "{}-{}-{} {}:{}:{} UTC",
                &s[0..4],
                &s[4..6],
                &s[6..8],
                &s[8..10],
                &s[10..12],
                &s[12..14]
            ));
        }
    }
    None
}

pub fn format_serial_number(data: &[u8]) -> String {
    let clean = if data.len() > 1 && data[0] == 0 {
        &data[1..]
    } else {
        data
    };
    clean.iter().map(|b| format!("{:02X}", b)).collect()
}

pub fn parse_rdn_name(name_bytes: &[u8]) -> String {
    let mut parts = Vec::new();
    let rdn_seq = parse_sequence(name_bytes);

    for rdn_set in rdn_seq {
        if rdn_set.tag == TAG_SET {
            let attrs = parse_sequence(rdn_set.data);
            for attr in attrs {
                if attr.tag == TAG_SEQUENCE {
                    let attr_items = parse_sequence(attr.data);
                    if attr_items.len() >= 2 && attr_items[0].tag == TAG_OID {
                        let oid_str = decode_oid(attr_items[0].data);
                        if let Some(val_str) = decode_string(&attr_items[1]) {
                            let prefix = match oid_str.as_str() {
                                OID_COMMON_NAME => "CN",
                                OID_ORGANIZATION => "O",
                                OID_ORG_UNIT => "OU",
                                OID_COUNTRY => "C",
                                OID_STATE_PROVINCE => "ST",
                                OID_LOCALITY => "L",
                                _ => continue,
                            };
                            parts.push(format!("{}={}", prefix, val_str));
                        }
                    }
                }
            }
        }
    }
    parts.join(", ")
}

pub fn parse_x509_certificate(cert_body: &[u8]) -> Option<CertificateInfo> {
    let top_elements = parse_sequence(cert_body);
    if top_elements.is_empty() || top_elements[0].tag != TAG_SEQUENCE {
        return None;
    }

    let tbs_elements = parse_sequence(top_elements[0].data);
    if tbs_elements.len() < 5 {
        return None;
    }

    // Determine element indices (optional version tag [0] shifts other items)
    let has_version = tbs_elements[0].tag == TAG_CONTEXT_0;
    let serial_idx = if has_version { 1 } else { 0 };
    let sig_algo_idx = serial_idx + 1;
    let issuer_idx = sig_algo_idx + 1;
    let validity_idx = issuer_idx + 1;
    let subject_idx = validity_idx + 1;

    if subject_idx >= tbs_elements.len() {
        return None;
    }

    let serial_number = format_serial_number(tbs_elements[serial_idx].data);
    let issuer = parse_rdn_name(tbs_elements[issuer_idx].data);

    let mut valid_from = None;
    let mut valid_to = None;
    if tbs_elements[validity_idx].tag == TAG_SEQUENCE {
        let v_times = parse_sequence(tbs_elements[validity_idx].data);
        if v_times.len() >= 2 {
            valid_from = decode_time(&v_times[0]);
            valid_to = decode_time(&v_times[1]);
        }
    }

    let subject = parse_rdn_name(tbs_elements[subject_idx].data);

    Some(CertificateInfo {
        subject,
        issuer,
        serial_number,
        valid_from,
        valid_to,
    })
}

pub struct AuthenticodeSignedData {
    pub digest_algorithm: String,
    pub expected_digest: String,
    pub certificates: Vec<CertificateInfo>,
    pub signer_serial: Option<String>,
    pub timestamp_signer: Option<CertificateInfo>,
    pub timestamp_time: Option<String>,
    pub program_name: Option<String>,
}

pub fn parse_authenticode_signed_data(pkcs7_data: &[u8]) -> Option<AuthenticodeSignedData> {
    let content_info = parse_tlv(pkcs7_data)?;
    if content_info.tag != TAG_SEQUENCE {
        return None;
    }

    let ci_elements = parse_sequence(content_info.data);
    if ci_elements.len() < 2 {
        return None;
    }

    // Check contentType == id-signedData (1.2.840.113549.1.7.2)
    if ci_elements[0].tag != TAG_OID || decode_oid(ci_elements[0].data) != OID_PKCS7_SIGNED_DATA {
        return None;
    }

    // content [0] EXPLICIT
    if ci_elements[1].tag != TAG_CONTEXT_0 {
        return None;
    }

    let signed_data_tlv = parse_tlv(ci_elements[1].data)?;
    if signed_data_tlv.tag != TAG_SEQUENCE {
        return None;
    }

    let sd_elements = parse_sequence(signed_data_tlv.data);
    if sd_elements.len() < 3 {
        return None;
    }

    // sd_elements:
    // [0] version INTEGER
    // [1] digestAlgorithms SET
    // [2] encapContentInfo SEQUENCE
    // [optional] certificates [0] IMPLICIT
    // [optional] crls [1] IMPLICIT
    // [optional] signerInfos SET

    let mut encap_content_info = None;
    let mut certs_elem = None;
    let mut signer_infos_elem = None;

    for elem in &sd_elements[2..] {
        match elem.tag {
            TAG_SEQUENCE if encap_content_info.is_none() => {
                encap_content_info = Some(elem);
            }
            TAG_CONTEXT_0 => {
                certs_elem = Some(elem);
            }
            TAG_SET => {
                signer_infos_elem = Some(elem);
            }
            _ => {}
        }
    }

    let encap = encap_content_info?;
    let encap_elements = parse_sequence(encap.data);
    if encap_elements.len() < 2 {
        return None;
    }

    // Check eContentType == spcIndirectDataContent (1.3.6.1.4.1.311.2.1.4)
    if encap_elements[0].tag != TAG_OID
        || decode_oid(encap_elements[0].data) != OID_SPC_INDIRECT_DATA
    {
        return None;
    }

    // eContent [0] EXPLICIT
    let spc_indirect_tlv = if encap_elements[1].tag == TAG_CONTEXT_0 {
        parse_tlv(encap_elements[1].data)?
    } else {
        encap_elements[1].clone()
    };

    if spc_indirect_tlv.tag != TAG_SEQUENCE {
        return None;
    }

    let spc_elements = parse_sequence(spc_indirect_tlv.data);
    if spc_elements.len() < 2 {
        return None;
    }

    // spc_elements[1] is DigestInfo: SEQUENCE { digestAlgorithm, digest OCTET STRING }
    let digest_info_tlv = &spc_elements[1];
    if digest_info_tlv.tag != TAG_SEQUENCE {
        return None;
    }

    let di_elements = parse_sequence(digest_info_tlv.data);
    if di_elements.len() < 2 {
        return None;
    }

    // di_elements[0] is AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters? }
    let algo_tlv = &di_elements[0];
    let algo_elements = parse_sequence(algo_tlv.data);
    if algo_elements.is_empty() || algo_elements[0].tag != TAG_OID {
        return None;
    }

    let digest_algo_oid = decode_oid(algo_elements[0].data);
    let digest_algo_name = match digest_algo_oid.as_str() {
        OID_SHA256 => "SHA256",
        OID_SHA1 => "SHA1",
        OID_SHA384 => "SHA384",
        OID_SHA512 => "SHA512",
        OID_MD5 => "MD5",
        _ => "UNKNOWN",
    };

    // di_elements[1] is OCTET STRING expected digest
    if di_elements[1].tag != TAG_OCTET_STRING {
        return None;
    }
    let expected_digest = hex_encode(di_elements[1].data);

    // Extract X.509 certificates
    let mut certificates = Vec::new();
    if let Some(certs) = certs_elem {
        let cert_list = parse_sequence(certs.data);
        for c in cert_list {
            if c.tag == TAG_SEQUENCE {
                if let Some(cert_info) = parse_x509_certificate(c.data) {
                    certificates.push(cert_info);
                }
            }
        }
    }

    // Inspect timestamp information from signerInfos
    let mut signer_serial = None;
    let mut timestamp_signer = None;
    let mut timestamp_time = None;

    if let Some(si_set) = signer_infos_elem {
        let si_list = parse_sequence(si_set.data);
        for si in si_list {
            if si.tag == TAG_SEQUENCE {
                let si_elems = parse_sequence(si.data);
                if si_elems.len() >= 2 && si_elems[1].tag == TAG_SEQUENCE {
                    let sid_elems = parse_sequence(si_elems[1].data);
                    if sid_elems.len() >= 2 {
                        signer_serial = Some(format_serial_number(sid_elems[1].data));
                    }
                }
                for elem in si_elems {
                    if elem.tag == TAG_CONTEXT_0 {
                        // authenticatedAttributes
                        let auth_attrs = parse_sequence(elem.data);
                        for attr in auth_attrs {
                            if attr.tag == TAG_SEQUENCE {
                                let attr_elems = parse_sequence(attr.data);
                                if attr_elems.len() >= 2 && attr_elems[0].tag == TAG_OID {
                                    let attr_oid = decode_oid(attr_elems[0].data);
                                    if attr_oid == OID_SIGNING_TIME && timestamp_time.is_none() {
                                        if let Some(t) = find_time_recursive(attr_elems[1].data, 0)
                                        {
                                            timestamp_time = Some(t);
                                        }
                                    }
                                }
                            }
                        }
                    } else if elem.tag == TAG_CONTEXT_1 {
                        // unauthenticatedAttributes
                        let unauth_attrs = parse_sequence(elem.data);
                        for attr in unauth_attrs {
                            if attr.tag == TAG_SEQUENCE {
                                let attr_elems = parse_sequence(attr.data);
                                if attr_elems.len() >= 2 && attr_elems[0].tag == TAG_OID {
                                    let attr_oid = decode_oid(attr_elems[0].data);
                                    if attr_oid == OID_TST_INFO || attr_oid == OID_COUNTERSIGNATURE
                                    {
                                        if let Some(t) = find_time_recursive(attr_elems[1].data, 0)
                                        {
                                            timestamp_time = Some(t);
                                        }
                                        let ts_certs =
                                            find_certificates_recursive(attr_elems[1].data, 0);
                                        if let Some(c) = ts_certs.first() {
                                            timestamp_signer = Some(c.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Some(AuthenticodeSignedData {
        digest_algorithm: digest_algo_name.to_string(),
        expected_digest,
        certificates,
        signer_serial,
        timestamp_signer,
        timestamp_time,
        program_name: None,
    })
}

fn find_time_recursive(data: &[u8], depth: usize) -> Option<String> {
    if depth > 10 {
        return None;
    }
    let elements = parse_sequence(data);
    for elem in elements {
        if elem.tag == TAG_UTC_TIME || elem.tag == TAG_GENERALIZED_TIME {
            if let Some(t) = decode_time(&elem) {
                return Some(t);
            }
        }
        if elem.tag == TAG_SEQUENCE
            || elem.tag == TAG_SET
            || elem.tag == TAG_CONTEXT_0
            || elem.tag == TAG_CONTEXT_1
        {
            if let Some(t) = find_time_recursive(elem.data, depth + 1) {
                return Some(t);
            }
        }
    }
    None
}

fn find_certificates_recursive(data: &[u8], depth: usize) -> Vec<CertificateInfo> {
    let mut certs = Vec::new();
    if depth > 8 {
        return certs;
    }
    let elements = parse_sequence(data);
    for elem in elements {
        if elem.tag == TAG_SEQUENCE {
            if let Some(c) = parse_x509_certificate(elem.data) {
                certs.push(c);
            }
        }
        if elem.tag == TAG_SEQUENCE
            || elem.tag == TAG_SET
            || elem.tag == TAG_CONTEXT_0
            || elem.tag == TAG_CONTEXT_1
        {
            let mut sub = find_certificates_recursive(elem.data, depth + 1);
            certs.append(&mut sub);
        }
    }
    certs
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
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
    if pe_offset + 0x18 + 68 > data.len() {
        return None;
    }

    let checksum_off = pe_offset + 0x18 + 64;
    let data_dirs_offset = if is_64 {
        pe_offset + 0x18 + 112
    } else {
        pe_offset + 0x18 + 96
    };
    let sec_dir_entry_offset = data_dirs_offset + 32;

    if sec_dir_entry_offset + 8 > data.len() || size_of_headers > data.len() {
        return None;
    }

    // Sort sections strictly in ascending order by pointer_to_raw_data
    let mut sorted_sections = raw_sections.to_vec();
    sorted_sections.sort_by_key(|s| s.pointer_to_raw_data);

    // Initialize appropriate cryptographic hasher
    match algo.to_uppercase().as_str() {
        "SHA256" => {
            let mut hasher = Sha256::new();

            // 1. From byte 0 up to CheckSum
            hasher.update(&data[..checksum_off]);

            // 2. From after CheckSum (4 bytes skipped) up to Security Directory entry
            hasher.update(&data[checksum_off + 4..sec_dir_entry_offset]);

            // 3. From after Security Directory entry (8 bytes skipped) up to size_of_headers
            hasher.update(&data[sec_dir_entry_offset + 8..size_of_headers]);

            // 4. Hash each section's raw data in sorted order
            let mut last_end = size_of_headers;
            for sec in &sorted_sections {
                let start = sec.pointer_to_raw_data as usize;
                let raw_size = sec.size_of_raw_data as usize;
                if start > 0 && raw_size > 0 && start < data.len() {
                    let end = (start + raw_size).min(data.len());
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

            Some(hex_encode(&hasher.finalize()))
        }
        "SHA1" => {
            let mut hasher = Sha1::new();

            hasher.update(&data[..checksum_off]);
            hasher.update(&data[checksum_off + 4..sec_dir_entry_offset]);
            hasher.update(&data[sec_dir_entry_offset + 8..size_of_headers]);

            let mut last_end = size_of_headers;
            for sec in &sorted_sections {
                let start = sec.pointer_to_raw_data as usize;
                let raw_size = sec.size_of_raw_data as usize;
                if start > 0 && raw_size > 0 && start < data.len() {
                    let end = (start + raw_size).min(data.len());
                    hasher.update(&data[start..end]);
                    if end > last_end {
                        last_end = end;
                    }
                }
            }

            let limit = if sec_dir_offset > 0 && sec_dir_offset <= data.len() {
                sec_dir_offset
            } else {
                data.len()
            };

            if limit > last_end {
                hasher.update(&data[last_end..limit]);
            }

            Some(hex_encode(&hasher.finalize()))
        }
        "SHA384" => {
            let mut hasher = Sha384::new();
            hasher.update(&data[..checksum_off]);
            hasher.update(&data[checksum_off + 4..sec_dir_entry_offset]);
            hasher.update(&data[sec_dir_entry_offset + 8..size_of_headers]);

            let mut last_end = size_of_headers;
            for sec in &sorted_sections {
                let start = sec.pointer_to_raw_data as usize;
                let raw_size = sec.size_of_raw_data as usize;
                if start > 0 && raw_size > 0 && start < data.len() {
                    let end = (start + raw_size).min(data.len());
                    hasher.update(&data[start..end]);
                    if end > last_end {
                        last_end = end;
                    }
                }
            }

            let limit = if sec_dir_offset > 0 && sec_dir_offset <= data.len() {
                sec_dir_offset
            } else {
                data.len()
            };

            if limit > last_end {
                hasher.update(&data[last_end..limit]);
            }

            Some(hex_encode(&hasher.finalize()))
        }
        "SHA512" => {
            let mut hasher = Sha512::new();
            hasher.update(&data[..checksum_off]);
            hasher.update(&data[checksum_off + 4..sec_dir_entry_offset]);
            hasher.update(&data[sec_dir_entry_offset + 8..size_of_headers]);

            let mut last_end = size_of_headers;
            for sec in &sorted_sections {
                let start = sec.pointer_to_raw_data as usize;
                let raw_size = sec.size_of_raw_data as usize;
                if start > 0 && raw_size > 0 && start < data.len() {
                    let end = (start + raw_size).min(data.len());
                    hasher.update(&data[start..end]);
                    if end > last_end {
                        last_end = end;
                    }
                }
            }

            let limit = if sec_dir_offset > 0 && sec_dir_offset <= data.len() {
                sec_dir_offset
            } else {
                data.len()
            };

            if limit > last_end {
                hasher.update(&data[last_end..limit]);
            }

            Some(hex_encode(&hasher.finalize()))
        }
        _ => None,
    }
}

pub fn verify_pe_authenticode(
    data: &[u8],
    pe_offset: usize,
    is_64: bool,
    cert_dir_offset: usize,
    cert_dir_size: usize,
    size_of_headers: usize,
    raw_sections: &[RawSection],
) -> Option<AuthenticodeReport> {
    if cert_dir_offset == 0 || cert_dir_size < 8 || cert_dir_offset + cert_dir_size > data.len() {
        return None;
    }

    // Read WIN_CERTIFICATE header:
    // DWORD dwLength
    // WORD  wRevision
    // WORD  wCertificateType
    let dw_length = u32::from_le_bytes([
        data[cert_dir_offset],
        data[cert_dir_offset + 1],
        data[cert_dir_offset + 2],
        data[cert_dir_offset + 3],
    ]) as usize;

    let w_cert_type = u16::from_le_bytes([data[cert_dir_offset + 6], data[cert_dir_offset + 7]]);

    // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
    if w_cert_type != 0x0002 || dw_length < 8 || dw_length > cert_dir_size {
        return Some(AuthenticodeReport {
            is_signed: true,
            status: AuthenticodeStatus::Malformed,
            digest_algorithm: String::new(),
            expected_digest: String::new(),
            calculated_digest: String::new(),
            signer_certificate: None,
            certificates: Vec::new(),
            timestamp_signer: None,
            timestamp_time: None,
            program_name: None,
        });
    }

    let pkcs7_slice = &data[cert_dir_offset + 8..cert_dir_offset + dw_length];
    let signed_data_info = match parse_authenticode_signed_data(pkcs7_slice) {
        Some(info) => info,
        None => {
            return Some(AuthenticodeReport {
                is_signed: true,
                status: AuthenticodeStatus::Malformed,
                digest_algorithm: String::new(),
                expected_digest: String::new(),
                calculated_digest: String::new(),
                signer_certificate: None,
                certificates: Vec::new(),
                timestamp_signer: None,
                timestamp_time: None,
                program_name: None,
            });
        }
    };

    let calculated_digest = calculate_pe_authenticode_hash(
        data,
        pe_offset,
        is_64,
        cert_dir_offset,
        size_of_headers,
        raw_sections,
        &signed_data_info.digest_algorithm,
    )
    .unwrap_or_default();

    let status = if calculated_digest.is_empty() {
        AuthenticodeStatus::Malformed
    } else if calculated_digest.eq_ignore_ascii_case(&signed_data_info.expected_digest) {
        AuthenticodeStatus::Valid
    } else {
        AuthenticodeStatus::HashMismatch
    };

    // Match signer certificate by serial number from SignerInfo, or fallback to first certificate
    let signer_cert = if let Some(ref ser) = signed_data_info.signer_serial {
        signed_data_info
            .certificates
            .iter()
            .find(|c| c.serial_number.eq_ignore_ascii_case(ser))
            .cloned()
            .or_else(|| signed_data_info.certificates.first().cloned())
    } else {
        signed_data_info.certificates.first().cloned()
    };

    Some(AuthenticodeReport {
        is_signed: true,
        status,
        digest_algorithm: signed_data_info.digest_algorithm,
        expected_digest: signed_data_info.expected_digest,
        calculated_digest,
        signer_certificate: signer_cert,
        certificates: signed_data_info.certificates,
        timestamp_signer: signed_data_info.timestamp_signer,
        timestamp_time: signed_data_info.timestamp_time,
        program_name: signed_data_info.program_name,
    })
}
