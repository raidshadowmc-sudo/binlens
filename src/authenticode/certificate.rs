use super::der::{decode_string, decode_time, format_serial_number, parse_sequence};
use super::oid::{
    OID_COMMON_NAME, OID_COUNTRY, OID_LOCALITY, OID_ORG_UNIT, OID_ORGANIZATION, OID_STATE_PROVINCE,
    TAG_CONTEXT_0, TAG_CONTEXT_1, TAG_GENERALIZED_TIME, TAG_OID, TAG_SEQUENCE, TAG_SET,
    TAG_UTC_TIME, decode_oid,
};
use crate::types::CertificateInfo;

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

pub fn find_time_recursive(data: &[u8], depth: usize) -> Option<String> {
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

pub fn find_certificates_recursive(data: &[u8], depth: usize) -> Vec<CertificateInfo> {
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
