pub mod certificate;
pub mod der;
pub mod digest;
pub mod oid;

pub use certificate::{
    find_certificates_recursive, find_time_recursive, parse_rdn_name, parse_x509_certificate,
};
pub use der::{
    DerElement, decode_string, decode_time, format_serial_number, parse_sequence, parse_tlv,
};
pub use digest::{calculate_pe_authenticode_hash, compute_authenticode_hash, hex_encode};
pub use oid::decode_oid;

use crate::pe::RawSection;
use crate::types::{AuthenticodeReport, AuthenticodeStatus, CertificateInfo};
use oid::{
    OID_COUNTERSIGNATURE, OID_MD5, OID_PKCS7_SIGNED_DATA, OID_SHA1, OID_SHA256, OID_SHA384,
    OID_SHA512, OID_SIGNING_TIME, OID_SPC_INDIRECT_DATA, OID_TST_INFO, TAG_CONTEXT_0,
    TAG_CONTEXT_1, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
};

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

pub fn verify_pe_authenticode(
    data: &[u8],
    pe_offset: usize,
    is_64: bool,
    cert_dir_offset: usize,
    cert_dir_size: usize,
    size_of_headers: usize,
    raw_sections: &[RawSection],
) -> Option<AuthenticodeReport> {
    if cert_dir_offset == 0
        || cert_dir_size < 8
        || cert_dir_offset
            .checked_add(cert_dir_size)
            .is_none_or(|end| end > data.len())
    {
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
        AuthenticodeStatus::DigestMatch
    } else {
        AuthenticodeStatus::DigestMismatch
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
