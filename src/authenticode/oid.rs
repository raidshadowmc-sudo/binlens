// ASN.1 DER Tags
#[allow(dead_code)]
pub const TAG_BOOLEAN: u8 = 0x01;
#[allow(dead_code)]
pub const TAG_INTEGER: u8 = 0x02;
#[allow(dead_code)]
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
#[allow(dead_code)]
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_CONTEXT_0: u8 = 0xa0;
pub const TAG_CONTEXT_1: u8 = 0xa1;

// OID Constants
pub const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
pub const OID_SHA1: &str = "1.3.14.3.2.26";
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const OID_MD5: &str = "1.2.840.113549.2.5";
pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
pub const OID_COUNTERSIGNATURE: &str = "1.2.840.113549.1.9.6";
pub const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

// RDN Attribute OIDs
pub const OID_COMMON_NAME: &str = "2.5.4.3";
pub const OID_ORGANIZATION: &str = "2.5.4.10";
pub const OID_ORG_UNIT: &str = "2.5.4.11";
pub const OID_COUNTRY: &str = "2.5.4.6";
pub const OID_STATE_PROVINCE: &str = "2.5.4.8";
pub const OID_LOCALITY: &str = "2.5.4.7";

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
