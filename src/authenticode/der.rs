use super::oid::{
    TAG_GENERALIZED_TIME, TAG_IA5_STRING, TAG_PRINTABLE_STRING, TAG_UTC_TIME, TAG_UTF8_STRING,
};

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
        let header_len: usize = 2;
        if header_len
            .checked_add(len)
            .is_some_and(|end| end <= slice.len())
        {
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
        if num_len_bytes == 0
            || num_len_bytes > 4
            || 2usize
                .checked_add(num_len_bytes)
                .is_none_or(|end| end > slice.len())
        {
            return None;
        }

        let mut len: usize = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (slice[2 + i] as usize);
        }

        let header_len = 2 + num_len_bytes;
        if header_len
            .checked_add(len)
            .is_some_and(|end| end <= slice.len())
        {
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
    // DoS hardening: cap sequence elements to 4096 to prevent pathological allocations
    while offset < buf.len() && elements.len() < 4096 {
        if let Some(elem) = parse_tlv(&buf[offset..]) {
            let step = elem.total_len();
            if step == 0 {
                break;
            }
            elements.push(elem);
            match offset.checked_add(step) {
                Some(next) => offset = next,
                None => break,
            }
        } else {
            break;
        }
    }
    elements
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
