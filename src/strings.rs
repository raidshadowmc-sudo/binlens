use crate::types::CategorizedString;

pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<CategorizedString> {
    let mut results = Vec::new();

    // 1. Scan ASCII strings delimited by null or control chars (< 0x20 except tab/newline)
    let mut current_ascii = Vec::new();
    let mut start_idx = 0;

    for (i, &b) in data.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) {
            if current_ascii.is_empty() {
                start_idx = i;
            }
            current_ascii.push(b);
        } else {
            if current_ascii.len() >= min_len {
                if let Ok(s) = String::from_utf8(current_ascii.clone()) {
                    // Avoid runaway strings by splitting on spaces or checking tokens
                    process_and_classify(&s, start_idx, &mut results);
                }
            }
            current_ascii.clear();
        }
    }

    // Process remainder
    if current_ascii.len() >= min_len {
        if let Ok(s) = String::from_utf8(current_ascii) {
            process_and_classify(&s, start_idx, &mut results);
        }
    }

    // 2. Scan UTF-16LE
    let mut current_utf16 = Vec::new();
    let mut u16_start = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        if b2 == 0 && (0x20..=0x7E).contains(&b1) {
            if current_utf16.is_empty() {
                u16_start = i;
            }
            current_utf16.push(b1 as char);
            i += 2;
        } else {
            if current_utf16.len() >= min_len {
                let s: String = current_utf16.iter().collect();
                process_and_classify(&s, u16_start, &mut results);
            }
            current_utf16.clear();
            i += 2;
        }
    }

    results
}

fn process_and_classify(s: &str, offset: usize, results: &mut Vec<CategorizedString>) {
    if let Some(cat) = classify_string(s) {
        results.push(CategorizedString {
            category: cat.to_string(),
            value: s.to_string(),
            offset,
        });
    }
}

fn classify_string(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();

    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://") {
        return Some("URL");
    }

    if is_ipv4(s) {
        return Some("IPv4");
    }

    if lower.starts_with("hkey_") || lower.starts_with("software\\") || lower.starts_with("system\\currentcontrolset") {
        return Some("Registry");
    }

    if (s.len() > 3 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\'))
        || lower.starts_with("/etc/")
        || lower.starts_with("/usr/")
        || lower.starts_with("/var/")
        || lower.starts_with("/tmp/")
    {
        return Some("Path");
    }

    let suspicious_apis = [
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "loadlibrary",
        "getprocaddress",
        "winexec",
        "shellexecute",
        "createprocess",
        "isdebuggerpresent",
        "ntqueryinformationprocess",
        "cmd.exe",
        "powershell",
        "vssadmin",
        "certutil",
        "bitsadmin",
        "schtasks",
        "regsvr32",
    ];

    // Only tag as suspicious API if string length is bounded (not a giant merged concatenation)
    if s.len() <= 64 {
        for api in &suspicious_apis {
            if lower == *api || lower == format!("{}.exe", api) || lower.starts_with(&format!("{}(", api)) {
                return Some("Suspicious API/Command");
            }
        }
    }

    if s.contains("BEGIN RSA") || s.contains("BEGIN CERTIFICATE") || s.contains("PRIVATE KEY") {
        return Some("Crypto/Certificate");
    }

    None
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    true
}
