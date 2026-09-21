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
                if let Ok(s) = std::str::from_utf8(&current_ascii) {
                    process_and_classify(s, start_idx, &mut results);
                }
            }
            current_ascii.clear();
        }
    }

    // Process remainder
    if current_ascii.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current_ascii) {
            process_and_classify(s, start_idx, &mut results);
        }
    }

    // 2. Scan UTF-16LE across both even and odd alignment offsets
    for start_align in 0..2 {
        let mut current_utf16 = Vec::new();
        let mut u16_start = 0;
        let mut i = start_align;
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
        if current_utf16.len() >= min_len {
            let s: String = current_utf16.iter().collect();
            process_and_classify(&s, u16_start, &mut results);
        }
    }

    // Sort by offset and deduplicate identical entries at the same offset
    results.sort_by_key(|r| r.offset);
    results.dedup_by(|a, b| a.offset == b.offset && a.value == b.value);

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

    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return Some("URL");
    }

    if is_ipv4(s) {
        return Some("IPv4");
    }

    if lower.starts_with("hkey_")
        || lower.starts_with("software\\")
        || lower.starts_with("system\\currentcontrolset")
    {
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
        "ntqueueapcthread",
        "queueuserapc",
        "ntcreatesection",
        "ntmapviewofsection",
        "setwindowshookex",
        "minidumpwritedump",
        "adjusttokenprivileges",
        "samopenuser",
        "cmd.exe",
        "powershell",
        "vssadmin",
        "certutil",
        "bitsadmin",
        "schtasks",
        "regsvr32",
        "lsass.exe",
        "psexec",
    ];

    // Substring and prefix matching for API variants (e.g. VirtualAllocEx, LoadLibraryA, CreateProcessW)
    if s.len() <= 64 {
        for api in &suspicious_apis {
            if lower == *api
                || lower == format!("{}.exe", api)
                || lower.starts_with(&format!("{}(", api))
                || lower.starts_with(&format!("{}ex", api))
                || lower.starts_with(&format!("{}a", api))
                || lower.starts_with(&format!("{}w", api))
                || lower.starts_with(&format!("{}numa", api))
                || (api.ends_with(".exe") && lower.contains(api))
                || (*api == "powershell" && lower.contains("powershell"))
                || (*api == "cmd.exe" && lower.contains("cmd.exe"))
            {
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

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        // Disallow leading zeroes (e.g. "01.02.03.04") unless single "0"
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        match part.parse::<u8>() {
            Ok(val) => octets[i] = val,
            Err(_) => return false,
        }
    }

    // Heuristics: reject 0.0.0.0, broadcast 255.255.255.255, and unroutable 0.x.x.x
    if octets[0] == 0
        || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
    {
        return false;
    }

    // Heuristic: reject software build/version numbers masquerading as IPs (e.g. 1.0.0.0, 2.0.0.0, 1.2.3.4)
    if octets[0] < 10 && octets[2] == 0 && octets[3] <= 1 {
        return false;
    }
    if octets[0] < 5 && octets[1] < 10 && octets[2] < 10 && octets[3] < 10 {
        return false;
    }

    true
}
