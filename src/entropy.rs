use colored::*;

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn calculate_block_entropy(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return vec![];
    }
    data.chunks(block_size).map(calculate_entropy).collect()
}

pub fn entropy_badge(entropy: f64) -> ColoredString {
    if entropy >= 7.2 {
        "LIKELY PACKED / ENCRYPTED".red().bold()
    } else if entropy >= 6.5 {
        "MODERATE / COMPRESSED".yellow().bold()
    } else if entropy >= 4.0 {
        "NORMAL CODE / DATA".green().bold()
    } else {
        "LOW / SPARSE PADDING".cyan()
    }
}

pub fn render_entropy_bar(blocks: &[f64], width: usize) -> String {
    if blocks.is_empty() {
        return String::new();
    }
    let mut bar = String::new();
    let num_samples = width.max(10);
    for i in 0..num_samples {
        let start = (i * blocks.len()) / num_samples;
        let end = (((i + 1) * blocks.len()) / num_samples)
            .max(start + 1)
            .min(blocks.len());
        let slice = &blocks[start..end];
        let avg = if slice.is_empty() {
            0.0
        } else {
            slice.iter().sum::<f64>() / slice.len() as f64
        };

        if avg >= 7.2 {
            bar.push_str(&"█".red().bold().to_string());
        } else if avg >= 6.5 {
            bar.push_str(&"█".yellow().to_string());
        } else if avg >= 4.5 {
            bar.push_str(&"█".green().to_string());
        } else if avg >= 2.0 {
            bar.push_str(&"▒".cyan().to_string());
        } else {
            bar.push_str(&"░".blue().dimmed().to_string());
        }
    }
    bar
}

pub fn render_entropy_histogram(blocks: &[f64]) -> Vec<String> {
    if blocks.is_empty() {
        return vec![];
    }
    let mut bins = [0usize; 8];
    for &val in blocks {
        let idx = (val.floor() as usize).min(7);
        bins[idx] += 1;
    }
    let max_count = *bins.iter().max().unwrap_or(&1);
    let bar_max = 24;

    let labels = [
        "0.0 - 1.0 (Zeroes/Null) ",
        "1.0 - 2.0 (Low Padding) ",
        "2.0 - 3.0 (Sparse Data) ",
        "3.0 - 4.0 (ASCII/Text)  ",
        "4.0 - 5.0 (Dense Text)  ",
        "5.0 - 6.0 (Exec Code)   ",
        "6.0 - 7.0 (Mixed/Dense) ",
        "7.0 - 8.0 (Packed/Crypt)",
    ];

    let mut lines = Vec::new();
    for (i, &count) in bins.iter().enumerate() {
        let bar_len = if max_count > 0 {
            (count * bar_max) / max_count
        } else {
            0
        };
        let bar_str = "█".repeat(bar_len);
        let colored_bar = match i {
            0..=1 => bar_str.blue(),
            2..=4 => bar_str.cyan(),
            5 => bar_str.green(),
            6 => bar_str.yellow(),
            7 => bar_str.red().bold(),
            _ => bar_str.normal(),
        };
        let pct = (count as f64 / blocks.len() as f64) * 100.0;
        lines.push(format!(
            "  {} [{:<24}] {:>5} ({:>5.1}%)",
            labels[i], colored_bar, count, pct
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let zeroes = vec![0u8; 1024];
        let ent = calculate_entropy(&zeroes);
        assert_eq!(ent, 0.0);
    }

    #[test]
    fn test_max_entropy() {
        let mut uniform = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255 {
                uniform.push(b);
            }
        }
        let ent = calculate_entropy(&uniform);
        assert!((ent - 8.0).abs() < 0.0001);
    }

    #[test]
    fn test_ascii_entropy() {
        let text = b"Hello, this is a test text string to calculate Shannon entropy on ASCII data!";
        let ent = calculate_entropy(text);
        assert!(ent > 3.0 && ent < 5.5);
    }

    #[test]
    fn test_block_entropy() {
        let data = vec![0u8; 2048];
        let blocks = calculate_block_entropy(&data, 512);
        assert_eq!(blocks.len(), 4);
        for &b in &blocks {
            assert_eq!(b, 0.0);
        }
    }
}
