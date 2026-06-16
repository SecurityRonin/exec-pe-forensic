//! String extraction from PE binary data.
//!
//! Scans raw bytes for runs of printable ASCII characters and UTF-16LE text.
//! Used to find embedded C2 URLs, file paths, registry keys, and IOC strings.

/// Minimum string length (in characters) to include in the output.
pub const MIN_STRING_LEN: usize = 6;

/// Shannon entropy of a byte slice (0.0 – 8.0).
///
/// Returns 0.0 for empty slices.
pub fn compute_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy = 0.0_f32;
    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Extract ASCII strings of at least `min_len` consecutive printable chars from `bytes`.
///
/// "Printable" means bytes 0x20 – 0x7E (space through tilde), matching the
/// behaviour of the classic `strings(1)` utility.
pub fn extract_ascii(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();
    for &b in bytes {
        if b >= 0x20 && b <= 0x7E {
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                results.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push(current);
    }
    results
}

/// Extract UTF-16LE strings of at least `min_len` printable chars from `bytes`.
///
/// Detects runs where every second byte is 0x00 and the preceding byte is a
/// printable ASCII character (0x20 – 0x7E).  This is a fast heuristic; it will
/// not decode arbitrary Unicode code points outside the ASCII range.
pub fn extract_utf16le(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let lo = bytes[i];
        let hi = bytes[i + 1];
        if hi == 0x00 && lo >= 0x20 && lo <= 0x7E {
            current.push(lo as char);
            i += 2;
        } else {
            if current.len() >= min_len {
                results.push(current.clone());
            }
            current.clear();
            i += 1;
        }
    }
    if current.len() >= min_len {
        results.push(current);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_ascii ─────────────────────────────────────────────────────────

    #[test]
    fn ascii_extracts_simple_string() {
        let input = b"Hello, World!";
        let strings = extract_ascii(input, 6);
        assert_eq!(strings, vec!["Hello, World!"]);
    }

    #[test]
    fn ascii_skips_short_runs() {
        let input = b"AB\x00CDEFGH";
        let strings = extract_ascii(input, 6);
        assert!(
            strings.iter().all(|s| s.len() >= 6),
            "all returned strings must be >= min_len chars"
        );
        assert!(
            !strings.iter().any(|s| s == "AB"),
            "two-char run must be filtered"
        );
    }

    #[test]
    fn ascii_empty_input_returns_empty() {
        assert!(extract_ascii(&[], 6).is_empty());
    }

    #[test]
    fn ascii_extracts_multiple_strings() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"VirtualAlloc");
        buf.push(0x00);
        buf.extend_from_slice(b"CreateRemoteThread");
        let strings = extract_ascii(&buf, 6);
        assert!(strings.contains(&"VirtualAlloc".to_string()));
        assert!(strings.contains(&"CreateRemoteThread".to_string()));
    }

    #[test]
    fn ascii_handles_all_non_printable() {
        let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert!(extract_ascii(&input, 6).is_empty());
    }

    #[test]
    fn ascii_returns_exact_min_len_string() {
        let input = b"ABCDEF"; // exactly 6 chars
        let strings = extract_ascii(input, 6);
        assert!(strings.contains(&"ABCDEF".to_string()));
    }

    // ── extract_utf16le ───────────────────────────────────────────────────────

    #[test]
    fn utf16le_extracts_simple_string() {
        // "Hello" as UTF-16LE
        let input: Vec<u8> = "Hello!"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let strings = extract_utf16le(&input, 6);
        assert!(
            strings.contains(&"Hello!".to_string()),
            "UTF-16LE 'Hello!' must be extracted"
        );
    }

    #[test]
    fn utf16le_empty_input_returns_empty() {
        assert!(extract_utf16le(&[], 6).is_empty());
    }

    #[test]
    fn utf16le_skips_short_runs() {
        // "AB" as UTF-16LE — only 2 chars, below min_len
        let input: Vec<u8> = "AB".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let strings = extract_utf16le(&input, 6);
        assert!(
            strings.iter().all(|s| s.len() >= 6),
            "two-char UTF-16LE run must be filtered"
        );
    }

    #[test]
    fn utf16le_mixed_with_binary_extracts_only_strings() {
        let mut buf: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        buf.extend("VirtualAlloc".encode_utf16().flat_map(|c| c.to_le_bytes()));
        buf.extend_from_slice(&[0xFF, 0xFE]);
        let strings = extract_utf16le(&buf, 6);
        assert!(strings.contains(&"VirtualAlloc".to_string()));
    }
}
