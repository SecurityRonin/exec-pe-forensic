//! Detect network / C2 indicator strings in PE string tables (T1071.001).

use exec_pe_core::PeFile;
use forensicnomicon::heuristics::pe::NETWORK_C2_PATTERNS;

use crate::{PeDetection, PeDetectionKind};

/// Detect C2 and network-indicator strings embedded in the PE string table.
///
/// Matches against [`NETWORK_C2_PATTERNS`]: HTTP/Tor scheme prefixes, embedded
/// HTTP request templates, common C2 path fragments, and framework-specific strings.
///
/// Returns one detection per matched string (one pattern match per string).
pub fn detect_network_iocs(pe: &PeFile) -> Vec<PeDetection> {
    pe.ascii_strings
        .iter()
        .chain(pe.utf16_strings.iter())
        .filter_map(|s| {
            NETWORK_C2_PATTERNS
                .iter()
                .find(|&&pat| s.contains(pat))
                .map(|&pat| PeDetection {
                    kind: PeDetectionKind::NetworkC2String,
                    mitre_technique_id: "T1071.001",
                    tactic: "Command and Control",
                    description: format!("C2/network pattern '{pat}' in string"),
                    evidence: vec![s.clone()],
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    #[test]
    fn http_url_detected() {
        let pe = make_pe(&[], vec![], &["http://evil.example.com/gate.php"]);
        let hits = detect_network_iocs(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::NetworkC2String);
        assert_eq!(hits[0].mitre_technique_id, "T1071.001");
    }

    #[test]
    fn https_url_detected() {
        let pe = make_pe(&[], vec![], &["https://c2.attacker.net/beacon"]);
        assert!(!detect_network_iocs(&pe).is_empty());
    }

    #[test]
    fn onion_address_detected() {
        let pe = make_pe(&[], vec![], &["abc123.onion/payment"]);
        assert!(!detect_network_iocs(&pe).is_empty());
    }

    #[test]
    fn user_agent_header_detected() {
        let pe = make_pe(&[], vec![], &["User-Agent: Mozilla/5.0 (compatible)"]);
        assert!(!detect_network_iocs(&pe).is_empty());
    }

    #[test]
    fn meterpreter_string_detected() {
        let pe = make_pe(&[], vec![], &["meterpreter reverse_tcp payload"]);
        assert!(!detect_network_iocs(&pe).is_empty());
    }

    #[test]
    fn cloudflare_workers_c2_detected() {
        // workers.dev is the RedCurl/QWCrypt C2 infrastructure (T1102)
        let pe = make_pe(&[], vec![], &["https://abc123.workers.dev/tasks"]);
        let hits = detect_network_iocs(&pe);
        assert!(!hits.is_empty(), "workers.dev C2 domain must be detected");
    }

    #[test]
    fn benign_strings_not_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &[
                "Loading configuration file...",
                "Error: file not found",
                "C:\\Windows\\System32\\notepad.exe",
            ],
        );
        assert!(detect_network_iocs(&pe).is_empty());
    }

    #[test]
    fn empty_string_table_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_network_iocs(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_matching_string() {
        let matching = "https://c2.evil.example/implant";
        let pe = make_pe(&[], vec![], &[matching]);
        let hits = detect_network_iocs(&pe);
        assert!(!hits.is_empty());
        assert!(hits[0].evidence.iter().any(|e| e.contains("https://")));
    }
}
