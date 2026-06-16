//! Detect TLS (Thread Local Storage) callbacks in PE binaries (T1055.005).

use exec_pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect TLS callbacks — functions that execute before the PE entry point.
///
/// Malware uses TLS callbacks to run anti-debug, anti-VM, and payload
/// decryption code before any user-visible entry point is reached, defeating
/// debuggers that break at the standard entry point.
///
/// Returns a single detection when `pe.tls_callback_count > 0`.
pub fn detect_tls_callbacks(pe: &PeFile) -> Vec<PeDetection> {
    if pe.tls_callback_count == 0 {
        return vec![];
    }
    let n = pe.tls_callback_count;
    vec![PeDetection {
        kind: PeDetectionKind::TlsCallbackPresent,
        mitre_technique_id: "T1055.005",
        tactic: "Defense Evasion",
        description: format!(
            "{n} TLS callback(s) registered — code executes before the PE entry point"
        ),
        evidence: vec![format!(
            "{n} TLS callback(s) registered in the TLS directory"
        )],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    fn make_pe_with_tls(count: usize) -> exec_pe_core::PeFile {
        let mut pe = make_pe(&[], vec![], &[]);
        pe.tls_callback_count = count;
        pe
    }

    #[test]
    fn single_tls_callback_detected() {
        let pe = make_pe_with_tls(1);
        let hits = detect_tls_callbacks(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::TlsCallbackPresent);
        assert_eq!(hits[0].mitre_technique_id, "T1055.005");
    }

    #[test]
    fn multiple_tls_callbacks_detected() {
        let pe = make_pe_with_tls(4);
        let hits = detect_tls_callbacks(&pe);
        assert!(!hits.is_empty());
        assert!(hits[0].description.contains("4"));
    }

    #[test]
    fn zero_callbacks_not_detected() {
        let pe = make_pe_with_tls(0);
        assert!(detect_tls_callbacks(&pe).is_empty());
    }

    #[test]
    fn default_pe_has_no_callbacks() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_tls_callbacks(&pe).is_empty());
    }

    #[test]
    fn evidence_mentions_callback_count() {
        let pe = make_pe_with_tls(3);
        let hits = detect_tls_callbacks(&pe);
        assert!(!hits.is_empty());
        assert!(
            hits[0].evidence.iter().any(|e| e.contains("3")),
            "evidence must mention the number of callbacks"
        );
    }
}
