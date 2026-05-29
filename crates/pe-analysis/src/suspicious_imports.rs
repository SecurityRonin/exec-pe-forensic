//! Detect suspicious API imports (T1055 / T1134 / T1059).

use forensicnomicon::heuristics::pe::SUSPICIOUS_IMPORT_NAMES;
use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect imports of known process-injection / privilege-escalation APIs.
///
/// Returns one [`PeDetection`] per matched import name.
pub fn detect_suspicious_imports(pe: &PeFile) -> Vec<PeDetection> {
    pe.imports
        .iter()
        .filter(|imp| SUSPICIOUS_IMPORT_NAMES.contains(&imp.as_str()))
        .map(|imp| PeDetection {
            kind: PeDetectionKind::SuspiciousImport,
            mitre_technique_id: "T1055",
            tactic: "defense-evasion",
            description: format!("Suspicious API import: '{imp}'"),
            evidence: vec![imp.clone()],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_pe, make_section};

    #[test]
    fn virtualalloc_detected() {
        let pe = make_pe(&["VirtualAlloc"], vec![], &[]);
        let hits = detect_suspicious_imports(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::SuspiciousImport);
        assert_eq!(hits[0].mitre_technique_id, "T1055");
        assert!(hits[0].evidence.contains(&"VirtualAlloc".to_string()));
    }

    #[test]
    fn write_process_memory_detected() {
        let pe = make_pe(&["WriteProcessMemory"], vec![], &[]);
        assert!(!detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn create_remote_thread_detected() {
        let pe = make_pe(&["CreateRemoteThread"], vec![], &[]);
        assert!(!detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn multiple_suspicious_imports_each_produce_finding() {
        let pe = make_pe(
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"],
            vec![],
            &[],
        );
        let hits = detect_suspicious_imports(&pe);
        assert_eq!(hits.len(), 4, "one finding per suspicious import");
    }

    #[test]
    fn benign_file_api_not_detected() {
        let pe = make_pe(
            &["CreateFile", "ReadFile", "WriteFile", "CloseHandle", "GetLastError"],
            vec![],
            &[],
        );
        assert!(detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn empty_imports_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn crypto_api_detected() {
        let pe = make_pe(&["BCryptEncrypt", "BCryptGenerateSymmetricKey"], vec![], &[]);
        let hits = detect_suspicious_imports(&pe);
        assert!(!hits.is_empty(), "BCrypt encryption API must be detected");
    }

    #[test]
    fn shell_execute_detected() {
        let pe = make_pe(&["ShellExecuteW"], vec![], &[]);
        assert!(!detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn network_api_detected() {
        let pe = make_pe(&["WSAStartup", "connect", "send", "recv"], vec![], &[]);
        let hits = detect_suspicious_imports(&pe);
        assert!(!hits.is_empty(), "raw winsock imports must be detected");
    }
}
