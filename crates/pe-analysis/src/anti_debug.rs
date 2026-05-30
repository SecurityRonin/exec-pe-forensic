//! Detect anti-debugging API imports (T1622).

use forensicnomicon::heuristics::pe::ANTI_DEBUG_IMPORT_NAMES;
use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect imports of known anti-debugging / anti-analysis APIs (T1622).
///
/// Individual hits are informational; three or more distinct anti-debug
/// imports on the same binary are a strong evasion signal.
pub fn detect_anti_debug(pe: &PeFile) -> Vec<PeDetection> {
    todo!("implement anti_debug detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    #[test]
    fn is_debugger_present_detected() {
        let pe = make_pe(&["IsDebuggerPresent"], vec![], &[]);
        let hits = detect_anti_debug(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::AntiDebugImport);
        assert_eq!(hits[0].mitre_technique_id, "T1622");
    }

    #[test]
    fn timing_attack_api_detected() {
        let pe = make_pe(&["QueryPerformanceCounter"], vec![], &[]);
        assert!(!detect_anti_debug(&pe).is_empty());
    }

    #[test]
    fn process_enumeration_api_detected() {
        let pe = make_pe(&["CreateToolhelp32Snapshot", "Process32First"], vec![], &[]);
        let hits = detect_anti_debug(&pe);
        assert_eq!(hits.len(), 2, "one detection per matching import");
    }

    #[test]
    fn window_scanning_api_detected() {
        let pe = make_pe(&["FindWindowA"], vec![], &[]);
        assert!(!detect_anti_debug(&pe).is_empty());
    }

    #[test]
    fn benign_file_api_not_detected() {
        let pe = make_pe(&["CreateFile", "ReadFile", "WriteFile"], vec![], &[]);
        assert!(detect_anti_debug(&pe).is_empty());
    }

    #[test]
    fn empty_imports_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_anti_debug(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_matched_api_name() {
        let pe = make_pe(&["NtQueryInformationProcess"], vec![], &[]);
        let hits = detect_anti_debug(&pe);
        assert!(!hits.is_empty());
        assert!(hits[0].evidence.iter().any(|e| e.contains("NtQueryInformationProcess")));
    }
}
