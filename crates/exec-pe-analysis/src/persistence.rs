//! Detect persistence mechanism strings in PE data sections (T1547 / T1543).

use exec_pe_core::PeFile;
use forensicnomicon::heuristics::pe::PERSISTENCE_STRING_PATTERNS;

use crate::{PeDetection, PeDetectionKind};

/// Detect registry keys and system paths indicating persistence installation.
///
/// Matches against [`PERSISTENCE_STRING_PATTERNS`]: autorun registry keys,
/// service paths, WMI event subscriptions, COM hijacking keys, and startup
/// folder paths embedded in PE `.data` / `.rdata` sections.
///
/// Returns one detection per matched string.
pub fn detect_persistence_strings(pe: &PeFile) -> Vec<PeDetection> {
    pe.ascii_strings
        .iter()
        .chain(pe.utf16_strings.iter())
        .filter_map(|s| {
            PERSISTENCE_STRING_PATTERNS
                .iter()
                .find(|&&pat| s.contains(pat))
                .map(|&pat| PeDetection {
                    kind: PeDetectionKind::PersistenceString,
                    mitre_technique_id: "T1547.001",
                    tactic: "Persistence",
                    description: format!("Persistence pattern '{pat}' in string"),
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
    fn registry_run_key_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        );
        let hits = detect_persistence_strings(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::PersistenceString);
        assert_eq!(hits[0].mitre_technique_id, "T1547.001");
    }

    #[test]
    fn winlogon_userinit_detected() {
        let pe = make_pe(&[], vec![], &["Winlogon\\Userinit = cmd.exe,"]);
        assert!(!detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn service_registry_key_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &["SYSTEM\\CurrentControlSet\\Services\\EvilSvc"],
        );
        assert!(!detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn scheduled_task_string_detected() {
        let pe = make_pe(&[], vec![], &["schtasks /create /tn EvilTask /tr evil.exe"]);
        assert!(!detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn wmi_event_filter_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &["SELECT * FROM __EventFilter WHERE TargetInstance"],
        );
        assert!(!detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn appinit_dlls_detected() {
        let pe = make_pe(&[], vec![], &["AppInit_DLLs = evil.dll"]);
        assert!(!detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn com_inprocserver32_detected() {
        let pe = make_pe(&[], vec![], &["InprocServer32\\Default = evil.dll"]);
        assert!(!detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn benign_strings_not_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &[
                "Hello World",
                "Loading plugin...",
                "C:\\Program Files\\App\\app.exe",
            ],
        );
        assert!(detect_persistence_strings(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_matched_fragment() {
        let pe = make_pe(&[], vec![], &["CurrentVersion\\Run\\MyMalware = evil.exe"]);
        let hits = detect_persistence_strings(&pe);
        assert!(!hits.is_empty());
        assert!(hits[0]
            .evidence
            .iter()
            .any(|e| e.contains("CurrentVersion\\Run")));
    }
}
