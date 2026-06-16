//! Detect process hollowing API cluster (T1055.012).

use exec_pe_core::PeFile;
use forensicnomicon::heuristics::pe::PROCESS_HOLLOWING_APIS;

use crate::{PeDetection, PeDetectionKind};

/// Minimum number of hollowing APIs needed to fire a detection.
///
/// Individual APIs like `WriteProcessMemory` appear in legitimate tools;
/// a cluster of 3+ specific to hollowing is high confidence.
pub const HOLLOWING_CLUSTER_THRESHOLD: usize = 3;

/// Detect process hollowing by requiring a cluster of ≥ 3 hollowing-specific APIs.
///
/// Returns a single detection when the threshold is met, with all matched
/// API names in `evidence`.  Returns empty when too few matches exist.
pub fn detect_process_hollowing(pe: &PeFile) -> Vec<PeDetection> {
    let known: std::collections::HashSet<&str> = PROCESS_HOLLOWING_APIS.iter().copied().collect();
    let matched: Vec<String> = pe
        .imports
        .iter()
        .filter(|imp| known.contains(imp.as_str()))
        .cloned()
        .collect();
    if matched.len() < HOLLOWING_CLUSTER_THRESHOLD {
        return vec![];
    }
    vec![PeDetection {
        kind: PeDetectionKind::ProcessHollowing,
        mitre_technique_id: "T1055.012",
        tactic: "Defense Evasion",
        description: format!(
            "Process hollowing API cluster: {} hollowing-specific imports detected",
            matched.len()
        ),
        evidence: matched,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    #[test]
    fn full_hollowing_cluster_detected() {
        let pe = make_pe(
            &[
                "NtUnmapViewOfSection",
                "WriteProcessMemory",
                "SetThreadContext",
                "ResumeThread",
            ],
            vec![],
            &[],
        );
        let hits = detect_process_hollowing(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::ProcessHollowing);
        assert_eq!(hits[0].mitre_technique_id, "T1055.012");
    }

    #[test]
    fn below_threshold_not_detected() {
        // Only 2 hollowing APIs — below the cluster threshold.
        let pe = make_pe(&["NtUnmapViewOfSection", "WriteProcessMemory"], vec![], &[]);
        assert!(
            detect_process_hollowing(&pe).is_empty(),
            "2 APIs is below threshold of 3 — must not fire"
        );
    }

    #[test]
    fn exactly_at_threshold_detected() {
        let pe = make_pe(
            &[
                "NtUnmapViewOfSection",
                "WriteProcessMemory",
                "SetThreadContext",
            ],
            vec![],
            &[],
        );
        assert!(!detect_process_hollowing(&pe).is_empty());
    }

    #[test]
    fn unrelated_imports_not_detected() {
        let pe = make_pe(
            &["CreateFile", "ReadFile", "MessageBoxA", "GetLastError"],
            vec![],
            &[],
        );
        assert!(detect_process_hollowing(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_all_matched_apis() {
        let pe = make_pe(
            &[
                "NtUnmapViewOfSection",
                "WriteProcessMemory",
                "SetThreadContext",
                "ResumeThread",
            ],
            vec![],
            &[],
        );
        let hits = detect_process_hollowing(&pe);
        assert!(!hits.is_empty());
        assert!(hits[0].evidence.len() >= 3);
        assert!(hits[0]
            .evidence
            .iter()
            .any(|e| e.contains("NtUnmapViewOfSection")));
    }

    #[test]
    fn returns_single_detection_for_cluster() {
        let pe = make_pe(
            &[
                "NtUnmapViewOfSection",
                "ZwUnmapViewOfSection",
                "WriteProcessMemory",
                "SetThreadContext",
                "ResumeThread",
                "VirtualAllocEx",
            ],
            vec![],
            &[],
        );
        // Should produce exactly 1 detection (the cluster), not one per API.
        let hits = detect_process_hollowing(&pe);
        assert_eq!(hits.len(), 1, "cluster must produce exactly 1 detection");
    }
}
