//! Detect AV exclusion path/registry fragments in PE string tables (T1562.001).

use forensicnomicon::heuristics::pe::AV_EXCLUSION_PATH_FRAGMENTS;
use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect AV product exclusion path or registry key fragments in the PE string table.
///
/// AV-tampering malware (including QWCrypt/RedCurl precursor droppers) frequently
/// embeds the registry paths it will write to as literal strings in .data/.rdata.
/// Matching any fragment from [`AV_EXCLUSION_PATH_FRAGMENTS`] is Medium confidence
/// because some legitimate AV management tools also reference these paths.
///
/// Returns one detection per matched string (deduplicated on fragment).
pub fn detect_av_exclusion_strings(pe: &PeFile) -> Vec<PeDetection> {
    let mut detections = Vec::new();
    for string in pe.all_strings() {
        for &fragment in AV_EXCLUSION_PATH_FRAGMENTS {
            if string.contains(fragment) {
                detections.push(PeDetection {
                    kind: PeDetectionKind::AvExclusionStrings,
                    mitre_technique_id: "T1562.001",
                    tactic: "defense-evasion",
                    description: format!(
                        "AV exclusion fragment '{fragment}' found in PE string table"
                    ),
                    evidence: vec![string.to_string()],
                });
                break; // one detection per string
            }
        }
    }
    detections
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    #[test]
    fn defender_exclusion_path_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &["SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"],
        );
        let hits = detect_av_exclusion_strings(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::AvExclusionStrings);
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn mpcmdrun_pattern_detected() {
        let pe = make_pe(&[], vec![], &["MpCmdRun.exe -RemoveDynamicSignature"]);
        assert!(!detect_av_exclusion_strings(&pe).is_empty());
    }

    #[test]
    fn kaspersky_path_detected() {
        let pe = make_pe(&[], vec![], &["Kaspersky Lab\\AVP\\12.0"]);
        assert!(!detect_av_exclusion_strings(&pe).is_empty());
    }

    #[test]
    fn mcafee_path_detected() {
        let pe = make_pe(&[], vec![], &["McAfee\\Endpoint Security\\Threat Prevention"]);
        assert!(!detect_av_exclusion_strings(&pe).is_empty());
    }

    #[test]
    fn exclude_from_scan_detected() {
        let pe = make_pe(&[], vec![], &["ExcludeFromScan = 1"]);
        assert!(!detect_av_exclusion_strings(&pe).is_empty());
    }

    // QWCrypt-specific AV products (Bitdefender report, Mar 2025)
    #[test]
    fn malwarebytes_exclusion_detected() {
        let pe = make_pe(&[], vec![], &["Malwarebytes\\Anti-Malware\\Quarantine"]);
        let hits = detect_av_exclusion_strings(&pe);
        assert!(!hits.is_empty(), "Malwarebytes path must be detected (QWCrypt exclusion list)");
    }

    #[test]
    fn vipre_exclusion_detected() {
        let pe = make_pe(&[], vec![], &["VIPRE\\Enterprise\\Definitions"]);
        assert!(!detect_av_exclusion_strings(&pe).is_empty(), "VIPRE path must be detected");
    }

    #[test]
    fn sentinelone_exclusion_detected() {
        let pe = make_pe(&[], vec![], &["SentinelOne\\Sentinel Agent"]);
        assert!(!detect_av_exclusion_strings(&pe).is_empty(), "SentinelOne path must be detected");
    }

    #[test]
    fn benign_strings_not_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &[
                "C:\\Windows\\System32\\notepad.exe",
                "Hello, World!",
                "error opening file",
                "https://example.com",
            ],
        );
        assert!(detect_av_exclusion_strings(&pe).is_empty());
    }

    #[test]
    fn empty_strings_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_av_exclusion_strings(&pe).is_empty());
    }

    #[test]
    fn detection_includes_matching_string_as_evidence() {
        let matching = "Windows Defender\\Exclusions\\Processes";
        let pe = make_pe(&[], vec![], &[matching]);
        let hits = detect_av_exclusion_strings(&pe);
        assert!(!hits.is_empty());
        assert!(
            hits[0].evidence.iter().any(|e| e.contains(matching)),
            "evidence must contain the matching string"
        );
    }
}
