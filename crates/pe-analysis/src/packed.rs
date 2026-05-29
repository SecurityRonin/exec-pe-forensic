//! Detect packed / protected PE binaries (T1027.002).

use forensicnomicon::heuristics::entropy::PACKED_SECTION_THRESHOLD;
use forensicnomicon::heuristics::pe::PACKED_SECTION_NAMES;
use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect packed or protected PE binaries.
///
/// Fires when any section has a name in [`PACKED_SECTION_NAMES`] **or** when
/// section entropy is ≥ [`PACKED_SECTION_THRESHOLD`] (6.8).
///
/// Returns one detection per suspicious section.
pub fn detect_packed_pe(pe: &PeFile) -> Vec<PeDetection> {
    pe.sections
        .iter()
        .filter(|sec| {
            PACKED_SECTION_NAMES.contains(&sec.name.as_str()) || sec.entropy >= PACKED_SECTION_THRESHOLD
        })
        .map(|sec| {
            let by_name = PACKED_SECTION_NAMES.contains(&sec.name.as_str());
            PeDetection {
                kind: PeDetectionKind::PackedExecutable,
                mitre_technique_id: "T1027.002",
                tactic: "defense-evasion",
                description: format!(
                    "Packed/protected section '{}' (entropy {:.2}{})",
                    sec.name,
                    sec.entropy,
                    if by_name { ", known packer name" } else { "" }
                ),
                evidence: vec![sec.name.clone()],
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_pe, make_section};

    #[test]
    fn upx0_section_detected() {
        let pe = make_pe(&[], vec![make_section("UPX0", 7.8, true)], &[]);
        let hits = detect_packed_pe(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::PackedExecutable);
        assert_eq!(hits[0].mitre_technique_id, "T1027.002");
    }

    #[test]
    fn upx1_section_detected() {
        let pe = make_pe(&[], vec![make_section("UPX1", 7.9, true)], &[]);
        assert!(!detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn mpress_section_detected() {
        let pe = make_pe(&[], vec![make_section("MPRESS1", 7.5, true)], &[]);
        assert!(!detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn themida_section_detected() {
        let pe = make_pe(&[], vec![make_section(".themida", 7.9, true)], &[]);
        assert!(!detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn high_entropy_normal_name_detected() {
        // Entropy 7.5 > threshold even without a packer name
        let pe = make_pe(&[], vec![make_section(".text", 7.5, true)], &[]);
        let hits = detect_packed_pe(&pe);
        assert!(!hits.is_empty(), "high entropy .text must trigger detection");
    }

    #[test]
    fn normal_entropy_normal_name_not_detected() {
        let pe = make_pe(
            &[],
            vec![make_section(".text", 5.2, true), make_section(".data", 3.1, false)],
            &[],
        );
        assert!(detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn empty_sections_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn multiple_packed_sections_each_produce_finding() {
        let pe = make_pe(
            &[],
            vec![
                make_section("UPX0", 7.8, true),
                make_section("UPX1", 7.9, false),
            ],
            &[],
        );
        let hits = detect_packed_pe(&pe);
        assert_eq!(hits.len(), 2, "one finding per packed section");
    }

    #[test]
    fn section_at_exactly_threshold_detected() {
        let pe = make_pe(&[], vec![make_section(".text", PACKED_SECTION_THRESHOLD, true)], &[]);
        assert!(!detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn section_just_below_threshold_not_detected_by_entropy() {
        let below = PACKED_SECTION_THRESHOLD - 0.1;
        let pe = make_pe(&[], vec![make_section(".text", below, true)], &[]);
        assert!(detect_packed_pe(&pe).is_empty());
    }
}
