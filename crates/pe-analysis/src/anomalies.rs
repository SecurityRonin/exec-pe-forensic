//! Wrap pe_core structural anomaly detection into PeDetection records (T1027).

use pe_core::{detect_structural_anomalies, PeAnomaly, PeFile};

use crate::{PeDetection, PeDetectionKind};

/// Detect structural PE anomalies indicating obfuscation, packing, or evasion.
///
/// Delegates to [`pe_core::detect_structural_anomalies`] and maps each
/// [`PeAnomaly`] to a [`PeDetection`] with kind [`PeDetectionKind::PeStructuralAnomaly`]
/// and MITRE technique T1027 (Obfuscated Files or Information).
///
/// Anomaly classes detected:
/// - W+X sections (combined write/execute permissions — packer staging area)
/// - Entry point outside all sections (manual mapping / shellcode drop)
/// - Virtual-only sections (`raw_size == 0`, `virtual_size > 0` — in-memory unpack)
/// - Large virtual-to-raw ratio (≥ 10× — high in-memory expansion)
/// - TLS callbacks present (pre-entry execution hook)
/// - Overlay present (appended payload after last section)
/// - Rich header absent on binary > 4 KiB (compiler fingerprint stripped)
pub fn detect_pe_anomalies(pe: &PeFile) -> Vec<PeDetection> {
    todo!("implement pe_anomalies detector")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_pe, make_section};
    use pe_core::parser::PeSection;

    fn wx_section() -> PeSection {
        PeSection {
            name: ".evil".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            virtual_address: 0x1000,
            entropy: 5.0,
            is_executable: true,
            is_writable: true,
            is_readable: true,
        }
    }

    #[test]
    fn wx_section_detected() {
        let pe = make_pe(&[], vec![wx_section()], &[]);
        let hits = detect_pe_anomalies(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::PeStructuralAnomaly);
        assert_eq!(hits[0].mitre_technique_id, "T1027");
    }

    #[test]
    fn clean_pe_not_detected() {
        // Entry point (0x1000) falls inside .text [0x1000, 0x2000), no W+X, no overlay.
        let pe = make_pe(&[], vec![make_section(".text", 5.0, true)], &[]);
        assert!(detect_pe_anomalies(&pe).is_empty());
    }

    #[test]
    fn entry_point_outside_sections_detected() {
        let mut pe = make_pe(&[], vec![make_section(".text", 5.0, true)], &[]);
        pe.entry_point_rva = 0xDEAD_BEEF;
        let hits = detect_pe_anomalies(&pe);
        assert!(!hits.is_empty());
    }

    #[test]
    fn evidence_contains_section_name_for_wx() {
        let pe = make_pe(&[], vec![wx_section()], &[]);
        let hits = detect_pe_anomalies(&pe);
        assert!(!hits.is_empty());
        assert!(
            hits[0].evidence.iter().any(|e| e.contains(".evil")),
            "evidence must name the W+X section"
        );
    }

    #[test]
    fn rich_header_absent_on_large_binary_detected() {
        let mut pe = make_pe(&[], vec![make_section(".text", 5.0, true)], &[]);
        pe.rich_header = None;
        pe.size = 1024 * 1024; // 1 MiB — above the 4 KiB threshold
        let hits = detect_pe_anomalies(&pe);
        assert!(
            hits.iter().any(|h| {
                h.description.to_lowercase().contains("rich")
                    || h.evidence.iter().any(|e| e.to_lowercase().contains("rich"))
            }),
            "must detect absent Rich header on large binary"
        );
    }
}
