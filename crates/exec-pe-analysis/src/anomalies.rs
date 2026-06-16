//! Wrap exec_pe_core structural anomaly detection into PeDetection records (T1027).

use exec_pe_core::{detect_structural_anomalies, PeAnomaly, PeFile};

use crate::{PeDetection, PeDetectionKind};

/// Detect structural PE anomalies indicating obfuscation, packing, or evasion.
///
/// Delegates to [`exec_pe_core::detect_structural_anomalies`] and maps each
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
    detect_structural_anomalies(pe)
        .into_iter()
        .map(|anomaly| {
            let (description, evidence) = describe_anomaly(&anomaly);
            PeDetection {
                kind: PeDetectionKind::PeStructuralAnomaly,
                mitre_technique_id: "T1027",
                tactic: "Defense Evasion",
                description,
                evidence,
            }
        })
        .collect()
}

fn describe_anomaly(anomaly: &PeAnomaly) -> (String, Vec<String>) {
    match anomaly {
        PeAnomaly::WritableExecutableSection { section_name } => (
            format!("W+X section '{section_name}' — writable and executable (packer staging area)"),
            vec![section_name.clone()],
        ),
        PeAnomaly::EntryPointOutsideSections { entry_point_rva } => (
            format!("Entry point {entry_point_rva:#010x} is outside all PE sections"),
            vec![format!("entry_point_rva={entry_point_rva:#010x}")],
        ),
        PeAnomaly::VirtualOnlySection { section_name } => (
            format!("Section '{section_name}' has zero raw size — in-memory decompression target"),
            vec![section_name.clone()],
        ),
        PeAnomaly::LargeVirtualToRawRatio {
            section_name,
            ratio,
        } => (
            format!(
                "Section '{section_name}' virtual/raw ratio {ratio}× — high in-memory expansion"
            ),
            vec![format!("{section_name}: virtual/raw ratio={ratio}")],
        ),
        PeAnomaly::TlsCallbacksPresent { count } => (
            format!("{count} TLS callback(s) — execution before the PE entry point"),
            vec![format!("{count} TLS callback(s) in TLS directory")],
        ),
        PeAnomaly::OverlayPresent { offset, size } => (
            format!("Overlay: {size} bytes at file offset {offset:#x}"),
            vec![format!("overlay offset={offset:#x} size={size}")],
        ),
        PeAnomaly::RichHeaderAbsent => (
            "Rich header absent — compiler fingerprint stripped (anti-attribution)".to_string(),
            vec!["no Rich header found in DOS stub area".to_string()],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_pe, make_section};
    use exec_pe_core::parser::PeSection;

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
