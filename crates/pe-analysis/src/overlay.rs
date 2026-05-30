//! Detect appended overlay data in PE files (T1027.009).

use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect data appended after the last PE section's raw bytes.
///
/// An overlay is any data beyond the last section's `pointer_to_raw_data +
/// size_of_raw_data`.  Common in droppers (embedded second-stage payload),
/// self-extracting archives, and resource-appended malware.  The PE loader
/// ignores overlays, making them a zero-overhead hidden-payload channel.
///
/// Returns a single detection when `pe.overlay_offset` is `Some`.
pub fn detect_overlay(pe: &PeFile) -> Vec<PeDetection> {
    let (offset, size) = match (pe.overlay_offset, pe.overlay_size) {
        (Some(off), Some(sz)) => (off, sz),
        _ => return vec![],
    };
    vec![PeDetection {
        kind: PeDetectionKind::OverlayDetected,
        mitre_technique_id: "T1027.009",
        tactic: "Defense Evasion",
        description: format!(
            "Overlay: {size} bytes appended at offset {offset:#x} — possible embedded payload"
        ),
        evidence: vec![format!("overlay_offset={offset:#x} overlay_size={size} bytes")],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    fn make_pe_with_overlay(offset: u64, size: u64) -> pe_core::PeFile {
        let mut pe = make_pe(&[], vec![], &[]);
        pe.overlay_offset = Some(offset);
        pe.overlay_size = Some(size);
        pe.size = (offset + size) as usize;
        pe
    }

    #[test]
    fn overlay_present_detected() {
        let pe = make_pe_with_overlay(0x8000, 0x1000);
        let hits = detect_overlay(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::OverlayDetected);
        assert_eq!(hits[0].mitre_technique_id, "T1027.009");
    }

    #[test]
    fn no_overlay_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_overlay(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_offset() {
        let pe = make_pe_with_overlay(0x6000, 512);
        let hits = detect_overlay(&pe);
        assert!(!hits.is_empty());
        let combined = [hits[0].description.as_str(), &hits[0].evidence.join(" ")].join(" ");
        assert!(
            combined.contains("0x6000") || combined.contains("24576"),
            "offset must appear in evidence or description"
        );
    }

    #[test]
    fn description_mentions_size() {
        let pe = make_pe_with_overlay(0x4000, 2048);
        let hits = detect_overlay(&pe);
        assert!(!hits.is_empty());
        let combined = [hits[0].description.as_str(), &hits[0].evidence.join(" ")].join(" ");
        assert!(
            combined.contains("2048") || combined.contains("2 KiB") || combined.contains("2048 bytes"),
            "description or evidence must mention overlay size"
        );
    }
}
