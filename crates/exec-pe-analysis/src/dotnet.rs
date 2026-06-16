//! Detect suspicious .NET CLR characteristics in PE binaries (T1027).

use exec_pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect suspicious combinations of .NET CLR presence with evasion indicators.
///
/// A managed (.NET) binary with TLS callbacks is anomalous: the CLR normally
/// owns the TLS directory.  Native TLS callbacks alongside a CLR data directory
/// indicate a mixed-mode loader or native anti-debug shim layered under managed code.
///
/// A managed binary with an overlay is suspicious: the CLR loader ignores appended
/// data, making overlays a zero-overhead dropper channel in .NET malware.
///
/// Returns one detection per suspicious combination.  A clean .NET binary without
/// these characteristics produces no detections.
pub fn detect_dotnet_anomalies(pe: &PeFile) -> Vec<PeDetection> {
    if !pe.is_dotnet {
        return vec![];
    }
    let mut results = Vec::new();
    if pe.tls_callback_count > 0 {
        let n = pe.tls_callback_count;
        results.push(PeDetection {
            kind: PeDetectionKind::DotNetAnomaly,
            mitre_technique_id: "T1027",
            tactic: "Defense Evasion",
            description: format!(
                "Managed .NET binary has {n} native TLS callback(s) — mixed-mode anti-debug shim"
            ),
            evidence: vec![format!(
                "{n} native TLS callback(s) alongside CLR data directory"
            )],
        });
    }
    if let (Some(offset), Some(size)) = (pe.overlay_offset, pe.overlay_size) {
        results.push(PeDetection {
            kind: PeDetectionKind::DotNetAnomaly,
            mitre_technique_id: "T1027",
            tactic: "Defense Evasion",
            description: format!(
                "Managed .NET binary has {size} bytes overlay at {offset:#x} — dropper channel"
            ),
            evidence: vec![format!(
                "overlay_offset={offset:#x} size={size} in .NET binary"
            )],
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    fn make_dotnet_pe() -> exec_pe_core::PeFile {
        let mut pe = make_pe(&[], vec![], &[]);
        pe.is_dotnet = true;
        pe
    }

    #[test]
    fn dotnet_with_tls_callbacks_detected() {
        let mut pe = make_dotnet_pe();
        pe.tls_callback_count = 2;
        let hits = detect_dotnet_anomalies(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::DotNetAnomaly);
        assert_eq!(hits[0].mitre_technique_id, "T1027");
    }

    #[test]
    fn dotnet_with_overlay_detected() {
        let mut pe = make_dotnet_pe();
        pe.overlay_offset = Some(0x8000);
        pe.overlay_size = Some(1024);
        let hits = detect_dotnet_anomalies(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::DotNetAnomaly);
    }

    #[test]
    fn clean_dotnet_not_detected() {
        let pe = make_dotnet_pe();
        assert!(detect_dotnet_anomalies(&pe).is_empty());
    }

    #[test]
    fn non_dotnet_with_tls_not_detected_here() {
        // tls_callbacks.rs handles native TLS; dotnet.rs only fires on .NET binaries.
        let mut pe = make_pe(&[], vec![], &[]);
        pe.tls_callback_count = 3;
        assert!(detect_dotnet_anomalies(&pe).is_empty());
    }

    #[test]
    fn evidence_mentions_tls_count() {
        let mut pe = make_dotnet_pe();
        pe.tls_callback_count = 4;
        let hits = detect_dotnet_anomalies(&pe);
        assert!(!hits.is_empty());
        let combined = [hits[0].description.as_str(), &hits[0].evidence.join(" ")].join(" ");
        assert!(
            combined.contains("4"),
            "evidence or description must mention the callback count (4)"
        );
    }

    #[test]
    fn both_tls_and_overlay_produce_two_detections() {
        let mut pe = make_dotnet_pe();
        pe.tls_callback_count = 1;
        pe.overlay_offset = Some(0x5000);
        pe.overlay_size = Some(512);
        let hits = detect_dotnet_anomalies(&pe);
        assert_eq!(hits.len(), 2, "one detection per suspicious combination");
    }
}
