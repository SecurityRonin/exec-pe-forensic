//! pe-core structural anomalies normalize onto the canonical
//! `forensicnomicon::report` model via the `Observation` producer trait.

use exec_pe_core::PeAnomaly;
use forensicnomicon::report::{Observation, Severity, Source};

#[test]
fn pe_anomaly_converts_to_a_canonical_finding() {
    let a = PeAnomaly::EntryPointOutsideSections {
        entry_point_rva: 0x4_1000,
    };
    let f = a.to_finding(Source {
        analyzer: "exec-pe-forensic".to_string(),
        scope: "PE".to_string(),
        version: None,
    });
    assert_eq!(f.code, "PE-ENTRYPOINT-OOB");
    assert_eq!(f.severity, Some(Severity::High));
    assert!(f.evidence.iter().any(|e| e.field == "entry_point_rva"));
}

#[test]
fn rich_header_absent_is_graded_low_concealment() {
    use forensicnomicon::report::Category;
    let f = PeAnomaly::RichHeaderAbsent.to_finding(Source {
        analyzer: "exec-pe-forensic".to_string(),
        scope: "PE".to_string(),
        version: None,
    });
    assert_eq!(f.code, "PE-RICH-ABSENT");
    assert_eq!(f.severity, Some(Severity::Low));
    assert_eq!(f.category, Category::Concealment);
}

fn src() -> Source {
    Source {
        analyzer: "exec-pe-forensic".to_string(),
        scope: "PE".to_string(),
        version: None,
    }
}

/// Every remaining `PeAnomaly` variant normalizes to its documented canonical
/// finding — exercising the severity/category/code/note/mitre/evidence mapping
/// arms for each. Correctness here is defined by the reporting spec (the code +
/// grade table), so this validates the mapping rule, not just line execution.
#[test]
fn each_anomaly_variant_maps_to_expected_canonical_finding() {
    use forensicnomicon::report::Category;

    // W+X section: Medium / Structure / T1055, evidence names the section.
    let f = PeAnomaly::WritableExecutableSection {
        section_name: ".rwx".to_string(),
    }
    .to_finding(src());
    assert_eq!(f.code, "PE-WX-SECTION");
    assert_eq!(f.severity, Some(Severity::Medium));
    assert_eq!(f.category, Category::Structure);
    assert!(f.note.contains(".rwx"));
    assert!(f.context.external_refs.iter().any(|r| r.id == "T1055"));
    assert!(f.evidence.iter().any(|e| e.field == "section"));

    // Virtual-only section: Medium / Structure / T1027.002.
    let f = PeAnomaly::VirtualOnlySection {
        section_name: ".bss".to_string(),
    }
    .to_finding(src());
    assert_eq!(f.code, "PE-VIRTUAL-ONLY-SECTION");
    assert_eq!(f.severity, Some(Severity::Medium));
    assert!(f.context.external_refs.iter().any(|r| r.id == "T1027.002"));
    assert!(f.evidence.iter().any(|e| e.field == "section"));

    // Large virtual/raw ratio: Medium, evidence carries both section and ratio.
    let f = PeAnomaly::LargeVirtualToRawRatio {
        section_name: ".packed".to_string(),
        ratio: 42,
    }
    .to_finding(src());
    assert_eq!(f.code, "PE-VSIZE-RATIO");
    assert_eq!(f.severity, Some(Severity::Medium));
    assert!(f.context.external_refs.iter().any(|r| r.id == "T1027.002"));
    assert!(f.evidence.iter().any(|e| e.field == "ratio"));
    assert!(f.note.contains("42"));

    // TLS callbacks: Low / Concealment / T1055.005.
    let f = PeAnomaly::TlsCallbacksPresent { count: 3 }.to_finding(src());
    assert_eq!(f.code, "PE-TLS-CALLBACKS");
    assert_eq!(f.severity, Some(Severity::Low));
    assert_eq!(f.category, Category::Concealment);
    assert!(f.context.external_refs.iter().any(|r| r.id == "T1055.005"));
    assert!(f.evidence.iter().any(|e| e.field == "count"));

    // Overlay: Low / Residue / no MITRE technique, evidence has size + offset.
    let f = PeAnomaly::OverlayPresent {
        offset: 0x8000,
        size: 512,
    }
    .to_finding(src());
    assert_eq!(f.code, "PE-OVERLAY");
    assert_eq!(f.severity, Some(Severity::Low));
    assert_eq!(f.category, Category::Residue);
    assert!(f.context.external_refs.is_empty());
    assert!(f.evidence.iter().any(|e| e.field == "size"));
    assert!(f.evidence.iter().any(|e| e.field == "offset"));
}
