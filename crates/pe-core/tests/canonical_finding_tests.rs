//! pe-core structural anomalies normalize onto the canonical
//! `forensicnomicon::report` model via the `Observation` producer trait.

use forensicnomicon::report::{Observation, Severity, Source};
use pe_core::PeAnomaly;

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
