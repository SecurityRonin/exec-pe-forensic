//! QWCrypt / RedCurl PE IOC detection.

use forensicnomicon::heuristics::pe::QWCRYPT_PE_STRING_IOCS;
use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect known QWCrypt / RedCurl PE IOC strings in the binary's string table.
///
/// Matches against [`QWCRYPT_PE_STRING_IOCS`] (attribution strings embedded in
/// QWCrypt payloads: `.qwCrypt`, `workers.dev`, `excludeVM`, `ZAM64`, etc.).
///
/// High confidence: these strings have no legitimate use in normal software.
pub fn detect_qwcrypt_pe_iocs(pe: &PeFile) -> Vec<PeDetection> {
    let mut detections = Vec::new();
    for string in pe.all_strings() {
        for &ioc in QWCRYPT_PE_STRING_IOCS {
            if string.contains(ioc) {
                detections.push(PeDetection {
                    kind: PeDetectionKind::QWCryptPeIoc,
                    mitre_technique_id: "T1486",
                    tactic: "impact",
                    description: format!("QWCrypt/RedCurl IOC '{ioc}' found in PE string table"),
                    evidence: vec![string.to_string()],
                });
                break;
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
    fn qwcrypt_extension_detected() {
        let pe = make_pe(&[], vec![], &["file encrypted as: document.docx.qwCrypt"]);
        let hits = detect_qwcrypt_pe_iocs(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::QWCryptPeIoc);
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn workers_dev_c2_detected() {
        let pe = make_pe(&[], vec![], &["https://payload.workers.dev/stage2.dll"]);
        assert!(!detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn exclude_vm_flag_detected() {
        let pe = make_pe(&[], vec![], &["--excludeVM GatewayVM key"]);
        assert!(!detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn zam64_driver_name_detected() {
        let pe = make_pe(&[], vec![], &["loading ZAM64.sys for privilege escalation"]);
        assert!(!detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn rbcw_string_detected() {
        let pe = make_pe(&[], vec![], &["C:\\Users\\Public\\rbcw.exe"]);
        assert!(!detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn benign_pe_not_detected() {
        let pe = make_pe(
            &["CreateFile", "ReadFile"],
            vec![],
            &["C:\\Program Files\\MyApp\\app.exe", "Loading configuration..."],
        );
        assert!(detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn empty_pe_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn detection_includes_ioc_as_evidence() {
        let pe = make_pe(&[], vec![], &[".qwCrypt"]);
        let hits = detect_qwcrypt_pe_iocs(&pe);
        assert!(!hits.is_empty());
        assert!(
            hits[0].evidence.iter().any(|e| e.contains(".qwCrypt")),
            "evidence must name the matched IOC"
        );
    }
}
