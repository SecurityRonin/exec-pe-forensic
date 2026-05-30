//! Detect ransomware-specific string patterns in PE string tables (T1486).

use forensicnomicon::heuristics::pe::RANSOMWARE_STRING_PATTERNS;
use pe_core::PeFile;

use crate::{PeDetection, PeDetectionKind};

/// Detect ransomware-characteristic strings in the PE string table.
///
/// Matches against [`RANSOMWARE_STRING_PATTERNS`]: encrypted file extension
/// markers (`.wncry`, `.locked`, `.enc`), ransom note keywords
/// (`HOW_TO_DECRYPT`, `YOUR_FILES_ARE_ENCRYPTED`), cryptocurrency payment
/// instructions (`bitcoin`, `.onion`), and dark-web contact strings.
///
/// Returns one detection per matched string.  High confidence when combined
/// with mass file-operation API imports and high-entropy sections.
pub fn detect_ransomware_strings(pe: &PeFile) -> Vec<PeDetection> {
    pe.ascii_strings
        .iter()
        .chain(pe.utf16_strings.iter())
        .filter_map(|s| {
            RANSOMWARE_STRING_PATTERNS
                .iter()
                .find(|&&pat| s.contains(pat))
                .map(|&pat| PeDetection {
                    kind: PeDetectionKind::RansomwareString,
                    mitre_technique_id: "T1486",
                    tactic: "Impact",
                    description: format!("Ransomware pattern '{pat}' in string"),
                    evidence: vec![s.clone()],
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_pe;

    #[test]
    fn wncry_extension_detected() {
        let pe = make_pe(&[], vec![], &["renaming to: important.docx.wncry"]);
        let hits = detect_ransomware_strings(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::RansomwareString);
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn how_to_decrypt_note_detected() {
        let pe = make_pe(&[], vec![], &["HOW_TO_DECRYPT_YOUR_FILES.txt"]);
        assert!(!detect_ransomware_strings(&pe).is_empty());
    }

    #[test]
    fn bitcoin_payment_detected() {
        let pe = make_pe(&[], vec![], &["Send 0.5 bitcoin to the following address"]);
        assert!(!detect_ransomware_strings(&pe).is_empty());
    }

    #[test]
    fn onion_address_detected() {
        let pe = make_pe(&[], vec![], &["Visit xyz123abc.onion for payment instructions"]);
        assert!(!detect_ransomware_strings(&pe).is_empty());
    }

    #[test]
    fn locked_extension_detected() {
        let pe = make_pe(&[], vec![], &["file.docx.locked"]);
        assert!(!detect_ransomware_strings(&pe).is_empty());
    }

    #[test]
    fn qwcrypt_extension_detected() {
        // .qwCrypt is the file extension used by RedCurl/QWCrypt ransomware
        let pe = make_pe(&[], vec![], &["important.docx.qwCrypt"]);
        let hits = detect_ransomware_strings(&pe);
        assert!(!hits.is_empty(), ".qwCrypt extension must be detected as ransomware IOC");
        assert_eq!(hits[0].kind, PeDetectionKind::RansomwareString);
    }

    #[test]
    fn benign_strings_not_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &[
                "Processing file...",
                "Error: access denied",
                "C:\\Users\\user\\Documents\\report.pdf",
            ],
        );
        assert!(detect_ransomware_strings(&pe).is_empty());
    }

    #[test]
    fn empty_string_table_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_ransomware_strings(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_matched_string() {
        let pe = make_pe(&[], vec![], &["All your files have been encrypted"]);
        let hits = detect_ransomware_strings(&pe);
        assert!(!hits.is_empty());
        assert!(!hits[0].evidence.is_empty());
    }
}
