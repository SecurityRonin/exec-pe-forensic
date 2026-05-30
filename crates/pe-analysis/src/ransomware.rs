//! Detect ransomware-specific string patterns in PE string tables (T1486).

use forensicnomicon::heuristics::pe::RANSOMWARE_STRING_PATTERNS;
use forensicnomicon::heuristics::ransomware::RANSOM_NOTE_FILENAMES;
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

/// Detect known ransom note filenames embedded in the PE string table.
///
/// Fires when any string in `pe.ascii_strings` or `pe.utf16_strings` has a
/// basename (everything after the last `\` or `/`) that exactly matches
/// (case-insensitive) a filename in [`RANSOM_NOTE_FILENAMES`].  Covers 50+
/// ransomware families whose binaries hardcode the note filename they will drop
/// (e.g. `_readme.txt`, `LockBit_README.txt`, `FILES_ENCRYPTED.txt`).
///
/// Returns one detection per matching string.
pub fn detect_ransom_note_filenames(pe: &PeFile) -> Vec<PeDetection> {
    todo!()
}

fn string_basename(s: &str) -> &str {
    s.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(s)
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

    // --- detect_ransom_note_filenames tests ---

    #[test]
    fn stop_djvu_readme_in_pe_strings_detected() {
        let pe = make_pe(&[], vec![], &["C:\\drop\\_readme.txt"]);
        let hits = detect_ransom_note_filenames(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::RansomNoteFilename);
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn lockbit_readme_in_pe_strings_detected() {
        let pe = make_pe(&[], vec![], &["C:\\Windows\\Temp\\LockBit_README.txt"]);
        assert!(!detect_ransom_note_filenames(&pe).is_empty());
    }

    #[test]
    fn qwcrypt_note_in_pe_strings_detected() {
        let pe = make_pe(&[], vec![], &["FILES_ENCRYPTED.txt"]);
        assert!(!detect_ransom_note_filenames(&pe).is_empty());
    }

    #[test]
    fn akira_readme_in_pe_strings_detected() {
        let pe = make_pe(&[], vec![], &["E:\\Backup\\akira_readme.txt"]);
        assert!(!detect_ransom_note_filenames(&pe).is_empty());
    }

    #[test]
    fn note_filename_case_insensitive() {
        let pe = make_pe(&[], vec![], &["_README.TXT"]);
        assert!(!detect_ransom_note_filenames(&pe).is_empty());
    }

    #[test]
    fn benign_filename_in_pe_strings_not_detected() {
        let pe = make_pe(&[], vec![], &["C:\\Users\\alice\\report.docx", "readme.md"]);
        assert!(detect_ransom_note_filenames(&pe).is_empty());
    }

    #[test]
    fn empty_string_table_ransom_note_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_ransom_note_filenames(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_matched_note_filename() {
        let pe = make_pe(&[], vec![], &["HOW_TO_DECRYPT.txt"]);
        let hits = detect_ransom_note_filenames(&pe);
        assert!(!hits.is_empty());
        let combined = hits[0].evidence.join(" ");
        assert!(combined.contains("HOW_TO_DECRYPT.txt"));
    }

    #[test]
    fn utf16_ransom_note_detected() {
        let mut pe = make_pe(&[], vec![], &[]);
        pe.utf16_strings.push("C:\\ProgramData\\_readme.txt".to_string());
        assert!(!detect_ransom_note_filenames(&pe).is_empty());
    }
}
