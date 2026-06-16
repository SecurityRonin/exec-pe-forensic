//! Detect hardcoded credential and secret patterns in PE string tables (T1552.001).

use exec_pe_core::PeFile;
use forensicnomicon::heuristics::pe::CREDENTIAL_PATTERNS;

use crate::{PeDetection, PeDetectionKind};

/// Detect hardcoded credentials, API keys, and secret material in PE string tables.
///
/// Matches against [`CREDENTIAL_PATTERNS`]: password/token assignment patterns,
/// cloud API key prefixes, HTTP auth headers, PEM-encoded key material markers,
/// and database connection string fragments.
///
/// Returns one detection per matched string.
pub fn detect_credential_strings(pe: &PeFile) -> Vec<PeDetection> {
    pe.ascii_strings
        .iter()
        .chain(pe.utf16_strings.iter())
        .filter_map(|s| {
            CREDENTIAL_PATTERNS
                .iter()
                .find(|&&pat| s.contains(pat))
                .map(|&pat| PeDetection {
                    kind: PeDetectionKind::CredentialString,
                    mitre_technique_id: "T1552.001",
                    tactic: "Credential Access",
                    description: format!("Credential pattern '{pat}' in string"),
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
    fn password_assignment_detected() {
        let pe = make_pe(&[], vec![], &["password=SuperSecret123!"]);
        let hits = detect_credential_strings(&pe);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, PeDetectionKind::CredentialString);
        assert_eq!(hits[0].mitre_technique_id, "T1552.001");
    }

    #[test]
    fn aws_access_key_detected() {
        let pe = make_pe(&[], vec![], &["AKIAIOSFODNN7EXAMPLE"]);
        assert!(!detect_credential_strings(&pe).is_empty());
    }

    #[test]
    fn api_key_detected() {
        let pe = make_pe(&[], vec![], &["api_key=d3adb33fdeadbeef01234567"]);
        assert!(!detect_credential_strings(&pe).is_empty());
    }

    #[test]
    fn pem_key_header_detected() {
        let pe = make_pe(&[], vec![], &["-----BEGIN RSA PRIVATE KEY-----"]);
        assert!(!detect_credential_strings(&pe).is_empty());
    }

    #[test]
    fn bearer_token_header_detected() {
        let pe = make_pe(&[], vec![], &["Authorization: Bearer eyJhbGciOiJSUzI1NiJ9"]);
        assert!(!detect_credential_strings(&pe).is_empty());
    }

    #[test]
    fn benign_strings_not_detected() {
        let pe = make_pe(
            &[],
            vec![],
            &[
                "Loading configuration...",
                "Error: invalid argument",
                "C:\\Windows\\System32\\kernel32.dll",
            ],
        );
        assert!(detect_credential_strings(&pe).is_empty());
    }

    #[test]
    fn empty_string_table_not_detected() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_credential_strings(&pe).is_empty());
    }

    #[test]
    fn evidence_contains_matched_string() {
        let pe = make_pe(&[], vec![], &["secret=my_private_secret_value"]);
        let hits = detect_credential_strings(&pe);
        assert!(!hits.is_empty());
        assert!(!hits[0].evidence.is_empty());
    }
}
