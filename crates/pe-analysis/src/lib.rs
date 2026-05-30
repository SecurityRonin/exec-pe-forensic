//! Forensic detectors for Portable Executable (PE) binaries.
//!
//! All detectors accept a parsed [`pe_core::PeFile`] and return a `Vec<PeDetection>`.
//! They are pure functions with no I/O — medium-agnostic by construction.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
)]

pub mod anomalies;
pub mod anti_debug;
pub mod av_exclusion;
pub mod credential;
pub mod dotnet;
pub mod ioc;
pub mod network_iocs;
pub mod overlay;
pub mod packed;
pub mod persistence;
pub mod process_hollowing;
pub mod ransomware;
pub mod suspicious_imports;
pub mod tls_callbacks;

pub use anomalies::detect_pe_anomalies;
pub use anti_debug::detect_anti_debug;
pub use av_exclusion::detect_av_exclusion_strings;
pub use credential::detect_credential_strings;
pub use dotnet::detect_dotnet_anomalies;
pub use ioc::detect_qwcrypt_pe_iocs;
pub use network_iocs::detect_network_iocs;
pub use overlay::detect_overlay;
pub use packed::detect_packed_pe;
pub use persistence::detect_persistence_strings;
pub use process_hollowing::detect_process_hollowing;
pub use ransomware::detect_ransomware_strings;
pub use suspicious_imports::detect_suspicious_imports;
pub use tls_callbacks::detect_tls_callbacks;

use pe_core::PeFile;

/// Category of a PE-level detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PeDetectionKind {
    /// Import of a known process-injection or privilege-escalation API (T1055 / T1134).
    SuspiciousImport,
    /// Section packer name or high entropy indicates the binary was packed (T1027.002).
    PackedExecutable,
    /// String table contains AV product exclusion registry/path fragments (T1562.001).
    AvExclusionStrings,
    /// Strings or section names match known QWCrypt / RedCurl IOCs.
    QWCryptPeIoc,
    /// Import of a known debugger-detection or timing-check API (T1622).
    AntiDebugImport,
    /// Cluster of process-hollowing API imports (T1055.012).
    ProcessHollowing,
    /// String matching a C2/network indicator pattern (T1071.001).
    NetworkC2String,
    /// String matching a persistence registry key or system path (T1547.001).
    PersistenceString,
    /// String matching a ransomware keyword or extension (T1486).
    RansomwareString,
    /// String matching a hardcoded credential or secret pattern (T1552.001).
    CredentialString,
    /// TLS callback(s) present — pre-entry execution hook (T1055.005).
    TlsCallbackPresent,
    /// Structural PE anomaly indicating obfuscation or evasion (T1027).
    PeStructuralAnomaly,
    /// Overlay data appended after the last section — common dropper technique (T1027.009).
    OverlayDetected,
    /// Suspicious .NET CLR characteristic combined with evasion indicator (T1027).
    DotNetAnomaly,
}

/// A single detection result produced by a PE detector.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeDetection {
    pub kind: PeDetectionKind,
    /// MITRE ATT&CK technique ID (e.g. "T1055").
    pub mitre_technique_id: &'static str,
    /// ATT&CK tactic name.
    pub tactic: &'static str,
    /// Human-readable description of the specific finding.
    pub description: String,
    /// Evidence items: the concrete strings / names that triggered this detection.
    pub evidence: Vec<String>,
}

/// Run all PE detectors and aggregate results, sorted by MITRE technique ID.
pub fn detect_all(pe: &PeFile) -> Vec<PeDetection> {
    let mut results = Vec::new();
    results.extend(detect_suspicious_imports(pe));
    results.extend(detect_packed_pe(pe));
    results.extend(detect_av_exclusion_strings(pe));
    results.extend(detect_qwcrypt_pe_iocs(pe));
    results.extend(detect_anti_debug(pe));
    results.extend(detect_process_hollowing(pe));
    results.extend(detect_network_iocs(pe));
    results.extend(detect_persistence_strings(pe));
    results.extend(detect_ransomware_strings(pe));
    results.extend(detect_credential_strings(pe));
    results.extend(detect_tls_callbacks(pe));
    results.extend(detect_overlay(pe));
    results.extend(detect_pe_anomalies(pe));
    results.extend(detect_dotnet_anomalies(pe));
    results.sort_by_key(|d| d.mitre_technique_id);
    results
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use pe_core::parser::{PeFile, PeSection};

    pub fn make_pe(
        imports: &[&str],
        sections: Vec<PeSection>,
        strings: &[&str],
    ) -> PeFile {
        PeFile {
            machine: 0x8664,
            compile_timestamp: 0x5F00_0000,
            is_dll: false,
            is_exe: true,
            entry_point_rva: 0x1000,
            image_base: 0x0040_0000,
            checksum: 0,
            is_dotnet: false,
            tls_callback_count: 0,
            has_reloc: false,
            is_signed: false,
            pdb_path: None,
            overlay_offset: None,
            overlay_size: None,
            rich_header: None,
            imports: imports.iter().map(|s| (*s).to_string()).collect(),
            exports: vec![],
            sections,
            ascii_strings: strings.iter().map(|s| (*s).to_string()).collect(),
            utf16_strings: vec![],
            sha256: "a".repeat(64),
            size: 512,
        }
    }

    pub fn make_section(name: &str, entropy: f32, executable: bool) -> PeSection {
        PeSection {
            name: name.to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            virtual_address: 0x1000,
            entropy,
            is_executable: executable,
            is_writable: false,
            is_readable: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::{make_pe, make_section};

    #[test]
    fn detect_all_empty_pe_returns_empty() {
        let pe = make_pe(&[], vec![], &[]);
        assert!(detect_all(&pe).is_empty());
    }

    #[test]
    fn detect_all_aggregates_multiple_detectors() {
        let pe = make_pe(
            &["VirtualAlloc", "CreateRemoteThread"],
            vec![make_section("UPX0", 7.8, true)],
            &["Windows Defender\\Exclusions\\Paths"],
        );
        let hits = detect_all(&pe);
        // At minimum: 2 suspicious imports + 1 packed + 1 AV exclusion
        assert!(hits.len() >= 4);
    }

    #[test]
    fn detect_all_results_sorted_by_mitre_id() {
        let pe = make_pe(
            &["VirtualAlloc"],
            vec![make_section("UPX0", 7.8, true)],
            &["Windows Defender\\Exclusions\\Paths"],
        );
        let hits = detect_all(&pe);
        let ids: Vec<_> = hits.iter().map(|h| h.mitre_technique_id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "detect_all results must be sorted by MITRE ID");
    }

    // --- RED: these tests fail because new detectors are not yet wired into detect_all ---

    #[test]
    fn detect_all_includes_anti_debug_results() {
        let pe = make_pe(&["IsDebuggerPresent"], vec![], &[]);
        let hits = detect_all(&pe);
        assert!(
            hits.iter().any(|h| h.kind == PeDetectionKind::AntiDebugImport),
            "detect_all must include anti_debug results"
        );
    }

    #[test]
    fn detect_all_includes_tls_callback_results() {
        let mut pe = make_pe(&[], vec![], &[]);
        pe.tls_callback_count = 1;
        let hits = detect_all(&pe);
        assert!(
            hits.iter().any(|h| h.kind == PeDetectionKind::TlsCallbackPresent),
            "detect_all must include tls_callbacks results"
        );
    }

    #[test]
    fn detect_all_includes_network_c2_results() {
        let pe = make_pe(&[], vec![], &["https://c2.evil.example/implant"]);
        let hits = detect_all(&pe);
        assert!(
            hits.iter().any(|h| h.kind == PeDetectionKind::NetworkC2String),
            "detect_all must include network_iocs results"
        );
    }
}
