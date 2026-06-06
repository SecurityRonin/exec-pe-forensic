//! Structural PE anomaly detection — pure computation over a parsed [`PeFile`].
//!
//! These heuristics fire on PE header fields that are valid by the spec but
//! statistically associated with malware: writable+executable sections,
//! entry points outside all sections, large virtual/raw size ratios, TLS
//! callbacks, and appended overlay data.
//!
//! All functions are pure (no I/O).  The caller provides a fully-parsed
//! [`PeFile`] from [`crate::parser::parse_pe`].

use forensicnomicon::report::{Category, Evidence, Location, Observation, Severity};
use crate::parser::{PeFile, PeSection};

/// A structural anomaly found in a PE binary.
///
/// Individual anomalies are low-to-medium confidence signals; clusters of
/// multiple anomalies on the same binary are high confidence.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum PeAnomaly {
    /// A section has both executable and writable characteristics (W+X).
    /// Legitimate code sections are executable but not writable; shellcode
    /// injected at runtime needs both.
    WritableExecutableSection { section_name: String },

    /// The entry-point RVA falls outside the virtual address range of every
    /// defined section.  This is the classic hallmark of shellcode loading
    /// or in-memory PE patching.
    EntryPointOutsideSections { entry_point_rva: u32 },

    /// A section's raw size on disk is zero but its virtual size is non-zero.
    /// The runtime loader expands this section, which is where packed malware
    /// decompresses into.
    VirtualOnlySection { section_name: String },

    /// A section's virtual size exceeds its raw size by more than `ratio`×.
    /// Legitimate compressed resources occasionally show this; ratios > 20
    /// almost always indicate runtime decompression of an encrypted payload.
    LargeVirtualToRawRatio { section_name: String, ratio: u32 },

    /// TLS (Thread Local Storage) callbacks are registered.  These execute
    /// *before* the PE entry point, giving malware a window for anti-debug
    /// and anti-VM checks before the main payload runs.
    TlsCallbacksPresent { count: usize },

    /// Extra bytes are appended after the last section's raw data.
    /// Legitimate packers (installers, SFX archives) use overlays; so do
    /// malware droppers that store an encrypted second stage here.
    OverlayPresent { offset: u64, size: u64 },

    /// No `Rich` header was found in the DOS stub area of a large binary.
    /// Every MSVC/MinGW binary emits a Rich header; its absence on a file
    /// > 4 KiB suggests deliberate stripping for anti-attribution.
    RichHeaderAbsent,
}

/// Compute structural anomalies from a fully-parsed [`PeFile`].
///
/// Returns one [`PeAnomaly`] per anomaly found.  An empty `Vec` means the
/// binary looks structurally normal (not necessarily benign).
pub fn detect_structural_anomalies(pe: &PeFile) -> Vec<PeAnomaly> {
    let mut out = Vec::new();

    for sec in &pe.sections {
        // W+X section — code injection target
        if sec.is_writable && sec.is_executable {
            out.push(PeAnomaly::WritableExecutableSection {
                section_name: sec.name.clone(),
            });
        }

        // Virtual-only section (raw_size=0, virtual_size>0) — runtime decompression area
        if sec.raw_size == 0 && sec.virtual_size > 0 {
            out.push(PeAnomaly::VirtualOnlySection {
                section_name: sec.name.clone(),
            });
        }

        // Large virtual/raw ratio (> 10×) — indicates decompression
        if sec.raw_size > 0 {
            let ratio = sec.virtual_size / sec.raw_size;
            if ratio > 10 {
                out.push(PeAnomaly::LargeVirtualToRawRatio {
                    section_name: sec.name.clone(),
                    ratio,
                });
            }
        }
    }

    // Entry point outside all sections (only meaningful when sections exist and EP is non-zero)
    if pe.entry_point_rva > 0 && !pe.sections.is_empty() {
        if !entry_point_in_section(pe.entry_point_rva, &pe.sections) {
            out.push(PeAnomaly::EntryPointOutsideSections {
                entry_point_rva: pe.entry_point_rva,
            });
        }
    }

    // TLS callbacks registered
    if pe.tls_callback_count > 0 {
        out.push(PeAnomaly::TlsCallbacksPresent {
            count: pe.tls_callback_count,
        });
    }

    // Overlay data appended after last section
    if let (Some(offset), Some(size)) = (pe.overlay_offset, pe.overlay_size) {
        out.push(PeAnomaly::OverlayPresent { offset, size });
    }

    // Rich header absent on a binary large enough to have been compiled (> 4 KiB)
    if pe.rich_header.is_none() && pe.size > 4096 {
        out.push(PeAnomaly::RichHeaderAbsent);
    }

    out
}

/// Return `true` when `entry_rva` falls within the virtual address range of
/// at least one section (`[va, va + virtual_size)`).
pub fn entry_point_in_section(entry_rva: u32, sections: &[PeSection]) -> bool {
    sections.iter().any(|s| {
        let end = s.virtual_address.saturating_add(s.virtual_size.max(1));
        entry_rva >= s.virtual_address && entry_rva < end
    })
}

impl Observation for PeAnomaly {
    fn severity(&self) -> Option<Severity> {
        use PeAnomaly::{
            EntryPointOutsideSections, LargeVirtualToRawRatio, OverlayPresent, RichHeaderAbsent,
            TlsCallbacksPresent, VirtualOnlySection, WritableExecutableSection,
        };
        Some(match self {
            EntryPointOutsideSections { .. } => Severity::High,
            WritableExecutableSection { .. }
            | VirtualOnlySection { .. }
            | LargeVirtualToRawRatio { .. } => Severity::Medium,
            TlsCallbacksPresent { .. } | OverlayPresent { .. } | RichHeaderAbsent => Severity::Low,
        })
    }

    fn category(&self) -> Category {
        use PeAnomaly::{OverlayPresent, RichHeaderAbsent, TlsCallbacksPresent};
        match self {
            TlsCallbacksPresent { .. } | RichHeaderAbsent => Category::Concealment,
            OverlayPresent { .. } => Category::Residue,
            _ => Category::Structure,
        }
    }

    fn code(&self) -> &'static str {
        use PeAnomaly::{
            EntryPointOutsideSections, LargeVirtualToRawRatio, OverlayPresent, RichHeaderAbsent,
            TlsCallbacksPresent, VirtualOnlySection, WritableExecutableSection,
        };
        match self {
            WritableExecutableSection { .. } => "PE-WX-SECTION",
            EntryPointOutsideSections { .. } => "PE-ENTRYPOINT-OOB",
            VirtualOnlySection { .. } => "PE-VIRTUAL-ONLY-SECTION",
            LargeVirtualToRawRatio { .. } => "PE-VSIZE-RATIO",
            TlsCallbacksPresent { .. } => "PE-TLS-CALLBACKS",
            OverlayPresent { .. } => "PE-OVERLAY",
            RichHeaderAbsent => "PE-RICH-ABSENT",
        }
    }

    fn note(&self) -> String {
        use PeAnomaly::{
            EntryPointOutsideSections, LargeVirtualToRawRatio, OverlayPresent, RichHeaderAbsent,
            TlsCallbacksPresent, VirtualOnlySection, WritableExecutableSection,
        };
        match self {
            WritableExecutableSection { section_name } => {
                format!("section '{section_name}' is both writable and executable (W+X)")
            }
            EntryPointOutsideSections { entry_point_rva } => {
                format!("entry-point RVA {entry_point_rva:#x} falls outside every defined section")
            }
            VirtualOnlySection { section_name } => {
                format!("section '{section_name}' has zero raw size but a non-zero virtual size")
            }
            LargeVirtualToRawRatio { section_name, ratio } => {
                format!("section '{section_name}' virtual size exceeds its raw size by ~{ratio}x")
            }
            TlsCallbacksPresent { count } => {
                format!("{count} TLS callback(s) execute before the entry point")
            }
            OverlayPresent { offset, size } => {
                format!("{size} bytes of overlay data appended after the last section at {offset:#x}")
            }
            RichHeaderAbsent => {
                "no Rich header in the DOS stub — consistent with anti-attribution stripping"
                    .to_string()
            }
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        use PeAnomaly::{
            EntryPointOutsideSections, LargeVirtualToRawRatio, OverlayPresent, RichHeaderAbsent,
            TlsCallbacksPresent, VirtualOnlySection, WritableExecutableSection,
        };
        match self {
            WritableExecutableSection { .. } | EntryPointOutsideSections { .. } => &["T1055"],
            TlsCallbacksPresent { .. } => &["T1055.005"],
            VirtualOnlySection { .. } | LargeVirtualToRawRatio { .. } => &["T1027.002"],
            RichHeaderAbsent => &["T1027"],
            OverlayPresent { .. } => &[],
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        use PeAnomaly::{
            EntryPointOutsideSections, LargeVirtualToRawRatio, OverlayPresent, RichHeaderAbsent,
            TlsCallbacksPresent, VirtualOnlySection, WritableExecutableSection,
        };
        let ev = |field: &str, value: String, location: Option<Location>| Evidence {
            field: field.to_string(),
            value,
            location,
        };
        match self {
            WritableExecutableSection { section_name } | VirtualOnlySection { section_name } => {
                vec![ev("section", section_name.clone(), None)]
            }
            EntryPointOutsideSections { entry_point_rva } => vec![ev(
                "entry_point_rva",
                format!("{entry_point_rva:#x}"),
                Some(Location::Rva(u64::from(*entry_point_rva))),
            )],
            LargeVirtualToRawRatio { section_name, ratio } => vec![
                ev("section", section_name.clone(), None),
                ev("ratio", ratio.to_string(), None),
            ],
            TlsCallbacksPresent { count } => vec![ev("count", count.to_string(), None)],
            OverlayPresent { offset, size } => vec![
                ev("size", size.to_string(), None),
                ev("offset", format!("{offset:#x}"), Some(Location::ByteOffset(*offset))),
            ],
            RichHeaderAbsent => Vec::new(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PeFile, PeSection};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn section(name: &str, va: u32, vsize: u32, rsize: u32, exec: bool, write: bool) -> PeSection {
        PeSection {
            name: name.to_string(),
            virtual_size: vsize,
            raw_size: rsize,
            virtual_address: va,
            entropy: 5.0,
            is_executable: exec,
            is_writable: write,
            is_readable: true,
        }
    }

    fn base_pe() -> PeFile {
        PeFile {
            machine: 0x8664,
            compile_timestamp: 0,
            is_dll: false,
            is_exe: true,
            imports: vec![],
            exports: vec![],
            sections: vec![section(".text", 0x1000, 0x500, 0x600, true, false)],
            ascii_strings: vec![],
            utf16_strings: vec![],
            sha256: "0".repeat(64),
            size: 0x800,
            // New fields — defaults for a "clean" PE
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
        }
    }

    // ── entry_point_in_section tests ──────────────────────────────────────────

    #[test]
    fn ep_inside_section_returns_true() {
        let secs = vec![section(".text", 0x1000, 0x1000, 0x1000, true, false)];
        assert!(entry_point_in_section(0x1500, &secs));
    }

    #[test]
    fn ep_at_section_start_returns_true() {
        let secs = vec![section(".text", 0x1000, 0x1000, 0x1000, true, false)];
        assert!(entry_point_in_section(0x1000, &secs));
    }

    #[test]
    fn ep_outside_all_sections_returns_false() {
        let secs = vec![section(".text", 0x1000, 0x1000, 0x1000, true, false)];
        assert!(!entry_point_in_section(0x5000, &secs));
    }

    #[test]
    fn ep_in_one_of_multiple_sections_returns_true() {
        let secs = vec![
            section(".text", 0x1000, 0x500, 0x600, true, false),
            section(".data", 0x2000, 0x200, 0x200, false, true),
        ];
        assert!(entry_point_in_section(0x2100, &secs));
    }

    // ── detect_structural_anomalies tests ─────────────────────────────────────

    #[test]
    fn clean_pe_has_no_anomalies() {
        let pe = base_pe();
        let anomalies = detect_structural_anomalies(&pe);
        assert!(anomalies.is_empty(), "clean PE should produce no anomalies, got: {anomalies:?}");
    }

    #[test]
    fn wx_section_produces_anomaly() {
        let mut pe = base_pe();
        pe.sections = vec![section(".rwx", 0x1000, 0x500, 0x600, true, true)];
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::WritableExecutableSection { .. })),
            "W+X section must produce anomaly"
        );
    }

    #[test]
    fn ep_outside_sections_produces_anomaly() {
        let mut pe = base_pe();
        pe.entry_point_rva = 0x9999; // outside .text at [0x1000, 0x1500)
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::EntryPointOutsideSections { .. })),
            "EP outside sections must produce anomaly"
        );
    }

    #[test]
    fn virtual_only_section_produces_anomaly() {
        let mut pe = base_pe();
        pe.sections = vec![section(".bss", 0x3000, 0x1000, 0, false, true)];
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::VirtualOnlySection { .. })),
            "virtual-only section must produce anomaly"
        );
    }

    #[test]
    fn large_virtual_raw_ratio_produces_anomaly() {
        // virtual = 100 000, raw = 512 → ratio = 195
        let mut pe = base_pe();
        pe.sections = vec![section(".packed", 0x1000, 100_000, 512, true, false)];
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::LargeVirtualToRawRatio { .. })),
            "large v/r ratio must produce anomaly"
        );
    }

    #[test]
    fn tls_callbacks_produce_anomaly() {
        let mut pe = base_pe();
        pe.tls_callback_count = 3;
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::TlsCallbacksPresent { count: 3 })),
            "TLS callbacks must produce anomaly with correct count"
        );
    }

    #[test]
    fn overlay_produces_anomaly() {
        let mut pe = base_pe();
        pe.overlay_offset = Some(0x8000);
        pe.overlay_size = Some(512);
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::OverlayPresent { offset: 0x8000, size: 512 })),
            "overlay must produce anomaly with correct offset and size"
        );
    }

    #[test]
    fn missing_rich_header_on_large_binary_produces_anomaly() {
        let mut pe = base_pe();
        pe.size = 1_000_000; // 1 MB — too large to legitimately lack a Rich header
        pe.rich_header = None;
        let anomalies = detect_structural_anomalies(&pe);
        assert!(
            anomalies.iter().any(|a| matches!(a, PeAnomaly::RichHeaderAbsent)),
            "missing Rich header on large binary must produce anomaly"
        );
    }

    #[test]
    fn small_binary_without_rich_header_no_anomaly() {
        let mut pe = base_pe();
        pe.size = 512; // tiny — Rich header absence is fine
        pe.rich_header = None;
        let anomalies = detect_structural_anomalies(&pe);
        // Should NOT produce RichHeaderAbsent for tiny files
        assert!(
            !anomalies.iter().any(|a| matches!(a, PeAnomaly::RichHeaderAbsent)),
            "small binary should not flag missing Rich header"
        );
    }

    #[test]
    fn multiple_anomalies_all_reported() {
        let mut pe = base_pe();
        pe.sections = vec![section(".evil", 0x1000, 50_000, 0, true, true)];
        pe.entry_point_rva = 0xFFFF;
        pe.tls_callback_count = 1;
        let anomalies = detect_structural_anomalies(&pe);
        assert!(anomalies.len() >= 3, "W+X + EP-outside + TLS should give ≥ 3 anomalies");
    }
}
