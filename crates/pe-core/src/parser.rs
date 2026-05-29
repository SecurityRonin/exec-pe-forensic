//! Core PE parser: `parse_pe(&[u8]) -> Result<PeFile, PeError>`.

use std::path::Path;

use crate::error::PeError;

/// All forensically-relevant fields extracted from a PE binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeFile {
    /// COFF machine type (0x8664 AMD64, 0x014C x86, 0xAA64 ARM64).
    pub machine: u16,
    /// COFF compile timestamp (Unix seconds; note: frequently zeroed or faked).
    pub compile_timestamp: u32,
    /// True when IMAGE_FILE_DLL characteristic is set.
    pub is_dll: bool,
    /// True when IMAGE_FILE_EXECUTABLE_IMAGE characteristic is set.
    pub is_exe: bool,
    /// Flat list of imported symbol names from all import descriptors.
    pub imports: Vec<String>,
    /// Exported symbol names (populated for DLLs).
    pub exports: Vec<String>,
    /// Section table with per-section attributes and entropy.
    pub sections: Vec<PeSection>,
    /// ASCII strings (≥ 6 printable chars) extracted from all raw data.
    pub ascii_strings: Vec<String>,
    /// UTF-16LE strings (≥ 6 printable chars) extracted from all raw data.
    pub utf16_strings: Vec<String>,
    /// SHA-256 hash of the full binary (hex-encoded).
    pub sha256: String,
    /// Size of the binary in bytes.
    pub size: usize,
}

impl PeFile {
    /// Combined string table: all ASCII and UTF-16 strings.
    pub fn all_strings(&self) -> impl Iterator<Item = &str> {
        self.ascii_strings
            .iter()
            .chain(self.utf16_strings.iter())
            .map(String::as_str)
    }
}

/// A single PE section with computed Shannon entropy.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeSection {
    /// Section name (up to 8 bytes, null-terminated, lossy UTF-8).
    pub name: String,
    /// Virtual size in bytes as reported in the section header.
    pub virtual_size: u32,
    /// Size of raw data on disk (may be 0 for BSS-style sections).
    pub raw_size: u32,
    /// Virtual address (RVA) relative to the image base.
    pub virtual_address: u32,
    /// Shannon entropy of the raw section data (0.0 – 8.0).
    pub entropy: f32,
    /// True when IMAGE_SCN_MEM_EXECUTE (0x2000_0000) is set.
    pub is_executable: bool,
    /// True when IMAGE_SCN_MEM_WRITE (0x8000_0000) is set.
    pub is_writable: bool,
    /// True when IMAGE_SCN_MEM_READ (0x4000_0000) is set.
    pub is_readable: bool,
}

/// Parse a PE binary from raw bytes.
///
/// Returns [`PeError::NotPe`] for non-PE inputs (empty, wrong magic, truncated header).
/// Returns [`PeError::Structure`] for PEs that pass the magic check but are malformed.
pub fn parse_pe(bytes: &[u8]) -> Result<PeFile, PeError> {
    todo!()
}

/// Parse a PE binary from a file path.
///
/// Reads the entire file into memory then calls [`parse_pe`].
pub fn parse_pe_path(path: &Path) -> Result<PeFile, PeError> {
    todo!()
}

#[cfg(test)]
pub(crate) mod test_helpers {
    /// Build a minimal valid PE32+ (x64, 0 sections, no imports) for unit tests.
    ///
    /// Layout: DOS header (64 B) + PE sig (4 B) + COFF header (20 B) +
    ///         Optional header PE32+ (240 B) = 328 B, padded to 512 B.
    pub fn make_minimal_pe_x64(timestamp: u32, is_dll: bool) -> Vec<u8> {
        let mut pe = vec![0u8; 512];

        // DOS header
        pe[0] = b'M'; pe[1] = b'Z';
        pe[0x3C] = 0x40; // e_lfanew = 64

        // PE signature at 0x40
        pe[0x40] = b'P'; pe[0x41] = b'E';

        // COFF header at 0x44 (20 bytes)
        pe[0x44] = 0x64; pe[0x45] = 0x86;          // Machine = AMD64
        pe[0x48..0x4C].copy_from_slice(&timestamp.to_le_bytes()); // TimeDateStamp
        pe[0x54] = 0xF0;                             // SizeOfOptionalHeader = 240
        // Characteristics: bit 1 = EXE, bit 5 = large addr, bit 13 = DLL
        pe[0x56] = if is_dll { 0x22 | 0x20 } else { 0x22 }; // 0x22 = exe+large, 0x20 = DLL... wait
        // Actually: IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002, IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
        // IMAGE_FILE_DLL = 0x2000
        if is_dll {
            let chars: u16 = 0x2022; // DLL | EXECUTABLE | LARGE_ADDRESS_AWARE
            pe[0x56..0x58].copy_from_slice(&chars.to_le_bytes());
        } else {
            let chars: u16 = 0x0022;
            pe[0x56..0x58].copy_from_slice(&chars.to_le_bytes());
        }

        // Optional header (PE32+) at 0x58 (240 bytes)
        pe[0x58] = 0x0B; pe[0x59] = 0x02;    // Magic = PE32+
        // ImageBase (u64) at 0x58+24 = 0x70
        pe[0x70] = 0x00; pe[0x71] = 0x00; pe[0x72] = 0x40; // 0x400000
        // SectionAlignment at 0x78
        pe[0x78] = 0x00; pe[0x79] = 0x10;    // 0x1000
        // FileAlignment at 0x7C
        pe[0x7C] = 0x00; pe[0x7D] = 0x02;    // 0x200
        // MajorSubsystemVersion at 0x88
        pe[0x88] = 0x06;
        // SizeOfImage at 0x90
        pe[0x90] = 0x00; pe[0x91] = 0x10;    // 0x1000
        // SizeOfHeaders at 0x94
        pe[0x94] = 0x00; pe[0x95] = 0x02;    // 0x200
        // Subsystem at 0x9C: 2 = GUI
        pe[0x9C] = 0x02;
        // SizeOfStackReserve at 0xA0
        pe[0xA0] = 0x00; pe[0xA1] = 0x00; pe[0xA2] = 0x10; // 0x100000
        // SizeOfStackCommit at 0xA8
        pe[0xA8] = 0x00; pe[0xA9] = 0x10;    // 0x1000
        // SizeOfHeapReserve at 0xB0
        pe[0xB0] = 0x00; pe[0xB1] = 0x00; pe[0xB2] = 0x10; // 0x100000
        // SizeOfHeapCommit at 0xB8
        pe[0xB8] = 0x00; pe[0xB9] = 0x10;    // 0x1000
        // NumberOfRvaAndSizes at 0xC4
        pe[0xC4] = 0x10;                      // 16 data directories

        pe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::make_minimal_pe_x64;

    // ── rejection tests ───────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_slice() {
        assert!(matches!(parse_pe(&[]), Err(PeError::NotPe)));
    }

    #[test]
    fn rejects_single_byte() {
        assert!(matches!(parse_pe(&[0x4D]), Err(PeError::NotPe)));
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(parse_pe(b"this is not a PE file at all").is_err());
    }

    #[test]
    fn rejects_elf_magic() {
        let elf = [0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_pe(&elf).is_err());
    }

    #[test]
    fn rejects_truncated_mz() {
        assert!(parse_pe(b"MZ").is_err());
    }

    #[test]
    fn rejects_mz_with_no_pe_sig() {
        let mut buf = vec![0u8; 64];
        buf[0] = b'M'; buf[1] = b'Z';
        buf[0x3C] = 0x40; // e_lfanew points beyond buffer
        assert!(parse_pe(&buf).is_err());
    }

    // ── successful parse tests ────────────────────────────────────────────────

    #[test]
    fn accepts_minimal_x64() {
        let bytes = make_minimal_pe_x64(0, false);
        assert!(
            parse_pe(&bytes).is_ok(),
            "minimal PE32+ must parse successfully"
        );
    }

    #[test]
    fn extracts_machine_amd64() {
        let bytes = make_minimal_pe_x64(0, false);
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert_eq!(pe.machine, 0x8664);
    }

    #[test]
    fn extracts_compile_timestamp() {
        let ts = 0x5F00_ABCD_u32;
        let bytes = make_minimal_pe_x64(ts, false);
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert_eq!(pe.compile_timestamp, ts);
    }

    #[test]
    fn exe_is_not_dll() {
        let bytes = make_minimal_pe_x64(0, false);
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert!(!pe.is_dll);
        assert!(pe.is_exe);
    }

    #[test]
    fn dll_flag_detected() {
        let bytes = make_minimal_pe_x64(0, true);
        let pe = parse_pe(&bytes).expect("minimal DLL PE");
        assert!(pe.is_dll);
    }

    #[test]
    fn minimal_pe_has_no_imports() {
        let bytes = make_minimal_pe_x64(0, false);
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert!(pe.imports.is_empty());
    }

    #[test]
    fn minimal_pe_has_no_sections() {
        let bytes = make_minimal_pe_x64(0, false);
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert!(pe.sections.is_empty());
    }

    #[test]
    fn populates_sha256() {
        let bytes = make_minimal_pe_x64(0, false);
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert_eq!(pe.sha256.len(), 64, "SHA-256 hex string is 64 chars");
        assert!(pe.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn populates_size() {
        let bytes = make_minimal_pe_x64(0, false);
        let expected_size = bytes.len();
        let pe = parse_pe(&bytes).expect("minimal PE");
        assert_eq!(pe.size, expected_size);
    }

    // ── parse_pe_path tests ───────────────────────────────────────────────────

    #[test]
    fn parse_pe_path_nonexistent_returns_io_error() {
        let result = parse_pe_path(Path::new("/nonexistent/rbcw.exe"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_pe_path_non_pe_file_returns_not_pe() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp file");
        tmp.write_all(b"this is plain text, not a PE").expect("write");
        let result = parse_pe_path(tmp.path());
        assert!(result.is_err());
    }
}
