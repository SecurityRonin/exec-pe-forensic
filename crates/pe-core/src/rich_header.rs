//! Rich header parsing — compiler fingerprint between DOS stub and PE signature.
//!
//! The Rich header records every compiler/linker tool version used to build
//! the binary, XOR-encoded with a 4-byte key.  It is an invaluable attribution
//! signal: identical `(product_id, build_id)` tuples across samples indicate
//! the same toolchain, and therefore likely the same threat actor or campaign.
//!
//! # Format (all DWORDs are little-endian)
//!
//! ```text
//!   [XOR(DanS, key)] [pad0^key] [pad1^key] [pad2^key]
//!   [XOR(comp_id0, key)] [XOR(use_count0, key)]
//!   ...
//!   "Rich"  [xor_key]
//! ```
//!
//! - `DanS` = 0x536E_6144 (`DanS` read as u32 LE)
//! - `comp_id` = `(product_id << 16) | build_id`
//! - `use_count` = number of objects compiled with that tool version
//! - `xor_key` = raw DWORD after the `Rich` terminator

/// One entry in the Rich header: a specific compiler/linker tool version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RichEntry {
    /// Compiler / linker product identifier (high 16 bits of comp_id).
    pub product_id: u16,
    /// Build number (low 16 bits of comp_id).
    pub build_id: u16,
    /// Number of object files compiled with this exact tool version.
    pub use_count: u32,
}

/// Decoded Rich header — compiler fingerprint from the DOS stub area.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RichHeader {
    /// Decoded tool-version entries in the order they appear.
    pub entries: Vec<RichEntry>,
    /// XOR key used to encode the header (also a rudimentary checksum).
    pub xor_key: u32,
}

/// Parse the Rich header from raw PE bytes.
///
/// Searches only within the DOS stub area (offset 0x40 → `e_lfanew`).
/// Returns `None` if no `Rich` marker is found or if the header is malformed.
pub fn parse_rich_header(bytes: &[u8]) -> Option<RichHeader> {
    todo!("implement Rich header parsing")
}

// ── private helpers (used by both impl and tests) ─────────────────────────────

pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
}

pub(crate) fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    /// Build raw bytes containing a valid Rich header in the DOS stub area.
    ///
    /// `e_lfanew` is set dynamically so the stub area exactly contains
    /// `entries` with `xor_key`.  The bytes end with `b"PE\0\0"` at `e_lfanew`
    /// so goblin (if used) does not reject them.
    pub fn make_pe_with_rich(entries: &[(u16, u16, u32)], xor_key: u32) -> Vec<u8> {
        const DANS: u32 = 0x536E_6144; // b"DanS" as LE u32

        let mut stub: Vec<u8> = Vec::new();
        // DanS XOR'd + 3 padding DWORDs
        stub.extend_from_slice(&(DANS ^ xor_key).to_le_bytes());
        for _ in 0..3 {
            stub.extend_from_slice(&xor_key.to_le_bytes()); // 0x00000000 ^ key
        }
        // Entries
        for &(prod, build, count) in entries {
            let comp_id = ((prod as u32) << 16) | (build as u32);
            stub.extend_from_slice(&(comp_id ^ xor_key).to_le_bytes());
            stub.extend_from_slice(&(count ^ xor_key).to_le_bytes());
        }
        // "Rich" + key
        stub.extend_from_slice(b"Rich");
        stub.extend_from_slice(&xor_key.to_le_bytes());

        let e_lfanew: u32 = 0x40 + stub.len() as u32;
        let mut buf = vec![0u8; e_lfanew as usize + 4];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        buf[0x40..e_lfanew as usize].copy_from_slice(&stub);
        buf[e_lfanew as usize..].copy_from_slice(b"PE\0\0");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::{test_helpers::make_pe_with_rich, *};

    #[test]
    fn returns_none_for_empty_bytes() {
        assert!(parse_rich_header(&[]).is_none());
    }

    #[test]
    fn returns_none_when_no_rich_marker() {
        // Minimal PE: dos header ends at 0x40, PE sig immediately follows → no stub area.
        let mut pe = vec![0u8; 68];
        pe[0] = b'M';
        pe[1] = b'Z';
        let e_lfanew: u32 = 0x40;
        pe[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert!(parse_rich_header(&pe).is_none());
    }

    #[test]
    fn returns_none_for_truncated_input() {
        let buf = [b'M', b'Z'];
        assert!(parse_rich_header(&buf).is_none());
    }

    #[test]
    fn parses_single_entry_correctly() {
        let key = 0xDEAD_BEEF_u32;
        let buf = make_pe_with_rich(&[(0x0103, 0x6B6B, 5)], key);
        let rh = parse_rich_header(&buf).expect("Rich header must be found");
        assert_eq!(rh.xor_key, key);
        assert_eq!(rh.entries.len(), 1);
        assert_eq!(rh.entries[0].product_id, 0x0103);
        assert_eq!(rh.entries[0].build_id, 0x6B6B);
        assert_eq!(rh.entries[0].use_count, 5);
    }

    #[test]
    fn parses_multiple_entries_in_order() {
        let key = 0x1234_5678_u32;
        let expected = [(0x0001, 0x6B00, 1), (0x010C, 0x6B1A, 12), (0x0103, 0x6B6B, 42)];
        let buf = make_pe_with_rich(&expected, key);
        let rh = parse_rich_header(&buf).expect("Rich header must be found");
        assert_eq!(rh.entries.len(), 3);
        assert_eq!(rh.entries[0].product_id, 0x0001);
        assert_eq!(rh.entries[1].use_count, 12);
        assert_eq!(rh.entries[2].product_id, 0x0103);
        assert_eq!(rh.entries[2].build_id, 0x6B6B);
    }

    #[test]
    fn zero_entry_rich_header_parses_successfully() {
        let key = 0xCAFE_BABE_u32;
        let buf = make_pe_with_rich(&[], key);
        let rh = parse_rich_header(&buf).expect("zero-entry Rich header");
        assert!(rh.entries.is_empty());
        assert_eq!(rh.xor_key, key);
    }

    #[test]
    fn xor_key_is_correct() {
        let expected_key = 0x0101_0202_u32;
        let buf = make_pe_with_rich(&[(1, 2, 3)], expected_key);
        let rh = parse_rich_header(&buf).unwrap();
        assert_eq!(rh.xor_key, expected_key);
    }
}
