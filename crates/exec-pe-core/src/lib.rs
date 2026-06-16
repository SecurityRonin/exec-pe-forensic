//! PE (Portable Executable) binary format parser.
//!
//! Medium-agnostic: accepts raw `&[u8]` bytes from any source — disk file,
//! memory dump page, AFF4 stream, network capture, or carved fragment.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use exec_pe_core::{parse_pe, PeFile};
//!
//! let bytes = std::fs::read("rbcw.exe").unwrap();
//! let pe = parse_pe(&bytes).expect("valid PE");
//! println!("machine: {:#06x}", pe.machine);
//! println!("imports: {:?}", pe.imports);
//! ```

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

pub mod anomalies;
pub mod error;
pub mod parser;
pub mod rich_header;
pub mod strings;

pub use anomalies::{detect_structural_anomalies, PeAnomaly};
pub use error::PeError;
pub use parser::{parse_pe, parse_pe_path, PeFile, PeSection};
pub use rich_header::{parse_rich_header, RichEntry, RichHeader};
