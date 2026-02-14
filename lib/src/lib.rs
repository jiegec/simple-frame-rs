//! Crate to parse SFrame stack trace information.
//!
//! Usage: Use [SFrameSection::from] to load sframe section content and access
//! its content.
//!
//! Spec: <https://sourceware.org/binutils/docs/sframe-spec.html>

use thiserror::Error;

pub mod v1;
pub mod v2;
pub mod v3;

#[macro_export]
macro_rules! read_binary {
    ($data: expr, $le: expr, $ty: ident, $offset: expr) => {{
        let data_offset = $offset;
        let mut data_bytes: [u8; core::mem::size_of::<$ty>()] = [0; core::mem::size_of::<$ty>()];
        data_bytes.copy_from_slice(&$data[data_offset..data_offset + core::mem::size_of::<$ty>()]);
        if $le {
            $ty::from_le_bytes(data_bytes)
        } else {
            $ty::from_be_bytes(data_bytes)
        }
    }};
}

#[macro_export]
macro_rules! read_struct {
    ($struct: ident, $data: expr, $le: expr, $x: ident, $ty: ident) => {{ read_binary!($data, $le, $ty, core::mem::offset_of!($struct, $x)) }};
}

/// Result type for the crate
pub type SFrameResult<T> = core::result::Result<T, SFrameError>;

/// SFrame section
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Section>
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum SFrameSection<'a> {
    V1(v1::SFrameSection<'a>),
    V2(v2::SFrameSection<'a>),
    V3(v3::SFrameSection<'a>),
}

/// The magic number for SFrame section: 0xdee2
const SFRAME_MAGIC: u16 = 0xdee2;

/// Raw SFrame Header
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Preamble>
#[repr(C, packed)]
struct RawSFramePreamble {
    magic: u16,
    version: u8,
    flags: u8,
}

impl<'a> SFrameSection<'a> {
    /// Parse SFrame section from data
    pub fn from(data: &'a [u8], section_base: u64) -> SFrameResult<SFrameSection<'a>> {
        // parse sframe_header
        if data.len() < core::mem::size_of::<RawSFramePreamble>() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        // probe magic
        let magic_offset = core::mem::offset_of!(RawSFramePreamble, magic);
        let mut magic_bytes: [u8; 2] = [0; 2];
        magic_bytes.copy_from_slice(&data[magic_offset..magic_offset + 2]);
        let magic_le = u16::from_le_bytes(magic_bytes);
        if magic_le != SFRAME_MAGIC {
            let magic_be = u16::from_be_bytes(magic_bytes);
            if magic_be != SFRAME_MAGIC {
                return Err(SFrameError::InvalidMagic);
            }
        }

        // probe version
        let version_offset = core::mem::offset_of!(RawSFramePreamble, version);
        let version = data[version_offset];
        match version {
            1 => Ok(SFrameSection::V1(v1::SFrameSection::from(
                data,
                section_base,
            )?)),
            2 => Ok(SFrameSection::V2(v2::SFrameSection::from(
                data,
                section_base,
            )?)),
            3 => Ok(SFrameSection::V3(v3::SFrameSection::from(
                data,
                section_base,
            )?)),
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }
}

/// Error types for the crate
#[derive(Error, Debug)]
pub enum SFrameError {
    /// Propagate core::fmt::Error
    #[error("format error")]
    Fmt(#[from] core::fmt::Error),
    /// Unexpected end of data
    #[error("unexpected end of data")]
    UnexpectedEndOfData,
    /// Invalid magic number
    #[error("invalid magic number")]
    InvalidMagic,
    /// Unsupported version
    #[error("unsupported version")]
    UnsupportedVersion,
    /// Unsupported flags
    #[error("unsupported flags")]
    UnsupportedFlags,
    /// Unsupported ABI
    #[error("unsupported abi")]
    UnsupportedABI,
    /// Unsupported FDE type
    #[error("unsupported fde type")]
    UnsupportedFDEType,
    /// Unsupported FRE type
    #[error("unsupported fre type")]
    UnsupportedFREType,
    /// Unsupported FRE stack offset size
    #[error("unsupported fre stack offset size")]
    UnsupportedFREStackOffsetSize,
    /// Unsupported FRE data word size
    #[error("unsupported fre data word size")]
    UnsupportedFREDataWordSize,
}
