//! Crate to parse SFrame stack trace information.
//!
//! Usage: Use [SFrameSection::from] to load sframe section content and access
//! its content.
//!
//! A version-agnostic API is provided at the crate level. You can use API from
//! v1/v2/v3 modules to parse sframe section of specific versions.
//!
//! Spec: <https://sourceware.org/binutils/docs/sframe-spec.html>

use fallible_iterator::FallibleIterator;
use thiserror::Error;

pub mod v1;
pub mod v2;
pub mod v3;

/// Utility macro to read binary data from slice
#[macro_export]
macro_rules! read_binary {
    ($data: expr, $le: expr, $ty: ident, $offset: expr) => {{
        let data_offset = $offset;
        let mut data_bytes: [u8; core::mem::size_of::<$ty>()] = [0; core::mem::size_of::<$ty>()];
        data_bytes.copy_from_slice(
            &$data
                .get(data_offset..data_offset + core::mem::size_of::<$ty>())
                .ok_or(SFrameError::UnexpectedEndOfData)?,
        );
        if $le {
            $ty::from_le_bytes(data_bytes)
        } else {
            $ty::from_be_bytes(data_bytes)
        }
    }};
}

/// Utility macro to read struct member from slice
#[macro_export]
macro_rules! read_struct {
    ($struct: ident, $data: expr, $le: expr, $x: ident, $ty: ident) => {{ read_binary!($data, $le, $ty, core::mem::offset_of!($struct, $x)) }};
}

/// Result type for the crate
pub type SFrameResult<T> = core::result::Result<T, SFrameError>;

/// SFrame ABI/arch Identifier
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-ABI_002farch-Identifier>
#[derive(Debug, Clone, Copy)]
pub enum SFrameABI {
    /// SFRAME_ABI_AARCH64_ENDIAN_BIG
    AArch64BigEndian,
    /// SFRAME_ABI_AARCH64_ENDIAN_LITTLE
    AArch64LittleEndian,
    /// SFRAME_ABI_AMD64_ENDIAN_LITTLE
    AMD64LittleEndian,
    /// SFRAME_ABI_S390X_ENDIAN_BIG, since SFrame V2
    S390XBigEndian,
}

/// SFrame Flags
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Flags>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFlags {
    /// SFrame version 1 flags
    V1(v1::SFrameFlags),
    /// SFrame version 2 flags
    V2(v2::SFrameFlags),
    /// SFrame version 3 flags
    V3(v3::SFrameFlags),
}

impl SFrameFlags {
    /// Function Descriptor Entries are sorted on PC.
    pub fn is_fde_sorted(&self) -> bool {
        match self {
            SFrameFlags::V1(flags) => flags.contains(v1::SFrameFlags::SFRAME_F_FDE_SORTED),
            SFrameFlags::V2(flags) => flags.contains(v2::SFrameFlags::SFRAME_F_FDE_SORTED),
            SFrameFlags::V3(flags) => flags.contains(v3::SFrameFlags::SFRAME_F_FDE_SORTED),
        }
    }

    /// All functions in the object file preserve frame pointer.
    pub fn preserve_frame_pointer(&self) -> bool {
        match self {
            SFrameFlags::V1(flags) => flags.contains(v1::SFrameFlags::SFRAME_F_FRAME_POINTER),
            SFrameFlags::V2(flags) => flags.contains(v2::SFrameFlags::SFRAME_F_FRAME_POINTER),
            SFrameFlags::V3(flags) => flags.contains(v3::SFrameFlags::SFRAME_F_FRAME_POINTER),
        }
    }

    /// The sfde_func_start_address(V2)/sfdi_func_start_offset(V3) field in the SFrame FDE is an offset in bytes to the function's start address, from the field itself.
    ///
    /// Returns `SFrameError::UnsupportedVersion` for version 1.
    pub fn is_fde_func_start_pcrel(&self) -> SFrameResult<bool> {
        match self {
            SFrameFlags::V1(_) => Err(SFrameError::UnsupportedVersion),
            SFrameFlags::V2(flags) => {
                Ok(flags.contains(v2::SFrameFlags::SFRAME_F_FDE_FUNC_START_PCREL))
            }
            SFrameFlags::V3(flags) => {
                Ok(flags.contains(v3::SFrameFlags::SFRAME_F_FDE_FUNC_START_PCREL))
            }
        }
    }
}

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
    /// Print the section in string in the same way as objdump
    pub fn to_string(&self) -> SFrameResult<String> {
        match self {
            SFrameSection::V1(sframe_section) => sframe_section.to_string(),
            SFrameSection::V2(sframe_section) => sframe_section.to_string(),
            SFrameSection::V3(sframe_section) => sframe_section.to_string(),
        }
    }

    /// Get the count of FDE entries
    pub fn get_fde_count(&self) -> u32 {
        match self {
            SFrameSection::V1(sframe_section) => sframe_section.get_fde_count(),
            SFrameSection::V2(sframe_section) => sframe_section.get_fde_count(),
            SFrameSection::V3(sframe_section) => sframe_section.get_fde_count(),
        }
    }

    /// Get SFrame ABI
    pub fn get_abi(&self) -> SFrameABI {
        match self {
            SFrameSection::V1(sframe_section) => sframe_section.get_abi(),
            SFrameSection::V2(sframe_section) => sframe_section.get_abi(),
            SFrameSection::V3(sframe_section) => sframe_section.get_abi(),
        }
    }

    /// Get SFrame flags
    pub fn get_flags(&self) -> SFrameResult<SFrameFlags> {
        match self {
            SFrameSection::V1(sframe_section) => Ok(SFrameFlags::V1(sframe_section.get_flags())),
            SFrameSection::V2(sframe_section) => Ok(SFrameFlags::V2(sframe_section.get_flags())),
            SFrameSection::V3(sframe_section) => Ok(SFrameFlags::V3(sframe_section.get_flags())),
        }
    }

    /// Get SFrame CFA fixed FP offset
    pub fn get_cfa_fixed_fp_offset(&self) -> i8 {
        match self {
            SFrameSection::V1(sframe_section) => sframe_section.get_cfa_fixed_fp_offset(),
            SFrameSection::V2(sframe_section) => sframe_section.get_cfa_fixed_fp_offset(),
            SFrameSection::V3(sframe_section) => sframe_section.get_cfa_fixed_fp_offset(),
        }
    }

    /// Get SFrame CFA fixed RA offset
    pub fn get_cfa_fixed_ra_offset(&self) -> i8 {
        match self {
            SFrameSection::V1(sframe_section) => sframe_section.get_cfa_fixed_ra_offset(),
            SFrameSection::V2(sframe_section) => sframe_section.get_cfa_fixed_ra_offset(),
            SFrameSection::V3(sframe_section) => sframe_section.get_cfa_fixed_ra_offset(),
        }
    }

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

    /// Find FDE entry by pc
    pub fn find_fde(&self, pc: u64) -> SFrameResult<Option<SFrameFDE>> {
        match self {
            SFrameSection::V1(sframe_section) => {
                Ok(sframe_section.find_fde(pc)?.map(SFrameFDE::V1))
            }
            SFrameSection::V2(sframe_section) => {
                Ok(sframe_section.find_fde(pc)?.map(SFrameFDE::V2))
            }
            SFrameSection::V3(sframe_section) => {
                Ok(sframe_section.find_fde(pc)?.map(SFrameFDE::V3))
            }
        }
    }

    /// Access FDE by index
    pub fn get_fde(&self, index: u32) -> SFrameResult<Option<SFrameFDE>> {
        match self {
            SFrameSection::V1(sframe_section) => {
                Ok(sframe_section.get_fde(index)?.map(SFrameFDE::V1))
            }
            SFrameSection::V2(sframe_section) => {
                Ok(sframe_section.get_fde(index)?.map(SFrameFDE::V2))
            }
            SFrameSection::V3(sframe_section) => {
                Ok(sframe_section.get_fde(index)?.map(SFrameFDE::V3))
            }
        }
    }

    /// Get underlying SFrameSection for sframe v1
    pub fn as_v1(self) -> Option<v1::SFrameSection<'a>> {
        match self {
            SFrameSection::V1(sframe_section) => Some(sframe_section),
            _ => None,
        }
    }

    /// Get underlying SFrameSection for sframe v2
    pub fn as_v2(self) -> Option<v2::SFrameSection<'a>> {
        match self {
            SFrameSection::V2(sframe_section) => Some(sframe_section),
            _ => None,
        }
    }

    /// Get underlying SFrameSection for sframe v3
    pub fn as_v3(self) -> Option<v3::SFrameSection<'a>> {
        match self {
            SFrameSection::V3(sframe_section) => Some(sframe_section),
            _ => None,
        }
    }

    /// Iterate FDE entries
    pub fn iter_fde(&self) -> SFrameFDEIterator<'_> {
        SFrameFDEIterator {
            section: self,
            index: 0,
        }
    }
}

/// SFrame FDE
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Function-Descriptor-Entries>
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum SFrameFDE {
    V1(v1::SFrameFDE),
    V2(v2::SFrameFDE),
    V3(v3::SFrameFDE),
}

impl SFrameFDE {
    /// Compute PC of the function
    pub fn get_pc(&self, section: &SFrameSection<'_>) -> SFrameResult<u64> {
        match (self, section) {
            (SFrameFDE::V1(sframe_fde), SFrameSection::V1(sframe_section)) => {
                Ok(sframe_fde.get_pc(sframe_section))
            }
            (SFrameFDE::V2(sframe_fde), SFrameSection::V2(sframe_section)) => {
                Ok(sframe_fde.get_pc(sframe_section))
            }
            (SFrameFDE::V3(sframe_fde), SFrameSection::V3(sframe_section)) => {
                Ok(sframe_fde.get_pc(sframe_section))
            }
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }

    /// Check if this is a signal frame
    ///
    /// Returns `SFrameError::UnsupportedVersion` for version 1 and 2.
    pub fn is_signal_frame(&self) -> SFrameResult<bool> {
        match self {
            SFrameFDE::V1(_) | SFrameFDE::V2(_) => Err(SFrameError::UnsupportedVersion),
            SFrameFDE::V3(sframe_fde) => sframe_fde.func_info.is_signal_frame(),
        }
    }

    /// Find FRE entry by pc
    pub fn find_fre(
        &self,
        section: &SFrameSection<'_>,
        pc: u64,
    ) -> SFrameResult<Option<SFrameFRE>> {
        match (self, section) {
            (SFrameFDE::V1(sframe_fde), SFrameSection::V1(sframe_section)) => {
                Ok(sframe_fde.find_fre(sframe_section, pc)?.map(SFrameFRE::V1))
            }
            (SFrameFDE::V2(sframe_fde), SFrameSection::V2(sframe_section)) => {
                Ok(sframe_fde.find_fre(sframe_section, pc)?.map(SFrameFRE::V2))
            }
            (SFrameFDE::V3(sframe_fde), SFrameSection::V3(sframe_section)) => {
                Ok(sframe_fde.find_fre(sframe_section, pc)?.map(SFrameFRE::V3))
            }
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }

    /// Iterate FRE entries
    pub fn iter_fre<'a>(
        &'a self,
        section: &'a SFrameSection<'a>,
    ) -> SFrameResult<SFrameFREIterator<'a>> {
        match (self, section) {
            (SFrameFDE::V1(sframe_fde), SFrameSection::V1(sframe_section)) => {
                Ok(SFrameFREIterator::V1(sframe_fde.iter_fre(sframe_section)))
            }
            (SFrameFDE::V2(sframe_fde), SFrameSection::V2(sframe_section)) => {
                Ok(SFrameFREIterator::V2(sframe_fde.iter_fre(sframe_section)))
            }
            (SFrameFDE::V3(sframe_fde), SFrameSection::V3(sframe_section)) => {
                Ok(SFrameFREIterator::V3(sframe_fde.iter_fre(sframe_section)))
            }
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }
}

/// Iterator for SFrame FDE
pub struct SFrameFDEIterator<'a> {
    section: &'a SFrameSection<'a>,
    index: u32,
}

impl<'a> FallibleIterator for SFrameFDEIterator<'a> {
    type Item = SFrameFDE;
    type Error = SFrameError;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        let res = self.section.get_fde(self.index);
        if let Ok(Some(_)) = res {
            self.index += 1;
        }
        res
    }
}

/// Iterator for SFrame FRE
pub enum SFrameFREIterator<'a> {
    V1(v1::SFrameFREIterator<'a>),
    V2(v2::SFrameFREIterator<'a>),
    V3(v3::SFrameFREIterator<'a>),
}

impl<'a> FallibleIterator for SFrameFREIterator<'a> {
    type Item = SFrameFRE;
    type Error = SFrameError;

    fn next(&mut self) -> SFrameResult<Option<SFrameFRE>> {
        match self {
            SFrameFREIterator::V1(sframe_fre_iter) => {
                Ok(sframe_fre_iter.next()?.map(SFrameFRE::V1))
            }
            SFrameFREIterator::V2(sframe_fre_iter) => {
                Ok(sframe_fre_iter.next()?.map(SFrameFRE::V2))
            }
            SFrameFREIterator::V3(sframe_fre_iter) => {
                Ok(sframe_fre_iter.next()?.map(SFrameFRE::V3))
            }
        }
    }
}

/// SFrame FRE
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Frame-Row-Entries>
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SFrameFRE {
    V1(v1::SFrameFRE),
    V2(v2::SFrameFRE),
    V3(v3::SFrameFRE),
}

impl SFrameFRE {
    /// Distinguish between SP or FP based CFA recovery.
    pub fn get_cfa_base_reg_id(&self) -> u8 {
        match self {
            SFrameFRE::V1(sframe_fre) => sframe_fre.info.get_cfa_base_reg_id(),
            SFrameFRE::V2(sframe_fre) => sframe_fre.info.get_cfa_base_reg_id(),
            SFrameFRE::V3(sframe_fre) => sframe_fre.info.get_cfa_base_reg_id(),
        }
    }

    /// Get CFA offset against base reg
    pub fn get_cfa_offset(&self, section: &SFrameSection<'_>) -> SFrameResult<Option<i32>> {
        match (self, section) {
            (SFrameFRE::V1(sframe_fre), SFrameSection::V1(sframe_section)) => {
                Ok(sframe_fre.get_cfa_offset(sframe_section))
            }
            (SFrameFRE::V2(sframe_fre), SFrameSection::V2(sframe_section)) => {
                Ok(sframe_fre.get_cfa_offset(sframe_section))
            }
            (SFrameFRE::V3(sframe_fre), SFrameSection::V3(sframe_section)) => {
                Ok(sframe_fre.get_cfa_offset(sframe_section))
            }
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }

    /// Get RA offset against CFA
    pub fn get_ra_offset(&self, section: &SFrameSection<'_>) -> SFrameResult<Option<i32>> {
        match (self, section) {
            (SFrameFRE::V1(sframe_fre), SFrameSection::V1(sframe_section)) => {
                Ok(sframe_fre.get_ra_offset(sframe_section))
            }
            (SFrameFRE::V2(sframe_fre), SFrameSection::V2(sframe_section)) => {
                Ok(sframe_fre.get_ra_offset(sframe_section))
            }
            (SFrameFRE::V3(sframe_fre), SFrameSection::V3(sframe_section)) => {
                Ok(sframe_fre.get_ra_offset(sframe_section))
            }
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }

    /// Get FP offset against CFA
    pub fn get_fp_offset(&self, section: &SFrameSection<'_>) -> SFrameResult<Option<i32>> {
        match (self, section) {
            (SFrameFRE::V1(sframe_fre), SFrameSection::V1(sframe_section)) => {
                Ok(sframe_fre.get_fp_offset(sframe_section))
            }
            (SFrameFRE::V2(sframe_fre), SFrameSection::V2(sframe_section)) => {
                Ok(sframe_fre.get_fp_offset(sframe_section))
            }
            (SFrameFRE::V3(sframe_fre), SFrameSection::V3(sframe_section)) => {
                Ok(sframe_fre.get_fp_offset(sframe_section))
            }
            _ => Err(SFrameError::UnsupportedVersion),
        }
    }

    /// Get underlying SFrameFRE for sframe v1
    pub fn as_v1(self) -> Option<v1::SFrameFRE> {
        match self {
            SFrameFRE::V1(sframe_fre) => Some(sframe_fre),
            _ => None,
        }
    }

    /// Get underlying SFrameFRE for sframe v2
    pub fn as_v2(self) -> Option<v2::SFrameFRE> {
        match self {
            SFrameFRE::V2(sframe_fre) => Some(sframe_fre),
            _ => None,
        }
    }

    /// Get underlying SFrameFRE for sframe v3
    pub fn as_v3(self) -> Option<v3::SFrameFRE> {
        match self {
            SFrameFRE::V3(sframe_fre) => Some(sframe_fre),
            _ => None,
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
