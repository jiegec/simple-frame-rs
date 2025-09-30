use bitflags::bitflags;
use thiserror::Error;

pub type SFrameResult<T> = core::result::Result<T, SFrameError>;

// follow https://sourceware.org/binutils/docs/sframe-spec.html

/// SFrame Version
/// https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Version
#[derive(Debug, Clone, Copy)]
pub enum SFrameVersion {
    /// SFRAME_VERSION_1
    V1,
    /// SFRAME_VERSION_2
    V2,
}

/// SFrame ABI/arch Identifier
/// https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-ABI_002farch-Identifier
#[derive(Debug, Clone, Copy)]
pub enum SFrameABI {
    /// SFRAME_ABI_AARCH64_ENDIAN_BIG
    AArch64BigEndian,
    /// SFRAME_ABI_AARCH64_ENDIAN_LITTLE
    AArch64LittleEndian,
    /// SFRAME_ABI_AMD64_ENDIAN_LITTLE
    AMD64LittleEndian,
    /// SFRAME_ABI_S390X_ENDIAN_BIG
    S390XBigEndian,
}

bitflags! {
    /// SFrame Flags
    /// https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Flags
    #[derive(Debug, Clone, Copy)]
    pub struct SFrameFlags: u8 {
        /// Function Descriptor Entries are sorted on PC.
        const SFRAME_F_FDE_SORTED = 0x1;
        /// All functions in the object file preserve frame pointer.
        const SFRAME_F_FRAME_POINTER = 0x2;
        /// The sfde_func_start_address field in the SFrame FDE is an offset in bytes to the function’s start address, from the field itself. If unset, the sfde_func_start_address field in the SFrame FDE is an offset in bytes to the function’s start address, from the start of the SFrame section.
        const SFRAME_F_FDE_FUNC_START_PCREL = 0x4;
    }
}

/// Contains information of the SFrame section
/// https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Section
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SFrameSection<'a> {
    pub data: &'a [u8],
    pub little_endian: bool,
    pub version: SFrameVersion,
    pub flags: SFrameFlags,
    pub abi: SFrameABI,
    pub cfa_fixed_fp_offset: i8,
    pub cfa_fixed_ra_offset: i8,
    pub auxhdr_len: u8,
    pub num_fdes: u32,
    pub num_fres: u32,
    pub fre_len: u32,
    pub fdeoff: u32,
    pub freoff: u32,
}

/// SFrame Header
/// https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Header
#[repr(packed)]
struct SFrameHeader {
    magic: u16,
    version: u8,
    flags: u8,
    abi_arch: u8,
    cfa_fixed_fp_offset: i8,
    cfa_fixed_ra_offset: i8,
    auxhdr_len: u8,
    num_fdes: u32,
    num_fres: u32,
    fre_len: u32,
    fdeoff: u32,
    freoff: u32,
}

/// The magic number for SFrame section: 0xdee2
const SFRAME_MAGIC: u16 = 0xdee2;

macro_rules! read_u32 {
    ($data: ident, $le: ident, $x: ident) => {{
        let data_offset = core::mem::offset_of!(SFrameHeader, $x);
        let mut data_bytes: [u8; 4] = [0; 4];
        data_bytes.copy_from_slice(&$data[data_offset..data_offset + 4]);
        if $le {
            u32::from_le_bytes(data_bytes)
        } else {
            u32::from_be_bytes(data_bytes)
        }
    }};
}

impl<'a> SFrameSection<'a> {
    pub fn from(data: &'a [u8]) -> SFrameResult<SFrameSection<'a>> {
        // parse sframe_header
        if data.len() < core::mem::size_of::<SFrameHeader>() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        // probe magic
        let magic_offset = core::mem::offset_of!(SFrameHeader, magic);
        let mut magic_bytes: [u8; 2] = [0; 2];
        magic_bytes.copy_from_slice(&data[magic_offset..magic_offset + 2]);
        let magic_le = u16::from_le_bytes(magic_bytes);
        let little_endian;
        if magic_le == SFRAME_MAGIC {
            little_endian = true;
        } else {
            let magic_be = u16::from_be_bytes(magic_bytes);
            if magic_be == SFRAME_MAGIC {
                little_endian = false;
            } else {
                return Err(SFrameError::InvalidMagic);
            }
        }

        // probe version
        let version_offset = core::mem::offset_of!(SFrameHeader, version);
        let version = data[version_offset];
        let version = match version {
            1 => SFrameVersion::V1,
            2 => SFrameVersion::V2,
            _ => return Err(SFrameError::UnsupportedVersion),
        };

        // probe flag
        let flags_offset = core::mem::offset_of!(SFrameHeader, flags);
        let flags = data[flags_offset];
        let flags = match SFrameFlags::from_bits(flags) {
            Some(flags) => flags,
            None => return Err(SFrameError::UnsupportedFlags),
        };

        // probe abi
        let abi_offset = core::mem::offset_of!(SFrameHeader, abi_arch);
        let abi = data[abi_offset];
        let abi = match abi {
            1 => SFrameABI::AArch64BigEndian,
            2 => SFrameABI::AArch64LittleEndian,
            3 => SFrameABI::AMD64LittleEndian,
            4 => SFrameABI::S390XBigEndian,
            _ => return Err(SFrameError::UnsupportedABI),
        };

        let cfa_fixed_fp_offset =
            data[core::mem::offset_of!(SFrameHeader, cfa_fixed_fp_offset)] as i8;
        let cfa_fixed_ra_offset =
            data[core::mem::offset_of!(SFrameHeader, cfa_fixed_ra_offset)] as i8;
        let auxhdr_len = data[core::mem::offset_of!(SFrameHeader, auxhdr_len)];

        Ok(SFrameSection {
            data,
            little_endian,
            version,
            flags,
            abi,
            cfa_fixed_fp_offset,
            cfa_fixed_ra_offset,
            auxhdr_len,
            num_fdes: read_u32!(data, little_endian, num_fdes),
            num_fres: read_u32!(data, little_endian, num_fres),
            fre_len: read_u32!(data, little_endian, fre_len),
            fdeoff: read_u32!(data, little_endian, fdeoff),
            freoff: read_u32!(data, little_endian, freoff),
        })
    }
}

#[derive(Error, Debug)]
pub enum SFrameError {
    #[error("unexpected end of data")]
    UnexpectedEndOfData,
    #[error("invalid magic number")]
    InvalidMagic,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("unsupported flags")]
    UnsupportedFlags,
    #[error("unsupported abi")]
    UnsupportedABI,
}

#[cfg(test)]
mod tests {}
