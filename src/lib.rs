//! Crate to parse SFrame stack trace information.
//!
//! Usage: Use [SFrameSection::from] to load sframe section content and access
//! its content.
//!
//! Spec: <https://sourceware.org/binutils/docs/sframe-spec.html>

use bitflags::bitflags;
use core::fmt::Write;
use fallible_iterator::FallibleIterator;
use std::cmp::Ordering;
use thiserror::Error;

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

macro_rules! read_struct {
    ($struct: ident, $data: expr, $le: expr, $x: ident, $ty: ident) => {{ read_binary!($data, $le, $ty, core::mem::offset_of!($struct, $x)) }};
}

/// Result type for the crate
pub type SFrameResult<T> = core::result::Result<T, SFrameError>;

/// SFrame Version
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Version>
#[derive(Debug, Clone, Copy)]
pub enum SFrameVersion {
    /// SFRAME_VERSION_1
    V1,
    /// SFRAME_VERSION_2
    V2,
}

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
    /// SFRAME_ABI_S390X_ENDIAN_BIG
    S390XBigEndian,
}

bitflags! {
    /// SFrame Flags
    ///
    /// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Flags>
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

/// SFrame section
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Section>
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SFrameSection<'a> {
    data: &'a [u8],
    section_base: u64,
    little_endian: bool,
    version: SFrameVersion,
    flags: SFrameFlags,
    abi: SFrameABI,
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

impl<'a> SFrameSection<'a> {
    /// Parse SFrame section from data
    pub fn from(data: &'a [u8], section_base: u64) -> SFrameResult<SFrameSection<'a>> {
        // parse sframe_header
        if data.len() < core::mem::size_of::<RawSFrameHeader>() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        // probe magic
        let magic_offset = core::mem::offset_of!(RawSFrameHeader, magic);
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
        let version_offset = core::mem::offset_of!(RawSFrameHeader, version);
        let version = data[version_offset];
        let version = match version {
            1 => SFrameVersion::V1,
            2 => SFrameVersion::V2,
            _ => return Err(SFrameError::UnsupportedVersion),
        };

        // probe flag
        let flags_offset = core::mem::offset_of!(RawSFrameHeader, flags);
        let flags = data[flags_offset];
        let flags = match SFrameFlags::from_bits(flags) {
            Some(flags) => flags,
            None => return Err(SFrameError::UnsupportedFlags),
        };

        // probe abi
        let abi_offset = core::mem::offset_of!(RawSFrameHeader, abi_arch);
        let abi = data[abi_offset];
        let abi = match abi {
            1 => SFrameABI::AArch64BigEndian,
            2 => SFrameABI::AArch64LittleEndian,
            3 => SFrameABI::AMD64LittleEndian,
            4 => SFrameABI::S390XBigEndian,
            _ => return Err(SFrameError::UnsupportedABI),
        };

        let cfa_fixed_fp_offset =
            data[core::mem::offset_of!(RawSFrameHeader, cfa_fixed_fp_offset)] as i8;
        let cfa_fixed_ra_offset =
            data[core::mem::offset_of!(RawSFrameHeader, cfa_fixed_ra_offset)] as i8;
        let auxhdr_len = data[core::mem::offset_of!(RawSFrameHeader, auxhdr_len)];

        Ok(SFrameSection {
            data,
            section_base,
            little_endian,
            version,
            flags,
            abi,
            cfa_fixed_fp_offset,
            cfa_fixed_ra_offset,
            auxhdr_len,
            num_fdes: read_struct!(RawSFrameHeader, data, little_endian, num_fdes, u32),
            num_fres: read_struct!(RawSFrameHeader, data, little_endian, num_fres, u32),
            fre_len: read_struct!(RawSFrameHeader, data, little_endian, fre_len, u32),
            fdeoff: read_struct!(RawSFrameHeader, data, little_endian, fdeoff, u32),
            freoff: read_struct!(RawSFrameHeader, data, little_endian, freoff, u32),
        })
    }

    /// Get the count of FDE entries
    pub fn get_fde_count(&self) -> u32 {
        self.num_fdes
    }

    /// Access FDE by index
    pub fn get_fde(&self, index: u32) -> SFrameResult<Option<SFrameFDE>> {
        if index >= self.num_fdes {
            // out of bounds
            return Ok(None);
        }

        // The sub-section offsets, namely sfh_fdeoff and sfh_freoff, in the
        // SFrame header are relative to the end of the SFrame header; they are
        // each an offset in bytes into the SFrame section where the SFrame FDE
        // sub-section and the SFrame FRE sub-section respectively start.
        let offset = self.fdeoff as usize
            + index as usize * core::mem::size_of::<RawSFrameFDE>()
            + core::mem::size_of::<RawSFrameHeader>();
        if offset + core::mem::size_of::<RawSFrameFDE>() > self.data.len() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        Ok(Some(SFrameFDE {
            offset,
            func_start_address: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                func_start_address,
                i32
            ),
            func_size: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                func_size,
                u32
            ),
            func_start_fre_off: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                func_start_fre_off,
                u32
            ),
            func_num_fres: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                func_num_fres,
                u32
            ),
            func_info: SFrameFDEInfo(
                self.data[offset + core::mem::offset_of!(RawSFrameFDE, func_info)],
            ),
            func_rep_size: self.data[offset + core::mem::offset_of!(RawSFrameFDE, func_rep_size)],
        }))
    }

    /// Print the section in string in the same way as objdump
    pub fn to_string(&self) -> SFrameResult<String> {
        let mut s = String::new();
        writeln!(&mut s, "Header :")?;
        writeln!(&mut s)?;
        writeln!(
            &mut s,
            "  Version: {}",
            match self.version {
                SFrameVersion::V1 => "SFRAME_VERSION_1",
                SFrameVersion::V2 => "SFRAME_VERSION_2",
            }
        )?;
        writeln!(
            &mut s,
            "  Flags: {}",
            self.flags
                .iter_names()
                .map(|(name, _flag)| name)
                .collect::<Vec<_>>()
                .join(" | ")
        )?;
        if self.cfa_fixed_fp_offset != 0 {
            writeln!(
                &mut s,
                "  CFA fixed FP offset: {:?}",
                self.cfa_fixed_fp_offset
            )?;
        }
        if self.cfa_fixed_ra_offset != 0 {
            writeln!(
                &mut s,
                "  CFA fixed RA offset: {:?}",
                self.cfa_fixed_ra_offset
            )?;
        }
        writeln!(&mut s, "  Num FDEs: {:?}", self.num_fdes)?;
        writeln!(&mut s, "  Num FREs: {:?}", self.num_fres)?;
        writeln!(&mut s)?;
        writeln!(&mut s, "Function Index :")?;
        writeln!(&mut s)?;
        for i in 0..self.num_fdes {
            let fde = self.get_fde(i)?.unwrap();
            let pc = fde.get_pc(self);
            writeln!(
                &mut s,
                "  func idx [{i}]: pc = 0x{:x}, size = {} bytes",
                pc, fde.func_size,
            )?;

            match fde.func_info.get_fde_type()? {
                SFrameFDEType::PCInc => {
                    writeln!(&mut s, "  STARTPC           CFA      FP     RA")?;
                }
                SFrameFDEType::PCMask => {
                    writeln!(&mut s, "  STARTPC[m]        CFA      FP     RA")?;
                }
            }
            let mut iter = fde.iter_fre(self);
            while let Some(fre) = iter.next()? {
                let start_pc = match fde.func_info.get_fde_type()? {
                    SFrameFDEType::PCInc => pc + fre.start_address.get() as u64,
                    SFrameFDEType::PCMask => fre.start_address.get() as u64,
                };
                let rest = match self.abi {
                    SFrameABI::AMD64LittleEndian => {
                        // https://sourceware.org/binutils/docs/sframe-spec.html#AMD64
                        let base_reg = if fre.info.get_cfa_base_reg_id() == 0 {
                            "fp"
                        } else {
                            "sp"
                        };
                        let cfa = format!("{}+{}", base_reg, fre.stack_offsets[0].get());
                        let fp = match fre.stack_offsets.get(1) {
                            Some(offset) => format!("c{:+}", offset.get()),
                            None => "u".to_string(), // without offset
                        };
                        let ra = "f"; // fixed
                        format!("{cfa:8} {fp:6} {ra}")
                    }
                    SFrameABI::AArch64LittleEndian => {
                        // https://sourceware.org/binutils/docs/sframe-spec.html#AArch64
                        let base_reg = if fre.info.get_cfa_base_reg_id() == 0 {
                            "fp"
                        } else {
                            "sp"
                        };
                        let cfa = format!("{}+{}", base_reg, fre.stack_offsets[0].get());
                        let fp = match fre.stack_offsets.get(1) {
                            Some(offset) => format!("c{:+}", offset.get()),
                            None => "u".to_string(), // without offset
                        };
                        let ra = match fre.stack_offsets.get(2) {
                            Some(offset) => format!("c{:+}", offset.get()),
                            None => "u".to_string(), // without offset
                        };
                        format!("{cfa:8} {fp:6} {ra}")
                    }
                    _ => todo!(),
                };
                writeln!(&mut s, "  {:016x}  {}", start_pc, rest)?;
            }
            writeln!(&mut s,)?;
        }
        Ok(s)
    }

    /// Iterate FDE entries
    pub fn iter_fde(&self) -> SFrameFDEIterator<'_> {
        SFrameFDEIterator {
            section: self,
            index: 0,
        }
    }

    /// Find FDE entry by pc
    pub fn find_fde(&self, pc: u64) -> SFrameResult<Option<SFrameFDE>> {
        // TODO: support SFRAME_FDE_TYPE_PCMASK
        if self.flags.contains(SFrameFlags::SFRAME_F_FDE_SORTED) {
            // binary search
            // mimic binary_search_by impl from rust std
            let mut size = self.num_fdes;
            if size == 0 {
                return Ok(None);
            }
            let mut base = 0;

            while size > 1 {
                let half = size / 2;
                let mid = base + half;

                let cmp = self.get_fde(mid)?.unwrap().get_pc(self).cmp(&pc);
                if cmp != Ordering::Greater {
                    base = mid;
                }
                size -= half;
            }

            let base_fde = self.get_fde(base)?.unwrap();
            let base_pc = base_fde.get_pc(self);
            let cmp = base_pc.cmp(&pc);
            match cmp {
                Ordering::Equal | Ordering::Less if pc < base_pc + base_fde.func_size as u64 => {
                    Ok(Some(base_fde))
                }
                _ => Ok(None),
            }
        } else {
            // linear scan
            let mut iter = self.iter_fde();
            while let Some(fde) = iter.next()? {
                let start = fde.get_pc(self);
                let end = start + fde.func_size as u64;
                if start <= pc && pc < end {
                    return Ok(Some(fde));
                }
            }
            Ok(None)
        }
    }

    /// Get SFrame version
    pub fn get_version(&self) -> SFrameVersion {
        self.version
    }

    /// Get SFrame flags
    pub fn get_flags(&self) -> SFrameFlags {
        self.flags
    }

    /// Get SFrame ABI
    pub fn get_abi(&self) -> SFrameABI {
        self.abi
    }

    /// Get SFrame CFA fixed FP offset
    pub fn get_cfa_fixed_fp_offset(&self) -> i8 {
        self.cfa_fixed_fp_offset
    }

    /// Get SFrame CFA fixed RA offset
    pub fn get_cfa_fixed_ra_offset(&self) -> i8 {
        self.cfa_fixed_ra_offset
    }
}

/// Raw SFrame Header
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Header>
#[repr(C, packed)]
struct RawSFrameHeader {
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

/// Raw SFrame FDE
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Function-Descriptor-Entries>
#[repr(C, packed)]
#[allow(dead_code)]
struct RawSFrameFDE {
    func_start_address: i32,
    func_size: u32,
    func_start_fre_off: u32,
    func_num_fres: u32,
    func_info: u8,
    func_rep_size: u8,
    func_padding2: u16,
}

/// SFrame FDE Info Word
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#The-SFrame-FDE-Info-Word>
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SFrameFDEInfo(u8);

impl SFrameFDEInfo {
    /// Get SFrame FRE type
    pub fn get_fre_type(&self) -> SFrameResult<SFrameFREType> {
        let fretype = self.0 & 0b1111;
        match fretype {
            0 => Ok(SFrameFREType::Addr0),
            1 => Ok(SFrameFREType::Addr1),
            2 => Ok(SFrameFREType::Addr2),
            _ => Err(SFrameError::UnsupportedFREType),
        }
    }

    /// Get SFrame FDE type
    pub fn get_fde_type(&self) -> SFrameResult<SFrameFDEType> {
        let fretype = (self.0 >> 4) & 0b1;
        match fretype {
            0 => Ok(SFrameFDEType::PCInc),
            1 => Ok(SFrameFDEType::PCMask),
            _ => unreachable!(),
        }
    }

    /// Get SFrame AArch64 pauth key
    pub fn get_aarch64_pauth_key(&self) -> SFrameResult<SFrameAArch64PAuthKey> {
        let fretype = (self.0 >> 5) & 0b1;
        match fretype {
            0 => Ok(SFrameAArch64PAuthKey::KeyA),
            1 => Ok(SFrameAArch64PAuthKey::KeyB),
            _ => unreachable!(),
        }
    }
}

/// SFrame FRE Types
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#The-SFrame-FRE-Types>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFREType {
    /// SFRAME_FRE_TYPE_ADDR0
    /// The start address offset (in bytes) of the SFrame FRE is an unsigned
    /// 8-bit value.
    Addr0,
    /// SFRAME_FRE_TYPE_ADDR1
    /// The start address offset (in bytes) of the SFrame FRE is an unsigned
    /// 16-bit value.
    Addr1,
    /// SFRAME_FRE_TYPE_ADDR2
    /// The start address offset (in bytes) of the SFrame FRE is an unsigned
    /// 32-bit value.
    Addr2,
}

/// SFrame FDE Types
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#The-SFrame-FDE-Types>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFDEType {
    /// SFRAME_FDE_TYPE_PCINC
    PCInc,
    /// SFRAME_FDE_TYPE_PCMASK
    PCMask,
}

/// SFrame PAuth key
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#The-SFrame-FDE-Info-Word>
#[derive(Debug, Clone, Copy)]
pub enum SFrameAArch64PAuthKey {
    /// SFRAME_AARCH64_PAUTH_KEY_A
    KeyA,
    /// SFRAME_AARCH64_PAUTH_KEY_B
    KeyB,
}

/// SFrame FDE
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Function-Descriptor-Entries>
#[derive(Debug, Clone, Copy)]
pub struct SFrameFDE {
    /// Offset from the beginning of sframe section
    offset: usize,
    /// Signed 32-bit integral field denoting the virtual memory address of the
    /// described function,for which the SFrame FDE applies. If the flag
    /// SFRAME_F_FDE_FUNC_START_PCREL, See SFrame Flags, in the SFrame header is
    /// set, the value encoded in the sfde_func_start_address field is the
    /// offset in bytes to the function’s start address, from the SFrame
    /// sfde_func_start_address field.
    pub func_start_address: i32,
    /// Unsigned 32-bit integral field specifying the size of the function in
    /// bytes.
    pub func_size: u32,
    /// Unsigned 32-bit integral field specifying the offset in bytes of the
    /// function’s first SFrame FRE in the SFrame section.
    pub func_start_fre_off: u32,
    /// Unsigned 32-bit integral field specifying the total number of SFrame
    /// FREs used for the function.
    pub func_num_fres: u32,
    /// Unsigned 8-bit integral field specifying the SFrame FDE info word. See
    /// The SFrame FDE Info Word.
    pub func_info: SFrameFDEInfo,
    /// Unsigned 8-bit integral field specifying the size of the repetitive code
    /// block for which an SFrame FDE of type SFRAME_FDE_TYPE_PCMASK is used.
    /// For example, in AMD64, the size of a pltN entry is 16 bytes.
    pub func_rep_size: u8,
}

impl SFrameFDE {
    /// Compute pc of the function
    pub fn get_pc(&self, section: &SFrameSection<'_>) -> u64 {
        // "If the flag SFRAME_F_FDE_FUNC_START_PCREL, See SFrame Flags, in the
        // SFrame header is set, the value encoded in the
        // sfde_func_start_address field is the offset in bytes to the
        // function’s start address, from the SFrame sfde_func_start_address
        // field."
        if section
            .flags
            .contains(SFrameFlags::SFRAME_F_FDE_FUNC_START_PCREL)
        {
            (self.func_start_address as i64 + self.offset as i64 + section.section_base as i64)
                as u64
        } else {
            (self.func_start_address as i64 + section.section_base as i64) as u64
        }
    }

    pub fn iter_fre<'a>(&'a self, section: &'a SFrameSection<'a>) -> SFrameFREIterator<'a> {
        // "The sub-section offsets, namely sfh_fdeoff and sfh_freoff, in the
        // SFrame header are relative to the end of the SFrame header; they are
        // each an offset in bytes into the SFrame section where the SFrame FDE
        // sub-section and the SFrame FRE sub-section respectively start."
        // "sfde_func_start_fre_off is the offset to the first SFrame FRE for
        // the function. This offset is relative to the end of the SFrame FDE
        // sub-section (unlike the sub-section offsets in the SFrame header,
        // which are relative to the end of the SFrame header)."
        let offset = section.freoff as usize
            + core::mem::size_of::<RawSFrameHeader>()
            + self.func_start_fre_off as usize;
        SFrameFREIterator {
            fde: self,
            section,
            offset,
            index: 0,
        }
    }
}

/// SFrame FRE Start Address
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Frame-Row-Entries>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFREStartAddress {
    U8(u8),
    U16(u16),
    U32(u32),
}

impl SFrameFREStartAddress {
    /// Convert the variable sized address to u32
    pub fn get(&self) -> u32 {
        match self {
            SFrameFREStartAddress::U8(i) => *i as u32,
            SFrameFREStartAddress::U16(i) => *i as u32,
            SFrameFREStartAddress::U32(i) => *i,
        }
    }
}

/// SFrame FRE Stack Offset
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Frame-Row-Entries>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFREStackOffset {
    I8(i8),
    I16(i16),
    I32(i32),
}

impl SFrameFREStackOffset {
    /// Convert the variable sized offset to i32
    pub fn get(&self) -> i32 {
        match self {
            SFrameFREStackOffset::I8(i) => *i as i32,
            SFrameFREStackOffset::I16(i) => *i as i32,
            SFrameFREStackOffset::I32(i) => *i,
        }
    }
}

/// SFrame FRE
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#SFrame-Frame-Row-Entries>
#[derive(Debug, Clone)]
pub struct SFrameFRE {
    /// Start address (in offset form) of the function
    pub start_address: SFrameFREStartAddress,
    /// FRE info
    pub info: SFrameFREInfo,
    /// Stack offsets to access CFA, FP and RA
    pub stack_offsets: Vec<SFrameFREStackOffset>,
}

impl SFrameFRE {
    /// Get CFA offset against base reg
    pub fn get_cfa_offset(&self) -> Option<i32> {
        // currently always the first offset
        self.stack_offsets.get(0).map(|offset| offset.get())
    }

    /// Get RA offset against CFA
    pub fn get_ra_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        match section.abi {
            // the second offset for aarch64
            SFrameABI::AArch64BigEndian | SFrameABI::AArch64LittleEndian => {
                self.stack_offsets.get(1).map(|offset| offset.get())
            }
            // always fixed for amd64
            SFrameABI::AMD64LittleEndian => Some(section.cfa_fixed_ra_offset as i32),
            // TODO: stack slot or register number
            SFrameABI::S390XBigEndian => todo!(),
        }
    }

    /// Get FP offset against CFA
    pub fn get_fp_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        match section.abi {
            // the third offset for aarch64
            SFrameABI::AArch64BigEndian | SFrameABI::AArch64LittleEndian => {
                self.stack_offsets.get(2).map(|offset| offset.get())
            }
            // the second offset for aarch64
            SFrameABI::AMD64LittleEndian => self.stack_offsets.get(1).map(|offset| offset.get()),
            // TODO: stack slot or register number
            SFrameABI::S390XBigEndian => todo!(),
        }
    }
}

/// SFrame FRE Info Word
///
/// Ref: <https://sourceware.org/binutils/docs/sframe-spec.html#The-SFrame-FRE-Info-Word>
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SFrameFREInfo(u8);

impl SFrameFREInfo {
    /// Indicate whether the return address is mangled with any authorization
    /// bits (signed RA).
    pub fn get_mangled_ra_p(&self) -> bool {
        (self.0 >> 7) & 0b1 == 1
    }

    /// Size of stack offsets in bytes.
    pub fn get_offset_size(&self) -> SFrameResult<usize> {
        match (self.0 >> 5) & 0b11 {
            // SFRAME_FRE_OFFSET_1B
            0x0 => Ok(1),
            // SFRAME_FRE_OFFSET_2B
            0x1 => Ok(2),
            // SFRAME_FRE_OFFSET_4B
            0x2 => Ok(4),
            _ => Err(SFrameError::UnsupportedFREStackOffsetSize),
        }
    }

    /// The number of stack offsets in the FRE
    pub fn get_offset_count(&self) -> u8 {
        (self.0 >> 1) & 0b111
    }

    /// Distinguish between SP or FP based CFA recovery.
    pub fn get_cfa_base_reg_id(&self) -> u8 {
        self.0 & 0b1
    }
}

/// Iterator for SFrame FRE
pub struct SFrameFREIterator<'a> {
    fde: &'a SFrameFDE,
    section: &'a SFrameSection<'a>,
    index: u32,
    offset: usize,
}

impl<'a> FallibleIterator for SFrameFREIterator<'a> {
    type Item = SFrameFRE;
    type Error = SFrameError;

    fn next(&mut self) -> SFrameResult<Option<SFrameFRE>> {
        if self.index >= self.fde.func_num_fres {
            return Ok(None);
        }

        let fre_type = self.fde.func_info.get_fre_type()?;
        let entry_size = match fre_type {
            SFrameFREType::Addr0 => 1 + 1,
            SFrameFREType::Addr1 => 2 + 1,
            SFrameFREType::Addr2 => 4 + 1,
        } as usize;
        let offset = self.offset;
        if offset + entry_size > self.section.data.len() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        let (start_address, info) = match self.fde.func_info.get_fre_type()? {
            SFrameFREType::Addr0 => (
                SFrameFREStartAddress::U8(self.section.data[offset]),
                SFrameFREInfo(self.section.data[offset + 1]),
            ),
            SFrameFREType::Addr1 => (
                SFrameFREStartAddress::U16(read_binary!(
                    self.section.data,
                    self.section.little_endian,
                    u16,
                    offset
                )),
                SFrameFREInfo(self.section.data[offset + 2]),
            ),
            SFrameFREType::Addr2 => (
                SFrameFREStartAddress::U32(read_binary!(
                    self.section.data,
                    self.section.little_endian,
                    u32,
                    offset
                )),
                SFrameFREInfo(self.section.data[offset + 4]),
            ),
        };

        let offset_size = info.get_offset_size()?;
        let offset_count = info.get_offset_count() as usize;
        let offset_total_size = offset_size * offset_count;
        if offset + entry_size + offset_total_size > self.section.data.len() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        let mut stack_offsets = vec![];
        for i in 0..offset_count {
            match offset_size {
                1 => stack_offsets.push(SFrameFREStackOffset::I8(
                    self.section.data[offset + entry_size + i * offset_size] as i8,
                )),
                2 => stack_offsets.push(SFrameFREStackOffset::I16(read_binary!(
                    self.section.data,
                    self.section.little_endian,
                    i16,
                    offset + entry_size + i * offset_size
                ))),
                4 => stack_offsets.push(SFrameFREStackOffset::I32(read_binary!(
                    self.section.data,
                    self.section.little_endian,
                    i32,
                    offset + entry_size + i * offset_size
                ))),
                _ => unreachable!(),
            }
        }

        self.offset += entry_size + offset_total_size;
        self.index += 1;

        Ok(Some(SFrameFRE {
            start_address,
            info,
            stack_offsets,
        }))
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
    /// Unsupported FRE type
    #[error("unsupported fre type")]
    UnsupportedFREType,
    /// Unsupported FRE stack offset size
    #[error("unsupported fre stack offset size")]
    UnsupportedFREStackOffsetSize,
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use serde::{Deserialize, Serialize};
    #[derive(Serialize, Deserialize)]
    struct Testcase {
        section_base: u64,
        content: Vec<u8>,
        groundtruth: String,
    }

    #[test]
    fn test() {
        for entry in std::fs::read_dir("testcases").unwrap() {
            let entry = entry.unwrap();
            let testcase: Testcase =
                serde_json::from_reader(std::fs::File::open(entry.path()).unwrap()).unwrap();
            let section =
                crate::SFrameSection::from(&testcase.content, testcase.section_base).unwrap();
            let s = section.to_string().unwrap();
            let mut lines_expected: Vec<&str> = testcase.groundtruth.trim().split("\n").collect();

            // drop prefix
            while let Some(line) = lines_expected.first() {
                if line.contains("Header :") {
                    break;
                }
                lines_expected.remove(0);
            }
            let lines_actual: Vec<&str> = s.trim().split("\n").collect();

            // compare line by line
            assert_eq!(lines_expected.len(), lines_actual.len());
            for (expected, actual) in zip(lines_expected, lines_actual) {
                let parts_expected: Vec<&str> =
                    expected.trim().split(" ").filter(|s| s.len() > 0).collect();
                let parts_actual: Vec<&str> =
                    actual.trim().split(" ").filter(|s| s.len() > 0).collect();
                assert_eq!(
                    parts_expected, parts_actual,
                    "\"{}\"({:?}) != \"{}\"({:?})",
                    expected, parts_expected, actual, parts_actual,
                );
            }
        }
    }
}
