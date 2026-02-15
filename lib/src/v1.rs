//! SFrame Version 1 types and implementation.
//!
//! Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html>

use crate::{SFrameABI, SFrameError, SFrameResult, read_binary, read_struct};
use bitflags::bitflags;
use fallible_iterator::FallibleIterator;
use std::{cmp::Ordering, fmt::Write};

bitflags! {
    /// SFrame Flags
    ///
    /// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Flags>
    #[derive(Debug, Clone, Copy)]
    pub struct SFrameFlags: u8 {
        /// Function Descriptor Entries are sorted on PC.
        const SFRAME_F_FDE_SORTED = 0x1;
        /// Functions preserve frame-pointer.
        const SFRAME_F_FRAME_POINTER = 0x2;
    }
}

/// SFrame section
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Section>
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SFrameSection<'a> {
    data: &'a [u8],
    section_base: u64,
    little_endian: bool,
    flags: SFrameFlags,
    /// The ABI/arch identifier. See SFrame ABI/arch identifier.
    abi: SFrameABI,
    /// The CFA fixed FP offset, if any.
    cfa_fixed_fp_offset: i8,
    /// The CFA fixed RA offset, if any.
    cfa_fixed_ra_offset: i8,
    /// Size in bytes of the auxilliary header that follows the sframe_header structure.
    auxhdr_len: u8,
    /// The number of SFrame FDEs in the section.
    num_fdes: u32,
    /// The number of SFrame FREs in the section.
    num_fres: u32,
    /// The length in bytes of the SFrame FRE sub-section.
    fre_len: u32,
    /// The offset in bytes of the SFrame FDE sub-section. This sub-section
    /// contains sfh_num_fdes number of fixed-length array elements. The array
    /// element is of type SFrame function desciptor entry, each providing a
    /// high-level function description for backtracing. See SFrame FDE.
    fdeoff: u32,
    /// The offset in bytes of the SFrame FRE sub-section, the core of the
    /// SFrame section, which describes the unwind information using
    /// variable-length array elements. See SFrame FRE.
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
        let magic_offset = core::mem::offset_of!(RawSFrameHeader, sfh_preamble.sfp_magic);
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
        let version_offset = core::mem::offset_of!(RawSFrameHeader, sfh_preamble.sfp_version);
        let version = data[version_offset];
        if version != 1 {
            return Err(SFrameError::UnsupportedVersion);
        }

        // probe flag
        let flags_offset = core::mem::offset_of!(RawSFrameHeader, sfh_preamble.sfp_flags);
        let flags = data[flags_offset];
        let flags = match SFrameFlags::from_bits(flags) {
            Some(flags) => flags,
            None => return Err(SFrameError::UnsupportedFlags),
        };

        // probe abi
        let abi_offset = core::mem::offset_of!(RawSFrameHeader, sfh_abi_arch);
        let abi = data[abi_offset];
        let abi = match abi {
            1 => SFrameABI::AArch64BigEndian,
            2 => SFrameABI::AArch64LittleEndian,
            3 => SFrameABI::AMD64LittleEndian,
            _ => return Err(SFrameError::UnsupportedABI),
        };

        let cfa_fixed_fp_offset =
            data[core::mem::offset_of!(RawSFrameHeader, sfh_cfa_fixed_fp_offset)] as i8;
        let cfa_fixed_ra_offset =
            data[core::mem::offset_of!(RawSFrameHeader, sfh_cfa_fixed_ra_offset)] as i8;
        let auxhdr_len = data[core::mem::offset_of!(RawSFrameHeader, sfh_auxhdr_len)];

        // initial validation
        let num_fdes = read_struct!(RawSFrameHeader, data, little_endian, sfh_num_fdes, u32);
        let fdeoff = read_struct!(RawSFrameHeader, data, little_endian, sfh_fdeoff, u32);
        if data.len() - core::mem::size_of::<RawSFrameHeader>() < fdeoff as usize {
            return Err(SFrameError::UnexpectedEndOfData);
        } else if (data.len() - core::mem::size_of::<RawSFrameHeader>() - fdeoff as usize)
            / core::mem::size_of::<RawSFrameFDE>()
            < num_fdes as usize
        {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        Ok(SFrameSection {
            data,
            section_base,
            little_endian,
            flags,
            abi,
            cfa_fixed_fp_offset,
            cfa_fixed_ra_offset,
            auxhdr_len,
            num_fdes,
            num_fres: read_struct!(RawSFrameHeader, data, little_endian, sfh_num_fres, u32),
            fre_len: read_struct!(RawSFrameHeader, data, little_endian, sfh_fre_len, u32),
            fdeoff,
            freoff: read_struct!(RawSFrameHeader, data, little_endian, sfh_freoff, u32),
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
            func_start_address: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                sfde_func_start_address,
                i32
            ),
            func_size: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                sfde_func_size,
                u32
            ),
            func_start_fre_off: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                sfde_func_start_fre_off,
                u32
            ),
            func_num_fres: read_struct!(
                RawSFrameFDE,
                &self.data[offset..],
                self.little_endian,
                sfde_func_num_fres,
                u32
            ),
            func_info: SFrameFDEInfo(
                self.data[offset + core::mem::offset_of!(RawSFrameFDE, sfde_func_info)],
            ),
        }))
    }

    /// Print the section in string in the same way as objdump
    pub fn to_string(&self) -> SFrameResult<String> {
        let mut s = String::new();
        writeln!(&mut s, "Header :")?;
        writeln!(&mut s)?;
        writeln!(&mut s, "  Version: SFRAME_VERSION_1")?;
        writeln!(
            &mut s,
            "  Flags: {}",
            self.flags
                .iter_names()
                .map(|(name, _flag)| name)
                .collect::<Vec<_>>()
                .join(" | ")
        )?;
        writeln!(&mut s, "  Num FDEs: {:?}", self.num_fdes)?;
        writeln!(&mut s, "  Num FREs: {:?}", self.num_fres)?;
        writeln!(&mut s)?;
        writeln!(&mut s, "Function Index :")?;
        writeln!(&mut s)?;
        for i in 0..self.num_fdes {
            let fde = self.get_fde(i)?.unwrap();
            let pc = fde.get_pc(self);
            let mut suffix = String::new();

            // aarch64 pauth
            if let SFrameAArch64PAuthKey::KeyB = fde.func_info.get_aarch64_pauth_key()? {
                suffix += ", pauth = B key";
            }
            writeln!(
                &mut s,
                "  func idx [{i}]: pc = 0x{:x}, size = {} bytes{}",
                pc, fde.func_size, suffix
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
                if fre.stack_offsets.is_empty() {
                    continue;
                }

                let start_pc = match fde.func_info.get_fde_type()? {
                    SFrameFDEType::PCInc => pc.wrapping_add(fre.start_address.get() as u64),
                    SFrameFDEType::PCMask => fre.start_address.get() as u64,
                };
                let base_reg = if fre.info.get_cfa_base_reg_id() == 0 {
                    "fp"
                } else {
                    "sp"
                };
                let cfa = format!("{}+{}", base_reg, fre.stack_offsets[0].get());
                let fp = match fre.get_fp_offset(self) {
                    Some(offset) if self.cfa_fixed_fp_offset == 0 => format!("c{:+}", offset),
                    _ => "u".to_string(), // without offset
                };
                let mut ra = match fre.get_ra_offset(self) {
                    Some(offset) if self.cfa_fixed_ra_offset == 0 => format!("c{:+}", offset),
                    _ => "u".to_string(), // without offset
                };
                if fre.info.get_mangled_ra_p() {
                    // ra is mangled with signature
                    ra.push_str("[s]");
                }
                let rest = format!("{cfa:8} {fp:6} {ra}");
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
                if start <= pc && pc - start < fde.func_size as u64 {
                    return Ok(Some(fde));
                }
            }
            Ok(None)
        }
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

/// Raw SFrame Preamble
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Preamble>
#[repr(C, packed)]
struct RawSFramePreamble {
    sfp_magic: u16,
    sfp_version: u8,
    sfp_flags: u8,
}

/// Raw SFrame Header
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Header>
#[repr(C, packed)]
struct RawSFrameHeader {
    sfh_preamble: RawSFramePreamble,
    sfh_abi_arch: u8,
    sfh_cfa_fixed_fp_offset: i8,
    sfh_cfa_fixed_ra_offset: i8,
    sfh_auxhdr_len: u8,
    sfh_num_fdes: u32,
    sfh_num_fres: u32,
    sfh_fre_len: u32,
    sfh_fdeoff: u32,
    sfh_freoff: u32,
}

/// Raw SFrame FDE
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Function-Descriptor-Entries>
#[repr(C, packed)]
#[allow(dead_code)]
struct RawSFrameFDE {
    sfde_func_start_address: i32,
    sfde_func_size: u32,
    sfde_func_start_fre_off: u32,
    sfde_func_num_fres: u32,
    sfde_func_info: u8,
}

/// SFrame FDE Info Word
///
/// Note: Bits 6-7 are unused per spec, but not validated to allow for future extensions.
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#The-SFrame-FDE-Info-Word>
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SFrameFDEInfo(u8);

impl SFrameFDEInfo {
    /// Get SFrame FRE type
    pub fn get_fre_type(&self) -> SFrameResult<SFrameFREType> {
        // Choice of three SFrame FRE types. See The SFrame FRE types.
        let fretype = self.0 & 0b1111;
        match fretype {
            0 => Ok(SFrameFREType::Addr1),
            1 => Ok(SFrameFREType::Addr2),
            2 => Ok(SFrameFREType::Addr4),
            _ => Err(SFrameError::UnsupportedFREType),
        }
    }

    /// Get SFrame FDE type
    pub fn get_fde_type(&self) -> SFrameResult<SFrameFDEType> {
        // SFRAME_FDE_TYPE_PCMASK (1) or SFRAME_FDE_TYPE_PCINC (0). See The
        // SFrame FDE types.
        let fdetype = (self.0 >> 4) & 0b1;
        match fdetype {
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
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#The-SFrame-FRE-Types>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFREType {
    /// SFRAME_FRE_TYPE_ADDR1
    /// The start address offset (in bytes) of the SFrame FRE is an unsigned
    /// 8-bit value.
    Addr1,
    /// SFRAME_FRE_TYPE_ADDR2
    /// The start address offset (in bytes) of the SFrame FRE is an unsigned
    /// 16-bit value.
    Addr2,
    /// SFRAME_FRE_TYPE_ADDR4
    /// The start address offset (in bytes) of the SFrame FRE is an unsigned
    /// 32-bit value.
    Addr4,
}

/// SFrame FDE Types
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#The-SFrame-FDE-Types>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFDEType {
    /// SFRAME_FDE_TYPE_PCINC
    /// Unwinders perform a (PC >= FRE_START_ADDR) to look up a matching FRE.
    PCInc,
    /// SFRAME_FDE_TYPE_PCMASK
    /// Unwinders perform a (PC & FRE_START_ADDR_AS_MASK >=
    /// FRE_START_ADDR_AS_MASK) to look up a matching FRE.
    PCMask,
}

/// SFrame PAuth key
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#The-SFrame-FDE-Info-Word>
#[derive(Debug, Clone, Copy)]
pub enum SFrameAArch64PAuthKey {
    /// SFRAME_AARCH64_PAUTH_KEY_A
    KeyA,
    /// SFRAME_AARCH64_PAUTH_KEY_B
    KeyB,
}

/// SFrame FDE
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Function-Descriptor-Entries>
#[derive(Debug, Clone, Copy)]
pub struct SFrameFDE {
    /// Signed 32-bit integral field denoting the virtual memory address of the
    /// described function.
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
    /// The SFrame FDE info word. See The SFrame FDE info word.
    pub func_info: SFrameFDEInfo,
}

impl SFrameFDE {
    /// Compute pc of the function
    pub fn get_pc(&self, section: &SFrameSection<'_>) -> u64 {
        (self.func_start_address as i64).wrapping_add_unsigned(section.section_base) as u64
    }

    /// Iterate FRE entries
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

    /// Find FRE entry by pc
    pub fn find_fre(
        &self,
        section: &SFrameSection<'_>,
        pc: u64,
    ) -> SFrameResult<Option<SFrameFRE>> {
        let fde_pc = self.get_pc(section);
        if pc < fde_pc || pc - fde_pc >= self.func_size as u64 {
            // out of bounds
            return Ok(None);
        }

        match self.func_info.get_fde_type()? {
            SFrameFDEType::PCInc => {
                // find matching fre entry with max pc
                let mut last: Option<SFrameFRE> = None;
                let mut iter = self.iter_fre(section);
                while let Some(fre) = iter.next()? {
                    if fre.start_address.get() as u64 + fde_pc > pc {
                        // last is the matching one
                        break;
                    }
                    last = Some(fre);
                }
                if let Some(fre) = last {
                    // PC >= FRE_START_ADDR
                    if fre.start_address.get() as u64 + fde_pc <= pc {
                        return Ok(Some(fre));
                    }
                }
                Ok(None)
            }
            SFrameFDEType::PCMask => {
                // match by pc masking
                let mut iter = self.iter_fre(section);
                while let Some(fre) = iter.next()? {
                    // Unwinders perform a (PC & FRE_START_ADDR_AS_MASK >= FRE_START_ADDR_AS_MASK) to look up a matching FRE.
                    if fre.start_address.get() != 0
                        && pc % fre.start_address.get() as u64 >= fre.start_address.get() as u64
                    {
                        // found
                        return Ok(Some(fre));
                    }
                }
                Ok(None)
            }
        }
    }
}

/// SFrame FRE Start Address
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Frame-Row-Entries>
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
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Frame-Row-Entries>
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
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#SFrame-Frame-Row-Entries>
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
    pub fn get_cfa_offset(&self, _section: &SFrameSection<'_>) -> Option<i32> {
        // currently always the first offset
        self.stack_offsets.first().map(|offset| offset.get())
    }

    /// Get RA offset against CFA
    pub fn get_ra_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        // case 1: RA offset is fixed
        if section.cfa_fixed_ra_offset != 0 {
            return Some(section.cfa_fixed_ra_offset as i32);
        }
        // case 2: RA offset is saved
        self.stack_offsets.get(1).map(|offset| offset.get())
    }

    /// Get FP offset against CFA
    pub fn get_fp_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        // case 1: FP offset is fixed
        if section.cfa_fixed_fp_offset != 0 {
            return Some(section.cfa_fixed_fp_offset as i32);
        }
        // case 2: RA offset is fixed, only FP offset is saved
        if section.cfa_fixed_ra_offset != 0 {
            return self.stack_offsets.get(1).map(|offset| offset.get());
        }
        // case 3: both FP and RA offsets are saved
        self.stack_offsets.get(2).map(|offset| offset.get())
    }
}

/// SFrame FRE Info Word
///
/// Ref: <https://sourceware.org/binutils/docs-2.40/sframe-spec.html#The-SFrame-FRE-Info-Word>
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
        // Size of stack offsets in bytes. Valid values are
        // SFRAME_FRE_OFFSET_1B, SFRAME_FRE_OFFSET_2B, and SFRAME_FRE_OFFSET_4B.
        match (self.0 >> 5) & 0b11 {
            // SFRAME_FRE_OFFSET_1B
            // All stack offsets following the fixed-length FRE structure are 1
            // byte long.
            0x0 => Ok(1),
            // SFRAME_FRE_OFFSET_2B
            // All stack offsets following the fixed-length FRE structure are 2
            // bytes long.
            0x1 => Ok(2),
            // SFRAME_FRE_OFFSET_4B
            // All stack offsets following the fixed-length FRE structure are 4
            // bytes long.
            0x2 => Ok(4),
            _ => Err(SFrameError::UnsupportedFREStackOffsetSize),
        }
    }

    /// The number of stack offsets in the FRE
    pub fn get_offset_count(&self) -> u8 {
        // A value of upto 3 is allowed to track all three of CFA, FP and RA.
        (self.0 >> 1) & 0b1111
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
            SFrameFREType::Addr1 => 1 + 1,
            SFrameFREType::Addr2 => 2 + 1,
            SFrameFREType::Addr4 => 4 + 1,
        } as usize;
        let offset = self.offset;
        if offset + entry_size > self.section.data.len() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        let (start_address, info) = match self.fde.func_info.get_fre_type()? {
            SFrameFREType::Addr1 => (
                SFrameFREStartAddress::U8(self.section.data[offset]),
                SFrameFREInfo(self.section.data[offset + 1]),
            ),
            SFrameFREType::Addr2 => (
                SFrameFREStartAddress::U16(read_binary!(
                    self.section.data,
                    self.section.little_endian,
                    u16,
                    offset
                )),
                SFrameFREInfo(self.section.data[offset + 2]),
            ),
            SFrameFREType::Addr4 => (
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
