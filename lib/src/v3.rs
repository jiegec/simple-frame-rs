//! SFrame Version 3 types and implementation.
//!
//! Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html>

use std::{cmp::Ordering, fmt::Write};

use bitflags::bitflags;
use fallible_iterator::FallibleIterator;

use crate::{SFrameError, SFrameResult, read_binary, read_struct};

/// SFrame ABI/arch Identifier
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-ABI_002farch-Identifier>
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

/// s390x-specific constants and helpers from binutils-gdb sframe.h
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#s390x>
pub mod s390x {
    /// On s390x, the CFA is defined as SP at call site + 160.
    /// Therefore the SP value offset from CFA is -160.
    pub const SFRAME_S390X_SP_VAL_OFFSET: i32 = -160;

    /// On s390x, the CFA offset from CFA base register is by definition a minimum
    /// of 160. Store it adjusted by -160 to enable use of 8-bit SFrame offsets.
    pub const SFRAME_S390X_CFA_OFFSET_ADJUSTMENT: i32 = SFRAME_S390X_SP_VAL_OFFSET;

    /// Additionally scale by an alignment factor of 8, as the SP and thus CFA
    /// offset on s390x is always 8-byte aligned.
    pub const SFRAME_S390X_CFA_OFFSET_ALIGNMENT_FACTOR: i32 = 8;

    /// Invalid RA offset.  Currently used for s390x as padding to represent FP
    /// without RA saved.
    pub const SFRAME_FRE_RA_OFFSET_INVALID: i32 = 0;

    /// Decode a CFA offset from the FRE stored value.
    pub const fn cfa_offset_decode(offset: i32) -> i32 {
        (offset * SFRAME_S390X_CFA_OFFSET_ALIGNMENT_FACTOR) - SFRAME_S390X_CFA_OFFSET_ADJUSTMENT
    }

    /// Check if an offset represents a DWARF register number.
    pub const fn offset_is_regnum(offset: i32) -> bool {
        (offset & 1) != 0
    }

    /// Decode a DWARF register number from an offset.
    pub const fn offset_decode_regnum(offset: i32) -> i32 {
        offset >> 1
    }
}

bitflags! {
    /// SFrame Flags
    ///
    /// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Flags>
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
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Section>
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SFrameSection<'a> {
    data: &'a [u8],
    section_base: u64,
    little_endian: bool,
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

/// Get register name from dwarf register number
fn get_regname_from_dwarf(regnum: i32, abi: SFrameABI) -> String {
    match (regnum, abi) {
        // rbp
        (6, SFrameABI::AMD64LittleEndian) => "fp".to_string(),
        // rsp
        (7, SFrameABI::AMD64LittleEndian) => "sp".to_string(),
        _ => format!("r{}", regnum),
    }
}

/// Print flex recovery rule to string
fn flex_recovery_rule_to_string(rule: &SFrameFlexRecoveryRule, abi: SFrameABI) -> String {
    match (
        rule.control.is_padding(),
        rule.control.reg_p(),
        rule.control.deref_p(),
    ) {
        (true, _, _) => {
            // undefined
            "U".to_string()
        }
        (false, true, true) => {
            // register deref
            format!(
                "({}{:+})",
                get_regname_from_dwarf(rule.control.regnum(), abi),
                rule.offset
            )
        }
        (false, true, false) => {
            // register
            format!(
                "{}{:+}",
                get_regname_from_dwarf(rule.control.regnum(), abi),
                rule.offset
            )
        }
        (false, false, _) => {
            // cfa
            format!("c{:+}", rule.offset)
        }
    }
}

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
        if version != 3 {
            return Err(SFrameError::UnsupportedVersion);
        }

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

        // initial validation
        let num_fdes = read_struct!(RawSFrameHeader, data, little_endian, num_fdes, u32);
        let fdeoff = read_struct!(RawSFrameHeader, data, little_endian, fdeoff, u32);
        if data.len() - core::mem::size_of::<RawSFrameHeader>() < fdeoff as usize {
            return Err(SFrameError::UnexpectedEndOfData);
        } else if (data.len() - core::mem::size_of::<RawSFrameHeader>() - fdeoff as usize)
            / core::mem::size_of::<RawSFrameFDEIndex>()
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
            num_fres: read_struct!(RawSFrameHeader, data, little_endian, num_fres, u32),
            fre_len: read_struct!(RawSFrameHeader, data, little_endian, fre_len, u32),
            fdeoff,
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
            + index as usize * core::mem::size_of::<RawSFrameFDEIndex>()
            + core::mem::size_of::<RawSFrameHeader>();
        if offset + core::mem::size_of::<RawSFrameFDEIndex>() > self.data.len() {
            return Err(SFrameError::UnexpectedEndOfData);
        }

        // read fde attribute in fre sub-section

        let func_start_fre_off = read_struct!(
            RawSFrameFDEIndex,
            &self.data[offset..],
            self.little_endian,
            func_start_fre_off,
            u32
        );

        let fre_offset = self.freoff as usize
            + core::mem::size_of::<RawSFrameHeader>()
            + func_start_fre_off as usize;
        if fre_offset + core::mem::size_of::<RawSFrameFDEAttr>() > self.data.len() {
            return Err(SFrameError::UnexpectedEndOfData);
        }
        let func_num_fres = read_struct!(
            RawSFrameFDEAttr,
            &self.data[fre_offset..],
            self.little_endian,
            func_num_fres,
            u16
        );
        let func_info = read_struct!(
            RawSFrameFDEAttr,
            &self.data[fre_offset..],
            self.little_endian,
            func_info,
            u8
        );
        let func_info2 = read_struct!(
            RawSFrameFDEAttr,
            &self.data[fre_offset..],
            self.little_endian,
            func_info2,
            u8
        );
        let func_rep_size = read_struct!(
            RawSFrameFDEAttr,
            &self.data[fre_offset..],
            self.little_endian,
            func_rep_size,
            u8
        );

        Ok(Some(SFrameFDE {
            offset,
            func_start_offset: read_struct!(
                RawSFrameFDEIndex,
                &self.data[offset..],
                self.little_endian,
                func_start_offset,
                i64
            ),
            func_size: read_struct!(
                RawSFrameFDEIndex,
                &self.data[offset..],
                self.little_endian,
                func_size,
                u32
            ),
            func_start_fre_off,
            func_num_fres,
            func_info: SFrameFDEInfo(func_info),
            func_info2: SFrameFDEInfo2(func_info2),
            func_rep_size,
        }))
    }

    /// Print the section in string in the same way as objdump
    pub fn to_string(&self) -> SFrameResult<String> {
        let mut s = String::new();
        writeln!(&mut s, "Header :")?;
        writeln!(&mut s)?;
        writeln!(&mut s, "  Version: SFRAME_VERSION_3")?;
        writeln!(
            &mut s,
            "  Flags: {}",
            self.flags
                .iter_names()
                .map(|(name, _flag)| name)
                .collect::<Vec<_>>()
                .join(",\n         ")
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
            let mut suffix = String::new();

            let mut attrs = "".to_string();
            if fde.func_info.is_signal_frame()? {
                attrs.push('S');
            }
            if let Ok(SFrameFDEType::Flex) = fde.func_info2.get_fde_type() {
                attrs.push('F');
            }

            if !attrs.is_empty() {
                suffix += &format!(", attr = \"{}\"", attrs);
            };

            // aarch64 pauth
            if let SFrameAArch64PAuthKey::KeyB = fde.func_info.get_aarch64_pauth_key()? {
                suffix += ", pauth = B key";
            }

            writeln!(
                &mut s,
                "  func idx [{i}]: pc = 0x{:x}, size = {} bytes{}",
                pc, fde.func_size, suffix
            )?;

            match fde.func_info.get_fde_pctype()? {
                SFrameFDEPCType::PCInc => {
                    writeln!(&mut s, "  STARTPC           CFA      FP     RA")?;
                }
                SFrameFDEPCType::PCMask => {
                    writeln!(&mut s, "  STARTPC[m]        CFA      FP     RA")?;
                }
            }
            let mut iter = fde.iter_fre(self);
            while let Some(fre) = iter.next()? {
                let start_pc = match fde.func_info.get_fde_pctype()? {
                    SFrameFDEPCType::PCInc => pc + fre.start_address.get() as u64,
                    SFrameFDEPCType::PCMask => fre.start_address.get() as u64,
                };

                match fde.func_info2.get_fde_type() {
                    Ok(SFrameFDEType::Default) => {
                        // default fde
                        if fre.stack_offsets.is_empty() {
                            // RA undefined: top level function
                            writeln!(&mut s, "  {:016x}  RA undefined", start_pc)?;
                        } else {
                            let base_reg = if fre.info.get_cfa_base_reg_id() == 0 {
                                "fp"
                            } else {
                                "sp"
                            };
                            let cfa = format!("{}+{}", base_reg, fre.stack_offsets[0].get());
                            let fp = match fre.get_fp_offset(self) {
                                Some(offset) => format!("c{:+}", offset),
                                None => "u".to_string(), // without offset
                            };
                            let mut ra = if self.cfa_fixed_ra_offset != 0 {
                                "f".to_string() // fixed
                            } else {
                                match fre.get_ra_offset(self) {
                                    Some(offset) => format!("c{:+}", offset),
                                    None => "u".to_string(), // without offset
                                }
                            };
                            if fre.info.get_mangled_ra_p() {
                                // ra is mangled with signature
                                ra.push_str("[s]");
                            }
                            let rest = format!("{cfa:8} {fp:6} {ra}");
                            writeln!(&mut s, "  {:016x}  {}", start_pc, rest)?;
                        }
                    }
                    Ok(SFrameFDEType::Flex) => {
                        // flex fde
                        if let Some(rules) = fre.get_flex_recovery_rules() {
                            let cfa = flex_recovery_rule_to_string(&rules.cfa, self.abi);
                            let fp = if let Some(fp_rule) = rules.fp {
                                flex_recovery_rule_to_string(&fp_rule, self.abi)
                            } else {
                                "u".to_string()
                            };
                            let ra = if let Some(ra_rule) = rules.ra {
                                flex_recovery_rule_to_string(&ra_rule, self.abi)
                            } else if self.cfa_fixed_ra_offset != 0 {
                                "f".to_string()
                            } else {
                                "u".to_string()
                            };
                            let rest = format!("{cfa:8} {fp:6} {ra}");
                            writeln!(&mut s, "  {:016x}  {}", start_pc, rest)?;
                        } else {
                            // RA undefined: top level function
                            writeln!(&mut s, "  {:016x}  RA undefined", start_pc)?;
                        }
                    }
                    _ => {}
                }
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

/// Raw SFrame Header
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Header>
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

/// Raw SFrame FDE Index
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Index>
#[repr(C, packed)]
#[allow(dead_code)]
struct RawSFrameFDEIndex {
    func_start_offset: i64,
    func_size: u32,
    func_start_fre_off: u32,
}

/// Raw SFrame FDE Attribute
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Attribute>
#[repr(C, packed)]
#[allow(dead_code)]
struct RawSFrameFDEAttr {
    func_num_fres: u16,
    func_info: u8,
    func_info2: u8,
    func_rep_size: u8,
}

/// SFrame FDE Info Byte
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Info-Bytes>
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SFrameFDEInfo(u8);

impl SFrameFDEInfo {
    /// Get SFrame FRE type
    pub fn get_fre_type(&self) -> SFrameResult<SFrameFREType> {
        let fretype = self.0 & 0b1111;
        match fretype {
            0 => Ok(SFrameFREType::Addr1),
            1 => Ok(SFrameFREType::Addr2),
            2 => Ok(SFrameFREType::Addr4),
            _ => Err(SFrameError::UnsupportedFREType),
        }
    }

    /// Get SFrame FDE PC type
    pub fn get_fde_pctype(&self) -> SFrameResult<SFrameFDEPCType> {
        let fretype = (self.0 >> 4) & 0b1;
        match fretype {
            0 => Ok(SFrameFDEPCType::PCInc),
            1 => Ok(SFrameFDEPCType::PCMask),
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

    /// Is Signal Frame?
    pub fn is_signal_frame(&self) -> SFrameResult<bool> {
        let fretype = (self.0 >> 7) & 0b1;
        match fretype {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!(),
        }
    }
}

/// SFrame FDE Info Byte 2
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Info-Bytes>
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SFrameFDEInfo2(u8);

impl SFrameFDEInfo2 {
    /// Get SFrame FDE type
    pub fn get_fde_type(&self) -> SFrameResult<SFrameFDEType> {
        let fdetype = self.0 & 0b11111;
        match fdetype {
            0 => Ok(SFrameFDEType::Default),
            1 => Ok(SFrameFDEType::Flex),
            _ => Err(SFrameError::UnsupportedFDEType),
        }
    }
}

/// SFrame FRE Types
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FRE-Types>
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

/// SFrame FDE PC Types
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Types>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFDEPCType {
    /// SFRAME_V3_FDE_TYPE_PCINC
    PCInc,
    /// SFRAME_V3_FDE_TYPE_PCMASK
    PCMask,
}

/// SFrame FDE Types
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Types>
#[derive(Debug, Clone, Copy)]
pub enum SFrameFDEType {
    /// SFRAME_FDE_TYPE_DEFAULT
    /// The default FDE type.
    /// CFA is recovered using the Stack Pointer (SP) or Frame Pointer (FP) plus
    /// a signed offset. Return Address (RA) and Frame Pointer (FP) are
    /// recovered using the CFA plus a signed offset (or a fixed register for
    /// specific architectures like s390x).
    /// The variable-length array of bytes trailing each SFrame FRE are
    /// interpreted according to the ABI/arch-specific rules for the target
    /// architecture. More details in Default FDE Type Interpretation.
    Default,

    /// SFRAME_FDE_TYPE_FLEX
    /// The flexible FDE type.
    /// Used for complex cases such as stack realignment (DRAP), non-standard
    /// CFA base registers, or when RA/FP recovery requires dereferencing or
    /// non-CFA base registers.
    /// The variable-length array of bytes may be interpreted as pairs of
    /// Control Data and Offset Data (or Padding Data), allowing for complex
    /// recovery rules (e.g., DRAP on AMD64, Stack Realignment). More details in
    /// Flexible FDE Type Interpretation.
    Flex,
}

/// SFrame PAuth key
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FDE-Info-Word>
#[derive(Debug, Clone, Copy)]
pub enum SFrameAArch64PAuthKey {
    /// SFRAME_AARCH64_PAUTH_KEY_A
    KeyA,
    /// SFRAME_AARCH64_PAUTH_KEY_B
    KeyB,
}

/// SFrame FDE
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Function-Descriptor-Entries>
#[derive(Debug, Clone, Copy)]
pub struct SFrameFDE {
    /// Offset from the beginning of sframe section
    offset: usize,
    /// Signed 64-bit integral field specifying the offset to the start address
    /// of the described function. If the flag SFRAME_F_FDE_FUNC_START_PCREL,
    /// See SFrame Flags, in the SFrame header is set, the value encoded in the
    /// sfdi_func_start_offset field is the offset in bytes to the function’s
    /// start address from the sfdi_func_start_offset field itself. Otherwise,
    /// it is the offset in bytes from the start of the SFrame section.
    pub func_start_offset: i64,
    /// Unsigned 32-bit integral field specifying the size of the function in
    /// bytes.
    pub func_size: u32,
    /// Unsigned 32-bit integral field specifying the offset to the start of the
    /// function’s stack trace data (SFrame FREs). This offset is relative to
    /// the beginning of the SFrame FRE sub-section.
    pub func_start_fre_off: u32,
    /// Unsigned 16-bit integral field specifying the total number of SFrame
    /// FREs used for the function.
    pub func_num_fres: u16,
    /// Unsigned 8-bit integral field specifying the SFrame FDE info word. See
    /// The SFrame FDE Info Word.
    pub func_info: SFrameFDEInfo,
    /// Additional unsigned 8-bit integral field specifying the SFrame FDE info byte.
    pub func_info2: SFrameFDEInfo2,
    /// Unsigned 8-bit integral field specifying the size of the repetitive code
    /// block for which an SFrame FDE of type SFRAME_FDE_PCTYPE_MASK is used.
    /// For example, in AMD64, the size of a pltN entry is 16 bytes.
    pub func_rep_size: u8,
}

impl SFrameFDE {
    /// Get the FDE type (Default or Flex)
    pub fn get_fde_type(&self) -> SFrameResult<SFrameFDEType> {
        self.func_info2.get_fde_type()
    }

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
            self.func_start_offset
                .wrapping_add_unsigned(self.offset as u64)
                .wrapping_add_unsigned(section.section_base) as u64
        } else {
            self.func_start_offset
                .wrapping_add_unsigned(section.section_base) as u64
        }
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
            + self.func_start_fre_off as usize
            + core::mem::size_of::<RawSFrameFDEAttr>();
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

        match self.func_info.get_fde_pctype()? {
            SFrameFDEPCType::PCInc => {
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
            SFrameFDEPCType::PCMask => {
                // match by pc masking
                let mut iter = self.iter_fre(section);
                while let Some(fre) = iter.next()? {
                    // PC % REP_BLOCK_SIZE >= FRE_START_ADDR
                    if self.func_rep_size != 0
                        && pc % self.func_rep_size as u64 >= fre.start_address.get() as u64
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
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Frame-Row-Entries>
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
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Frame-Row-Entries>
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
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#SFrame-Frame-Row-Entries>
#[derive(Debug, Clone)]
pub struct SFrameFRE {
    /// Start address (in offset form) of the function
    pub start_address: SFrameFREStartAddress,
    /// FRE info
    pub info: SFrameFREInfo,
    /// Stack offsets to access CFA, FP and RA
    pub stack_offsets: Vec<SFrameFREStackOffset>,
}

/// Flex FDE Control Data Word
///
/// For flexible FDE types (SFRAME_FDE_TYPE_FLEX), the variable-length bytes
/// trailing an SFrame FRE are interpreted as pairs of Control Data and Offset
/// Data for each tracked entity (CFA, RA, FP).
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#Flexible-FDE-Type-Interpretation>
#[derive(Debug, Clone, Copy)]
pub struct SFrameFlexControlData {
    /// The raw control data value
    value: i32,
}

impl SFrameFlexControlData {
    /// Create a new Control Data from raw value
    pub fn new(value: i32) -> Self {
        Self { value }
    }

    /// Check if this is a padding data word (value is 0)
    ///
    /// A value of 0 indicates that no further data words follow for the
    /// tracked entity, meaning the fixed offsets apply or the entity is absent.
    pub fn is_padding(&self) -> bool {
        self.value == 0
    }

    /// Register-based Location Rule
    ///
    /// If true, the base is a DWARF register (encoded in regnum bits).
    /// If false, the base is the CFA (used for RA/FP recovery).
    pub fn reg_p(&self) -> bool {
        (self.value & 0b1) != 0
    }

    /// Dereference Flag
    ///
    /// If true, the location of the value is the address (Base + Offset):
    ///   value = *(Base + Offset)
    /// If false, the value is (Base + Offset).
    pub fn deref_p(&self) -> bool {
        (self.value & 0b10) != 0
    }

    /// DWARF register number used as the base
    ///
    /// Effective only if reg_p is true.
    pub fn regnum(&self) -> i32 {
        self.value >> 3
    }
}

/// Flex FDE Recovery Rule
///
/// Contains the control and offset data for recovering a tracked entity
/// (CFA, RA, or FP) in a flexible FDE.
#[derive(Debug, Clone, Copy)]
pub struct SFrameFlexRecoveryRule {
    /// Control data word
    pub control: SFrameFlexControlData,
    /// Offset data (signed offset to be added to the base)
    pub offset: i32,
}

impl SFrameFRE {
    /// Get CFA offset against base reg (for Default FDE type)
    pub fn get_cfa_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        self.stack_offsets.first().map(|offset| {
            let offset = offset.get();
            match section.abi {
                // On s390x, the CFA offset is encoded. Decode it.
                SFrameABI::S390XBigEndian => s390x::cfa_offset_decode(offset),
                _ => offset,
            }
        })
    }

    /// Get RA offset against CFA (for Default FDE type)
    ///
    /// For s390x, the returned value may represent:
    /// - A stack slot offset if the LSB is 0
    /// - A DWARF register number (encoded as (regnum << 1) | 1) if the LSB is 1
    /// - SFRAME_FRE_RA_OFFSET_INVALID (0) if RA is not saved
    pub fn get_ra_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        match section.abi {
            // the second offset for aarch64
            SFrameABI::AArch64BigEndian | SFrameABI::AArch64LittleEndian => {
                self.stack_offsets.get(1).map(|offset| offset.get())
            }
            // always fixed for amd64
            SFrameABI::AMD64LittleEndian => Some(section.cfa_fixed_ra_offset as i32),
            // the second offset for s390x
            SFrameABI::S390XBigEndian => self.stack_offsets.get(1).map(|offset| offset.get()),
        }
    }

    /// Get FP offset against CFA (for Default FDE type)
    ///
    /// For s390x, the returned value may represent:
    /// - A stack slot offset if the LSB is 0
    /// - A DWARF register number (encoded as (regnum << 1) | 1) if the LSB is 1
    pub fn get_fp_offset(&self, section: &SFrameSection<'_>) -> Option<i32> {
        match section.abi {
            // the third offset for aarch64
            SFrameABI::AArch64BigEndian | SFrameABI::AArch64LittleEndian => {
                self.stack_offsets.get(2).map(|offset| offset.get())
            }
            // the second offset for amd64
            SFrameABI::AMD64LittleEndian => self.stack_offsets.get(1).map(|offset| offset.get()),
            // the third offset for s390x
            SFrameABI::S390XBigEndian => self.stack_offsets.get(2).map(|offset| offset.get()),
        }
    }

    /// Get Flex FDE recovery rules
    ///
    /// For flexible FDE types, returns the recovery rules for CFA, RA, and FP.
    /// Each rule consists of a Control Data word and an Offset Data word.
    ///
    /// Returns None if the data is invalid.
    pub fn get_flex_recovery_rules(&self) -> Option<SFrameFlexRecoveryRules> {
        let data_words: Vec<i32> = self.stack_offsets.iter().map(|o| o.get()).collect();

        // Parse CFA recovery rule (always present)
        let cfa_control = SFrameFlexControlData::new(*data_words.first()?);
        let cfa_offset = *data_words.get(1)?;
        let cfa = SFrameFlexRecoveryRule {
            control: cfa_control,
            offset: cfa_offset,
        };

        // Parse RA recovery rule (if present)
        let mut offset = 2;
        let mut ra = None;
        if data_words.len() >= 3 {
            let ra_control = SFrameFlexControlData::new(*data_words.get(2)?);
            if ra_control.is_padding() {
                ra = Some(SFrameFlexRecoveryRule {
                    control: ra_control,
                    offset: 0,
                });
                offset += 1;
            } else {
                ra = Some(SFrameFlexRecoveryRule {
                    control: ra_control,
                    offset: *data_words.get(3)?,
                });
                offset += 2;
            }
        }

        // Parse FP recovery rule (if present)
        let mut fp = None;
        if data_words.len() > offset {
            let fp_control = SFrameFlexControlData::new(*data_words.get(offset)?);
            if fp_control.is_padding() {
                fp = Some(SFrameFlexRecoveryRule {
                    control: fp_control,
                    offset: 0,
                });
            } else {
                fp = Some(SFrameFlexRecoveryRule {
                    control: fp_control,
                    offset: *data_words.get(offset + 1)?,
                });
            }
        }

        Some(SFrameFlexRecoveryRules { cfa, ra, fp })
    }
}

/// Flex FDE Recovery Rules for all tracked entities
#[derive(Debug, Clone)]
pub struct SFrameFlexRecoveryRules {
    /// CFA recovery rule (always present)
    pub cfa: SFrameFlexRecoveryRule,
    /// RA recovery rule (None if padding)
    pub ra: Option<SFrameFlexRecoveryRule>,
    /// FP recovery rule (None if padding)
    pub fp: Option<SFrameFlexRecoveryRule>,
}

/// SFrame FRE Info Byte
///
/// Ref: <https://sourceware.org/binutils/docs-2.46/sframe-spec.html#The-SFrame-FRE-Info-Word>
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SFrameFREInfo(u8);

impl SFrameFREInfo {
    /// Indicate whether the return address is mangled with any authorization
    /// bits (signed RA).
    pub fn get_mangled_ra_p(&self) -> bool {
        (self.0 >> 7) & 0b1 == 1
    }

    /// Size of data word in bytes.
    pub fn get_dataword_size(&self) -> SFrameResult<usize> {
        match (self.0 >> 5) & 0b11 {
            // SFRAME_FRE_DATAWORD_1B
            0x0 => Ok(1),
            // SFRAME_FRE_DATAWORD_2B
            0x1 => Ok(2),
            // SFRAME_FRE_DATAWORD_4B
            0x2 => Ok(4),
            _ => Err(SFrameError::UnsupportedFREDataWordSize),
        }
    }

    /// The number of data word in the FRE
    pub fn get_dataword_count(&self) -> u8 {
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
    index: u16,
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

        let offset_size = info.get_dataword_size()?;
        let offset_count = info.get_dataword_count() as usize;
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
