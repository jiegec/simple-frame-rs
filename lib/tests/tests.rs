//! Tests for the simple-frame-rs crate

use fallible_iterator::FallibleIterator;
use serde::{Deserialize, Serialize};
use simple_frame_rs::{SFrameError, v2::*};
use std::iter::zip;

// Test data from simple.json testcase
// Header :
//
//   Version: SFRAME_VERSION_2
//   Flags: SFRAME_F_FDE_SORTED
//   CFA fixed RA offset: -8
//   Num FDEs: 3
//   Num FREs: 7
//
// Function Index :
//
//   func idx [0]: pc = 0x1020, size = 16 bytes
//   STARTPC         CFA       FP        RA
//   0000000000001020  sp+16     u         f
//   0000000000001026  sp+24     u         f
//
//   func idx [1]: pc = 0x1030, size = 8 bytes
//   STARTPC[m]      CFA       FP        RA
//   0000000000000000  sp+16     u         f
//
//   func idx [2]: pc = 0x1129, size = 11 bytes
//   STARTPC         CFA       FP        RA
//   0000000000001129  sp+8      u         f
//   000000000000112a  sp+16     c-16      f
//   000000000000112d  fp+16     c-16      f
//   0000000000001133  sp+8      c-16      f
const SIMPLE_SFRAME_DATA: [u8; 112] = [
    226, 222, 2, 1, 3, 0, 248, 0, 3, 0, 0, 0, 7, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 64,
    239, 255, 255, 16, 0, 0, 0, 15, 0, 0, 0, 2, 0, 0, 0, 0, 16, 0, 0, 80, 239, 255, 255, 8, 0, 0,
    0, 21, 0, 0, 0, 1, 0, 0, 0, 16, 8, 0, 0, 73, 240, 255, 255, 11, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0,
    0, 0, 0, 0, 0, 0, 3, 8, 1, 5, 16, 240, 4, 4, 16, 240, 10, 5, 8, 240, 0, 3, 16, 6, 3, 24, 0, 3,
    16,
];

#[test]
fn test_sframe_section_creation() {
    // Test valid SFrame section creation
    let section_base = 8416;

    let result = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base);
    assert!(result.is_ok());

    let section = result.unwrap();
    assert_eq!(section.get_fde_count(), 3);
    assert!(matches!(section.get_abi(), SFrameABI::AMD64LittleEndian));
}

#[test]
fn test_invalid_magic() {
    // Test with invalid magic number
    let mut invalid_data = SIMPLE_SFRAME_DATA.clone();
    invalid_data[0] = 0; // Corrupt magic
    invalid_data[1] = 0;
    let section_base = 8416;

    let result = SFrameSection::from(&invalid_data, section_base);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SFrameError::InvalidMagic));
}

#[test]
fn test_unsupported_version() {
    // Test with unsupported version
    let mut invalid_data = SIMPLE_SFRAME_DATA.clone();
    invalid_data[2] = 3; // Unsupported version
    let section_base = 8416;

    let result = SFrameSection::from(&invalid_data, section_base);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SFrameError::UnsupportedVersion
    ));
}

#[test]
fn test_unsupported_abi() {
    // Test with unsupported ABI
    let mut invalid_data = SIMPLE_SFRAME_DATA.clone();
    invalid_data[4] = 99; // Unsupported ABI (byte 4 is abi_arch)
    let section_base = 8416;

    let result = SFrameSection::from(&invalid_data, section_base);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SFrameError::UnsupportedABI));
}

#[test]
fn test_insufficient_data() {
    // Test with insufficient data
    let data = &SIMPLE_SFRAME_DATA[0..10]; // Only partial data
    let section_base = 8416;

    let result = SFrameSection::from(data, section_base);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SFrameError::UnexpectedEndOfData
    ));
}

#[test]
fn test_fde_access() {
    // Test accessing FDE entries
    let section_base = 8416;

    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Test valid FDE access
    let fde_result = section.get_fde(0);
    assert!(fde_result.is_ok());
    assert!(fde_result.unwrap().is_some());

    // Test out of bounds FDE access
    let fde_result = section.get_fde(10);
    assert!(fde_result.is_ok());
    assert!(fde_result.unwrap().is_none());
}

#[test]
fn test_sframe_flags() {
    // Test SFrameFlags functionality
    let flags = SFrameFlags::SFRAME_F_FDE_SORTED | SFrameFlags::SFRAME_F_FRAME_POINTER;
    assert!(flags.contains(SFrameFlags::SFRAME_F_FDE_SORTED));
    assert!(flags.contains(SFrameFlags::SFRAME_F_FRAME_POINTER));
    assert!(!flags.contains(SFrameFlags::SFRAME_F_FDE_FUNC_START_PCREL));

    // Test from_bits
    assert!(
        SFrameFlags::from_bits(0x1)
            .unwrap()
            .contains(SFrameFlags::SFRAME_F_FDE_SORTED)
    );
    assert!(
        SFrameFlags::from_bits(0x3)
            .unwrap()
            .contains(SFrameFlags::SFRAME_F_FDE_SORTED)
    );
    assert!(
        SFrameFlags::from_bits(0x3)
            .unwrap()
            .contains(SFrameFlags::SFRAME_F_FRAME_POINTER)
    );
    assert!(SFrameFlags::from_bits(0xFF).is_none()); // Invalid bits
}

#[test]
fn test_sframe_abi_conversion() {
    // Test ABI conversion from raw values used in parsing
    assert_eq!(SFrameABI::AArch64BigEndian as u8, 0); // Rust enums start from 0
    assert_eq!(SFrameABI::AArch64LittleEndian as u8, 1);
    assert_eq!(SFrameABI::AMD64LittleEndian as u8, 2);
    assert_eq!(SFrameABI::S390XBigEndian as u8, 3);
}

#[test]
fn test_to_string_format() {
    // Test the to_string method produces expected format
    let section_base = 8416;

    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();
    let result = section.to_string();

    assert!(result.is_ok());
    let output = result.unwrap();

    // Check that basic header information is present
    assert!(output.contains("Header :"));
    assert!(output.contains("Version: SFRAME_VERSION_2"));
    assert!(output.contains("Num FDEs: 3"));
    assert!(output.contains("Num FREs: 7"));
}

#[test]
fn test_fre_iteration() {
    // Test FRE iteration and access
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Get first FDE and iterate its FREs
    let fde = section.get_fde(0).unwrap().unwrap();
    let mut fre_iter = fde.iter_fre(&section);

    // First FRE
    let fre = fre_iter.next().unwrap().unwrap();
    assert_eq!(fre.start_address.get(), 0);
    assert_eq!(fre.stack_offsets.len(), 1); // Only CFA offset for AMD64

    // Second FRE
    let fre = fre_iter.next().unwrap().unwrap();
    assert_eq!(fre.start_address.get(), 6);
    assert_eq!(fre.stack_offsets.len(), 1);

    // No more FREs
    assert!(fre_iter.next().unwrap().is_none());
}

#[test]
fn test_fde_iteration() {
    // Test FDE iteration
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    let mut fde_iter = section.iter_fde();
    let mut count = 0;

    while let Some(fde) = fde_iter.next().unwrap() {
        count += 1;
        assert!(fde.func_size > 0);
    }

    assert_eq!(count, 3);
}

#[test]
fn test_find_fde() {
    // Test finding FDE by PC
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Test PC within function range
    let fde = section.find_fde(0x1020).unwrap();
    assert!(fde.is_some());
    assert_eq!(fde.unwrap().func_size, 16);

    // Test PC at function start
    let fde = section.find_fde(0x1030).unwrap();
    assert!(fde.is_some());
    assert_eq!(fde.unwrap().func_size, 8);

    // Test PC at function end (should not match)
    let fde = section.find_fde(0x1040).unwrap();
    assert!(fde.is_none());

    // Test PC outside all functions
    let fde = section.find_fde(0x2000).unwrap();
    assert!(fde.is_none());
}

#[test]
fn test_find_fre() {
    // Test finding FRE by PC
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Get first FDE
    let fde = section.get_fde(0).unwrap().unwrap();

    // Test PC at FRE start
    let fre = fde.find_fre(&section, 0x1020).unwrap();
    assert!(fre.is_some());
    assert_eq!(fre.unwrap().start_address.get(), 0);

    // Test PC within FRE range
    let fre = fde.find_fre(&section, 0x1023).unwrap();
    assert!(fre.is_some());
    assert_eq!(fre.unwrap().start_address.get(), 0);

    // Test PC at next FRE start
    let fre = fde.find_fre(&section, 0x1026).unwrap();
    assert!(fre.is_some());
    assert_eq!(fre.unwrap().start_address.get(), 6);

    let fde_pc = fde.get_pc(&section);

    // Test PC outside function
    let fre = fde
        .find_fre(&section, fde_pc + fde.func_size as u64)
        .unwrap();
    assert!(fre.is_none());
}

#[test]
fn test_sframe_fre_methods() {
    // Test SFrameFRE helper methods
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Get first FDE and first FRE
    let fde = section.get_fde(0).unwrap().unwrap();
    let fre = fde.iter_fre(&section).next().unwrap().unwrap();

    // Test CFA offset
    let cfa_offset = fre.get_cfa_offset();
    assert!(cfa_offset.is_some());
    assert_eq!(cfa_offset.unwrap(), 16);

    // Test RA offset (fixed for AMD64)
    let ra_offset = fre.get_ra_offset(&section);
    assert!(ra_offset.is_some());
    assert_eq!(ra_offset.unwrap(), -8);

    // Test FP offset (should be None for this FRE)
    let fp_offset = fre.get_fp_offset(&section);
    assert!(fp_offset.is_none());
}

#[test]
fn test_sframe_fde_info() {
    // Test SFrameFDEInfo parsing
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Get FDEs and test their info
    for i in 0..section.get_fde_count() {
        let fde = section.get_fde(i).unwrap().unwrap();
        let info = fde.func_info;

        // Test FDE type
        let fde_type = info.get_fde_type().unwrap();
        if i == 1 {
            assert!(matches!(fde_type, SFrameFDEType::PCMask));
        } else {
            assert!(matches!(fde_type, SFrameFDEType::PCInc));
        }

        // Test FRE type
        let fre_type = info.get_fre_type().unwrap();
        assert!(matches!(fre_type, SFrameFREType::Addr0)); // All use Addr0 in test data
    }
}

#[test]
fn test_sframe_fre_info() {
    // Test SFrameFREInfo parsing
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Get first FDE and first FRE
    let fde = section.get_fde(0).unwrap().unwrap();
    let fre = fde.iter_fre(&section).next().unwrap().unwrap();
    let info = fre.info;

    // Test offset size
    let offset_size = info.get_offset_size().unwrap();
    assert_eq!(offset_size, 1); // 1 byte offsets in test data

    // Test offset count
    let offset_count = info.get_offset_count();
    assert_eq!(offset_count, 1); // Only CFA offset for this FRE

    // Test CFA base register
    let cfa_base_reg = info.get_cfa_base_reg_id();
    assert_eq!(cfa_base_reg, 1); // SP-based in test data

    // Test mangled RA (should be false in test data)
    let mangled_ra = info.get_mangled_ra_p();
    assert!(!mangled_ra);
}

#[test]
fn test_aarch64_sframe() {
    // Test AArch64 SFrame parsing
    let aarch64_data = std::fs::read("testcases/simple-aarch64.json").unwrap();
    let testcase: Testcase = serde_json::from_slice(&aarch64_data).unwrap();

    let section = SFrameSection::from(&testcase.content, testcase.section_base).unwrap();

    // Verify AArch64 ABI
    assert!(matches!(section.get_abi(), SFrameABI::AArch64LittleEndian));

    // Test FDE access
    let fde = section.get_fde(0).unwrap().unwrap();
    assert_eq!(fde.func_size, 8);

    // Test FRE access
    let mut fre_iter = fde.iter_fre(&section);
    let fre = fre_iter.next().unwrap().unwrap();

    // Test AArch64 specific offsets
    let ra_offset = fre.get_ra_offset(&section);
    assert!(ra_offset.is_none()); // No RA offset in this test case

    let fp_offset = fre.get_fp_offset(&section);
    assert!(fp_offset.is_none()); // No FP offset in this test case
}

#[test]
fn test_complex_sframe() {
    // Test complex SFrame with multiple functions
    let complex_data = std::fs::read("testcases/complex.json").unwrap();
    let testcase: Testcase = serde_json::from_slice(&complex_data).unwrap();

    let section = SFrameSection::from(&testcase.content, testcase.section_base).unwrap();

    // Verify complex section
    assert_eq!(section.get_fde_count(), 6);
    assert_eq!(section.get_flags().bits(), 0x1); // SFRAME_F_FDE_SORTED

    // Test all FDEs
    for i in 0..section.get_fde_count() {
        let fde = section.get_fde(i).unwrap().unwrap();
        assert!(fde.func_size > 0);

        // Test FRE iteration for each FDE
        let mut fre_count = 0;
        let mut fre_iter = fde.iter_fre(&section);
        while let Some(fre) = fre_iter.next().unwrap() {
            fre_count += 1;
            assert!(!fre.stack_offsets.is_empty());
        }
        assert!(fre_count > 0);
    }
}

#[test]
fn test_error_conditions() {
    // Test various error conditions

    // Test invalid flags
    let mut invalid_data = SIMPLE_SFRAME_DATA.clone();
    invalid_data[3] = 0xFF; // Invalid flags
    let section_base = 8416;
    let result = SFrameSection::from(&invalid_data, section_base);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SFrameError::UnsupportedFlags));
}

#[test]
fn test_fre_start_address_types() {
    // Test different FRE start address types
    let section_base = 8416;
    let section = SFrameSection::from(&SIMPLE_SFRAME_DATA, section_base).unwrap();

    // Test Addr0 type (used in test data)
    let fde = section.get_fde(0).unwrap().unwrap();
    let fre = fde.iter_fre(&section).next().unwrap().unwrap();

    match fre.start_address {
        SFrameFREStartAddress::U8(_) => {} // Expected for Addr0
        _ => panic!("Unexpected FRE start address type"),
    }

    assert_eq!(fre.start_address.get(), 0);
}

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
        let section = crate::SFrameSection::from(&testcase.content, testcase.section_base).unwrap();
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
