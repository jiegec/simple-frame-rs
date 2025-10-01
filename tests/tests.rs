//! Tests for the simple-frame-rs crate

use serde::{Deserialize, Serialize};
use simple_frame_rs::*;
use std::iter::zip;

// Test data from simple.json testcase
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
    assert!(matches!(section.get_version(), SFrameVersion::V2));
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
fn test_sframe_version_conversion() {
    // Test version conversion from raw values used in parsing
    assert_eq!(SFrameVersion::V1 as u8, 0); // Rust enums start from 0
    assert_eq!(SFrameVersion::V2 as u8, 1);
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
