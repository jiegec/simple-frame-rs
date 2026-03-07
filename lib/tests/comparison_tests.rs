//! Comparison tests between simple-frame-rs and libsframe-sys
//!
//! These tests verify that both libraries produce identical results when given the same input.

use fallible_iterator::FallibleIterator;
use serde::{Deserialize, Serialize};
use simple_frame_rs::SFrameSection;

/// Test all test cases - both libraries must produce identical results
#[test]
fn test_all_testcases_comparison() {
    for entry in std::fs::read_dir("testcases").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        // Skip non-JSON files
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let testcase: Testcase =
            serde_json::from_reader(std::fs::File::open(&path).unwrap()).unwrap();

        if testcase.content.is_empty() {
            continue;
        }

        println!("Testing {}", path.display());

        // Parse with Rust library
        let rust_section = SFrameSection::from(&testcase.content, testcase.section_base);

        assert!(
            rust_section.is_ok(),
            "Rust library failed to parse {}",
            path.display()
        );
        let rust_section = rust_section.unwrap();
        if matches!(rust_section, SFrameSection::V1(_)) {
            // sframe v1 not supported by current libsframe-sys
            continue;
        }

        // Parse with libsframe-sys
        let c_section = parse_with_libsframe(&testcase.content, testcase.section_base);

        // Compare header fields
        assert_eq!(
            rust_section.get_fde_count(),
            c_section.fde_count,
            "FDE count mismatch in {}",
            path.display()
        );
        assert_eq!(
            rust_section.get_cfa_fixed_fp_offset(),
            c_section.fixed_fp_offset,
            "Fixed FP offset mismatch in {}",
            path.display()
        );
        assert_eq!(
            rust_section.get_cfa_fixed_ra_offset(),
            c_section.fixed_ra_offset,
            "Fixed RA offset mismatch in {}",
            path.display()
        );

        // Compare each FDE
        for i in 0..rust_section.get_fde_count() {
            let rust_fde = rust_section.get_fde(i).unwrap().unwrap();
            let c_fde = &c_section.fdes[i as usize];

            // Compare function size
            assert_eq!(
                rust_fde.get_func_size(),
                c_fde.func_size,
                "FDE {}: func_size mismatch",
                i
            );

            // Compare FRE count
            assert_eq!(
                rust_fde.get_num_fres(),
                c_fde.num_fres,
                "FDE {}: num_fres mismatch",
                i
            );

            // Get all FREs from Rust library
            let rust_fres: Vec<_> = rust_fde.iter_fre(&rust_section).unwrap().collect().unwrap();

            // Verify FRE counts match
            assert_eq!(
                rust_fres.len(),
                c_fde.fres.len(),
                "FDE {}: FRE count mismatch",
                i
            );

            for (j, (rust_fre, c_fre)) in rust_fres.iter().zip(c_fde.fres.iter()).enumerate() {
                // Skip offset comparison for flex fde: the API does not agree now
                if c_fde.fde_type == libsframe_sys::SFRAME_FDE_TYPE_DEFAULT {
                    // Compare CFA offset
                    let rust_cfa_offset = rust_fre.get_cfa_offset(&rust_section).unwrap();
                    assert_eq!(
                        rust_cfa_offset, c_fre.cfa_offset,
                        "FDE {} FRE {}: CFA offset mismatch",
                        i, j
                    );

                    // Compare RA offset
                    let rust_ra_offset = rust_fre.get_ra_offset(&rust_section).unwrap();
                    assert_eq!(
                        rust_ra_offset, c_fre.ra_offset,
                        "FDE {} FRE {}: RA offset mismatch",
                        i, j
                    );

                    // Compare FP offset
                    let rust_fp_offset = rust_fre.get_fp_offset(&rust_section).unwrap();
                    assert_eq!(
                        rust_fp_offset, c_fre.fp_offset,
                        "FDE {} FRE {}: FP offset mismatch",
                        i, j
                    );
                }

                // Compare base register
                let rust_base_reg = rust_fre.get_cfa_base_reg_id();
                assert_eq!(
                    rust_base_reg, c_fre.base_reg,
                    "FDE {} FRE {}: base_reg mismatch",
                    i, j
                );
            }
        }
    }
}

// Helper structs for libsframe-sys

#[derive(Debug)]
struct TestSection {
    fde_count: u32,
    fixed_fp_offset: i8,
    fixed_ra_offset: i8,
    fdes: Vec<TestFDE>,
}

#[derive(Debug)]
struct TestFDE {
    func_size: u32,
    num_fres: u32,
    fres: Vec<TestFRE>,
    fde_type: u32,
}

#[derive(Debug)]
struct TestFRE {
    cfa_offset: Option<i32>,
    ra_offset: Option<i32>,
    fp_offset: Option<i32>,
    base_reg: u8,
}

fn parse_with_libsframe(content: &[u8], _section_base: u64) -> TestSection {
    use libsframe_sys::*;
    use std::ffi::c_char;

    let mut err: i32 = 0;

    // Create decoder
    let dctx = unsafe { sframe_decode(content.as_ptr() as *const c_char, content.len(), &mut err) };

    assert!(
        !dctx.is_null(),
        "libsframe-sys failed to decode: error {}",
        err
    );

    unsafe {
        // Get header info
        let fde_count = sframe_decoder_get_num_fidx(dctx);
        let fixed_fp = sframe_decoder_get_fixed_fp_offset(dctx);
        let fixed_ra = sframe_decoder_get_fixed_ra_offset(dctx);

        let mut fdes = Vec::new();

        // Iterate over FDEs
        for i in 0..fde_count {
            let mut num_fres: u32 = 0;
            let mut func_size: u32 = 0;
            let mut start_pc_offset: i64 = 0;
            let mut func_info: u8 = 0;
            let mut func_info2: u8 = 0;
            let mut rep_block_size: u8 = 0;
            let mut func_start_address: i32 = 0;
            let fde_type;

            let ret = sframe_decoder_get_funcdesc_v3(
                dctx,
                i,
                &mut num_fres,
                &mut func_size,
                &mut start_pc_offset,
                &mut func_info,
                &mut func_info2,
                &mut rep_block_size,
            );

            if ret != 0 {
                // Try v2 format

                let ret2 = sframe_decoder_get_funcdesc_v2(
                    dctx,
                    i,
                    &mut num_fres,
                    &mut func_size,
                    &mut func_start_address,
                    &mut func_info,
                    &mut rep_block_size,
                );

                assert_eq!(ret2, 0, "Failed to get FDE {}", i);

                // v2 only support default fde type
                fde_type = libsframe_sys::SFRAME_FDE_TYPE_DEFAULT;
            } else {
                // fde type is lowest 5 bits of func_info2
                fde_type = func_info2 as u32 & 0b11111;
                assert!(
                    fde_type == libsframe_sys::SFRAME_FDE_TYPE_DEFAULT
                        || fde_type == libsframe_sys::SFRAME_FDE_TYPE_FLEX
                );
            }
            println!("fde type {}", fde_type);

            let mut fres = Vec::new();

            // Get FREs for this FDE
            for j in 0..num_fres {
                let mut fre: sframe_frame_row_entry = std::mem::zeroed();
                let ret = sframe_decoder_get_fre(dctx, i, j, &mut fre);

                assert_eq!(ret, 0, "Failed to get FRE {} for FDE {}", j, i);

                // Get base register
                let mut err_reg: i32 = 0;
                let base_reg = sframe_fre_get_base_reg_id(&fre, &mut err_reg);

                // Get CFA offset using the API
                let mut err_cfa: i32 = 0;
                let cfa_val = sframe_fre_get_cfa_offset(dctx, &fre, fde_type, &mut err_cfa);
                let cfa_offset = if err_cfa == 0 { Some(cfa_val) } else { None };

                // Get FP offset using the API
                let mut err_fp: i32 = 0;
                let fp_val = sframe_fre_get_fp_offset(dctx, &fre, fde_type, &mut err_fp);
                let fp_offset = if err_fp == 0 { Some(fp_val) } else { None };

                // Get RA offset using the API
                let mut err_ra: i32 = 0;
                let ra_val = sframe_fre_get_ra_offset(dctx, &fre, fde_type, &mut err_ra);
                let ra_offset = if err_ra == 0 { Some(ra_val) } else { None };

                fres.push(TestFRE {
                    cfa_offset,
                    ra_offset,
                    fp_offset,
                    base_reg,
                });
            }

            fdes.push(TestFDE {
                func_size,
                num_fres,
                fres,
                fde_type,
            });
        }

        sframe_decoder_free(&mut (dctx as *mut _));

        TestSection {
            fde_count,
            fixed_fp_offset: fixed_fp,
            fixed_ra_offset: fixed_ra,
            fdes,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Testcase {
    section_base: u64,
    content: Vec<u8>,
    groundtruth: String,
}
