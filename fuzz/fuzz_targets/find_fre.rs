use afl::fuzz;
use simple_frame_rs::v2::SFrameSection;

/// Fuzz target for SFrameFDE::find_fre()
/// This tests finding FREs by PC within a function
///
/// The fuzzer will generate two inputs concatenated:
/// 1. First 8 bytes: PC address to search for
/// 2. Remaining bytes: SFrame data to parse
fn main() {
    fuzz!(|data: &[u8]| {
        if data.len() < 8 {
            return;
        }

        // Extract section_base from first 8 bytes
        let section_base = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]) as u64;
        let data = &data[8..];

        if data.len() < 8 {
            return;
        }

        // Extract PC from first 8 bytes
        let pc = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let data = &data[8..];

        // Parse SFrame data from remaining bytes
        let sframe = match SFrameSection::from(data, section_base) {
            Ok(section) => section,
            Err(_) => return, // Skip if parsing fails
        };

        // Test find_fre on all FDEs
        // This exercises the find_fre logic with various PCs and FDE configurations
        for i in 0..sframe.get_fde_count() {
            if let Ok(Some(fde)) = sframe.get_fde(i) {
                let _ = fde.find_fre(&sframe, pc);
            };
        }
    });
}
