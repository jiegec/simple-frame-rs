use afl::fuzz;
use simple_frame_rs::SFrameSection;

/// Fuzz target for SFrameSection::find_fde()
/// This tests finding FDEs by PC with various inputs
///
/// The fuzzer will generate two inputs concatenated:
/// 1. First 4 bytes: PC address to search for
/// 2. Remaining bytes: SFrame data to parse
fn main() {
    fuzz!(|data: &[u8]| {
        if data.len() < 4 {
            return;
        }

        // Extract PC from first 4 bytes
        let pc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;

        // Parse SFrame data from remaining bytes
        let sframe = match SFrameSection::from(&data[4..], 0) {
            Ok(section) => section,
            Err(_) => return, // Skip if parsing fails
        };

        // Attempt to find FDE by PC - should not panic on any PC value
        let _ = sframe.find_fde(pc);
    });
}
