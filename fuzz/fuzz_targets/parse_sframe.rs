use afl::fuzz;
use simple_frame_rs::SFrameSection;

/// Fuzz target for SFrameSection::from()
/// This tests the main parsing logic with various byte inputs
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

        // Attempt to parse the input as SFrame data
        // The function should handle all inputs gracefully without panicking
        let _ = SFrameSection::from(data, section_base);
    });
}
