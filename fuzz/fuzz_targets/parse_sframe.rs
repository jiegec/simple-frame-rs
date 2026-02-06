use afl::fuzz;
use simple_frame_rs::SFrameSection;

/// Fuzz target for SFrameSection::from()
/// This tests the main parsing logic with various byte inputs
fn main() {
    fuzz!(|data: &[u8]| {
        // Attempt to parse the input as SFrame data
        // The function should handle all inputs gracefully without panicking
        let _ = SFrameSection::from(data, 0);
    });
}
