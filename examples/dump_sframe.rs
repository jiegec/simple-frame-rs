use object::{Object, ObjectSection};
use simple_frame_rs::SFrameSection;

fn main() -> anyhow::Result<()> {
    for arg in std::env::args() {
        let data = std::fs::read(arg)?;
        let file = object::File::parse(&*data)?;
        for section in file.sections() {
            if section.name()? == ".sframe" {
                let content = section.data()?;
                let parsed = SFrameSection::from(content)?;
                println!("Header:");
                println!("  Version: {:?}", parsed.version);
                println!("  Flags: {:?}", parsed.flags);
                if parsed.cfa_fixed_fp_offset != 0 {
                    println!("  CFA fixed FP offset: {:?}", parsed.cfa_fixed_fp_offset);
                }
                if parsed.cfa_fixed_ra_offset != 0 {
                    println!("  CFA fixed RA offset: {:?}", parsed.cfa_fixed_ra_offset);
                }
                println!("  Num FDEs: {:?}", parsed.num_fdes);
                println!("  Num FREs: {:?}", parsed.num_fres);
            }
        }
    }
    Ok(())
}
