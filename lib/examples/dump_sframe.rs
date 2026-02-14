use object::{Object, ObjectSection};
use simple_frame_rs::SFrameSection;

fn main() -> anyhow::Result<()> {
    for arg in std::env::args().skip(1) {
        let data = std::fs::read(arg)?;
        let file = object::File::parse(&*data)?;
        for section in file.sections() {
            if section.name()? == ".sframe" {
                let section_base = section.address();
                let content = section.data()?;
                let parsed = SFrameSection::from(content, section_base)?;
                match parsed {
                    SFrameSection::V1(sframe_section) => {
                        println!("{}", sframe_section.to_string()?)
                    }
                    SFrameSection::V2(sframe_section) => {
                        println!("{}", sframe_section.to_string()?)
                    }
                }
            }
        }
    }
    Ok(())
}
