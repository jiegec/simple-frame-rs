use fallible_iterator::FallibleIterator;
use object::{Object, ObjectSection};
use simple_frame_rs::SFrameSection;

fn main() -> anyhow::Result<()> {
    for arg in std::env::args() {
        let data = std::fs::read(arg)?;
        let file = object::File::parse(&*data)?;
        for section in file.sections() {
            if section.name()? == ".sframe" {
                let section_base = section.address();
                let content = section.data()?;
                let parsed = SFrameSection::from(content, section_base)?;
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
                println!();
                println!("Function Index:");
                println!();
                for i in 0..parsed.num_fdes {
                    let fde = parsed.get_fde(i)?.unwrap();
                    let pc = fde.get_pc(&parsed);
                    println!(
                        "  func index[{i}]: pc = 0x{:x} size = {} bytes",
                        pc, fde.func_size,
                    );

                    match fde.func_info.get_fde_type()? {
                        simple_frame_rs::SFrameFDEType::PCInc => {
                            println!("  STARTPC           CFA      FP     RA")
                        }
                        simple_frame_rs::SFrameFDEType::PCMask => {
                            println!("  STARTPC[m]        CFA      FP     RA")
                        }
                    }
                    let mut iter = fde.iter_fre(&parsed);
                    while let Some(fre) = iter.next()? {
                        let start_pc = match fde.func_info.get_fde_type()? {
                            simple_frame_rs::SFrameFDEType::PCInc => {
                                pc + fre.start_address.get() as u64
                            }
                            simple_frame_rs::SFrameFDEType::PCMask => {
                                fre.start_address.get() as u64
                            }
                        };
                        let rest;
                        match parsed.abi {
                            simple_frame_rs::SFrameABI::AMD64LittleEndian => {
                                let base_reg = if fre.info.get_cfa_base_reg_id() == 0 {
                                    "fp"
                                } else {
                                    "sp"
                                };
                                let cfa = format!("{}+{}", base_reg, fre.stack_offsets[0].get());
                                let fp = match fre.stack_offsets.get(1) {
                                    Some(offset) => format!("c{:+}", offset.get()),
                                    None => format!("u"), // without offset
                                };
                                let ra = "f"; // fixed
                                rest = format!("{cfa:8} {fp:6} {ra}");
                            }
                            _ => todo!(),
                        }
                        println!("  {:016x}  {}", start_pc, rest);
                    }
                    println!();
                }
            }
        }
    }
    Ok(())
}
