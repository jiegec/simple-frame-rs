#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn inner_main() -> anyhow::Result<()> {
    use object::{Object, ObjectSection};
    use simple_frame_rs::SFrameSection;
    use std::mem::MaybeUninit;

    for arg in std::env::args().skip(1) {
        let pid = usize::from_str_radix(&arg, 10)?;
        println!("Attempt to dump backtrace of process with pid {}", pid);

        let data = std::fs::read(format!("/proc/{}/exe", pid))?;
        let file = object::File::parse(&*data)?;
        let mut done = false;
        for section in file.sections() {
            if section.name()? == ".sframe" {
                let section_base = section.address();
                let content = section.data()?;
                let parsed = SFrameSection::from(content, section_base)?;
                println!("Found sframe info of the process:");
                println!("{}", parsed.to_string()?);

                // dump stacktrace
                unsafe {
                    libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0);
                    libc::waitpid(pid as i32, 0 as *mut i32, 0);
                }

                // get registers
                let mut regs: MaybeUninit<libc::user_regs_struct> = MaybeUninit::zeroed();
                let regs = unsafe {
                    libc::ptrace(libc::PTRACE_GETREGS, pid, 0, regs.as_mut_ptr());
                    regs.assume_init()
                };

                // TODO: other archs
                let mut pc = regs.rip;
                let mut sp = regs.rsp;
                let mut fp = regs.rbp;

                let mut frame = 1;
                loop {
                    println!("Frame {}:", frame);
                    println!("PC = 0x{:x}", pc);
                    println!("SP = 0x{:x}", sp);
                    println!("FP = 0x{:x}", fp);

                    // find fre by pc
                    if let Some(fde) = parsed.find_fde(pc)? {
                        if let Some(fre) = fde.find_fre(&parsed, pc)? {
                            let base_reg = if fre.get_cfa_base_reg_id() == 0 {
                                fp
                            } else {
                                sp
                            };
                            let cfa = (base_reg as i64
                                + fre.get_cfa_offset(&parsed).unwrap().unwrap() as i64)
                                as u64;

                            // new sp
                            sp = cfa;

                            let ra_addr = (cfa as i64
                                + fre.get_ra_offset(&parsed).unwrap().unwrap() as i64)
                                as u64;
                            // new pc
                            pc = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, ra_addr, 0) }
                                as u64;

                            if let Some(fp_offset) = fre.get_fp_offset(&parsed).unwrap() {
                                let fp_addr = (cfa as i64 + fp_offset as i64) as u64;
                                // new fp
                                fp = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, fp_addr, 0) }
                                    as u64;
                            }
                            frame += 1;
                            continue;
                        }
                    }

                    break;
                }

                unsafe {
                    libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
                }

                done = true;
                break;
            }
        }

        if !done {
            println!("Requires the ELF to contain sframe information");
        }
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn inner_main() -> anyhow::Result<()> {
    println!("This example only works on Linux x86_64 systems");
    println!("It requires /proc filesystem and ptrace functionality");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    inner_main()
}
