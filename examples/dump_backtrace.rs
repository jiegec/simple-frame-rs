use fallible_iterator::FallibleIterator;
use object::{Object, ObjectSection};
use simple_frame_rs::{SFrameFRE, SFrameSection};
use std::mem::MaybeUninit;

fn main() -> anyhow::Result<()> {
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

                    let mut found = false;
                    // find fre by pc
                    if let Some(fde) = parsed.find_fde(pc)? {
                        // found fde
                        let offset = pc - fde.get_pc(&parsed);

                        // find fre
                        let mut iter = fde.iter_fre(&parsed);
                        let mut last: Option<SFrameFRE> = None;
                        while let Some(fre) = iter.next()? {
                            if fre.start_address.get() as u64 > offset {
                                // last is the matching one
                                let fre = last.unwrap();
                                let base_reg = if fre.info.get_cfa_base_reg_id() == 0 {
                                    fp
                                } else {
                                    sp
                                };
                                let cfa =
                                    (base_reg as i64 + fre.stack_offsets[0].get() as i64) as u64;

                                // new sp
                                sp = cfa;

                                // amd64: fixed ra offset
                                let ra_addr =
                                    (cfa as i64 + parsed.get_cfa_fixed_ra_offset() as i64) as u64;
                                // new pc
                                pc = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, ra_addr, 0) }
                                    as u64;

                                if let Some(fp_offset) = fre.stack_offsets.get(1) {
                                    let fp_addr = (cfa as i64 + fp_offset.get() as i64) as u64;
                                    // new fp
                                    fp = unsafe {
                                        libc::ptrace(libc::PTRACE_PEEKDATA, pid, fp_addr, 0)
                                    } as u64;
                                }
                                found = true;
                                break;
                            }
                            last = Some(fre);
                        }
                    }

                    if !found {
                        break;
                    }
                    frame += 1;
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
