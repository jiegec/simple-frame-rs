use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Command};

#[derive(Serialize, Deserialize)]
struct Testcase {
    section_base: u64,
    content: Vec<u8>,
    groundtruth: String,
}

fn main() -> anyhow::Result<()> {
    for arg in std::env::args().skip(1) {
        let path = PathBuf::from(&arg);
        let data = std::fs::read(&arg)?;
        let file = object::File::parse(&*data)?;
        for section in file.sections() {
            if section.name()? == ".sframe" {
                let section_base = section.address();
                let content = section.data()?;
                let testcase = Testcase {
                    section_base,
                    content: content.to_vec(),
                    groundtruth: String::from_utf8(
                        Command::new("sh")
                            .arg("-c")
                            .arg(format!("objdump --sframe {}", arg))
                            .output()?
                            .stdout,
                    )?,
                };
                let out_path = PathBuf::from("testcases").join(format!(
                    "{}.json",
                    path.file_name().unwrap().to_str().unwrap()
                ));
                let file = std::fs::File::create(&out_path)?;
                serde_json::to_writer(file, &testcase)?;
                println!("Saved to {}", out_path.display());
            }
        }
    }
    Ok(())
}
