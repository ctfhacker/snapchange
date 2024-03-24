#![feature(lazy_cell)]

use anyhow::Result;
use snapchange::snapchange_main;
use snapchange::FuzzInput;

mod constants;
mod fuzzer;

use std::path::Path;

fn main() -> Result<()> {
    /*
    if std::env::args().nth(1) == Some("dump".to_string()) {
        let input = std::env::args().nth(2).expect(
            "USAGE: cargo run -r -- dump <INPUT FILE> <OUTPUT DIR>: No output directory given",
        );
        let output_dir = std::env::args().nth(3).expect(
            "USAGE: cargo run -r -- dump <INPUT FILE> <OUTPUT DIR>: No output directory given",
        );

        let input = Path::new(&input);
        let output = Path::new(&output_dir);

        if output.exists() {
            println!("ERROR: Output directory already exists");
            return Ok(());
        }

        std::fs::create_dir_all(output);

        let Ok(bytes) = fuzzer::InputFromAnywhere::from_bytes(&std::fs::read(input).unwrap())
        else {
            println!("ERROR: Failed to parse input file");
            return Ok(());
        };

        for (name, data) in bytes.file_names.iter().zip(bytes.file_datas.iter()) {
            let name = Path::new(&name);
            let file = output.join(name.strip_prefix("/").unwrap());

            std::fs::create_dir_all(file.parent().unwrap());

            let _ = std::fs::write(file, data);
        }

        return Ok((()));
    }

    return Ok((()));
    */

    snapchange_main::<fuzzer::GenericFuzzerFromMain>()
}
