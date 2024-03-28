#![feature(lazy_cell)]

use anyhow::Result;
use snapchange::snapchange_main;
use snapchange::FuzzInput;

mod constants;
mod fuzzer;

use std::path::Path;

fn main() -> Result<()> {
    snapchange_main::<snapchange::NetFileFuzzer<fuzzer::TiffInfoFuzzer>>()
}
