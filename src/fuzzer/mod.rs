//! Provides [`Fuzzer`] trait along with pre-built fuzzers

mod fuzzer;
mod net_file_fuzzer;

pub use fuzzer::*;
pub use net_file_fuzzer::{InputFromAnywhere, NetFileFuzzer};
