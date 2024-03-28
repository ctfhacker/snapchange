//! Provides [`Fuzzer`] trait along with pre-built fuzzers

mod fuzzer;

#[cfg(feature = "netfile")]
mod net_file_fuzzer;

pub use fuzzer::*;

#[cfg(feature = "netfile")]
pub use net_file_fuzzer::{InputFromAnywhere, InputlessFuzzer, NetFileFuzzer};
