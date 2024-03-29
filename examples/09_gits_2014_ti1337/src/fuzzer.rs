//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::cmp_analysis::RedqueenRule;
use snapchange::filesystem::FileSystem;
use snapchange::fuzz_input::{Endian, GetRuleMode, InputWithMetadata};
use snapchange::fuzzer::{
    AddressLookup, Breakpoint, BreakpointType, InputFromAnywhere, InputlessFuzzer, NetFileFuzzer,
};
use snapchange::fuzzvm::FuzzVm;
use snapchange::linux;
use snapchange::prelude::*;
use snapchange::Execution;
use snapchange::FuzzInput;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default)]
pub struct TiffInfoFuzzer {}

impl InputlessFuzzer for TiffInfoFuzzer {
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x1;
    const MAX_MUTATIONS: u64 = 0x8;
    const MAX_PACKETS: usize = 2048;

    /*
    fn crash_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[AddressLookup::Virtual(VirtAddr(0x4013f7), CR3)])
    }
    */
}
