//! Fuzzer where the inputs come from files and network packets

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

use crate::addrs::{Cr3, VirtAddr};
use crate::cmp_analysis::RedqueenRule;
use crate::filesystem::FileSystem;
use crate::fuzz_input::{Endian, GetRuleMode, InputWithMetadata};
use crate::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer};
use crate::fuzzvm::FuzzVm;
use crate::linux;
use crate::prelude::*;
use crate::Execution;
use crate::FuzzInput;

#[derive(Debug)]
pub enum RedqueenCandidate {
    File {
        /// Index in `file_datas for this candidate
        index: usize,

        /// Offset in this file
        offset: usize,

        /// Endianness of the data
        endian: Endian,
    },
}

/// A input type that fuzzes files and network packets
#[derive(Default, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InputFromAnywhere {
    /// The names of fuzzed files in this input
    pub file_names: Vec<String>,

    /// The data for the fuzzed files in this input
    pub file_datas: Vec<Vec<u8>>,

    /// The names of fuzzed sockets in this input
    pub sockets: Vec<String>,

    /// The initial file from ./snapshot/input. At the beginning of the fuzz run, we don't know
    /// what this input could mean (a file, a packet, ect). So we store it here and use it as
    /// part of a mutation later on
    pub starting_input: Vec<u8>,
}

impl FuzzInput for InputFromAnywhere {
    type RuleCandidate = RedqueenCandidate;
    type MinState = NullMinimizerState;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // FUZZER::Input::from_bytes is called on every file in ./snapshot/input at
        // the beginning of a fuzz run. We want to enable dumping blobs of data in
        // ./snapshot/input without much labeling. If we can't
        let res = match rmp_serde::from_slice(bytes) {
            Ok(res) => Ok(res),
            Err(_) => Ok(Self {
                file_names: Vec::new(),
                file_datas: Vec::new(),
                sockets: Vec::new(),
                starting_input: bytes.to_vec(),
            }),
        };

        res
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();

        let bytes = rmp_serde::to_vec(self)?;
        output.extend(bytes);

        Ok(())
    }

    fn generate(
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
    ) -> InputWithMetadata<Self> {
        let mut file_names: Vec<String> = Vec::new();
        let mut file_datas = Vec::new();
        let mut sockets = Vec::new();

        // Choose a random starting input if there is one from the corpus
        let starting_input = if corpus.is_empty() {
            Vec::new()
        } else {
            corpus.choose(rng).unwrap().starting_input.clone()
        };

        // Attempt to fill in some file information from other files in the corpus
        for _ in 0..4 {
            if let Some(other_input) = corpus.choose(rng) {
                if other_input.file_names.is_empty() {
                    continue;
                }

                // Choose a random file in this other input
                let random_file = rng.gen_range(0..other_input.file_names.len());

                // Check if this new input already knows about this file
                let filename = &other_input.file_names[random_file];
                if file_names.contains(&filename) {
                    continue;
                }

                // If not, add the filedata to this input to be mutated later
                let filedata = &other_input.file_datas[random_file];
                file_names.push(filename.clone());
                file_datas.push(filedata.clone());
            }
        }

        InputWithMetadata::from_input(Self {
            file_names,
            file_datas,
            sockets,
            starting_input,
        })
    }

    fn mutate(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
        max_mutations: u64,
        redqueen_rules: Option<&FxHashSet<RedqueenRule>>,
    ) -> Vec<String> {
        let mut mutations = Vec::new();

        // Randomly add new files from other files in the corpus
        for _ in 0..rng.gen_range(1..8) {
            if let Some(other_file) = corpus.choose(rng) {
                for (index, file_name) in other_file.file_names.iter().enumerate() {
                    // Small chance to add another input's file and data to this input
                    if !input.file_names.contains(&file_name) && rng.gen_bool(1.0 / 32.0) {
                        let file_data = other_file.file_datas[index].clone();
                        input.file_names.push(file_name.clone());
                        input.file_datas.push(file_data.clone());
                    }
                }
            }
        }

        // Mutate all known files in this input
        for data in input.file_datas.iter_mut() {
            if rng.next() % 10 == 1 && !input.starting_input.is_empty() {
                *data = input.starting_input.clone();
            }

            <Vec<u8> as FuzzInput>::mutate(
                data,
                &[],
                rng,
                dictionary,
                min_length,
                max_length,
                max_mutations,
                #[cfg(feature = "redqueen")]
                redqueen_rules,
            );
        }

        mutations
    }

    /// Upper bound for the ranges produced during increasing entropy for redqueen
    fn entropy_limit(&self) -> usize {
        self.file_datas.iter().map(|x| x.len()).max().unwrap_or(0)
    }

    fn increase_entropy(&mut self, rng: &mut Rng, start: usize, end: usize) -> Result<()> {
        use rand::Fill;

        // Randomize the entropy of all files to start/end
        for data in self.file_datas.iter_mut() {
            let curr_start = start.min(data.len());
            let curr_end = end.min(data.len());

            data[curr_start..curr_end].try_fill(rng)?;
        }

        // Randomize these bytes
        Ok(())
    }

    fn get_redqueen_rule_candidates(&self, rule: &RedqueenRule) -> Vec<Self::RuleCandidate> {
        let mut all_rules = Vec::new();

        for (i, data) in self.file_datas.iter().enumerate() {
            let rules = data.get_redqueen_rule_candidates(rule);
            for (offset, endian) in rules {
                all_rules.push(RedqueenCandidate::File {
                    index: i,
                    offset,
                    endian,
                });
            }
        }

        all_rules
    }

    fn has_redqueen_rule_candidates(&self, rule: &RedqueenRule) -> bool {
        for data in &self.file_datas {
            let rules = data.get_redqueen_rule_candidates(rule);
            if !rules.is_empty() {
                return true;
            }
        }

        false
    }

    fn apply_redqueen_rule(
        &mut self,
        rule: &RedqueenRule,
        candidate: &Self::RuleCandidate,
    ) -> Option<String> {
        match candidate {
            RedqueenCandidate::File {
                index,
                offset,
                endian,
            } => {
                let vec_candidate = (*offset, *endian);
                self.file_datas[*index].apply_redqueen_rule(rule, &vec_candidate)
            }
        }
    }
}

/// Fuzzer where the fuzzed inputs are automatically handled from file operations (read) and
/// network operations (recv)
#[derive(Default)]
pub struct NetFileFuzzer<T: InputlessFuzzer> {
    target_fuzzer: T,
}

/// A fuzzer whose inputs come from files/network and are not specifically set by the fuzzer itself
pub trait InputlessFuzzer: Default {
    /// The maximum length for an input used to truncate long inputs.
    const MAX_INPUT_LENGTH: usize;

    /// The minimum length for an input
    const MIN_INPUT_LENGTH: usize = 1;

    /// The expected starting address of the snapshot for this fuzzer. This is a
    /// sanity check to ensure the fuzzer matches the given snapshot.
    const START_ADDRESS: u64;

    /// Maximum number of mutation functions called during mutation
    const MAX_MUTATIONS: u64 = 16;

    /// Reset the state of the current fuzzer
    fn reset_fuzzer_state(&mut self) {
        // By default, resetting fuzzer state does nothing
    }

    /// Set of syscalls the fuzzer will manually handle, while ignoring all others.
    /// Cannot be used with `syscall_blacklist`
    fn syscall_whitelist(&self) -> &'static [u64] {
        &[]
    }

    /// Set of syscalls the fuzzer will manually NOT handle, while handling all others.
    /// Cannot be used with `syscall_whitelist`
    fn syscall_blacklist(&self) -> &'static [u64] {
        &[]
    }

    /// One-time initialization of the snapshot
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to initialize the VM
    fn init_snapshot(&mut self, _fuzzvm: &mut FuzzVm<NetFileFuzzer<Self>>) -> Result<()> {
        Ok(())
    }

    /// Initialize the VM before starting any fuzz case
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to initialize the VM
    fn init_vm(&mut self, _fuzzvm: &mut FuzzVm<NetFileFuzzer<Self>>) -> Result<()> {
        Ok(())
    }

    /// Addresses or symbols that, if hit, trigger execution of a callback function.  All
    /// symbols are checked to see if they contain the given symbol substring.
    fn breakpoints(&self) -> Option<&[Breakpoint<NetFileFuzzer<Self>>]> {
        None
    }

    /// Breakpoints that, if hit, will cause the VM to be reset without saving state
    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        None
    }

    /// Breakpoints that, if hit, will cause the VM to be reset while saving input and
    /// state
    fn crash_breakpoints(&self) -> Option<&[AddressLookup]> {
        None
    }

    /// Fuzzer specific handling of a crashing `input` bytes with the [`FuzzVm`] that
    /// originally will write to `crash_file`. Defaults to nothing.
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to handle a crashing input
    fn handle_crash(
        &self,
        _input: &InputWithMetadata<<NetFileFuzzer<Self> as Fuzzer>::Input>,
        _fuzzvm: &mut FuzzVm<NetFileFuzzer<Self>>,
        _crash_file: &Path,
    ) -> Result<()> {
        // No action by default
        Ok(())
    }

    /// Fuzzer specific handling of opening a new file. Used primarily for `InputlessFuzzer` to
    /// know which files to create on mutation/generation.
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to handle the new path
    fn handle_opened_file(
        &self,
        _input: &InputWithMetadata<<NetFileFuzzer<Self> as Fuzzer>::Input>,
        _opened_file: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// Initialize files available to the guest
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to initialize a filesystem
    fn init_files(&self, _fs: &mut FileSystem) -> Result<()> {
        Ok(())
    }
}

impl<F: InputlessFuzzer> Fuzzer for NetFileFuzzer<F> {
    type Input = InputFromAnywhere;
    const START_ADDRESS: u64 = F::START_ADDRESS;
    const MIN_INPUT_LENGTH: usize = F::MIN_INPUT_LENGTH;
    const MAX_INPUT_LENGTH: usize = F::MAX_INPUT_LENGTH;
    const MAX_MUTATIONS: u64 = F::MAX_MUTATIONS;

    fn init_snapshot(&mut self, _fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Init the list of known files
        log::info!("INIT known files");

        Ok(())
    }

    fn crash_breakpoints(&self) -> Option<&[AddressLookup]> {
        self.target_fuzzer.crash_breakpoints()
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        self.target_fuzzer.reset_breakpoints()
    }

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<NetFileFuzzer<F>>,
    ) -> Result<()> {
        // The snapshot was taken at `main+4`. Restore current RIP back to the original RIP.
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        // Apply the target fuzzer's set_input function as well
        // self.target_fuzzer.set_input(input, fuzzvm)?;

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("do_sys_openat2", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    // Read the arguments to openat2
                    let dirfd = fuzzvm.rdi();
                    let filename = fuzzvm.read_c_string(VirtAddr(fuzzvm.rsi()), fuzzvm.cr3())?;
                    let open_how = fuzzvm.rdx();

                    // If this is the first time seeing this open file, add this filename to the
                    // list of input files to generate. This will be picked up when these
                    if !input.file_names.contains(&filename) {
                        return Ok(Execution::OpenedNewFileReset {
                            path: filename.clone(),
                        });
                    }

                    for (input_filename, bytes) in
                        input.file_names.iter().zip(input.file_datas.iter())
                    {
                        if *input_filename != filename {
                            continue;
                        }

                        let fd = fuzzvm
                            .filesystem
                            .as_mut()
                            .unwrap()
                            .new_file(filename.clone(), bytes.clone());

                        fuzzvm.set_rax(fd);
                        fuzzvm.fake_immediate_return();

                        // log::info!("open({filename}) -> {fd:#x}");
                        return Ok(Execution::Continue);
                    }

                    return Ok(Execution::Reset);
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("ksys_read", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let fd = fuzzvm.rdi();
                    let buf = fuzzvm.rsi();
                    let size = fuzzvm.rdx() as usize;

                    let Some(mut filesystem) = fuzzvm.filesystem.take() else {
                        log::error!("No filesystem found to read from.");
                        fuzzvm.filesystem = Some(FileSystem::default());
                        return Ok(Execution::Reset);
                    };

                    let Ok(bytes) = filesystem.read(fd, size) else {
                        log::error!("Failed to read from fd {fd:#x} of size {size:#x}");
                        fuzzvm.filesystem = Some(filesystem);
                        return Ok(Execution::Reset);
                    };

                    // log::info!("Bytes: {}", bytes.len());

                    let read_bytes = bytes.len();

                    let translation =
                        fuzzvm.translate(VirtAddr(buf + bytes.len() as u64 - 1), fuzzvm.cr3());

                    if translation.phys_addr().is_none() {
                        fuzzvm.filesystem = Some(filesystem);
                        return Ok(Execution::Continue);
                    }

                    if let Err(e) = fuzzvm.write_bytes_dirty(VirtAddr(buf), fuzzvm.cr3(), bytes) {
                        fuzzvm.filesystem = Some(filesystem);
                        return Ok(Execution::Reset);
                    }

                    fuzzvm.filesystem = Some(filesystem);

                    // Set the return values
                    fuzzvm.set_rax(read_bytes as u64);

                    // Immediately return from this function
                    fuzzvm.fake_immediate_return().unwrap();

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("ksys_lseek", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let linux::LseekArgs { fd, offset, whence } = linux::lseek_args(fuzzvm);

                    // Seek in the given file descriptor
                    let offset =
                        fuzzvm
                            .filesystem
                            .as_mut()
                            .unwrap()
                            .seek(fd, offset as i32, whence)?;

                    // Set the return value of this lseek
                    fuzzvm.set_rax(offset as u64);

                    // Immediately return from this function
                    fuzzvm.fake_immediate_return().unwrap();

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("__do_sys_newfstat", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let fd = fuzzvm.rdi();
                    let stat_buf = fuzzvm.rsi();

                    // Get the stats struct for this fd
                    let Ok(stats) = fuzzvm.filesystem.as_mut().unwrap().fstat(fd) else {
                        return Ok(Execution::Reset);
                    };

                    // Write the stats struct to the buffer
                    match fuzzvm.write(VirtAddr(stat_buf), fuzzvm.cr3(), stats) {
                        Ok(()) => {}
                        Err(e) => {
                            println!("Write err: {e:?}");
                            return Ok(Execution::Reset);
                        }
                    }

                    // Return success
                    fuzzvm.set_rax(0);

                    // Immediately return from this function
                    fuzzvm.fake_immediate_return()?;

                    Ok(Execution::Continue)
                },
            },
        ])
    }

    fn handle_crash(
        &self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
        crash_file: &Path,
    ) -> Result<()> {
        // Get the output directory path
        let output = crash_file.with_extension("inputs");

        // Create the output directory
        std::fs::create_dir_all(&output);

        // Write all fuzzed files into the output directory structure
        for (name, data) in input.file_names.iter().zip(input.file_datas.iter()) {
            let name = Path::new(&name);
            let file = output.join(name.strip_prefix("/").unwrap());

            // Create the directory that holds this fuzzed input file
            std::fs::create_dir_all(file.parent().unwrap());

            if let Err(e) = std::fs::write(&file, data) {
                log::error!("Failed to write crash file: {file:?}");
            }
        }

        Ok(())
    }

    fn handle_opened_file(
        &self,
        input: &mut InputWithMetadata<Self::Input>,
        opened_file: &str,
    ) -> Result<()> {
        // Allow the target fuzzer to handle opened files
        self.target_fuzzer.handle_opened_file(input, opened_file)?;

        // If this input doesn't currently know about this
        input.file_names.push(opened_file.to_string());

        let starting_input = input.starting_input.clone();
        input.file_datas.push(starting_input);

        Ok(())
    }
}
