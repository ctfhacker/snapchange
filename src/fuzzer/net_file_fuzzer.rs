//! Fuzzer where the inputs come from files and network packets

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use std::cell::Cell;
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InputFromAnywhere {
    /// The names of fuzzed files in this input
    pub file_names: Vec<String>,

    /// The data for the fuzzed files in this input
    pub file_datas: Vec<Vec<u8>>,

    /// The number of packets to generate for this input
    pub number_of_packets: usize,

    /// The names of fuzzed sockets in this input
    pub packets: Vec<Vec<u8>>,

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
        // let res = match rmp_serde::from_slice(bytes) {
        let res = match serde_json::from_slice(bytes) {
            Ok(res) => Ok(res),
            Err(_) => Ok(Self {
                file_names: Vec::new(),
                file_datas: Vec::new(),
                number_of_packets: 0,
                packets: Vec::new(),
                starting_input: bytes.to_vec(),
            }),
        };

        res
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();

        // let bytes = rmp_serde::to_vec(self)?;
        let bytes = serde_json::to_vec(self)?;
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
        let mut packets = Vec::new();

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
            packets,
            starting_input,
            number_of_packets: 0,
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

        // Mutate packets in a variety of ways
        if !input.packets.is_empty() {
            for _ in 0..rng.gen_range(1..=max_mutations) {
                let packet_num = rng.gen_range(0..input.packets.len());

                // Random chance to delete the packet
                if rng.gen_bool(1.0 / 10000.0) {
                    input.packets.remove(packet_num);
                    continue;
                }

                // Get the random packet
                let Some(mut random_packet) = input.packets.get_mut(packet_num) else {
                    continue;
                };

                // Random chance to copy a packet from another input
                if rng.gen_bool(1.0 / 1024.0) {
                    if let Some(other_input) = corpus.choose(rng) {
                        if other_input.packets.len() >= packet_num {
                            // Copy a packet from another input at this packet index
                            input.packets[packet_num] = other_input.packets[packet_num].clone();
                            continue;
                        }
                    }
                }

                // Random chance to empty a packet and have `recv` return `0`
                if rng.gen_bool(1.0 / 128.0) {
                    random_packet.clear();
                    continue;
                }

                // Otherwise, mutate the packet as normal
                mutations.extend(<Vec<u8> as FuzzInput>::mutate(
                    random_packet,
                    &[],
                    rng,
                    dictionary,
                    min_length,
                    max_length,
                    max_mutations,
                    #[cfg(feature = "redqueen")]
                    redqueen_rules,
                ));
            }
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

    /// The maximum number of packets this fuzzer will generate per input
    number_of_packets: usize,

    /// The index to the next packet to send to the target from the input
    packet_index: usize,
}

/// A fuzzer whose inputs come from files/network and are not specifically set by the fuzzer itself
pub trait InputlessFuzzer: Default {
    /// The maximum length for an input used to truncate long inputs.
    const MAX_INPUT_LENGTH: usize = 0x1000;

    /// The minimum length for an input
    const MIN_INPUT_LENGTH: usize = 1;

    /// The expected starting address of the snapshot for this fuzzer. This is a
    /// sanity check to ensure the fuzzer matches the given snapshot.
    const START_ADDRESS: u64;

    /// Maximum number of mutation functions called during mutation
    const MAX_MUTATIONS: u64 = 16;

    /// Maximum number of packets to generate for this fuzzer
    const MAX_PACKETS: usize = 8;

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

    fn reset_fuzzer_state(&mut self) {
        self.target_fuzzer.reset_fuzzer_state();
        self.packet_index = 0;
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
        // let fuzzer_bps = self.target_fuzzer.breakpoints().unwrap_or(&[]);

        Some(&[
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___sigaction", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    // Set success
                    fuzzvm.set_rax(0);
                    fuzzvm.fake_immediate_return();
                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___socket", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let domain = (fuzzvm.rdi() as i32).into();
                    let socket_type = (fuzzvm.rsi() as i32).into();
                    let protocol = (fuzzvm.rdx() as i32).into();

                    // Create the new emulated socket
                    let fd =
                        fuzzvm
                            .network
                            .as_mut()
                            .unwrap()
                            .new_socket(domain, socket_type, protocol);

                    // Set the return result to the emulated file descriptor
                    fuzzvm.set_rax(fd);
                    fuzzvm.fake_immediate_return();

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___setsockopt", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let fd = fuzzvm.rdi();
                    let level = fuzzvm.rsi() as i32;
                    let optname = fuzzvm.rdx() as i32;
                    let opts = fuzzvm.rcx();
                    let opt_len = fuzzvm.r8() as usize;

                    let mut opt_data = vec![0_u8; opt_len];
                    fuzzvm.read_bytes(VirtAddr(opts), fuzzvm.cr3(), &mut opt_data)?;

                    fuzzvm
                        .network
                        .as_mut()
                        .unwrap()
                        .setsockopt(fd, level, optname, opt_data);

                    // Return success
                    fuzzvm.set_rax(0);
                    fuzzvm.fake_immediate_return()?;

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___bind", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let socket = fuzzvm.rdi();
                    let address_ptr = fuzzvm.rsi();
                    let address_len = fuzzvm.rdx() as usize;

                    // Read the address data
                    let mut address_data = vec![0_u8; address_len];
                    fuzzvm.read_bytes(VirtAddr(address_ptr), fuzzvm.cr3(), &mut address_data)?;

                    // Emulate the bind
                    fuzzvm.network.as_mut().unwrap().bind(socket, address_data);

                    // Return success
                    fuzzvm.set_rax(0);
                    fuzzvm.fake_immediate_return()?;

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___listen", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let socket = fuzzvm.rdi();
                    let backlog = fuzzvm.rsi() as i32;

                    // Emulate the bind
                    fuzzvm.network.as_mut().unwrap().listen(socket, backlog);

                    // Return success
                    fuzzvm.set_rax(0);
                    fuzzvm.fake_immediate_return()?;

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI_accept", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let socket = fuzzvm.rdi();
                    let address_ptr = fuzzvm.rsi();
                    let address_len = fuzzvm.rdx() as usize;

                    // Only open one socket at a time?
                    if fuzzvm.network.as_ref().unwrap().sockets.len() >= 2 {
                        fuzzvm.set_rax(u64::MAX);
                        fuzzvm.fake_immediate_return()?;
                        return Ok(Execution::Continue);
                    }

                    assert!(
                        address_ptr == 0,
                        "TODO(corydu): Address ptr is null. Fuzz results of accept."
                    );

                    // Emulate the accept
                    let fd = fuzzvm.network.as_mut().unwrap().accept(socket)?;

                    // Return success
                    fuzzvm.set_rax(fd);
                    fuzzvm.fake_immediate_return()?;
                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI_verr", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let err_msg = fuzzvm.read_c_string(VirtAddr(fuzzvm.rsi()), fuzzvm.cr3())?;
                    let err_rip = fuzzvm.rcx();
                    let err_sym = match fuzzvm.get_symbol(err_rip) {
                        Some(msg) => msg,
                        None => "unknown_symbol".to_string(),
                    };

                    log::error!("Error @ {err_rip:#x} ({err_sym})-- {err_msg}");

                    Ok(Execution::Reset)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___bind", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let socket_name = format!("socket_fd_");
                    fuzzvm.print_context()?;

                    Ok(Execution::Reset)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___recv", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, fuzzer, _feedback| {
                    // The input doesn't have any more packets to send to the client, reset
                    if input.packets.is_empty() || fuzzer.packet_index >= input.packets.len() {
                        // Already hit the maximum number of packets, just reset
                        if fuzzer.number_of_packets >= F::MAX_PACKETS {
                            return Ok(Execution::Reset);
                        }

                        // The fuzzer can still create more packets, bump up the number of packets
                        fuzzer.number_of_packets += 1;

                        return Ok(Execution::NeedAnotherPacketReset {
                            number_of_packets: fuzzer.packet_index as u64,
                        });
                    }

                    // Parse the arguments to the function
                    let socket = fuzzvm.rdi();
                    let buffer_ptr = fuzzvm.rsi();
                    let buffer_len = fuzzvm.rdx() as usize;
                    let flags = fuzzvm.rcx();

                    // Get the index of the next packet from the input
                    let packet_index = fuzzer.packet_index;
                    fuzzer.packet_index += 1;

                    let data = input.packets[packet_index].as_slice();

                    // Use the smaller of the `recv` packet length.
                    // NOTE(corydu): Currently, every `recv` call is a different "packet" for
                    // mutation/generation purposes.
                    let packet_len = data.len().min(buffer_len);

                    // Write the bytes into the given buffer
                    fuzzvm.write_bytes(VirtAddr(buffer_ptr), fuzzvm.cr3(), &data[..packet_len])?;

                    // Set the return value to the number of bytes written to the buffer
                    fuzzvm.set_rax(packet_len as u64);
                    fuzzvm.fake_immediate_return();

                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___fork", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let cr3 = fuzzvm.cr3().0;
                    log::info!("Fork -- cr3 {cr3:#x}");

                    Ok(Execution::Continue)
                },
            },
            /*
            // FILE OPERATIONS
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("do_sys_openat2", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    // Read the arguments to openat2
                    let dirfd = fuzzvm.rdi();
                    let filename = fuzzvm.read_c_string(VirtAddr(fuzzvm.rsi()), fuzzvm.cr3())?;
                    let open_how = fuzzvm.rdx();

                    log::info!("Opening: {filename}");
                    return Ok(Execution::Continue);

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
            */
            /*
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
            */
        ])
    }

    fn mutate_input(
        &mut self,
        input: &mut Self::Input,
        corpus: &[Arc<InputWithMetadata<Self::Input>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        #[cfg(feature = "redqueen")] redqueen_rules: Option<&FxHashSet<RedqueenRule>>,
    ) -> Vec<String> {
        // Increase the upper bound of the maximum number of packets to generate.
        if self.number_of_packets < input.packets.len() {
            self.number_of_packets = self.number_of_packets.max(input.packets.len());
            assert!(self.number_of_packets <= F::MAX_PACKETS);
        }

        if self.number_of_packets > 0 {
            // Include up the maximum number of packets
            let wanted_packets = rng.gen_range(1..(self.number_of_packets + 1));

            let missing_packets = wanted_packets.saturating_sub(input.packets.len());

            let before_len = input.packets.len();

            for _ in 0..missing_packets {
                // Choose a random input from the corpus
                let Some(rand_input) = corpus.choose(rng) else {
                    input.packets.push(Vec::new());
                    break;
                };

                // Choose a random packet from this random input
                let Some(rand_packet) = rand_input.packets.choose(rng) else {
                    input.packets.push(Vec::new());
                    continue;
                };

                // Use this random packet for this missing input
                input.packets.push(rand_packet.clone());
            }

            // If packets are expected, always include at least one
            if wanted_packets > 0 && input.packets.is_empty() {
                // Use this random packet for this missing input
                input.packets.push(Vec::new());
            }
        }

        // Mutate the input in place
        Self::Input::mutate(
            input,
            corpus,
            rng,
            dictionary,
            Self::MIN_INPUT_LENGTH,
            Self::MAX_INPUT_LENGTH,
            Self::MAX_MUTATIONS,
            #[cfg(feature = "redqueen")]
            redqueen_rules,
        )
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
