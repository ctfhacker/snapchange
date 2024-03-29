//! Execute the `project` command

use anyhow::{Context, Result};
use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};

use crate::memory::WriteMem;
use crate::{cmdline, symbols, utils, Symbol};
use crate::{Cr3, ProjectState, VirtAddr, COLUMNS};

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;

/// File containing all physical memory modifications
const PATCHES_FILE: &str = "patches";

/// Maximum number of bytes to print for an instruction symbol
const MAX_SYMBOL_LENGTH: usize = 50;

/// A modification to physical memory
#[derive(Debug, Serialize, Deserialize)]
struct MemoryPatch {
    /// The symbol where this memory is being patched
    symbol: Option<String>,

    /// The original bytes before the patch
    bytes_before: Vec<u8>,

    /// The bytes used for that patch
    bytes_after: Vec<u8>,
}

/// Collect data about the given project
pub(crate) fn run(project_state: &ProjectState, args: &cmdline::Project) -> Result<()> {
    // Get the sorted symbols and crashing breakpoints
    let (symbols, _) = cmdline::parse_symbols(
        &project_state.symbols,
        Cr3(project_state.vbcpu.cr3 & !0xfff),
    )?;

    // Early exit for the `symbols` command as it does not require opening the memory
    if matches!(args.command, cmdline::ProjectSubCommand::Symbols) {
        if let Some(symbols) = symbols {
            for Symbol { address, symbol } in symbols {
                println!("{address:#018x} {symbol}");
            }
        } else {
            log::warn!("No symbols found.. Is there a .symbols file in project directory?");
        }

        return Ok(());
    }

    // Early exit for the `init_config` command as it doesn't require opening the memory
    if matches!(args.command, cmdline::ProjectSubCommand::InitConfig) {
        // Get the default configuration
        let default_config = crate::config::Config::default();

        // Get the path to write the config file
        let config_file = project_state.path.join("config.toml");

        // Write the initial config file
        std::fs::write(config_file, toml::to_string(&default_config).unwrap())?;

        return Ok(());
    }

    // Open the phyiscal memory for the project
    let mut memory = project_state.memory()?;

    /// Print N instructions
    macro_rules! print_instructions {
        ($addr:expr, $cr3:expr, $num_instrs:expr) => {
            let mut curr_addr = $addr;
            for _ in 0..$num_instrs {
                let (output_str, instr) = memory.get_instruction_string_at(curr_addr, $cr3)?;

                let instr_bytes: [u8; 0x10] = memory.read(curr_addr, $cr3)?;

                let symbol = if let Some(sym_data) = &symbols {
                    symbols::get_symbol(curr_addr.0, sym_data)
                        .unwrap_or_else(|| "UnknownSym".to_string())
                } else {
                    "".to_string()
                };

                let instr_bytes = instr_bytes[..instr.len()]
                    .iter()
                    .map(|x| format!("{:02x}", x))
                    .collect::<Vec<_>>()
                    .join("");

                let min_bytes = symbol.len().min(MAX_SYMBOL_LENGTH);

                let sym = if symbol.len() > MAX_SYMBOL_LENGTH {
                    format!("{}+", &symbol[..MAX_SYMBOL_LENGTH - 1])
                } else {
                    symbol[..min_bytes].to_string()
                };

                println!(
                    "{:#018x}: {instr_bytes:22} {sym: <width$} | {output_str}",
                    curr_addr.0,
                    width = MAX_SYMBOL_LENGTH
                );

                curr_addr = curr_addr.offset(instr.len() as u64);
            }
        };
    }

    let cols = COLUMNS.load(Ordering::SeqCst);
    let patches_file = project_state.path.join(PATCHES_FILE);

    // Get the current physical memory patches
    let mut patches: BTreeMap<String, MemoryPatch> = if patches_file.exists() {
        serde_json::from_slice(&std::fs::read(&patches_file)?)?
    } else {
        BTreeMap::new()
    };

    match &args.command {
        cmdline::ProjectSubCommand::Translate(translate) => {
            // Parse the given translation address or default to the starting RIP of the snapshot
            let virt_addr = match &translate.virt_addr {
                Some(addr) => crate::utils::parse_cli_symbol(addr, &symbols)?,
                None => VirtAddr(project_state.vbcpu.rip),
            };

            let curr_cr3 = translate.cr3.unwrap_or(VirtAddr(project_state.vbcpu.cr3)).0;
            let cr3 = Cr3(curr_cr3 & !0xfff);

            log::info!("Translating VirtAddr {:#x} Cr3 {:#x}", virt_addr.0, cr3.0);

            let phys_addr = memory.translate(virt_addr, cr3).phys_addr();

            // Bail early if the translation was not found
            if phys_addr.is_none() {
                log::error!("Translation not found for VirtAddr: {:#x}", virt_addr.0);
                return Ok(());
            }

            // Now we have a valid translation
            let phys_addr = phys_addr.unwrap();

            log::info!(
                "VirtAddr {:#x} -> PhysAddr {:#x?}",
                virt_addr.0,
                phys_addr.0
            );

            println!("{:-^cols$}", " HEXDUMP ".blue());
            memory.hexdump(virt_addr, cr3, 0x40)?;

            println!("{:-^cols$}", " POTENTIAL INSTRUCTIONS ".blue());
            print_instructions!(virt_addr, cr3, translate.instrs);
        }
        cmdline::ProjectSubCommand::WriteBp(translate) => {
            // Get the virtual address and cr3 from the command line
            let virt_addr = crate::utils::parse_cli_symbol(&translate.virt_addr, &symbols)?;
            let curr_cr3 = translate.cr3.unwrap_or(VirtAddr(project_state.vbcpu.cr3)).0;
            let cr3 = Cr3(curr_cr3 & !0xfff);
            let patches_key = format!("{:#x}_{:#x}", virt_addr.0, cr3.0);

            // Init the array to read the instruction bytes into
            let mut old_bytes = vec![0u8; 0x10];
            memory
                .read_bytes(virt_addr, cr3, &mut old_bytes)
                .context("Failed to read bytes")?;

            log::info!("{:#x}: Bytes before: {:x?}", virt_addr.0, old_bytes);

            // Write a breakpoint to the given virtual address
            memory.write(virt_addr, cr3, [0xcc_u8], WriteMem::NotDirty)?;

            // Init the array to read the instruction bytes into
            let mut new_bytes = vec![0u8; 0x10];
            memory
                .read_bytes(virt_addr, cr3, &mut new_bytes)
                .context("Failed to read bytes")?;

            log::info!("{:#x}: Bytes  after: {:x?}", virt_addr.0, new_bytes);

            let symbol = if let Some(sym_data) = &symbols {
                symbols::get_symbol(virt_addr.0, sym_data)
            } else {
                None
            };

            // Only add if we actually modified memory
            let mut should_add = old_bytes != new_bytes;

            if let Some(MemoryPatch { bytes_before, .. }) = patches.get(&patches_key) {
                // Keep using the original old bytes
                old_bytes = bytes_before.clone();

                if new_bytes == *bytes_before {
                    log::info!("Reverted a previous patch.. removing this patch");
                    patches.remove(&patches_key);
                    should_add = false;
                }
            }

            // Add this patch to the patches file
            if should_add {
                patches.insert(
                    patches_key,
                    MemoryPatch {
                        symbol,
                        bytes_before: old_bytes,
                        bytes_after: new_bytes,
                    },
                );
            }
        }

        cmdline::ProjectSubCommand::WriteMem(translate) => {
            // Get the virtual addrekss and cr3 from the command line
            let virt_addr = crate::utils::parse_cli_symbol(&translate.virt_addr, &symbols)?;

            let curr_cr3 = translate.cr3.unwrap_or(VirtAddr(project_state.vbcpu.cr3)).0;
            let cr3 = Cr3(curr_cr3 & !0xfff);
            let bytes: Vec<u8> = cmdline::parse_hex_bytes(&translate.bytes)?;
            let patches_key = format!("{:#x}_{:#x}", virt_addr.0, cr3.0);

            log::info!("{:x?}", translate);
            log::info!("{:x?}", virt_addr);

            // Init the array to read the instruction bytes into
            let mut old_bytes = vec![0u8; bytes.len()];
            memory
                .read_bytes(virt_addr, cr3, &mut old_bytes)
                .context("Failed to read bytes")?;

            println!("{:-^cols$}", " BYTES BEFORE ".blue());
            utils::hexdump(&old_bytes, virt_addr.0);

            println!(
                "{:-^cols$}",
                " POTENTIAL INSTRUCTIONS BEFORE ".blue(),
                cols = cols
            );
            print_instructions!(virt_addr, cr3, 5);

            println!();
            log::info!(
                "Writing {len} ({len:#x}) bytes to {:#x} {:#x}",
                virt_addr.0,
                cr3.0,
                len = bytes.len()
            );

            // Write a breakpoint to the given virtual address
            memory.write_bytes(virt_addr, cr3, &bytes)?;

            println!();

            // Init the array to read the instruction bytes into
            let mut new_bytes = vec![0u8; bytes.len()];
            memory
                .read_bytes(virt_addr, cr3, &mut new_bytes)
                .context("Failed to read bytes")?;

            println!("{:-^cols$}", " BYTES AFTER ".blue());
            utils::hexdump(&new_bytes, virt_addr.0);

            println!(
                "{:-^cols$}",
                " POTENTIAL INSTRUCTIONS AFTER ".blue(),
                cols = cols
            );
            print_instructions!(virt_addr, cr3, 20);

            let symbol = if let Some(sym_data) = &symbols {
                symbols::get_symbol(virt_addr.0, sym_data)
            } else {
                None
            };

            // Only add if we actually modified memory
            let mut should_add = old_bytes != new_bytes;

            if let Some(MemoryPatch { bytes_before, .. }) = patches.get(&patches_key) {
                // Keep using the original old bytes
                old_bytes = bytes_before.clone();

                if new_bytes == *bytes_before {
                    log::info!("Reverted a previous patch.. removing this patch");
                    patches.remove(&patches_key);
                    should_add = false;
                }
            }

            // Add this patch to the patches file
            if should_add {
                patches.insert(
                    patches_key,
                    MemoryPatch {
                        symbol,
                        bytes_before: old_bytes,
                        bytes_after: new_bytes,
                    },
                );
            }
        }
        cmdline::ProjectSubCommand::WriteDebugInfoJson => {
            log::info!("loading debug info from available binaries");
            let debug_info = crate::stats::DebugInfo::new(project_state)?;
            log::info!(
                "loaded debug info with {} debug locations based on {} coverage breakpoints",
                debug_info.len(),
                project_state
                    .coverage_basic_blocks
                    .as_ref()
                    .and_then(|covbps| Some(covbps.len()))
                    .unwrap_or(0_usize)
            );
            let filepath = project_state.path.join("debug_info.json");
            std::fs::write(&filepath, serde_json::to_string(&debug_info)?)
                .expect("Failed to write debug_info json");
            log::info!("wrote debug info to {}", filepath.display());
        }
        cmdline::ProjectSubCommand::Symbols | cmdline::ProjectSubCommand::InitConfig => {
            unreachable!()
        }

        cmdline::ProjectSubCommand::Cr3 => {
            use simd_json::prelude::*;

            let file = "/home/user/workspace/dwarf2json/Linux670.json";

            let mut data = std::fs::read_to_string(file).unwrap();
            let json: simd_json::BorrowedValue = unsafe { simd_json::from_str(&mut data).unwrap() };

            #[derive(Debug)]
            struct StructField {
                offset: i64,
                type_name: Option<String>,
            }

            // Parse a struct type from the `user_types` from the dwarf2json output
            fn get_struct(
                name: &str,
                json: &simd_json::BorrowedValue,
            ) -> HashMap<String, StructField> {
                let mut results = HashMap::new();

                let obj = json.get_object("user_types").unwrap();

                let task_struct = obj.get(name).unwrap().try_as_object().unwrap();
                // dbg!(task_struct);

                let fields = task_struct.get("fields");
                let fields = fields.try_as_object().unwrap();

                for (index, val) in fields.values().enumerate() {
                    // dbg!(val);
                    if let Ok(offset) = val.get("offset").unwrap().try_as_i64() {
                        let type_ = val.get("type").unwrap().try_as_object().unwrap();

                        let kind = type_.get("kind").unwrap().try_as_str().unwrap();
                        let type_name = type_
                            .get("name")
                            .and_then(|x| Some(x.try_as_str().unwrap().to_string()));

                        // dbg!(kind);

                        let field = StructField { offset, type_name };

                        let name = fields.keys().nth(index).unwrap().to_string();
                        // offset_to_name.push(offset, (name, kind));

                        results.insert(name, field);
                    }
                }

                results
            }

            // Get the `task_struct` struct
            let task_struct = get_struct("task_struct", &json);

            // Get the struct offset of `task_struct.tasks`
            dbg!(task_struct.get("tasks").unwrap());
            let tasks_offset = task_struct.get("tasks").unwrap().offset;

            // Get the struct offset of `task_struct.mm`
            let mm_offset = task_struct.get("mm").unwrap().offset;
            let mm_struct = get_struct("mm_struct", &json);
            dbg!(&mm_struct);

            // Get the struct offset of `task_struct.mm`
            let unnamed_field_0 = mm_struct.get("unnamed_field_0");
            dbg!(unnamed_field_0);
            let unnamed_struct = unnamed_field_0.unwrap().type_name.as_ref().unwrap();

            let mm_struct = get_struct(&unnamed_struct, &json);
            let pgd_offset = mm_struct.get("pgd").unwrap().offset;
            dbg!(pgd_offset);

            let comm_offset = task_struct.get("comm").unwrap().offset;
            dbg!(comm_offset);

            let mut init_task = 0;
            for Symbol { address, symbol } in symbols.as_ref().unwrap() {
                if symbol != "init_task" {
                    continue;
                }

                init_task = *address;
                break;
            }

            dbg!(init_task);

            let cr3 = project_state.vbcpu.cr3;

            println!("INIT TASK");
            let mut task_base = init_task;

            let mut cr3s = Vec::new();

            for i in 0.. {
                println!("Task {i} base");
                memory.hexdump(VirtAddr(task_base), Cr3(cr3), 0x40)?;

                println!("Task {i}: .mm (+{mm_offset})");
                memory.hexdump(
                    VirtAddr(task_base.wrapping_add_signed(mm_offset)),
                    Cr3(cr3),
                    0x10,
                )?;

                println!("Task {i}: .comm (+{comm_offset})");
                let name = memory.read::<[u8; 16]>(
                    VirtAddr(task_base.wrapping_add_signed(comm_offset)),
                    Cr3(cr3),
                )?;

                let name = name
                    .iter()
                    .take_while(|x| **x != 0)
                    .map(|x| *x as char)
                    .collect::<String>();

                memory.hexdump(
                    VirtAddr(task_base.wrapping_add_signed(comm_offset)),
                    Cr3(cr3),
                    0x20,
                )?;

                let mm_addr = memory
                    .read::<u64>(VirtAddr(task_base.wrapping_add_signed(mm_offset)), Cr3(cr3))?;
                if mm_addr > 0 {
                    let page_table_ptr = mm_addr.wrapping_add_signed(pgd_offset);
                    memory.hexdump(VirtAddr(mm_addr), Cr3(cr3), 0x90)?;

                    let page_table = memory
                        .read::<u64>(VirtAddr(page_table_ptr), Cr3(cr3))
                        .unwrap();

                    if let Some(cr3) = memory.translate(VirtAddr(page_table), Cr3(cr3)).phys_addr {
                        println!("CR3: {page_table:x?}");
                        cr3s.push((name.to_string(), cr3))
                    }
                }

                println!("Task {i}: .tasks (+{tasks_offset})");
                memory.hexdump(
                    VirtAddr(task_base.wrapping_add_signed(tasks_offset)),
                    Cr3(cr3),
                    0x20,
                )?;

                println!("Goto next task..");
                task_base = memory
                    .read::<u64>(
                        VirtAddr(task_base.wrapping_add_signed(tasks_offset)),
                        Cr3(cr3),
                    )
                    .unwrap();

                // Go back to the base of the struct
                task_base -= tasks_offset as u64;

                if task_base == init_task {
                    println!("FOUND END");
                    break;
                }
            }

            for cr3 in cr3s {
                println!("{cr3:x?}");
            }
        }
    }

    // Re-write the patches
    std::fs::write(&patches_file, serde_json::to_string(&patches)?)?;

    Ok(())
}
