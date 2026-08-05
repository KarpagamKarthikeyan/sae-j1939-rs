// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decode a `candump` capture offline.
//!
//! Capture once on the vehicle, then analyse it anywhere — no CAN interface, no
//! Linux, no hardware:
//!
//! ```text
//! candump -l can0                              # on the vehicle
//! cargo run -p sae-j1939-host --example replay -- candump-2026-08-02_120000.log
//! ```
//!
//! Multi-packet transfers are reassembled, engine parameters are decoded into
//! engineering units, and trouble codes are read out. Pass `--address` to
//! reconstruct a particular ECU's view of the bus, since a node only sees
//! broadcasts and traffic addressed to it.
//!
//! This is also how to check the crate against real traffic. Three modules —
//! the extended transport protocol, working sets, and the task controller — are
//! built from the specification with no reference implementation to compare
//! against. If your capture contains any of them and this reports something you
//! do not recognise, that is worth an issue.

use std::collections::BTreeMap;

use sae_j1939_host::log::{self, Replay};
use sae_j1939_host::sae_j1939_rs::diagnostics::{
    is_dtc_list, Dm5 as Readiness, Lamp, LampStatus, Message as Diagnostic,
};
use sae_j1939_host::sae_j1939_rs::iso11783::task_controller::{Command, ProcessData, PROCESS_DATA};
use sae_j1939_host::sae_j1939_rs::iso11783::working_set::{WorkingSetMaster, WORKING_SET_MASTER};
use sae_j1939_host::sae_j1939_rs::spn::{catalogue, SpnValue};
use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut path = None;
    let mut address = Address::new(0xF9); // the usual service-tool address

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--address" | "-a" => {
                let text = args.next().ok_or("--address needs a value")?;
                let raw = text
                    .strip_prefix("0x")
                    .map(|hex| u8::from_str_radix(hex, 16))
                    .unwrap_or_else(|| text.parse())?;
                address = Address::new(raw);
            }
            "--help" | "-h" => {
                println!("usage: replay [--address 0xF9] <candump.log>");
                return Ok(());
            }
            other => path = Some(other.to_string()),
        }
    }

    let Some(path) = path else {
        eprintln!("usage: replay [--address 0xF9] <candump.log>");
        eprintln!("capture one first with:  candump -l can0");
        std::process::exit(2);
    };

    let entries = log::from_file(&path)?;
    println!(
        "{path}: {} J1939 frames, replayed as ECU {address}\n",
        entries.len()
    );

    let name = Name::new()
        .with_manufacturer_code(300)
        .with_identity_number(1);
    let mut replay = Replay::new(name, address);

    // A capture is worth summarising as well as listing: which ECUs spoke, and
    // which parameter groups they used.
    let mut senders: BTreeMap<u8, usize> = BTreeMap::new();
    let mut groups: BTreeMap<u32, usize> = BTreeMap::new();
    let mut messages = 0;

    for entry in &entries {
        let Some(message) = replay.feed(entry) else {
            continue;
        };
        messages += 1;
        *senders.entry(message.source.as_u8()).or_default() += 1;
        *groups.entry(message.pgn.as_u32()).or_default() += 1;

        println!(
            "[{:.3}] {:#08x} from {} ({} bytes)",
            entry.timestamp,
            message.pgn.as_u32(),
            message.source,
            message.data.len()
        );

        if message.pgn == pgn::ADDRESS_CLAIMED && message.data.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&message.data[..8]);
            println!("    {}", Name::from_bytes(&bytes));
        } else if message.pgn == pgn::DM5 && message.data.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&message.data[..8]);
            let readiness = Readiness::decode(&bytes);
            println!(
                "    {} active, {} previously active faults",
                readiness.active_faults, readiness.previously_active_faults
            );
        } else if is_dtc_list(message.pgn) {
            if let Ok(dm) = Diagnostic::parse(&message.data) {
                let lit: Vec<&str> = Lamp::ALL
                    .iter()
                    .filter(|&&lamp| dm.lamps().status(lamp) == LampStatus::On)
                    .map(|lamp| match lamp {
                        Lamp::MalfunctionIndicator => "MIL",
                        Lamp::RedStop => "red-stop",
                        Lamp::AmberWarning => "amber-warning",
                        Lamp::Protect => "protect",
                    })
                    .collect();
                if !lit.is_empty() {
                    println!("    lamps: {}", lit.join(", "));
                }
                for dtc in dm.dtcs().filter(|d| !d.is_no_fault()) {
                    println!("    {dtc}");
                }
            }
        } else if message.pgn == WORKING_SET_MASTER && message.data.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&message.data[..8]);
            if let Ok(master) = WorkingSetMaster::decode(&bytes) {
                println!("    working set of {} ECUs", master.members);
            }
        } else if message.pgn == PROCESS_DATA && message.data.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&message.data[..8]);
            let pd = ProcessData::decode(&bytes);
            println!(
                "    element {} {} = {}{}",
                pd.element,
                pd.ddi,
                pd.value,
                if pd.command == Command::RequestValue {
                    "  (a request)"
                } else {
                    ""
                }
            );
        } else {
            // What the crate knows how to read out of this group. The mapping
            // lives in the catalogue, not here — a decoder that keeps its own
            // copy is a decoder that drifts from the definitions it decodes with.
            for spn in catalogue::for_pgn(message.pgn) {
                match spn.decode(&message.data) {
                    Ok(SpnValue::Valid(value)) => {
                        println!("    {} = {value:.2} {}", spn.name, spn.unit)
                    }
                    Ok(SpnValue::NotAvailable) => println!("    {}: not available", spn.name),
                    Ok(SpnValue::Error) => println!("    {}: ERROR reported", spn.name),
                    Ok(SpnValue::Reserved) => println!("    {}: reserved", spn.name),
                    Err(_) => {}
                }
            }
        }
    }

    println!("\n--- summary ---");

    // The bus inventory: who claimed an address, and what they said they are.
    // Claims are network management, so they never appear as messages.
    let inventory: Vec<_> = replay.claimed_addresses().collect();
    if inventory.is_empty() {
        println!("no address claims in this capture");
    } else {
        println!("{} ECUs claimed an address:", inventory.len());
        for (address, name) in inventory {
            println!("  {address}  {name}");
        }
    }

    println!("{messages} complete messages from {} ECUs", senders.len());
    for (address, count) in &senders {
        println!("  {:#04X}: {count} messages", address);
    }
    println!("parameter groups seen:");
    for (group, count) in &groups {
        println!("  {group:#08x}: {count}");
    }
    if !replay.transmitted().is_empty() {
        println!(
            "this ECU would have transmitted {} frames in response",
            replay.transmitted().len()
        );
    }

    Ok(())
}
