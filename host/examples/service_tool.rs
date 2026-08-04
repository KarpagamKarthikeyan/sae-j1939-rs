// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A diagnostic tool: find what is on the bus, and ask it what is wrong.
//!
//! The other half of `vcan_ecu`. That example is an ECU that *has* faults; this
//! one is the tool a technician plugs in to read them.
//!
//! ```text
//! sudo tools/vcan_setup.sh                                  # bring up vcan0
//! cargo run -p sae-j1939-host --example vcan_ecu            # in one terminal
//! cargo run -p sae-j1939-host --example service_tool        # in another
//! ```
//!
//! With no `--target` it scans the bus and reports every ECU it finds. Given
//! one, it reads that ECU's readiness, active faults, fault history, and
//! software version:
//!
//! ```text
//! cargo run -p sae-j1939-host --example service_tool -- --target 0x80
//! ```
//!
//! `--clear` then asks the ECU to reset its codes. That is a deliberate,
//! separate step: an active code is a fault happening *now*, and clearing it
//! destroys the evidence without fixing anything. Read first.
//!
//! # What the tool has to do for itself
//!
//! Almost nothing. `Ecu` claims an address, sends the requests, waits out the
//! timeouts, reassembles the multi-packet answers, and decodes them. What is
//! left here is argument parsing and printing.

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::time::Duration;

    use sae_j1939_host::ecu::{SocketCanEcu, DIAGNOSTIC_TIMEOUT};
    use sae_j1939_host::sae_j1939_rs::diagnostics::{Lamp, LampStatus};
    use sae_j1939_host::sae_j1939_rs::{name::industry_group, Address, Name};

    let mut interface = String::from("vcan0");
    let mut target: Option<Address> = None;
    let mut clear = false;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" | "-t" => {
                let text = args
                    .next()
                    .ok_or_else(|| invalid("--target needs an address"))?;
                let raw = parse_address(&text)?;
                target = Some(Address::new(raw));
            }
            "--clear" => clear = true,
            "--help" | "-h" => {
                println!("usage: service_tool [interface] [--target 0x80] [--clear]");
                return Ok(());
            }
            other => interface = other.to_string(),
        }
    }

    // 0xF9 is the address conventionally reserved for an off-board diagnostic
    // tool, which is what this is.
    let name = Name::new()
        .with_identity_number(1)
        .with_manufacturer_code(300)
        .with_function(0x81) // off-board diagnostic service tool
        .with_industry_group(industry_group::ON_HIGHWAY)
        .with_arbitrary_address_capable(true);

    let mut tool = SocketCanEcu::open(&interface, name, Address::new(0xF9))?;
    tool.claim_address()?;
    if !tool.has_address() {
        eprintln!("could not claim an address on {interface}; is 0xF9 taken?");
        return Ok(());
    }
    println!("tool at {} on {interface}\n", tool.address());

    // ---- Who is out there? ----------------------------------------------
    let found = tool.scan(Duration::from_secs(1))?;
    if found.is_empty() {
        println!("no ECUs answered. Is anything transmitting on {interface}?");
        return Ok(());
    }
    println!("{} ECU(s) on the bus:", found.len());
    for (address, name) in &found {
        println!("  {address}  {name}");
    }

    let Some(target) = target else {
        println!("\npass --target <address> to interrogate one of them");
        return Ok(());
    };
    println!("\n--- {target} ---");

    // ---- What does it say about itself? ----------------------------------
    match tool.read_software_identification(target, DIAGNOSTIC_TIMEOUT)? {
        Some(fields) if !fields.is_empty() => println!("software: {}", fields.join(", ")),
        Some(_) => println!("software: reported, but with no fields"),
        None => println!("software: no answer"),
    }

    // Readiness first: it says how many faults to expect, so a mismatch with
    // the DM1 below is itself informative.
    match tool.read_readiness(target, DIAGNOSTIC_TIMEOUT)? {
        Some(readiness) => println!(
            "readiness: {} active, {} previously active",
            readiness.active_faults, readiness.previously_active_faults
        ),
        None => println!("readiness: no answer (DM5 is emissions-related and often unsupported)"),
    }

    // ---- What is wrong with it? ------------------------------------------
    match tool.read_active_faults(target, DIAGNOSTIC_TIMEOUT)? {
        Some(report) if report.is_healthy() => println!("\nactive faults: none"),
        Some(report) => {
            let lit: Vec<&str> = Lamp::ALL
                .iter()
                .filter(|&&lamp| report.lamps.status(lamp) == LampStatus::On)
                .map(lamp_name)
                .collect();
            println!(
                "\nactive faults: {} — lamps: {}",
                report.dtcs.len(),
                if lit.is_empty() {
                    String::from("none lit")
                } else {
                    lit.join(", ")
                }
            );
            for dtc in &report.dtcs {
                println!("  {dtc}");
            }
        }
        None => println!("\nactive faults: no answer"),
    }

    match tool.read_previously_active_faults(target, DIAGNOSTIC_TIMEOUT)? {
        Some(report) if report.is_healthy() => println!("fault history: empty"),
        Some(report) => {
            println!("fault history: {}", report.dtcs.len());
            for dtc in &report.dtcs {
                println!("  {dtc}");
            }
        }
        None => println!("fault history: no answer"),
    }

    // ---- Clear, only if asked --------------------------------------------
    if clear {
        println!("\nclearing...");
        // History first. Clearing the active codes may immediately re-detect
        // the fault, and doing history afterwards would erase that fresh entry.
        report_clear(
            "fault history (DM3)",
            tool.clear_previously_active_faults(target, DIAGNOSTIC_TIMEOUT),
        );
        report_clear(
            "active codes (DM11)",
            tool.clear_active_faults(target, DIAGNOSTIC_TIMEOUT),
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn report_clear(what: &str, outcome: std::io::Result<bool>) {
    match outcome {
        Ok(true) => println!("  {what}: cleared"),
        Ok(false) => println!("  {what}: no answer"),
        Err(error) => println!("  {what}: refused — {error}"),
    }
}

#[cfg(target_os = "linux")]
fn lamp_name(lamp: &sae_j1939_host::sae_j1939_rs::diagnostics::Lamp) -> &'static str {
    use sae_j1939_host::sae_j1939_rs::diagnostics::Lamp;
    match lamp {
        Lamp::MalfunctionIndicator => "malfunction indicator",
        Lamp::RedStop => "red stop",
        Lamp::AmberWarning => "amber warning",
        Lamp::Protect => "protect",
    }
}

#[cfg(target_os = "linux")]
fn parse_address(text: &str) -> std::io::Result<u8> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| invalid(&format!("{text} is not an address in 0..=255")))
}

#[cfg(target_os = "linux")]
fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.to_string())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example needs SocketCAN, which is Linux-only.");
    eprintln!("On any platform, `--example replay` reads a candump capture instead.");
}
