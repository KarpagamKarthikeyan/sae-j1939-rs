// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decode live J1939 traffic from a CAN interface, reassembling multi-packet
//! messages.
//!
//! Opens `vcan0` (override with the first argument, e.g. `can0`), broadcasts a
//! Request for the Address Claimed PGN so every ECU announces itself, then
//! prints each complete message. Transport-protocol transfers are reassembled,
//! so a 3-code DM1 spread over a BAM prints as one message, not four frames.
//! DM1/DM2 payloads are decoded into lamps and trouble codes.
//!
//! ```text
//! sudo tools/vcan_setup.sh                              # bring up vcan0
//! cargo run -p sae-j1939-host --example vcan_dump
//!
//! # in another terminal, a single-frame DM1 with one trouble code:
//! cansend vcan0 18FECA80#04002B010483FFFF
//!
//! # ...or a 3-code DM1 as a BAM: announce 14 bytes in 2 packets, then push them
//! cansend vcan0 1CECFF80#200E0002FFCAFE00
//! cansend vcan0 1CEBFF80#0104002B01048364
//! cansend vcan0 1CEBFF80#0200018721061FFE
//!
//! # ...or an engine controller frame, decoded into rpm and percent:
//! cansend vcan0 0CF00400#FF8796E02EFFFFFF
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use sae_j1939_host::ecu::SocketCanEcu;
    use sae_j1939_host::sae_j1939_rs::diagnostics::{
        Lamp, LampStatus, Message as DiagnosticMessage,
    };
    use sae_j1939_host::sae_j1939_rs::spn::{catalogue, Spn, SpnValue};
    use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name, Pgn};

    /// The parameters this dumper knows how to read, grouped by the PGN that
    /// carries them. An SPN is only meaningful inside its own parameter group.
    const KNOWN: &[(u32, &[Spn])] = &[
        (
            0x00F004, // Electronic Engine Controller 1
            &[
                catalogue::ENGINE_SPEED,
                catalogue::ACTUAL_ENGINE_PERCENT_TORQUE,
                catalogue::DRIVERS_DEMAND_ENGINE_PERCENT_TORQUE,
            ],
        ),
        (
            0x00F003, // Electronic Engine Controller 2
            &[
                catalogue::ACCELERATOR_PEDAL_POSITION,
                catalogue::ENGINE_PERCENT_LOAD,
            ],
        ),
        (
            0x00FEEE, // Engine Temperature 1
            &[
                catalogue::ENGINE_COOLANT_TEMPERATURE,
                catalogue::ENGINE_FUEL_TEMPERATURE,
                catalogue::ENGINE_OIL_TEMPERATURE,
            ],
        ),
        (
            0x00FEEF, // Engine Fluid Level/Pressure 1
            &[catalogue::ENGINE_OIL_PRESSURE, catalogue::ENGINE_OIL_LEVEL],
        ),
        (0x00FEF2, &[catalogue::ENGINE_FUEL_RATE]),
        (0x00FEF1, &[catalogue::WHEEL_BASED_VEHICLE_SPEED]),
        (0x00FEF7, &[catalogue::BATTERY_POTENTIAL]),
    ];

    fn parameters_for(pgn: Pgn) -> &'static [Spn] {
        KNOWN
            .iter()
            .find(|(raw, _)| *raw == pgn.as_u32())
            .map(|(_, spns)| *spns)
            .unwrap_or(&[])
    }

    let interface = std::env::args().nth(1).unwrap_or_else(|| "vcan0".into());

    // A listener still needs an address of its own to request anything.
    let name = Name::new()
        .with_identity_number(1)
        .with_manufacturer_code(300)
        .with_arbitrary_address_capable(true);
    let mut ecu = SocketCanEcu::open(&interface, name, Address::new(0xF9))?;
    ecu.claim_address()?;
    if !ecu.has_address() {
        println!("could not claim an address on {interface}");
        return Ok(());
    }
    println!("listening on {interface} as {:#04x}", ecu.address().as_u8());

    // Ask every ECU on the bus to announce itself.
    ecu.request(Address::GLOBAL, pgn::ADDRESS_CLAIMED)?;
    println!("sent a global request for the Address Claimed PGN\n");

    let quiet_limit = 100; // ~5 s of empty polls
    let mut quiet = 0;

    loop {
        // `poll` returns None on a quiet bus, not at end-of-stream.
        let Some(message) = ecu.poll()? else {
            quiet += 1;
            if quiet >= quiet_limit {
                println!("(no traffic for a while — exiting)");
                return Ok(());
            }
            continue;
        };
        quiet = 0;

        println!(
            "PGN {:#08x} from {:#04x}  ({} bytes)  {:02X?}",
            message.pgn.as_u32(),
            message.source.as_u8(),
            message.data.len(),
            message.data,
        );

        // Decode the parameter groups we understand.
        if message.pgn == pgn::ADDRESS_CLAIMED && message.data.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&message.data[..8]);
            let name = Name::from_bytes(&bytes);
            println!(
                "    NAME: manufacturer {}, identity {}, function {:#04x}, industry group {}",
                name.manufacturer_code(),
                name.identity_number(),
                name.function(),
                name.industry_group(),
            );
        } else if !parameters_for(message.pgn).is_empty() {
            // A parameter group we can read: print each parameter in its unit,
            // and say plainly when a value is a status code, not a measurement.
            for spn in parameters_for(message.pgn) {
                match spn.decode(&message.data) {
                    Ok(SpnValue::Valid(value)) => {
                        println!("    {} = {value:.2} {}", spn.name, spn.unit)
                    }
                    Ok(SpnValue::NotAvailable) => println!("    {}: not available", spn.name),
                    Ok(SpnValue::Error) => println!("    {}: ERROR reported", spn.name),
                    Ok(SpnValue::Reserved) => println!("    {}: reserved value", spn.name),
                    Err(e) => println!("    {}: {e}", spn.name),
                }
            }
        } else if message.pgn == pgn::DM1 || message.pgn == pgn::DM2 {
            match DiagnosticMessage::parse(&message.data) {
                Ok(dm) => {
                    let lamps = dm.lamps();
                    let lit: Vec<&str> = Lamp::ALL
                        .iter()
                        .filter(|&&lamp| lamps.status(lamp) == LampStatus::On)
                        .map(|lamp| match lamp {
                            Lamp::MalfunctionIndicator => "MIL",
                            Lamp::RedStop => "red-stop",
                            Lamp::AmberWarning => "amber-warning",
                            Lamp::Protect => "protect",
                        })
                        .collect();
                    println!(
                        "    lamps: {}",
                        if lit.is_empty() {
                            "none lit".to_string()
                        } else {
                            lit.join(", ")
                        }
                    );
                    if dm.is_fault_free() {
                        println!("    no active trouble codes");
                    }
                    for dtc in dm.dtcs().filter(|dtc| !dtc.is_no_fault()) {
                        println!(
                            "    DTC: SPN {} FMI {} (seen {}x)",
                            dtc.spn, dtc.fmi, dtc.occurrence_count
                        );
                    }
                }
                Err(e) => println!("    (malformed diagnostic message: {e})"),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example needs SocketCAN, which is Linux-only.");
}
