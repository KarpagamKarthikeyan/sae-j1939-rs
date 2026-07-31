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
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::time::Duration;

    use sae_j1939_host::sae_j1939_rs::diagnostics::{
        Lamp, LampStatus, Message as DiagnosticMessage,
    };
    use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name};
    use sae_j1939_host::transport::SocketCan;

    let interface = std::env::args().nth(1).unwrap_or_else(|| "vcan0".into());
    let this_ecu = Address::new(0x80);

    let mut bus = SocketCan::open(&interface)?;
    bus.set_read_timeout(Duration::from_secs(5))?;
    println!("listening on {interface} as ECU {:#04x}", this_ecu.as_u8());

    // Ask every ECU on the bus to announce itself.
    bus.request(this_ecu, Address::GLOBAL, pgn::ADDRESS_CLAIMED)?;
    println!("sent a global request for the Address Claimed PGN\n");

    loop {
        let message = match bus.recv_message(this_ecu) {
            Ok(message) => message,
            // A read timeout is the expected end of a quiet bus, not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("(no traffic for 5s — exiting)");
                return Ok(());
            }
            Err(e) => return Err(e),
        };

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
