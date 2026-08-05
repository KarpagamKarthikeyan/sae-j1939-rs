// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A complete virtual ECU: claims an address, answers requests, reassembles
//! multi-packet traffic, and reports its own faults.
//!
//! This is the whole stack running on a real bus. `Ecu` does the protocol work
//! — address claiming, the receive filter, transport-protocol reassembly, the
//! CTS/acknowledgement handshake, BAM pacing, and the clock — so what is left
//! here is just the application: decide what to answer, and answer it.
//!
//! ```text
//! sudo tools/vcan_setup.sh                              # bring up vcan0
//! cargo run -p sae-j1939-host --example vcan_ecu
//!
//! # in another terminal, ask who is on the bus:
//! cansend vcan0 18EAFFF9#00EE00
//!
//! # ...or ask this ECU for its active faults:
//! cansend vcan0 18EA80F9#CAFE00
//!
//! # ...or read them properly, with the service tool:
//! cargo run -p sae-j1939-host --example service_tool -- --target 0x80
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::time::{Duration, Instant};

    use sae_j1939_host::ecu::SocketCanEcu;
    use sae_j1939_host::sae_j1939_rs::diagnostics::Lamp;
    use sae_j1939_host::sae_j1939_rs::request::Request;
    use sae_j1939_host::sae_j1939_rs::{name::industry_group, pgn, Address, Name, Priority};

    let interface = std::env::args().nth(1).unwrap_or_else(|| "vcan0".into());

    // Who this ECU says it is.
    let name = Name::new()
        .with_identity_number(4242)
        .with_manufacturer_code(300)
        .with_function(0x87) // vehicle dynamic stability control module
        .with_industry_group(industry_group::ON_HIGHWAY)
        .with_arbitrary_address_capable(true);

    // `SocketCanEcu` is `Ecu<SocketCan, 1785, 8>` — a host-sized node on a
    // Linux interface.
    let mut ecu = SocketCanEcu::open(&interface, name, Address::new(0x80))?;
    println!(
        "claiming address {:#04x} on {interface}",
        ecu.address().as_u8()
    );

    // Blocks for the 250 ms contention window, handling anything that arrives.
    ecu.claim_address()?;
    if !ecu.has_address() {
        println!("lost arbitration; this ECU is off the bus");
        return Ok(());
    }
    println!("address {:#04x} held", ecu.address().as_u8());
    println!("listening. Try:  cansend {interface} 18EA80F9#CAFE00");

    // Three things wrong with this ECU. From here on it broadcasts a DM1 once a
    // second naming them, answers a request for DM1 or DM2, and honours a DM11
    // or DM3 clear — all inside `poll`. Three codes exceed one frame, so the
    // DM1 goes out over the transport protocol, paced as J1939-21 requires.
    ecu.set_fault(100, 1, Lamp::RedStop)?; // oil pressure low
    ecu.set_fault(110, 0, Lamp::AmberWarning)?; // coolant temperature high
    ecu.set_fault(1569, 31, Lamp::Protect)?; // engine protection derate
    println!(
        "reporting {} active faults; a tool can read them with a DM1 request",
        ecu.faults().active().len()
    );

    // What a running engine controller actually puts on the bus: parameter
    // groups broadcast on a schedule, whether or not anyone asked. `poll` sends
    // them, so the loop below stays a loop over `poll`.
    ecu.broadcast_every(pgn::EEC1, &engine_speed(1500.0), Duration::from_millis(50))?;
    // Engine speed is a control input, so it should win arbitration against
    // diagnostics: priority 3 rather than the default 6. On the bus that is the
    // difference between identifier 0x0CF00480 and 0x18F00480.
    ecu.set_periodic_priority(pgn::EEC1, Address::GLOBAL, Priority::new(3).expect("0..=7"))?;
    ecu.broadcast_every(
        pgn::ENGINE_TEMPERATURE_1,
        &coolant_temperature(80),
        Duration::from_secs(1),
    )?;
    println!(
        "broadcasting {} parameter groups on a schedule",
        ecu.periodic().count()
    );
    // Every network in a DM13 defaults to "do not care" (0b11), so an all-0xFF
    // payload commands nothing; clearing the low two bits says "stop" to the
    // data link the message arrived on.
    println!("quieten this with DM13:  cansend {interface} 18DFFFF9#FCFFFFFFFFFFFFFF");
    println!("...and start it again:   cansend {interface} 18DFFFF9#FDFFFFFFFFFFFFFF");

    let mut reported_healthy = false;
    let mut suspended = false;
    let mut rpm = 1500.0f32;
    let mut next_update = Instant::now();

    loop {
        // A real control loop recomputes its published values. The rate is set
        // once; only the value changes.
        if Instant::now() >= next_update {
            next_update = Instant::now() + Duration::from_millis(100);
            rpm = if rpm >= 1800.0 { 1200.0 } else { rpm + 25.0 };
            ecu.update_periodic(pgn::EEC1, &engine_speed(rpm))?;
        }

        if ecu.broadcasts_suspended() != suspended {
            suspended = ecu.broadcasts_suspended();
            println!(
                "  -> broadcasts {}",
                if suspended {
                    "stopped by DM13 (they resume on their own if nobody renews it)"
                } else {
                    "running again"
                }
            );
        }

        // `poll` returns None on a quiet bus, not at end-of-stream.
        let Some(message) = ecu.poll()? else {
            // A tool may have cleared the codes while we were not looking.
            if ecu.faults().is_healthy() && !reported_healthy {
                reported_healthy = true;
                println!("  -> a tool cleared the active codes");
            }
            continue;
        };

        println!(
            "{:#08x} from {:#04x}: {} bytes",
            message.pgn.as_u32(),
            message.source.as_u8(),
            message.data.len()
        );

        // Requests for the diagnostic groups have already been answered by the
        // time this returns; anything else is the application's to decide about.
        if message.pgn == pgn::REQUEST {
            if let Ok(request) = Request::decode(&message.data) {
                println!("  request for {:#08x}", request.pgn.as_u32());
            }
        }
    }
}

/// Build an EEC1 payload carrying an engine speed.
///
/// SPN 190 is a 16-bit little-endian field at byte 4, scaled 0.125 rpm per
/// count — the same definition `spn::catalogue::ENGINE_SPEED` decodes with, so
/// a receiver reads back exactly what went in. Everything else is `0xFF`, which
/// is J1939 for "not available" rather than for zero.
#[cfg(target_os = "linux")]
fn engine_speed(rpm: f32) -> [u8; 8] {
    let raw = (rpm / 0.125) as u16;
    let mut payload = [0xFFu8; 8];
    payload[3] = raw as u8;
    payload[4] = (raw >> 8) as u8;
    payload
}

/// Build an ET1 payload carrying a coolant temperature.
///
/// SPN 110 is one byte at byte 1, offset -40 °C.
#[cfg(target_os = "linux")]
fn coolant_temperature(celsius: i16) -> [u8; 8] {
    let mut payload = [0xFFu8; 8];
    payload[0] = (celsius + 40).clamp(0, 250) as u8;
    payload
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example needs SocketCAN, which is Linux-only.");
}
