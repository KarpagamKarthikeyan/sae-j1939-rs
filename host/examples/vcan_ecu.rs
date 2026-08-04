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
    use sae_j1939_host::ecu::SocketCanEcu;
    use sae_j1939_host::sae_j1939_rs::diagnostics::Lamp;
    use sae_j1939_host::sae_j1939_rs::request::Request;
    use sae_j1939_host::sae_j1939_rs::{name::industry_group, pgn, Address, Name};

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

    let mut reported_healthy = false;

    loop {
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example needs SocketCAN, which is Linux-only.");
}
