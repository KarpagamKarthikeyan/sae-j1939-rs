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
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use sae_j1939_host::ecu::Ecu;
    use sae_j1939_host::sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
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

    // The bus type is inferred as SocketCan; 1785-byte messages from up to
    // eight peers at once.
    let mut ecu = Ecu::<_, 1785, 8>::open(&interface, name, Address::new(0x80))?;
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

    // The faults this ECU reports if asked. Three codes exceed one frame, so
    // answering takes a BAM — which `broadcast` handles, pacing included.
    let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
    let faults = [
        Dtc::new(100, 1, 2).unwrap(),
        Dtc::new(110, 0, 5).unwrap(),
        Dtc::new(1569, 31, 126).unwrap(),
    ];
    let mut dm1 = [0u8; 64];
    let dm1_len = diagnostics::encode(lamps, &faults, &mut dm1).unwrap();

    loop {
        // `poll` returns None on a quiet bus, not at end-of-stream.
        let Some(message) = ecu.poll()? else {
            continue;
        };

        println!(
            "{:#08x} from {:#04x}: {} bytes",
            message.pgn.as_u32(),
            message.source.as_u8(),
            message.data.len()
        );

        // Answer a request for our active trouble codes.
        if message.pgn == pgn::REQUEST {
            if let Ok(request) = Request::decode(&message.data) {
                if request.pgn == pgn::DM1 {
                    ecu.broadcast(pgn::DM1, &dm1[..dm1_len])?;
                    println!("  -> reported {} active faults over a BAM", faults.len());
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example needs SocketCAN, which is Linux-only.");
}
