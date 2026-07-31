// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A complete virtual ECU: claims an address, answers requests, reassembles
//! multi-packet traffic, and reports its own faults.
//!
//! This is the whole stack running on a real bus. `Node` does the protocol
//! work — address claiming, the receive filter, transport-protocol reassembly,
//! and the CTS/acknowledgement handshake — so this file is mostly I/O.
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
    use std::time::{Duration, Instant};

    use sae_j1939_host::sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
    use sae_j1939_host::sae_j1939_rs::node::{Event, Node, ADDRESS_CLAIM_WINDOW_MS};
    use sae_j1939_host::sae_j1939_rs::request::Request;
    use sae_j1939_host::sae_j1939_rs::tp::Transmitter;
    use sae_j1939_host::sae_j1939_rs::{name::industry_group, pgn, Address, Frame, Name};
    use sae_j1939_host::transport::SocketCan;

    let interface = std::env::args().nth(1).unwrap_or_else(|| "vcan0".into());

    // Who this ECU says it is.
    let name = Name::new()
        .with_identity_number(4242)
        .with_manufacturer_code(300)
        .with_function(0x87) // vehicle dynamic stability control module
        .with_industry_group(industry_group::ON_HIGHWAY)
        .with_arbitrary_address_capable(true);

    // Accept messages up to 1785 bytes from up to four peers at once.
    let mut node = Node::<1785, 4>::new(name, Address::new(0x80));

    let bus = SocketCan::open(&interface)?;
    bus.set_read_timeout(Duration::from_millis(50))?;

    // Announce ourselves.
    let claim = node.start();
    bus.send_frame(&claim)?;
    println!(
        "claiming address {:#04x} on {interface}",
        node.address().as_u8()
    );

    // The faults this ECU would report if asked. Three codes exceed one frame,
    // so answering the request takes a BAM.
    let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
    let faults = [
        Dtc::new(100, 1, 2).unwrap(),
        Dtc::new(110, 0, 5).unwrap(),
        Dtc::new(1569, 31, 126).unwrap(),
    ];
    let mut dm1_payload = [0u8; 64];
    let dm1_len = diagnostics::encode(lamps, &faults, &mut dm1_payload).unwrap();

    let mut last_tick = Instant::now();
    let mut announced = false;

    loop {
        // Anything to send as a result of a frame, collected before the event's
        // borrow of `node` ends.
        let mut outgoing: Vec<Frame> = Vec::new();
        let mut send_dm1 = false;

        match bus.recv() {
            Ok(frame) => match node.on_frame(&frame) {
                Event::Idle => {}
                Event::Transmit(reply) => outgoing.push(reply),
                Event::Message {
                    pgn: group,
                    source,
                    data,
                    reply,
                } => {
                    outgoing.extend(reply);
                    println!(
                        "{:#08x} from {:#04x}: {} bytes",
                        group.as_u32(),
                        source.as_u8(),
                        data.len()
                    );
                    // Someone asking for our active trouble codes.
                    if group == pgn::REQUEST {
                        if let Ok(request) = Request::decode(data) {
                            if request.pgn == pgn::DM1 {
                                send_dm1 = true;
                            }
                        }
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        for frame in &outgoing {
            bus.send_frame(frame)?;
        }

        if send_dm1 {
            // Three codes do not fit one frame, so broadcast them over a BAM.
            // J1939-21 wants 50-200 ms between packets; that pacing is ours to
            // provide, since the state machine owns no clock.
            let mut tx = Transmitter::broadcast(pgn::DM1, &dm1_payload[..dm1_len]).unwrap();
            let source = node.address();
            bus.send_tp_cm(source, Address::GLOBAL, &tx.start())?;
            while let Some(packet) = tx.next_packet() {
                std::thread::sleep(Duration::from_millis(50));
                bus.send_tp_dt(source, Address::GLOBAL, &packet)?;
            }
            println!("  -> reported {} active faults over a BAM", faults.len());
        }

        // Advance the node's timers with however long the loop actually took.
        let elapsed = last_tick.elapsed();
        last_tick = Instant::now();
        let elapsed_ms = elapsed.as_millis().min(u16::MAX as u128) as u16;

        let mut timeouts: Vec<Frame> = Vec::new();
        node.tick(elapsed_ms, |frame| timeouts.push(frame));
        for frame in &timeouts {
            println!("  (a stalled transfer timed out; sending abort)");
            bus.send_frame(frame)?;
        }

        if !announced && node.has_address() {
            announced = true;
            println!(
                "address {:#04x} held after the {ADDRESS_CLAIM_WINDOW_MS} ms contention window",
                node.address().as_u8()
            );
            println!("listening. Try:  cansend {interface} 18EA80F9#CAFE00");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example needs SocketCAN, which is Linux-only.");
}
