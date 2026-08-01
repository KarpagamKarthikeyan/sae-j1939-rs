// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A J1939 ECU as it would be written for a microcontroller.
//!
//! This is the shape of a bare-metal main loop: no allocation, no `std`, fixed
//! buffers sized at compile time, and a CAN peripheral behind the
//! [`embedded_can`] traits. Copy the structure; replace [`MockCan`] with your
//! HAL's CAN type and the counter with your timer.
//!
//! Run it on a host to watch the logic work:
//!
//! ```text
//! cargo run -p sae-j1939-rs --example mcu_node
//! ```
//!
//! The example itself needs `std` only to print and to fake a bus. Everything
//! it calls is `no_std` and allocation-free, which the CI `no_std` job proves by
//! building the crate for `thumbv7em-none-eabihf`.
//!
//! # What a real MCU main loop adds
//!
//! - **A timer.** [`Node::tick`] takes elapsed milliseconds; here a counter
//!   stands in for `SysTick`.
//! - **Interrupt or polled receive.** Either works — `Node` is sans-I/O and does
//!   not care where a frame came from.
//! - **BAM pacing.** J1939-21 wants 50–200 ms between broadcast packets, which
//!   on an MCU means a timer, not a sleep.

use core::cell::RefCell;

use embedded_can::Id as CanId;

use sae_j1939_rs::can::{decode, encode};
use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
use sae_j1939_rs::node::{Event, Node, Outgoing, ADDRESS_CLAIM_WINDOW_MS};
use sae_j1939_rs::request::Request;
use sae_j1939_rs::{name::industry_group, pgn, Address, Frame, Name};

/// How much memory this ECU gives to reassembling one incoming message.
///
/// The whole point of the const parameter: a 1785-byte buffer is fine on a host
/// and absurd on a part with 16 KiB of RAM. A transfer larger than this is
/// refused with an abort rather than overrunning anything.
const MAX_MESSAGE: usize = 128;

/// How many peers may have a transfer in flight at once. Each costs
/// `MAX_MESSAGE` bytes.
const PEERS: usize = 2;

fn main() {
    // ---- Identity -------------------------------------------------------
    let name = Name::new()
        .with_identity_number(4242)
        .with_manufacturer_code(300)
        .with_function(0x87) // vehicle dynamic stability control module
        .with_industry_group(industry_group::ON_HIGHWAY)
        .with_arbitrary_address_capable(true);

    let mut node = Node::<MAX_MESSAGE, PEERS>::new(name, Address::new(0x80));
    let can = MockCan::default();

    // ---- Faults this ECU would report ------------------------------------
    // Built into a fixed buffer, no allocation. Three codes exceed one frame,
    // so answering a request for them takes the transport protocol.
    let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
    let faults = [
        Dtc::new(100, 1, 2).unwrap(),
        Dtc::new(110, 0, 5).unwrap(),
        Dtc::new(1569, 31, 126).unwrap(),
    ];
    let mut dm1 = [0u8; 32];
    let dm1_len = diagnostics::encode(lamps, &faults, &mut dm1).unwrap();

    // ---- Start up --------------------------------------------------------
    transmit(&can, &node.start());
    println!("claiming address {:#04x}", node.address().as_u8());

    // Stand-in for a SysTick counter. On real hardware this comes from a timer.
    let mut elapsed_ms: u16 = 0;
    let tick_ms: u16 = 10;

    // A scripted bus, so the example does something. On hardware these frames
    // arrive from the CAN peripheral.
    let mut asked = false;

    // ---- Main loop -------------------------------------------------------
    for _ in 0..64 {
        // 1. Drain the receive path.
        while let Some(frame) = receive(&can) {
            let mut answer_dm1 = false;

            match node.on_frame(&frame) {
                Event::Idle => {}
                Event::Transmit(reply) => transmit(&can, &reply),
                Event::Message {
                    pgn: group,
                    source,
                    data,
                    reply,
                } => {
                    if let Some(reply) = reply {
                        transmit(&can, &reply);
                    }
                    println!(
                        "  rx {:#08x} from {:#04x} ({} bytes)",
                        group.as_u32(),
                        source.as_u8(),
                        data.len()
                    );
                    if group == pgn::REQUEST {
                        if let Ok(request) = Request::decode(data) {
                            answer_dm1 = request.pgn == pgn::DM1;
                        }
                    }
                }
            }

            // 2. Application work, once the borrow of `node` has ended.
            if answer_dm1 && node.has_address() {
                broadcast_dm1(&can, node.address(), &dm1[..dm1_len]);
            }
        }

        // 3. Advance the protocol timers. Address claiming and transport
        //    protocol timeouts both hang off this.
        node.tick(tick_ms, |frame| transmit(&can, &frame));
        elapsed_ms = elapsed_ms.saturating_add(tick_ms);

        if node.has_address() && !asked {
            asked = true;
            println!(
                "address {:#04x} held after the {ADDRESS_CLAIM_WINDOW_MS} ms contention window",
                node.address().as_u8()
            );
            // Only now may this ECU be asked for anything: J1939-81 does not
            // allow transmitting from an address that has not been claimed.
            println!("\na diagnostic tool asks for our active trouble codes:");
            can.inject(request_frame(pgn::DM1, node.address(), Address::new(0xF9)));
        }
    }

    println!("\n{} frames transmitted", can.sent.borrow().len());
}

/// Broadcast a message, however many frames that takes.
///
/// `Outgoing` decides whether this fits one frame or needs the transport
/// protocol, and hands back frames either way — the caller never builds a TP.CM
/// or a TP.DT by hand.
fn broadcast_dm1(can: &MockCan, source: Address, payload: &[u8]) {
    let mut tx =
        Outgoing::new(pgn::DM1, source, Address::GLOBAL, payload).expect("a valid message size");

    println!(
        "  tx DM1 with 3 trouble codes in {} frames{}",
        tx.frame_count(),
        if tx.needs_pacing() { " (paced)" } else { "" }
    );

    while let Some(frame) = tx.next_frame() {
        transmit(can, &frame);
        // A BAM is not acknowledged, so J1939-21 paces it instead: wait 50-200 ms
        // here on hardware. `needs_pacing` is what tells you it is required.
        if tx.needs_pacing() {
            // delay_ms(50);
        }
    }
}

/// Build a Request frame, as another ECU on the bus would send it.
fn request_frame(requested: sae_j1939_rs::Pgn, to: Address, from: Address) -> Frame {
    use sae_j1939_rs::{Id, Priority};

    let id = Id::from_parts(Priority::DEFAULT, pgn::REQUEST, to, from).expect("PDU1");
    Frame::new(id, &Request::new(requested).encode()).expect("three bytes")
}

/// Hand a J1939 frame to the CAN peripheral.
fn transmit(can: &MockCan, frame: &Frame) {
    if let Some(raw) = encode::<MockFrame>(frame) {
        can.send(raw);
    }
}

/// Take the next J1939 frame from the CAN peripheral.
fn receive(can: &MockCan) -> Option<Frame> {
    decode(&can.recv()?)
}

// ---------------------------------------------------------------------------
// A stand-in for a HAL's CAN peripheral. Replace with your driver: anything
// implementing `embedded_can::Frame` works with `can::encode` / `can::decode`.
// ---------------------------------------------------------------------------

/// One CAN frame, as an `embedded-can` driver would model it.
#[derive(Debug, Clone, Copy)]
struct MockFrame {
    id: CanId,
    data: [u8; 8],
    len: usize,
}

impl embedded_can::Frame for MockFrame {
    fn new(id: impl Into<CanId>, data: &[u8]) -> Option<Self> {
        if data.len() > 8 {
            return None;
        }
        let mut buf = [0xFFu8; 8];
        buf[..data.len()].copy_from_slice(data);
        Some(MockFrame {
            id: id.into(),
            data: buf,
            len: data.len(),
        })
    }

    fn new_remote(_id: impl Into<CanId>, _dlc: usize) -> Option<Self> {
        None // J1939 does not use remote frames.
    }

    fn is_extended(&self) -> bool {
        matches!(self.id, CanId::Extended(_))
    }

    fn is_remote_frame(&self) -> bool {
        false
    }

    fn id(&self) -> CanId {
        self.id
    }

    fn dlc(&self) -> usize {
        self.len
    }

    fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// A fake peripheral with a transmit log and a receive queue.
#[derive(Default)]
struct MockCan {
    sent: RefCell<Vec<MockFrame>>,
    incoming: RefCell<std::collections::VecDeque<MockFrame>>,
}

impl MockCan {
    fn send(&self, frame: MockFrame) {
        self.sent.borrow_mut().push(frame);
    }

    fn recv(&self) -> Option<MockFrame> {
        self.incoming.borrow_mut().pop_front()
    }

    /// Put a frame on the fake bus, as another ECU would.
    fn inject(&self, frame: Frame) {
        if let Some(raw) = encode::<MockFrame>(&frame) {
            self.incoming.borrow_mut().push_back(raw);
        }
    }
}
