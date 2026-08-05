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
use sae_j1939_rs::diagnostics::Lamp;
use sae_j1939_rs::fault_log::FaultLog;
use sae_j1939_rs::node::{Event, Node, Outgoing, ADDRESS_CLAIM_WINDOW_MS};
use sae_j1939_rs::request::Request;
use sae_j1939_rs::schedule::Schedule;
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

/// How many distinct faults this ECU can report at once. Size it for what the
/// firmware can *detect*, not what you expect to happen: one broken connector
/// sets several at a time.
const MAX_FAULTS: usize = 8;

/// Room for the longest DM1 this ECU can produce: two lamp bytes plus four per
/// code. Fixed at compile time, like everything else here.
const DM1_BUFFER: usize = 2 + 4 * MAX_FAULTS;

/// How many parameter groups this ECU broadcasts on its own schedule.
const MAX_PERIODIC: usize = 4;

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

    // ---- What is wrong with this ECU -------------------------------------
    // The fault log owns no bus and no clock, so it belongs here in the
    // application rather than inside `Node`. Raise and clear codes as the
    // firmware detects conditions; it works out the lamps, the occurrence
    // counts, and when the next DM1 is due.
    let mut faults = FaultLog::<MAX_FAULTS>::new();
    faults.set(100, 1, Lamp::RedStop).unwrap(); // oil pressure low
    faults.set(110, 0, Lamp::AmberWarning).unwrap(); // coolant temperature high

    // ---- What this ECU publishes without being asked ---------------------
    // The other half of an ECU's life. `Schedule` holds only the timing; the
    // payload is built fresh each time it comes due, because a periodic value
    // that was cached would be a value that is always one cycle stale.
    let mut schedule = Schedule::<MAX_PERIODIC>::new();
    schedule.broadcast_every(pgn::EEC1, 50).unwrap();
    schedule
        .broadcast_every(pgn::ENGINE_TEMPERATURE_1, 1000)
        .unwrap();

    // ---- Start up --------------------------------------------------------
    transmit(&can, &node.start());
    println!("claiming address {:#04x}", node.address().as_u8());

    // Stand-in for a SysTick counter. On real hardware this comes from a timer.
    let mut elapsed_ms: u16 = 0;
    let tick_ms: u16 = 25;

    // A scripted bus, so the example does something. On hardware these frames
    // arrive from the CAN peripheral.
    let mut asked = false;
    let mut repaired = false;
    let mut periodic_frames = 0usize;

    // ---- Main loop -------------------------------------------------------
    for _ in 0..160 {
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
                println!("  answering the request");
                broadcast_dm1(&can, node.address(), &faults);
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

        // 4. The periodic DM1. The same timer drives it: the fault log says
        //    when one is due — once a second while anything is active, once
        //    more when the last code clears, then nothing.
        if node.has_address() && faults.tick(tick_ms) {
            print!("  [{elapsed_ms:>4} ms] periodic ");
            broadcast_dm1(&can, node.address(), &faults);
        }

        // 5. Everything else this ECU publishes. One timer drives the lot;
        //    drain it to empty, because more than one may come due at once.
        if node.has_address() {
            schedule.tick(tick_ms);
            while let Some(due) = schedule.next_due() {
                let payload = match due.pgn {
                    p if p == pgn::EEC1 => engine_speed(1500.0),
                    _ => coolant_temperature(80),
                };
                transmit_single(&can, due.pgn, node.address(), &payload);
                periodic_frames += 1;
            }
        }

        // The oil pressure recovers two seconds in. The code stops being
        // active, becomes history for DM2, and the red lamp goes out.
        if elapsed_ms >= 2000 && !repaired {
            repaired = true;
            faults.clear(100, 1);
            println!("\noil pressure recovered — SPN 100 is no longer active");
        }
    }

    println!(
        "\n{} frames transmitted, {periodic_frames} of them scheduled broadcasts",
        can.sent.borrow().len()
    );
}

/// Broadcast a message, however many frames that takes.
///
/// `Outgoing` decides whether this fits one frame or needs the transport
/// protocol, and hands back frames either way — the caller never builds a TP.CM
/// or a TP.DT by hand.
fn broadcast_dm1(can: &MockCan, source: Address, faults: &FaultLog<MAX_FAULTS>) {
    // A fixed buffer on the stack, sized at compile time. No allocation, and no
    // way for a long fault list to overrun it.
    let mut payload = [0u8; DM1_BUFFER];
    let len = faults
        .dm1(&mut payload)
        .expect("DM1_BUFFER is large enough");

    let mut tx = Outgoing::new(pgn::DM1, source, Address::GLOBAL, &payload[..len])
        .expect("a valid message size");

    println!(
        "tx DM1: {} active code(s) in {} frame(s){}",
        faults.active().len(),
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

/// Broadcast one frame's worth of data. No transport protocol, no allocation:
/// a periodic parameter group is eight bytes by design.
fn transmit_single(can: &MockCan, group: sae_j1939_rs::Pgn, source: Address, payload: &[u8; 8]) {
    use sae_j1939_rs::{Id, Priority};

    // Engine data runs at priority 3 rather than the default 6, so a burst of
    // diagnostics cannot delay a control input.
    let id = Id::broadcast(Priority::new(3).expect("0..=7"), group, source);
    transmit(can, &Frame::from_payload(id, *payload));
}

/// SPN 190 — Engine Speed: 16 bits at byte 4, 0.125 rpm per count. The same
/// definition `spn::catalogue::ENGINE_SPEED` decodes with, so a receiver reads
/// back exactly what went in. `0xFF` elsewhere is J1939 for "not available".
fn engine_speed(rpm: f32) -> [u8; 8] {
    let raw = (rpm / 0.125) as u16;
    let mut payload = [0xFFu8; 8];
    payload[3] = raw as u8;
    payload[4] = (raw >> 8) as u8;
    payload
}

/// SPN 110 — Engine Coolant Temperature: one byte at byte 1, offset -40 °C.
fn coolant_temperature(celsius: i16) -> [u8; 8] {
    let mut payload = [0xFFu8; 8];
    payload[0] = (celsius + 40).clamp(0, 250) as u8;
    payload
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
