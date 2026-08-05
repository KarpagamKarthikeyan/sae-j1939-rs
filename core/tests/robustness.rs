// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nothing on the bus may panic this stack.
//!
//! A J1939 node parses data it did not produce, from ECUs it does not control,
//! on a bus it shares with faulty hardware and half-implemented tools. A panic
//! in a decoder is not a bug report — on a microcontroller it is an ECU that
//! stops controlling something.
//!
//! These tests feed arbitrary bytes to every public decoder and to the
//! top-level [`Node::on_frame`] dispatch, and assert only that nothing panics,
//! aborts, or overruns. What the decoders *return* for nonsense is not the
//! point here; the module tests cover that. The point is that they return at
//! all.
//!
//! The generator is a deterministic xorshift, so a failure is always
//! reproducible from the seed printed in the assertion.

use sae_j1939_rs::address_claim::AddressClaimer;
use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, Lamps};
use sae_j1939_rs::fault_log::FaultLog;
use sae_j1939_rs::identification::{
    self, ComponentIdentification, EcuIdentification, SoftwareIdentification,
};
use sae_j1939_rs::iso11783::{
    AuxiliaryValveCommand, AuxiliaryValveEstimatedFlow, AuxiliaryValveMeasuredPosition,
    GeneralPurposeValveCommand, GeneralPurposeValveEstimatedFlow, ValveNumber,
};
use sae_j1939_rs::memory_access::{Dm14, Dm15, Dm16};
use sae_j1939_rs::node::Node;
use sae_j1939_rs::proprietary::ProprietaryB;
use sae_j1939_rs::request::{Acknowledgement, Request};
use sae_j1939_rs::schedule::Schedule;
use sae_j1939_rs::spn::Spn;
use sae_j1939_rs::tp::{Reassembler, TpCm, TpDt};
use sae_j1939_rs::{Address, Frame, Id, Name, Pgn};

/// Every lamp, so the fuzz picks among real values rather than a fixed one.
const LAMPS: [Lamp; 4] = Lamp::ALL;

/// A deterministic generator, so any failure reproduces from its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn payload(&mut self) -> [u8; 8] {
        self.next_u64().to_le_bytes()
    }

    /// A slice of arbitrary bytes, arbitrary length, including empty.
    fn bytes(&mut self, buf: &mut [u8; 64]) -> usize {
        let len = (self.u8() as usize) % (buf.len() + 1);
        for byte in buf.iter_mut().take(len) {
            *byte = self.u8();
        }
        len
    }
}

const ROUNDS: usize = 40_000;

/// Every fixed-width decoder, fed arbitrary bytes.
#[test]
fn fixed_width_decoders_never_panic() {
    let mut rng = Rng::new(0x5AE_1939_0001);

    for round in 0..ROUNDS {
        let seed = rng.0;
        let bytes = rng.payload();
        let context = || format!("round {round}, seed {seed:#018x}, bytes {bytes:02X?}");

        // Identifiers and parameter groups.
        let id = Id::new_masked(rng.u32());
        let _ = id.pgn();
        let _ = id.priority();
        let _ = id.destination_address();
        let _ = id.is_addressed_to(Address::new(rng.u8()));
        let _ = Id::new(rng.u32());
        let pgn = Pgn::new_masked(rng.u32());
        let _ = pgn.group_extension();
        let _ = pgn.is_proprietary_b();
        let _ = ProprietaryB::from_pgn(pgn);
        let _ = Pgn::new(rng.u32());

        // Transport protocol.
        let _ = TpCm::decode(&bytes);
        let dt = TpDt::decode(&bytes);
        assert_eq!(dt.encode(), bytes, "TP.DT must round-trip: {}", context());

        // Request and acknowledgement.
        let _ = Request::decode(&bytes);
        let ack = Acknowledgement::decode(&bytes);
        let _ = ack.encode();

        // Network management.
        let name = Name::from_bytes(&bytes);
        assert_eq!(
            name.to_bytes(),
            bytes,
            "NAME must round-trip: {}",
            context()
        );
        let _ = name.arbitrary_address_capable();
        let _ = name.industry_group();

        // Diagnostics.
        let _ = Lamps::decode(&[bytes[0], bytes[1]]);
        let dtc = Dtc::decode(&[bytes[0], bytes[1], bytes[2], bytes[3]]);
        let _ = dtc.is_no_fault();
        let _ = Dtc::new(rng.u32(), rng.u8(), rng.u8());

        // Memory access.
        let dm14 = Dm14::decode(&bytes);
        let _ = dm14.encode();
        let dm15 = Dm15::decode(&bytes);
        let _ = dm15.encode();
        let _ = Dm14::new(rng.u32() as u16, dm14.command, rng.u32());
        let _ = Dm15::new(rng.u32() as u16, dm15.status);

        // ISO 11783.
        let _ = AuxiliaryValveCommand::decode(&bytes);
        let _ = AuxiliaryValveEstimatedFlow::decode(&bytes);
        let _ = AuxiliaryValveMeasuredPosition::decode(&bytes);
        let _ = GeneralPurposeValveCommand::decode(&bytes);
        let _ = GeneralPurposeValveEstimatedFlow::decode(&bytes);
        let _ = ValveNumber::new(rng.u8());
        let _ = ValveNumber::from_command_pgn(pgn);
        let _ = ValveNumber::from_measured_position_pgn(pgn);
    }
}

/// Every variable-length parser, fed arbitrary slices of arbitrary length —
/// including empty ones and ones that lie about their own contents.
#[test]
fn variable_length_parsers_never_panic() {
    let mut rng = Rng::new(0xD1A6_1939);
    let mut buf = [0u8; 64];

    for round in 0..ROUNDS {
        let seed = rng.0;
        let len = rng.bytes(&mut buf);
        let data = &buf[..len];
        let context = || format!("round {round}, seed {seed:#018x}, len {len}");

        // Diagnostics: a DM1 whose length may not be a whole number of codes.
        if let Ok(dm) = diagnostics::Message::parse(data) {
            let count = dm.dtc_count();
            let collected = dm.dtcs().count();
            assert_eq!(count, collected, "dtc_count must match: {}", context());
            let _ = dm.is_fault_free();
            let _ = dm.lamps().any_on();
        }

        // Memory access: a DM16 that may claim more bytes than it carries.
        if let Ok(dm16) = Dm16::parse(data) {
            assert!(
                dm16.data().len() <= data.len(),
                "DM16 must not report more data than it was given: {}",
                context()
            );
        }

        // Identification: delimiters in arbitrary places, or none at all.
        let counted = identification::fields(data).count();
        for index in 0..counted + 2 {
            let _ = identification::field(data, index);
            let _ = identification::field_str(data, index);
        }
        let ecu = EcuIdentification::new(data);
        let _ = (ecu.part_number_str(), ecu.manufacturer_name_str());
        assert_eq!(
            ecu.field_count(),
            counted,
            "field counts agree: {}",
            context()
        );
        let component = ComponentIdentification::new(data);
        let _ = (component.make_str(), component.unit_number_str());
        if let Ok(software) = SoftwareIdentification::parse(data) {
            let _ = software.count_is_consistent();
            let _ = software.field_str(rng.u8() as usize);
        }

        // Commanded Address: nine bytes expected, arbitrary length supplied.
        let mut claimer = AddressClaimer::new(Name::from_u64(rng.next_u64()), Address::new(0x80));
        let _ = claimer.on_commanded_address(data);

        // SPN extraction with arbitrary field geometry against arbitrary data.
        let spn = Spn::new(
            rng.u32(),
            "fuzz",
            (rng.u8() % 72) as u16,
            (rng.u8() % 40) as u16,
            1.0,
            0.0,
            "",
        );
        let _ = spn.extract(data);
        let _ = spn.decode(data);

        // Encoders into buffers that may be far too small.
        let mut out = [0u8; 16];
        let _ = diagnostics::encode(Lamps::new(), &[], &mut out[..len.min(16)]);
        let _ = identification::encode(&[data], &mut out[..len.min(16)]);
    }
}

/// The reassembler, driven by arbitrary connection-management and data frames
/// from arbitrary peers — the shape a hostile or broken bus actually takes.
#[test]
fn the_reassembler_never_panics_on_arbitrary_traffic() {
    let mut rng = Rng::new(0x7F5B_1939);
    let mut rx = Reassembler::<512, 4>::new();

    for round in 0..ROUNDS {
        let seed = rng.0;
        let peer = Address::new(rng.u8());
        let bytes = rng.payload();

        match rng.u8() % 4 {
            0 => {
                if let Ok(cm) = TpCm::decode(&bytes) {
                    let _ = rx.on_tp_cm(peer, &cm);
                }
            }
            1 => {
                let _ = rx.on_tp_dt(peer, &TpDt::decode(&bytes));
            }
            2 => {
                rx.tick(rng.u8() as u16 * 8, |_, _| {});
            }
            _ => {
                let _ = rx.abandon(peer);
            }
        }

        assert!(
            rx.active_sessions() <= 4,
            "never more sessions than slots: round {round}, seed {seed:#018x}"
        );
    }
}

/// The top-level dispatch, fed arbitrary frames. This is the entry point real
/// bus traffic reaches, so it is the one that most needs to be unpanickable.
#[test]
fn node_dispatch_never_panics_on_arbitrary_frames() {
    let mut rng = Rng::new(0x0DE_1939_0002);
    let name = Name::new()
        .with_manufacturer_code(300)
        .with_identity_number(42)
        .with_arbitrary_address_capable(true);
    let mut node = Node::<512, 4>::new(name, Address::new(0x80));
    node.start();

    for round in 0..ROUNDS {
        let seed = rng.0;

        // An arbitrary identifier with an arbitrary payload of arbitrary length.
        let id = Id::new_masked(rng.u32());
        let payload = rng.payload();
        let len = (rng.u8() % 9) as usize;
        let frame = Frame::new(id, &payload[..len]).expect("at most eight bytes");

        if let sae_j1939_rs::node::Event::Message { data, .. } = node.on_frame(&frame) {
            assert!(
                data.len() <= 512,
                "a delivered message must fit the buffer: round {round}, seed {seed:#018x}"
            );
        }

        if round % 16 == 0 {
            node.tick(rng.u8() as u16 * 4, |_| {});
        }

        // The node's own address must always stay a value it could legitimately
        // hold: a specific address, or null once it has given up.
        let address = node.address();
        assert!(
            address.is_specific() || address.is_null(),
            "address became {:#04x}: round {round}, seed {seed:#018x}",
            address.as_u8()
        );
    }
}

/// The fault log, driven by an arbitrary sequence of operations.
///
/// A decoder is fed one input at a time and can be checked in isolation; a
/// state machine cannot. The invariants that matter here are the ones a wrong
/// sequence would break silently: a list longer than its capacity, the same
/// fault recorded twice, or a code that no longer fits the wire format it will
/// be encoded into.
#[test]
fn the_fault_log_survives_any_sequence_of_operations() {
    const CAPACITY: usize = 8;
    let mut rng = Rng::new(0x0FA0_1939);
    let mut faults = FaultLog::<CAPACITY>::new();
    let mut buffer = [0u8; 2 + 4 * CAPACITY];

    for round in 0..ROUNDS {
        let seed = rng.0;

        // A small pool of faults, so the same code is raised, cleared and
        // raised again — which is where the state transitions live. Every
        // eighth operation uses a fully arbitrary value instead, to keep the
        // rejection paths exercised too.
        let (spn, fmi) = if rng.u8() % 8 == 0 {
            (rng.u32(), rng.u8())
        } else {
            ((rng.u8() % 12) as u32 + 100, rng.u8() % 4)
        };

        match rng.u8() % 8 {
            // Mostly raise and clear, since those carry the interesting state.
            0..=3 => {
                let _ = faults.set(spn, fmi, LAMPS[(rng.u8() % 4) as usize]);
            }
            4..=5 => {
                let _ = faults.clear(spn, fmi);
            }
            6 => {
                let _ = faults.tick(rng.u8() as u16 * 8);
            }
            _ => match rng.u8() % 2 {
                0 => faults.clear_active(),
                _ => faults.clear_previously_active(),
            },
        }

        let context = || format!("round {round}, seed {seed:#018x}");

        assert!(
            faults.active().len() <= CAPACITY && faults.previously_active().len() <= CAPACITY,
            "a list outgrew its capacity: {}",
            context()
        );

        // Identity is (SPN, FMI). A duplicate would be reported twice in one
        // DM1, which a tool reads as two separate faults.
        for (index, dtc) in faults.active().iter().enumerate() {
            assert!(
                !faults.active()[..index]
                    .iter()
                    .any(|other| other.spn == dtc.spn && other.fmi == dtc.fmi),
                "duplicate active fault: {}",
                context()
            );
            // Whatever went in must still fit the four bytes it goes out in.
            assert_eq!(
                Dtc::decode(&dtc.encode()),
                *dtc,
                "an active fault stopped round-tripping: {}",
                context()
            );
        }

        // And the encoders must always agree with the lengths they advertise.
        assert_eq!(
            faults.dm1(&mut buffer),
            Ok(faults.dm1_len()),
            "dm1 disagreed with dm1_len: {}",
            context()
        );
        assert_eq!(
            faults.dm2(&mut buffer),
            Ok(faults.dm2_len()),
            "dm2 disagreed with dm2_len: {}",
            context()
        );
    }
}

/// The transmission schedule, driven by an arbitrary sequence of operations.
///
/// The invariants that matter are the ones a wrong sequence would break
/// quietly: more entries than slots, the same group registered twice, or a
/// suspension that never ends — which on a real bus is an ECU that has gone
/// silent and will not come back.
#[test]
fn the_schedule_survives_any_sequence_of_operations() {
    const CAPACITY: usize = 8;
    let mut rng = Rng::new(0x5C_1939_0001);
    let mut schedule = Schedule::<CAPACITY>::new();

    for round in 0..ROUNDS {
        let seed = rng.0;
        // A small pool, so registration collisions and removals actually happen.
        let group = Pgn::new_masked(0x00F000 + (rng.u8() % 12) as u32);
        let destination = Address::new(if rng.u8() % 2 == 0 {
            0xFF
        } else {
            rng.u8() % 4
        });

        match rng.u8() % 8 {
            0..=2 => {
                let _ = schedule.send_every(group, destination, rng.u8() as u16);
            }
            3 => {
                let _ = schedule.remove(group, destination);
            }
            4..=5 => {
                schedule.tick(rng.u8() as u16 * 4);
                // Drain a random amount, so leftovers are exercised too.
                for _ in 0..rng.u8() % 4 {
                    let _ = schedule.next_due();
                }
            }
            6 => schedule.suspend(rng.u8() as u16 * 8),
            _ => match rng.u8() % 2 {
                0 => schedule.resume(),
                _ => schedule.clear(),
            },
        }

        let context = || format!("round {round}, seed {seed:#018x}");

        assert!(
            schedule.len() <= CAPACITY,
            "the schedule outgrew its capacity: {}",
            context()
        );
        assert!(
            schedule.pending() <= schedule.len(),
            "more messages due than are registered: {}",
            context()
        );

        // A group may appear once per destination, never twice for the same
        // one — a duplicate would double that message's rate on the bus.
        let registered: std::vec::Vec<(u32, u8)> = schedule
            .entries()
            .map(|(due, _)| (due.pgn.as_u32(), due.destination.as_u8()))
            .collect();
        for (index, entry) in registered.iter().enumerate() {
            assert!(
                !registered[..index].contains(entry),
                "duplicate schedule entry: {}",
                context()
            );
        }

        // A suspension must always be running down toward zero.
        if let Some(remaining) = schedule.resumes_in_ms() {
            assert!(
                remaining > 0,
                "suspended with nothing left to run: {}",
                context()
            );
            assert!(schedule.is_suspended(), "{}", context());
        } else {
            assert!(!schedule.is_suspended(), "{}", context());
        }
    }

    // Whatever state the fuzz left it in, enough quiet time must bring it back:
    // an ECU that could be silenced permanently is a worse failure than any
    // decoding bug.
    schedule.clear();
    schedule
        .broadcast_every(Pgn::new_masked(0x00F004), 100)
        .unwrap();
    for _ in 0..100 {
        schedule.tick(1000);
    }
    assert!(
        !schedule.is_suspended(),
        "a suspension outlived every timeout"
    );
    assert!(schedule.pending() > 0, "transmission never resumed");
}
