// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An ECU reporting its own faults, end to end, the way a microcontroller does.
//!
//! `host`'s `Ecu` wires `FaultLog` to a bus for you, but the whole point of the
//! core crate is that the same thing works without it: a fault log, `Outgoing`
//! to frame the DM1, and a peer's `Reassembler` to put it back together. No
//! allocation, no clock, no `std`.
//!
//! These tests drive that path directly, so the bare-metal story is covered by
//! something that fails when it breaks rather than only by an example nobody
//! runs.

use sae_j1939_rs::diagnostics::{Dtc, Lamp, LampStatus, Message};
use sae_j1939_rs::fault_log::{FaultLog, DM1_INTERVAL_MS};
use sae_j1939_rs::node::{Node, Outgoing};
use sae_j1939_rs::tp::{Reassembler, Rx, TpCm, TpDt};
use sae_j1939_rs::{pgn, Address, Frame, Name, Pgn};

const REPORTER: Address = Address::new(0x80);

/// Frame a payload the way an ECU would, then feed the frames to a peer's
/// reassembler and hand back whatever whole message came out.
///
/// This is the entire transmit-to-receive path in one function: `Outgoing`
/// decides single-frame versus BAM, and `Reassembler` puts it back.
fn round_trip(group: Pgn, payload: &[u8], rx: &mut Reassembler<1785>) -> Option<Vec<u8>> {
    let mut tx = Outgoing::new(group, REPORTER, Address::GLOBAL, payload).expect("a valid size");
    let mut frames = Vec::new();
    while let Some(frame) = tx.next_frame() {
        frames.push(frame);
    }

    let mut received = None;
    for frame in &frames {
        let outcome = match frame.pgn() {
            p if p == pgn::TP_CM => {
                let cm = TpCm::decode(frame.payload()).expect("a valid TP.CM");
                rx.on_tp_cm(REPORTER, &cm)
            }
            p if p == pgn::TP_DT => rx.on_tp_dt(REPORTER, &TpDt::decode(frame.payload())),
            // A single frame is the whole message already.
            _ => {
                received = Some(frame.data().to_vec());
                continue;
            }
        };
        if let Rx::Message { data, .. } = outcome {
            received = Some(data.to_vec());
        }
    }
    received
}

/// Encode the current DM1 into a fixed buffer, as an MCU would.
fn dm1_payload<const N: usize>(faults: &FaultLog<N>) -> Vec<u8> {
    let mut buffer = [0u8; 1785];
    let len = faults.dm1(&mut buffer).expect("the buffer is large enough");
    buffer[..len].to_vec()
}

#[test]
fn one_fault_crosses_the_bus_in_a_single_frame() {
    let mut faults = FaultLog::<8>::new();
    faults.set(100, 1, Lamp::RedStop).unwrap();

    let mut rx = Reassembler::<1785>::new();
    let payload = dm1_payload(&faults);
    assert_eq!(payload.len(), 8, "one code still fits a CAN frame");

    let received = round_trip(pgn::DM1, &payload, &mut rx).expect("nothing arrived");
    let dm = Message::parse(&received).unwrap();

    assert_eq!(dm.lamps().status(Lamp::RedStop), LampStatus::On);
    let dtcs: Vec<Dtc> = dm.dtcs().collect();
    assert_eq!(dtcs, faults.active());
}

#[test]
fn a_long_fault_list_crosses_the_bus_over_the_transport_protocol() {
    // Every capacity from "just over one frame" to a full log, so the boundary
    // between a single frame and a BAM is crossed rather than assumed.
    for count in 1..=32u32 {
        let mut faults = FaultLog::<32>::new();
        for spn in 0..count {
            faults
                .set(spn + 1, (spn % 32) as u8, Lamp::AmberWarning)
                .unwrap();
        }

        let payload = dm1_payload(&faults);
        assert_eq!(payload.len(), faults.dm1_len(), "{count} codes");

        let mut rx = Reassembler::<1785>::new();
        let received =
            round_trip(pgn::DM1, &payload, &mut rx).unwrap_or_else(|| panic!("{count} codes"));
        let dm = Message::parse(&received).unwrap();

        let dtcs: Vec<Dtc> = dm.dtcs().collect();
        assert_eq!(dtcs, faults.active(), "{count} codes did not survive");
    }
}

#[test]
fn the_history_crosses_the_bus_as_dm2() {
    let mut faults = FaultLog::<8>::new();
    for spn in [100u32, 110, 190] {
        faults.set(spn, 1, Lamp::AmberWarning).unwrap();
        faults.clear(spn, 1);
    }

    let mut buffer = [0u8; 1785];
    let len = faults.dm2(&mut buffer).unwrap();
    let mut rx = Reassembler::<1785>::new();
    let received = round_trip(pgn::DM2, &buffer[..len], &mut rx).expect("nothing arrived");

    let dm = Message::parse(&received).unwrap();
    assert!(!dm.lamps().any_on(), "history lights no lamps");
    let spns: Vec<u32> = dm.dtcs().map(|d| d.spn).collect();
    assert_eq!(spns, [100, 110, 190]);
}

#[test]
fn a_healthy_ecu_reports_itself_healthy_across_the_bus() {
    // The failure this guards against is subtle: an all-`0xFF` padded DM1 reads
    // back as SPN 0x7FFFF / FMI 31, which a naive parser calls a fault.
    let faults = FaultLog::<8>::new();
    let mut rx = Reassembler::<1785>::new();
    let received = round_trip(pgn::DM1, &dm1_payload(&faults), &mut rx).expect("nothing arrived");

    let dm = Message::parse(&received).unwrap();
    assert!(dm.is_fault_free());
    assert!(!dm.lamps().any_on());
}

#[test]
fn the_reporting_ecu_still_serves_the_rest_of_the_protocol() {
    // A fault log next to a `Node` must not disturb it: the node keeps claiming
    // and defending its address while DM1s go out.
    let name = Name::new()
        .with_manufacturer_code(300)
        .with_identity_number(1);
    let mut node = Node::<256, 2>::new(name, REPORTER);
    let mut faults = FaultLog::<8>::new();
    faults.set(100, 1, Lamp::RedStop).unwrap();

    let _ = node.start();
    let mut sent: Vec<Frame> = Vec::new();
    let mut dm1_count = 0;

    // Four seconds at 25 ms, the shape of a real main loop.
    for _ in 0..160 {
        node.tick(25, |frame| sent.push(frame));
        if node.has_address() && faults.tick(25) {
            dm1_count += 1;
        }
    }

    assert!(node.has_address(), "the node must still claim its address");
    assert!(
        (3..=4).contains(&dm1_count),
        "expected about one DM1 per second, got {dm1_count}"
    );
}

#[test]
fn a_fault_raised_between_reports_waits_for_the_next_slot() {
    // J1939-73 caps DM1 at once per second however fast faults appear, so a
    // flapping sensor cannot be turned into a broadcast storm.
    let mut faults = FaultLog::<32>::new();
    assert!(!faults.tick(DM1_INTERVAL_MS), "nothing is wrong yet");

    faults.set(100, 1, Lamp::RedStop).unwrap();
    assert!(faults.tick(1), "the first report is prompt");

    let mut reports = 0;
    // Thirty-one more, filling the log exactly, a tenth of a second apart.
    for spn in 200..231u32 {
        faults.set(spn, 1, Lamp::AmberWarning).unwrap();
        if faults.tick(100) {
            reports += 1;
        }
    }
    assert_eq!(faults.active().len(), faults.capacity());
    // Thirty-one faults over 3.1 seconds is three reports, not thirty-one.
    assert_eq!(
        reports, 3,
        "one per second, regardless of how fast faults arrive"
    );
}
