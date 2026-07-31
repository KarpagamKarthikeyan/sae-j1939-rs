// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests driving the whole stack through the public API only.
//!
//! These simulate two ECUs on a shared bus: they claim addresses, exchange
//! requests, and ship a multi-packet diagnostic message between them. Nothing
//! here reaches into crate internals, so the tests double as a check that the
//! public surface is actually usable for building an ECU.

use sae_j1939_rs::address_claim::{AddressClaimer, ClaimAction, ClaimState};
use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
use sae_j1939_rs::identification::{self, EcuIdentification};
use sae_j1939_rs::request::{AckControl, Acknowledgement, Request};
use sae_j1939_rs::tp::{Reassembler, Rx, TpCm, TpDt, Transmitter, Tx};
use sae_j1939_rs::{pgn, Address, Id, Name, Priority};

/// A frame as it would appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BusFrame {
    id: Id,
    data: [u8; 8],
    len: usize,
}

impl BusFrame {
    fn new(id: Id, data: &[u8]) -> Self {
        let mut buf = [0xFFu8; 8];
        buf[..data.len()].copy_from_slice(data);
        BusFrame {
            id,
            data: buf,
            len: data.len(),
        }
    }

    fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

fn name_for(identity: u32, manufacturer: u16) -> Name {
    Name::new()
        .with_identity_number(identity)
        .with_manufacturer_code(manufacturer)
        .with_function(0x87)
}

/// Both ECUs come up, claim distinct addresses, and each records the other.
#[test]
fn two_ecus_claim_distinct_addresses_and_discover_each_other() {
    let engine_name = name_for(1, 100);
    let gearbox_name = name_for(2, 200);

    let mut engine = AddressClaimer::new(engine_name, Address::new(0x00));
    let mut gearbox = AddressClaimer::new(gearbox_name, Address::new(0x03));

    // Each broadcasts its claim; neither wants the other's address.
    let engine_claim = engine.claim();
    let gearbox_claim = gearbox.claim();

    assert_eq!(
        engine.on_address_claimed(gearbox_claim.source, gearbox_claim.name),
        ClaimAction::Idle
    );
    assert_eq!(
        gearbox.on_address_claimed(engine_claim.source, engine_claim.name),
        ClaimAction::Idle
    );

    engine.contention_window_elapsed();
    gearbox.contention_window_elapsed();

    assert_eq!(engine.state(), ClaimState::Claimed);
    assert_eq!(gearbox.state(), ClaimState::Claimed);
    assert_eq!(engine.address(), Address::new(0x00));
    assert_eq!(gearbox.address(), Address::new(0x03));

    // Each now knows the other is on the bus.
    assert!(engine.is_address_taken(Address::new(0x03)));
    assert!(gearbox.is_address_taken(Address::new(0x00)));
}

/// A global request for Address Claimed is how a tool enumerates the bus.
#[test]
fn a_global_request_makes_every_ecu_announce_itself() {
    let tool = Address::new(0xF9);
    let request_id =
        Id::from_parts(Priority::DEFAULT, pgn::REQUEST, Address::GLOBAL, tool).unwrap();
    let request = Request::new(pgn::ADDRESS_CLAIMED);

    // On the wire: a PDU1 request to the global address.
    let frame = BusFrame::new(request_id, &request.encode());
    assert_eq!(frame.len, 3, "a Request payload is three bytes");
    assert_eq!(frame.id.destination_address(), Some(Address::GLOBAL));

    // Two ECUs receive it. Both must answer, because it is addressed globally.
    let mut ecus = [
        AddressClaimer::new(name_for(1, 100), Address::new(0x00)),
        AddressClaimer::new(name_for(2, 200), Address::new(0x03)),
    ];

    for ecu in ecus.iter_mut() {
        ecu.claim();
        ecu.contention_window_elapsed();

        assert!(frame.id.is_addressed_to(ecu.address()));
        let decoded = Request::decode(frame.payload()).unwrap();
        assert_eq!(decoded.pgn, pgn::ADDRESS_CLAIMED);

        let ClaimAction::Announce(claim) = ecu.on_request() else {
            panic!("every ECU must answer a global Address Claimed request");
        };
        // The reply is a broadcast from the ECU's own address.
        let reply_id = Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, claim.source);
        assert_eq!(reply_id.source_address(), ecu.address());
        assert_eq!(Name::from_bytes(&claim.payload()), ecu.name());
    }
}

/// An ECU that does not implement a parameter group must say so, not stay
/// silent — otherwise the requester waits for a timeout.
#[test]
fn an_unsupported_request_is_answered_with_a_nack() {
    let requester = Address::new(0xF9);
    let responder = Address::new(0x03);

    let request = Request::new(pgn::COMPONENT_IDENTIFICATION);
    let nack = Acknowledgement {
        address: responder,
        ..Acknowledgement::negative(request.pgn)
    };

    let id = Id::from_parts(
        Priority::DEFAULT,
        pgn::ACKNOWLEDGEMENT,
        requester,
        responder,
    )
    .unwrap();
    let frame = BusFrame::new(id, &nack.encode());

    // The requester decodes the refusal.
    let mut payload = [0u8; 8];
    payload.copy_from_slice(frame.payload());
    let decoded = Acknowledgement::decode(&payload);
    assert_eq!(decoded.control, AckControl::NotSupported);
    assert!(!decoded.control.is_positive());
    assert_eq!(decoded.pgn, pgn::COMPONENT_IDENTIFICATION);
    assert_eq!(decoded.address, responder);
}

/// The full path a real fault takes: an ECU with three trouble codes announces
/// them over a BAM, and a listener reassembles and decodes them.
#[test]
fn a_three_fault_dm1_reaches_a_listener_over_a_broadcast() {
    let ecu = Address::new(0x00);

    let lamps = Lamps::new()
        .with_status(Lamp::AmberWarning, LampStatus::On)
        .with_status(Lamp::RedStop, LampStatus::On);
    let faults = [
        Dtc::new(100, 1, 2).unwrap(), // oil pressure, data valid but low
        Dtc::new(110, 0, 5).unwrap(), // coolant temperature, data valid but high
        Dtc::new(1569, 31, 126).unwrap(),
    ];

    let mut payload = [0u8; 64];
    let len = diagnostics::encode(lamps, &faults, &mut payload).unwrap();
    assert_eq!(len, 14, "two lamp bytes plus three 4-byte codes");

    // Sender: announce, then push every packet. A real ECU paces these 50-200ms
    // apart; the state machine owns no clock, so nothing here depends on timing.
    let mut tx = Transmitter::broadcast(pgn::DM1, &payload[..len]).unwrap();
    let announce = tx.start();
    assert!(matches!(
        announce,
        TpCm::Bam {
            size: 14,
            packets: 2,
            ..
        }
    ));

    let announce_id = Id::broadcast(Priority::LOWEST, pgn::TP_CM, ecu);
    let mut wire = vec![BusFrame::new(announce_id, &announce.encode())];
    while let Some(packet) = tx.next_packet() {
        let id = Id::broadcast(Priority::LOWEST, pgn::TP_DT, ecu);
        wire.push(BusFrame::new(id, &packet.encode()));
    }
    assert_eq!(wire.len(), 3, "one announcement plus two data packets");

    // Listener: feed the frames off the bus into a reassembler.
    let mut rx = Reassembler::<256>::new();
    let mut reassembled = None;
    for frame in &wire {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(frame.payload());
        let source = frame.id.source_address();

        let outcome = if frame.id.pgn() == pgn::TP_CM {
            rx.on_tp_cm(source, &TpCm::decode(&bytes).unwrap())
        } else {
            rx.on_tp_dt(source, &TpDt::decode(&bytes))
        };
        if let Rx::Message { pgn, data, ack, .. } = outcome {
            assert_eq!(pgn, pgn::DM1);
            assert_eq!(ack, None, "a broadcast is never acknowledged");
            reassembled = Some(data.to_vec());
        }
    }

    // Decode what came back.
    let reassembled = reassembled.expect("the DM1 should reassemble");
    let dm = diagnostics::Message::parse(&reassembled).unwrap();
    assert_eq!(dm.lamps().status(Lamp::AmberWarning), LampStatus::On);
    assert_eq!(dm.lamps().status(Lamp::RedStop), LampStatus::On);
    assert!(dm.lamps().any_on());
    assert!(!dm.is_fault_free());
    assert_eq!(dm.dtcs().collect::<Vec<_>>(), faults);
}

/// A destination-specific transfer with a constrained sender: the receiver must
/// never ask for more packets than the RTS allows, on any window.
#[test]
fn an_rts_cts_transfer_honours_a_constrained_sender() {
    let sender = Address::new(0x00);

    let values: [&[u8]; 5] = [b"PN-1234", b"SN-99", b"ENGINE BAY", b"ECM", b"ACME MOTORS"];
    let mut payload = [0u8; 128];
    let len = identification::encode(&values, &mut payload).unwrap();

    // This ECU can only keep two packets in flight.
    let mut tx = Transmitter::addressed(pgn::ECU_IDENTIFICATION, &payload[..len])
        .unwrap()
        .with_max_packets_per_cts(2);
    let mut rx = Reassembler::<256>::new();

    let rts = tx.start();
    assert!(
        matches!(
            rts,
            TpCm::Rts {
                max_packets_per_cts: 2,
                ..
            }
        ),
        "the limit must be advertised in the RTS, got {rts:?}"
    );

    let mut response = match rx.on_tp_cm(sender, &rts) {
        Rx::Send(cm) => Some(cm),
        other => panic!("expected a CTS, got {other:?}"),
    };

    let mut reassembled = None;
    let mut windows = 0;
    'transfer: while let Some(cm) = response.take() {
        if let TpCm::Cts { packets, .. } = cm {
            assert!(
                packets <= 2,
                "window of {packets} exceeds the sender's limit"
            );
            windows += 1;
        }
        assert_eq!(tx.on_tp_cm(&cm), Tx::SendData);

        while let Some(packet) = tx.next_packet() {
            match rx.on_tp_dt(sender, &packet) {
                Rx::Idle => {}
                Rx::Send(next) => response = Some(next),
                Rx::Message { data, ack, .. } => {
                    reassembled = Some(data.to_vec());
                    // Close the transfer out properly.
                    assert_eq!(
                        tx.on_tp_cm(&ack.expect("RTS/CTS is acknowledged")),
                        Tx::Complete
                    );
                    break 'transfer;
                }
            }
        }
    }

    assert!(windows > 1, "a capped window must take several CTS rounds");
    assert!(tx.is_complete());

    let reassembled = reassembled.expect("the identification should reassemble");
    let ecu = EcuIdentification::new(&reassembled);
    assert_eq!(ecu.part_number_str(), Some("PN-1234"));
    assert_eq!(ecu.manufacturer_name_str(), Some("ACME MOTORS"));
    assert_eq!(ecu.field_count(), 5);
}

/// Traffic addressed to another ECU must be ignored, and a PDU2 broadcast must
/// be processed by everyone — the two halves of the receive filter.
#[test]
fn the_receive_filter_separates_addressed_from_broadcast_traffic() {
    let us = Address::new(0x03);
    let them = Address::new(0x17);
    let sender = Address::new(0x00);

    let to_us = Id::from_parts(Priority::DEFAULT, pgn::REQUEST, us, sender).unwrap();
    let to_them = Id::from_parts(Priority::DEFAULT, pgn::REQUEST, them, sender).unwrap();
    let to_all = Id::broadcast(Priority::DEFAULT, pgn::REQUEST, sender);
    let broadcast_pgn = Id::broadcast(Priority::DEFAULT, pgn::DM1, sender);

    assert!(to_us.is_addressed_to(us));
    assert!(!to_them.is_addressed_to(us));
    assert!(to_all.is_addressed_to(us));
    assert!(broadcast_pgn.is_addressed_to(us));

    // A reassembler must not be disturbed by a transfer aimed elsewhere.
    let mut rx = Reassembler::<256>::new();
    rx.on_tp_cm(sender, &TpCm::bam(14, pgn::DM1).unwrap());
    assert!(rx.is_busy());
    assert_eq!(rx.on_tp_dt(them, &TpDt::new(1, &[0; 7])), Rx::Idle);
    assert!(
        rx.is_busy(),
        "another ECU's packet must not advance our session"
    );
}

/// An ECU that loses arbitration and cannot move must fall silent, and keep
/// answering requests with Cannot Claim so tools know why it is gone.
#[test]
fn a_displaced_ecu_reports_cannot_claim() {
    // A low manufacturer code dominates, so this NAME always wins.
    let winner = Name::new().with_manufacturer_code(1);
    let loser = name_for(500, 2000);
    assert!(winner.wins_arbitration_against(loser));
    assert!(!loser.arbitrary_address_capable());

    let mut ecu = AddressClaimer::new(loser, Address::new(0x80));
    ecu.claim();
    ecu.contention_window_elapsed();

    let ClaimAction::Announce(claim) = ecu.on_address_claimed(Address::new(0x80), winner) else {
        panic!("losing arbitration must produce an announcement");
    };
    assert!(claim.is_cannot_claim());
    assert_eq!(claim.source, Address::NULL);
    assert_eq!(ecu.state(), ClaimState::CannotClaim);

    // The Cannot Claim message goes out from the null address, exactly as the
    // reference builds it: 0x18EEFFFE.
    let id = Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, claim.source);
    assert_eq!(id.as_u32(), 0x18EE_FFFE);

    // It still answers requests, so a tool can tell "displaced" from "absent".
    let ClaimAction::Announce(reply) = ecu.on_request() else {
        panic!("a displaced ECU must still answer");
    };
    assert!(reply.is_cannot_claim());
}
