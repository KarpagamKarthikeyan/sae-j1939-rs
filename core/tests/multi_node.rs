// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Several ECUs on one bus, and the state transitions only they can reach.
//!
//! The module tests drive one state machine at a time. That is the right way to
//! pin down a transition, but it cannot reach the situations that only exist
//! because a bus has more than two participants on it: three ECUs wanting the
//! same address, a peer that is sending to us *and* receiving from us at the
//! same moment, a node that relocates with somebody's transfer half delivered.
//!
//! Those are the cases where a stack quietly does the wrong thing, because each
//! machine is behaving correctly in isolation and the mistake is in how they are
//! wired together.
//!
//! The second half of the file is bookkeeping rather than scenario: it walks the
//! transitions of [`Reassembler`], [`AddressClaimer`], [`Node`] and [`Outgoing`]
//! and covers the ones the per-module tests leave out.

use std::collections::VecDeque;

use sae_j1939_rs::address_claim::{
    AddressClaimer, ClaimAction, ClaimState, DYNAMIC_ADDRESS_END, DYNAMIC_ADDRESS_START,
};
use sae_j1939_rs::node::{Event, Node, Outgoing, Progress};
use sae_j1939_rs::request::Request;
use sae_j1939_rs::tp::{AbortReason, Reassembler, Rx, TpCm, TpDt, T1_TIMEOUT_MS};
use sae_j1939_rs::{pgn, Address, Frame, Id, Name, Priority};

const CLAIM_WINDOW_MS: u16 = sae_j1939_rs::node::ADDRESS_CLAIM_WINDOW_MS;

fn name_for(identity: u32, manufacturer: u16) -> Name {
    Name::new()
        .with_identity_number(identity)
        .with_manufacturer_code(manufacturer)
}

fn flexible_name(identity: u32, manufacturer: u16) -> Name {
    name_for(identity, manufacturer).with_arbitrary_address_capable(true)
}

/// A node that has already settled on its address, so a test can get to the
/// interesting part.
fn settled_node(name: Name, address: Address) -> Node<1785, 4> {
    let mut node = Node::new(name, address);
    node.start();
    node.tick(CLAIM_WINDOW_MS, |_| {});
    assert!(node.has_address(), "the node should come up uncontested");
    node
}

fn tp_cm_frame(source: Address, destination: Address, cm: &TpCm) -> Frame {
    Frame::from_payload(
        Id::from_parts(Priority::LOWEST, pgn::TP_CM, destination, source).unwrap(),
        cm.encode(),
    )
}

fn tp_dt_frame(source: Address, destination: Address, dt: &TpDt) -> Frame {
    Frame::from_payload(
        Id::from_parts(Priority::LOWEST, pgn::TP_DT, destination, source).unwrap(),
        dt.encode(),
    )
}

fn claim_frame(source: Address, name: Name) -> Frame {
    Frame::from_payload(
        Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, source),
        name.to_bytes(),
    )
}

// ---------------------------------------------------------------------------
// Address contention with more than two ECUs
// ---------------------------------------------------------------------------

/// Three arbitrary-address-capable ECUs powered up wanting the same address.
///
/// Two-way contention always terminates after one exchange; three-way does not,
/// because the ECU that moves can land on top of somebody who has *also* just
/// moved. The property that matters is that it converges at all, and that no two
/// end up on the same address.
#[test]
fn three_ecus_wanting_one_address_converge_on_three_distinct_ones() {
    let wanted = Address::new(0x80);
    let mut ecus = [
        AddressClaimer::new(flexible_name(1, 100), wanted),
        AddressClaimer::new(flexible_name(2, 200), wanted),
        AddressClaimer::new(flexible_name(3, 300), wanted),
    ];

    // Everybody announces at once, and every announcement reaches everybody.
    let mut pending: VecDeque<_> = ecus.iter_mut().map(|ecu| ecu.claim()).collect();

    let mut rounds = 0;
    while let Some(claim) = pending.pop_front() {
        rounds += 1;
        assert!(rounds < 100, "three-way contention failed to settle");
        for ecu in ecus.iter_mut() {
            if let ClaimAction::Announce(next) = ecu.on_address_claimed(claim.source, claim.name) {
                pending.push_back(next);
            }
        }
    }

    for ecu in ecus.iter_mut() {
        ecu.contention_window_elapsed();
    }

    let addresses: Vec<u8> = ecus.iter().map(|e| e.address().as_u8()).collect();
    for (i, a) in addresses.iter().enumerate() {
        assert_eq!(
            ecus[i].state(),
            ClaimState::Claimed,
            "ECU {i} never settled, it is {:?}",
            ecus[i].state()
        );
        assert!(
            (DYNAMIC_ADDRESS_START..=DYNAMIC_ADDRESS_END).contains(a),
            "ECU {i} settled outside the self-configurable range at {a:#04x}"
        );
        for b in addresses.iter().skip(i + 1) {
            assert_ne!(a, b, "two ECUs both ended up on {a:#04x}");
        }
    }
}

/// A fixed-address ECU between two flexible ones keeps its address, and both
/// flexible ones move out of its way.
///
/// This is the arrangement J1939-81's arbitration rule exists for: the ECU that
/// *cannot* move must be the one that stays, and the NAME comparison has to
/// deliver that without anybody coordinating it.
#[test]
fn a_fixed_address_ecu_keeps_its_address_and_the_flexible_ones_move() {
    let contested = Address::new(0x80);

    // The fixed ECU wins on NAME because a lower manufacturer code dominates,
    // and because being arbitrary-address-capable sets the top bit of the NAME.
    let fixed_name = name_for(500, 10);
    let mut fixed = AddressClaimer::new(fixed_name, contested);
    let mut early = AddressClaimer::new(flexible_name(1, 20), contested);
    let mut late = AddressClaimer::new(flexible_name(2, 30), contested);

    let mut pending: VecDeque<_> = [fixed.claim(), early.claim(), late.claim()]
        .into_iter()
        .collect();

    let mut rounds = 0;
    while let Some(claim) = pending.pop_front() {
        rounds += 1;
        assert!(rounds < 100, "contention failed to settle");
        for ecu in [&mut fixed, &mut early, &mut late] {
            if let ClaimAction::Announce(next) = ecu.on_address_claimed(claim.source, claim.name) {
                pending.push_back(next);
            }
        }
    }

    for ecu in [&mut fixed, &mut early, &mut late] {
        ecu.contention_window_elapsed();
    }

    assert_eq!(
        fixed.address(),
        contested,
        "the ECU that cannot move must be the one that keeps the address"
    );
    assert_eq!(fixed.state(), ClaimState::Claimed);
    assert_ne!(early.address(), contested);
    assert_ne!(late.address(), contested);
    assert_ne!(
        early.address(),
        late.address(),
        "the two that moved must not land on each other"
    );
}

/// A whole bus enumerating itself: a tool asks globally for Address Claimed and
/// every ECU answers, including one that has given up.
#[test]
fn a_global_request_is_answered_by_every_node_including_a_displaced_one() {
    let tool = Address::new(0xF9);

    let mut engine = settled_node(name_for(1, 100), Address::new(0x00));
    let mut gearbox = settled_node(name_for(2, 200), Address::new(0x03));
    let mut displaced = settled_node(name_for(3, 300), Address::new(0x21));
    displaced.give_up_address();

    let request = Frame::new(
        Id::from_parts(Priority::DEFAULT, pgn::REQUEST, Address::GLOBAL, tool).unwrap(),
        &Request::new(pgn::ADDRESS_CLAIMED).encode(),
    )
    .unwrap();

    let mut answers = Vec::new();
    for node in [&mut engine, &mut gearbox, &mut displaced] {
        match node.on_frame(&request) {
            Event::Transmit(reply) => {
                assert_eq!(reply.id().pgn(), pgn::ADDRESS_CLAIMED);
                answers.push((
                    reply.id().source_address(),
                    Name::from_bytes(reply.payload()),
                ));
            }
            other => panic!("every ECU must answer a global request, got {other:?}"),
        }
    }

    assert_eq!(answers.len(), 3);
    assert_eq!(answers[0].0, Address::new(0x00));
    assert_eq!(answers[1].0, Address::new(0x03));
    assert_eq!(
        answers[2].0,
        Address::NULL,
        "a displaced ECU answers from the null address, so a tool can tell \
         'gave up' from 'not there'"
    );
    assert_eq!(answers[2].1, name_for(3, 300), "...but still names itself");
}

// ---------------------------------------------------------------------------
// Concurrent transfers between the same pair of ECUs
// ---------------------------------------------------------------------------

/// One side of a two-node exchange: a running [`Node`] plus whatever it is
/// currently sending.
struct Peer<'a> {
    node: Node<1785, 4>,
    outgoing: Outgoing<'a>,
    received: Option<Vec<u8>>,
}

impl<'a> Peer<'a> {
    fn new(
        name: Name,
        address: Address,
        group: sae_j1939_rs::Pgn,
        to: Address,
        data: &'a [u8],
    ) -> Self {
        Peer {
            node: settled_node(name, address),
            outgoing: Outgoing::new(group, address, to, data).unwrap(),
            received: None,
        }
    }

    /// Handle one frame from the other side, returning everything to transmit.
    ///
    /// A real node does both of these for every frame: it offers it to whatever
    /// it is sending, and it dispatches it. Only one of the two ever claims it.
    fn handle(&mut self, frame: &Frame) -> Vec<Frame> {
        let mut out = Vec::new();

        match self.outgoing.on_frame(frame) {
            Progress::Ready => {
                while let Some(next) = self.outgoing.next_frame() {
                    out.push(next);
                }
                return out;
            }
            Progress::Complete => return out,
            Progress::Aborted(reason) => panic!("the transfer was aborted: {reason:?}"),
            // Not part of our transfer, so it is ordinary traffic.
            Progress::Idle => {}
        }

        match self.node.on_frame(frame) {
            Event::Idle => {}
            Event::Transmit(reply) => out.push(reply),
            Event::Message { data, reply, .. } => {
                self.received = Some(data.to_vec());
                out.extend(reply);
            }
        }
        out
    }
}

/// Two ECUs each pushing a multi-packet message to the other at the same time.
///
/// Every connection-management frame on the wire is then ambiguous by address
/// alone: a TP.CM from the peer might belong to the transfer we are sending or
/// to the one we are receiving. Only the PGN inside it separates them, and if a
/// stack does not check it, one transfer's flow control silently drives the
/// other.
#[test]
fn two_nodes_run_multi_packet_transfers_in_both_directions_at_once() {
    let a_address = Address::new(0x80);
    let b_address = Address::new(0x90);
    let a_payload: [u8; 60] = core::array::from_fn(|i| i as u8);
    let b_payload: [u8; 45] = core::array::from_fn(|i| (i * 5) as u8);

    let mut a = Peer::new(name_for(1, 100), a_address, pgn::DM1, b_address, &a_payload);
    let mut b = Peer::new(
        name_for(2, 200),
        b_address,
        pgn::ECU_IDENTIFICATION,
        a_address,
        &b_payload,
    );

    // Both announce before either has heard the other — the interleaving that
    // makes the two sessions overlap for their whole lifetime.
    let mut wire: VecDeque<(bool, Frame)> = VecDeque::new();
    while let Some(frame) = a.outgoing.next_frame() {
        wire.push_back((true, frame));
    }
    while let Some(frame) = b.outgoing.next_frame() {
        wire.push_back((false, frame));
    }

    let mut delivered = 0;
    while let Some((from_a, frame)) = wire.pop_front() {
        delivered += 1;
        assert!(delivered < 500, "the exchange is not making progress");

        let replies = if from_a {
            b.handle(&frame)
        } else {
            a.handle(&frame)
        };
        for reply in replies {
            wire.push_back((!from_a, reply));
        }
    }

    assert_eq!(
        b.received.as_deref(),
        Some(a_payload.as_slice()),
        "B must reassemble A's message intact"
    );
    assert_eq!(
        a.received.as_deref(),
        Some(b_payload.as_slice()),
        "A must reassemble B's message intact"
    );
    assert!(a.outgoing.is_complete(), "A's send was never acknowledged");
    assert!(b.outgoing.is_complete(), "B's send was never acknowledged");
    assert_eq!(a.node.transfers_in_flight(), 0, "A leaked a session");
    assert_eq!(b.node.transfers_in_flight(), 0, "B leaked a session");
}

/// Regression: the peer we are sending to is also sending to us, and it aborts
/// *its* transfer. That abort names its own parameter group, and must not tear
/// down the one we are receiving from it.
#[test]
fn a_peers_abort_of_its_own_transfer_leaves_our_session_with_it_alone() {
    let us = Address::new(0x80);
    let peer = Address::new(0x90);
    let mut node = settled_node(name_for(1, 100), us);

    // The peer starts sending us an ECU identification, and gets one packet in.
    let rts = tp_cm_frame(peer, us, &TpCm::rts(30, pgn::ECU_IDENTIFICATION).unwrap());
    assert!(matches!(node.on_frame(&rts), Event::Transmit(_)));
    let first = tp_dt_frame(peer, us, &TpDt::new(1, &[1; 7]));
    assert_eq!(node.on_frame(&first), Event::Idle);
    assert_eq!(node.transfers_in_flight(), 1);

    // Meanwhile it refuses a DM1 we were trying to push to it.
    let abort = tp_cm_frame(
        peer,
        us,
        &TpCm::Abort {
            reason: AbortReason::ResourcesUnavailable,
            pgn: pgn::DM1,
        },
    );
    assert_eq!(node.on_frame(&abort), Event::Idle);
    assert_eq!(
        node.transfers_in_flight(),
        1,
        "an abort naming DM1 must not drop the ECU identification we are receiving"
    );

    // The identification still completes: thirty bytes is five packets.
    for sequence in 2..5u8 {
        let packet = tp_dt_frame(peer, us, &TpDt::new(sequence, &[sequence; 7]));
        assert_eq!(node.on_frame(&packet), Event::Idle, "packet {sequence}");
    }
    let last = tp_dt_frame(peer, us, &TpDt::new(5, &[5; 7]));
    let outcome = node.on_frame(&last);
    let Event::Message { pgn, data, .. } = outcome else {
        panic!("the surviving transfer should complete, got {outcome:?}");
    };
    assert_eq!(pgn, pgn::ECU_IDENTIFICATION);
    assert_eq!(data.len(), 30);
}

/// Four peers broadcasting at once through one node, with their packets fully
/// interleaved. Each message must come out whole and attributed to the right ECU.
#[test]
fn four_peers_broadcasting_at_once_are_kept_apart() {
    let mut node = settled_node(name_for(1, 100), Address::new(0x80));

    let peers = [
        (Address::new(0x00), pgn::DM1, 0xA0u8),
        (Address::new(0x03), pgn::DM2, 0xB0),
        (Address::new(0x21), pgn::ECU_IDENTIFICATION, 0xC0),
        (Address::new(0xF9), pgn::COMPONENT_IDENTIFICATION, 0xD0),
    ];
    let payloads: Vec<Vec<u8>> = peers
        .iter()
        .map(|(_, _, fill)| (0..20).map(|i| fill ^ i as u8).collect())
        .collect();

    // Every peer announces before any of them sends a packet.
    for (i, (address, group, _)) in peers.iter().enumerate() {
        let bam = tp_cm_frame(
            *address,
            Address::GLOBAL,
            &TpCm::bam(payloads[i].len() as u16, *group).unwrap(),
        );
        assert_eq!(node.on_frame(&bam), Event::Idle);
    }
    assert_eq!(node.transfers_in_flight(), 4, "all four slots in use");

    // Then round-robin their packets: peer 0 packet 1, peer 1 packet 1, ...
    let mut delivered: Vec<Option<(sae_j1939_rs::Pgn, Vec<u8>)>> = vec![None; peers.len()];
    for sequence in 1..=3u8 {
        for (i, (address, _, _)) in peers.iter().enumerate() {
            let offset = (sequence as usize - 1) * 7;
            let end = (offset + 7).min(payloads[i].len());
            let packet = tp_dt_frame(
                *address,
                Address::GLOBAL,
                &TpDt::new(sequence, &payloads[i][offset..end]),
            );
            if let Event::Message {
                pgn, source, data, ..
            } = node.on_frame(&packet)
            {
                assert_eq!(source, *address, "message attributed to the wrong ECU");
                delivered[i] = Some((pgn, data.to_vec()));
            }
        }
    }

    for (i, (_, group, _)) in peers.iter().enumerate() {
        let (pgn, data) = delivered[i]
            .clone()
            .unwrap_or_else(|| panic!("peer {i} never delivered"));
        assert_eq!(pgn, *group, "peer {i} delivered under the wrong PGN");
        assert_eq!(data, payloads[i], "peer {i}'s payload was corrupted");
    }
    assert_eq!(node.transfers_in_flight(), 0, "every slot released");
}

// ---------------------------------------------------------------------------
// A node moving while a transfer is in flight
// ---------------------------------------------------------------------------

/// A node loses arbitration and relocates with somebody's transfer half done.
///
/// Reassembly is keyed by the *sender's* address, not ours, so the session
/// survives the move — but only packets sent to the new address reach it, and
/// anything still addressed to where we used to be is somebody else's traffic
/// now.
#[test]
fn a_node_that_relocates_mid_transfer_keeps_the_session_but_moves_its_ear() {
    let peer = Address::new(0x00);
    let original = Address::new(0x80);
    let mut node = settled_node(flexible_name(1, 300), original);

    let rts = tp_cm_frame(peer, original, &TpCm::rts(21, pgn::DM1).unwrap());
    assert!(matches!(node.on_frame(&rts), Event::Transmit(_)));
    let first = tp_dt_frame(peer, original, &TpDt::new(1, &[1; 7]));
    assert_eq!(node.on_frame(&first), Event::Idle);
    assert_eq!(node.transfers_in_flight(), 1);

    // A stronger NAME takes our address and we move.
    let rival = claim_frame(original, Name::new().with_manufacturer_code(1));
    let Event::Transmit(reply) = node.on_frame(&rival) else {
        panic!("an arbitrary-address-capable node must relocate");
    };
    let relocated = reply.id().source_address();
    assert_ne!(relocated, original);
    assert_eq!(node.claim_state(), ClaimState::Claiming);
    assert_eq!(
        node.transfers_in_flight(),
        1,
        "relocating must not silently drop a transfer already in progress"
    );

    // Traffic still aimed at the old address now belongs to whoever took it.
    let stale = tp_dt_frame(peer, original, &TpDt::new(2, &[2; 7]));
    assert_eq!(
        node.on_frame(&stale),
        Event::Idle,
        "a packet addressed to our old home is not ours to consume"
    );

    // The peer notices and re-addresses; the session picks up where it left off.
    let resumed = tp_dt_frame(peer, relocated, &TpDt::new(2, &[2; 7]));
    assert_eq!(node.on_frame(&resumed), Event::Idle);
    let last = tp_dt_frame(peer, relocated, &TpDt::new(3, &[3; 7]));
    let outcome = node.on_frame(&last);
    let Event::Message { data, reply, .. } = outcome else {
        panic!("the transfer should still complete, got {outcome:?}");
    };
    assert_eq!(
        data,
        &[1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3]
    );

    // ...and the acknowledgement goes out from where we are now, not from where
    // the session started.
    let ack = reply.expect("an RTS/CTS transfer is acknowledged");
    assert_eq!(
        ack.id().source_address(),
        relocated,
        "the acknowledgement must carry our current address"
    );
}

/// A node that gives up entirely while receiving. The peer keeps sending into
/// the void, and the session is reclaimed by the T1 timeout rather than leaking.
#[test]
fn a_node_that_gives_up_mid_transfer_reclaims_the_session_on_timeout() {
    let peer = Address::new(0x00);
    let mut node = settled_node(name_for(1, 300), Address::new(0x80));

    let bam = tp_cm_frame(peer, Address::GLOBAL, &TpCm::bam(21, pgn::DM1).unwrap());
    assert_eq!(node.on_frame(&bam), Event::Idle);
    assert_eq!(node.transfers_in_flight(), 1);

    node.give_up_address();
    assert_eq!(node.claim_state(), ClaimState::CannotClaim);

    // Nothing more arrives for this session, whatever the peer does.
    let mut sent = Vec::new();
    node.tick(T1_TIMEOUT_MS + 1, |frame| sent.push(frame));
    assert_eq!(
        node.transfers_in_flight(),
        0,
        "the session must be reclaimed"
    );
    assert!(
        sent.is_empty(),
        "a broadcast has no back-channel, so there is nothing to abort"
    );
}

// ---------------------------------------------------------------------------
// Reassembler transitions the module tests do not reach
// ---------------------------------------------------------------------------

/// A BAM from a fifth peer when every slot is busy is dropped, not squeezed in.
///
/// The RTS case answers with a resources-unavailable abort; a BAM has no
/// back-channel, so silence is all there is — but the existing sessions must be
/// untouched.
#[test]
fn a_broadcast_from_a_new_peer_with_no_slot_free_is_dropped() {
    let mut rx = Reassembler::<256, 2>::new();
    let first = Address::new(0x01);
    let second = Address::new(0x02);

    rx.on_tp_cm(first, &TpCm::bam(14, pgn::DM1).unwrap());
    rx.on_tp_cm(second, &TpCm::bam(14, pgn::DM2).unwrap());
    assert_eq!(rx.active_sessions(), 2);

    let newcomer = Address::new(0x03);
    assert_eq!(
        rx.on_tp_cm(newcomer, &TpCm::bam(14, pgn::ECU_IDENTIFICATION).unwrap()),
        Rx::Idle
    );
    assert!(!rx.is_receiving_from(newcomer));
    assert_eq!(
        rx.active_sessions(),
        2,
        "the sitting sessions are untouched"
    );
    assert!(rx.is_receiving_from(first));
    assert!(rx.is_receiving_from(second));
}

/// A peer that abandons a broadcast and immediately announces a different one
/// takes over its own slot rather than being refused.
///
/// A BAM cannot be aborted, so a sender that gives up halfway simply stops. If
/// its slot stayed occupied, the peer would be locked out until T1.
#[test]
fn a_new_announcement_from_the_same_peer_replaces_its_abandoned_one() {
    let peer = Address::new(0x90);
    let mut rx = Reassembler::<256>::new();

    // A broadcast that stops after one packet.
    rx.on_tp_cm(peer, &TpCm::bam(21, pgn::DM1).unwrap());
    rx.on_tp_dt(peer, &TpDt::new(1, &[0xAA; 7]));

    // The same peer starts a different one, and it goes through cleanly.
    assert_eq!(
        rx.on_tp_cm(peer, &TpCm::bam(14, pgn::DM2).unwrap()),
        Rx::Idle
    );
    assert_eq!(
        rx.active_sessions(),
        1,
        "the peer still has just one session"
    );
    rx.on_tp_dt(peer, &TpDt::new(1, &[1; 7]));
    match rx.on_tp_dt(peer, &TpDt::new(2, &[2; 7])) {
        Rx::Message { pgn, data, .. } => {
            assert_eq!(pgn, pgn::DM2, "the new announcement wins");
            assert_eq!(data, &[1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2]);
        }
        other => panic!("the replacement transfer should complete, got {other:?}"),
    }
}

/// An RTS from a peer that has a *broadcast* in flight is accepted, because the
/// "one session per peer" rule only bars a second connection-managed one.
#[test]
fn an_rts_takes_over_from_the_same_peers_broadcast() {
    let peer = Address::new(0x90);
    let mut rx = Reassembler::<256>::new();
    rx.on_tp_cm(peer, &TpCm::bam(21, pgn::DM1).unwrap());

    assert_eq!(
        rx.on_tp_cm(peer, &TpCm::rts(14, pgn::DM2).unwrap()),
        Rx::Send(TpCm::Cts {
            packets: 2,
            next_packet: 1,
            pgn: pgn::DM2,
        }),
        "a broadcast is not a connection-managed session, so it does not block one"
    );
    assert_eq!(rx.active_sessions(), 1);
}

/// The two sender-side messages, fed to a receiver. They belong to a
/// [`Transmitter`](sae_j1939_rs::tp::Transmitter) and must pass straight
/// through — in particular they must not be mistaken for progress on the
/// session we are receiving.
#[test]
fn sender_side_connection_management_does_not_disturb_a_receiver() {
    let peer = Address::new(0x90);
    let mut rx = Reassembler::<256>::new();
    rx.on_tp_cm(peer, &TpCm::rts(21, pgn::DM1).unwrap());
    rx.on_tp_dt(peer, &TpDt::new(1, &[1; 7]));

    for stray in [
        TpCm::Cts {
            packets: 3,
            next_packet: 1,
            pgn: pgn::DM1,
        },
        TpCm::EndOfMsgAck {
            size: 21,
            packets: 3,
            pgn: pgn::DM1,
        },
    ] {
        assert_eq!(rx.on_tp_cm(peer, &stray), Rx::Idle, "{stray:?}");
        assert!(rx.is_receiving_from(peer), "{stray:?} ended the session");
    }

    // The transfer still completes exactly where it was.
    rx.on_tp_dt(peer, &TpDt::new(2, &[2; 7]));
    assert!(matches!(
        rx.on_tp_dt(peer, &TpDt::new(3, &[3; 7])),
        Rx::Message { .. }
    ));
}

/// Every slot times out, and the reassembler is then as usable as it was new.
/// A stack that only ever loses capacity is a stack that stops working after a
/// day on a noisy bus.
#[test]
fn a_reassembler_recovers_every_slot_after_its_peers_go_quiet() {
    let mut rx = Reassembler::<256, 3>::new();
    let peers = [Address::new(0x01), Address::new(0x02), Address::new(0x03)];

    for round in 0..3 {
        for peer in peers {
            rx.on_tp_cm(peer, &TpCm::rts(21, pgn::DM1).unwrap());
        }
        assert_eq!(rx.active_sessions(), 3, "round {round}: slots not refilled");

        let mut expired = Vec::new();
        rx.tick(T1_TIMEOUT_MS + 1, |address, abort| {
            expired.push((address, abort))
        });
        assert_eq!(expired.len(), 3, "round {round}: not every session expired");
        for (_, abort) in &expired {
            assert!(
                matches!(
                    abort,
                    Some(TpCm::Abort {
                        reason: AbortReason::Timeout,
                        ..
                    })
                ),
                "round {round}: a stalled RTS/CTS session must be aborted"
            );
        }
        assert_eq!(rx.active_sessions(), 0, "round {round}: slots not released");
    }
}

// ---------------------------------------------------------------------------
// AddressClaimer transitions the module tests do not reach
// ---------------------------------------------------------------------------

/// An ECU that has given up stays given up, whatever else happens on the bus.
///
/// It is off the air by definition: it holds no address, so nothing can contend
/// with it, and it must not wake up because somebody else's claim went past.
#[test]
fn a_displaced_ecu_ignores_further_contention() {
    let mut ecu = AddressClaimer::new(name_for(100, 300), Address::new(0x80));
    ecu.claim();
    ecu.contention_window_elapsed();
    ecu.give_up();
    assert_eq!(ecu.state(), ClaimState::CannotClaim);

    for (address, name) in [
        (Address::new(0x80), Name::new().with_manufacturer_code(1)),
        (Address::NULL, Name::new().with_manufacturer_code(9000)),
        (Address::new(0x90), name_for(7, 700)),
    ] {
        assert_eq!(
            ecu.on_address_claimed(address, name),
            ClaimAction::Idle,
            "a displaced ECU must stay quiet, but reacted to a claim on {address}"
        );
        assert_eq!(ecu.state(), ClaimState::CannotClaim);
        assert_eq!(ecu.address(), Address::NULL);
    }

    // It does keep watching who is out there, so a later restart is informed.
    assert!(ecu.is_address_taken(Address::new(0x90)));
    assert!(
        !ecu.is_address_taken(Address::NULL),
        "the null address is nobody's, so it is never 'taken'"
    );
}

/// Closing a contention window that is not open changes nothing, from any state.
/// A caller with a free-running 250 ms timer will do this constantly.
#[test]
fn closing_a_contention_window_that_is_not_open_is_harmless() {
    // Never claimed.
    let mut idle = AddressClaimer::new(name_for(1, 300), Address::new(0x80));
    idle.contention_window_elapsed();
    assert_eq!(idle.state(), ClaimState::Idle);
    assert_eq!(idle.address(), Address::new(0x80));

    // Already settled.
    let mut claimed = AddressClaimer::new(name_for(1, 300), Address::new(0x80));
    claimed.claim();
    claimed.contention_window_elapsed();
    claimed.contention_window_elapsed();
    assert_eq!(claimed.state(), ClaimState::Claimed);

    // Given up: the window must not resurrect it.
    let mut displaced = AddressClaimer::new(name_for(1, 300), Address::new(0x80));
    displaced.claim();
    displaced.give_up();
    displaced.contention_window_elapsed();
    assert_eq!(displaced.state(), ClaimState::CannotClaim);
    assert_eq!(displaced.address(), Address::NULL);
}

/// A claimer told to want a reserved address cannot have it. `0xFE` and `0xFF`
/// are not addresses an ECU may hold, so the claim is a Cannot Claim from the
/// start rather than something that "succeeds" 250 ms later.
#[test]
fn a_reserved_preferred_address_is_never_claimed() {
    for preferred in [Address::NULL, Address::GLOBAL] {
        let mut ecu = AddressClaimer::new(name_for(1, 300), preferred);
        let claim = ecu.claim();

        assert!(
            claim.is_cannot_claim(),
            "claiming {preferred} should announce Cannot Claim"
        );
        assert_eq!(ecu.state(), ClaimState::CannotClaim);
        ecu.contention_window_elapsed();
        assert_eq!(
            ecu.state(),
            ClaimState::CannotClaim,
            "the window must not hand it {preferred}"
        );
    }
}

// ---------------------------------------------------------------------------
// Node dispatch paths the module tests do not reach
// ---------------------------------------------------------------------------

/// Regression: an RTS sent to the global address draws no CTS.
///
/// An RTS is destination-specific by definition. If a node answered a broadcast
/// one, a single malformed frame would make every ECU on the bus transmit a CTS
/// at the same instant — and each would then sit on a session slot waiting for
/// data that is not coming.
#[test]
fn a_globally_addressed_rts_is_ignored_rather_than_answered() {
    let mut node = settled_node(name_for(1, 300), Address::new(0x80));
    let sender = Address::new(0x00);

    let rts = tp_cm_frame(sender, Address::GLOBAL, &TpCm::rts(21, pgn::DM1).unwrap());
    assert_eq!(
        node.on_frame(&rts),
        Event::Idle,
        "a broadcast RTS must not draw a CTS from every listener"
    );
    assert_eq!(node.transfers_in_flight(), 0, "and must not open a session");

    // A properly addressed RTS is still answered.
    let addressed = tp_cm_frame(
        sender,
        Address::new(0x80),
        &TpCm::rts(21, pgn::DM1).unwrap(),
    );
    assert!(matches!(node.on_frame(&addressed), Event::Transmit(_)));
    assert_eq!(node.transfers_in_flight(), 1);
}

/// A connection-management frame with a control byte J1939-21 does not define is
/// dropped. The sender's own timeout closes it out — there is nothing useful to
/// say back to an ECU that is speaking a protocol we do not recognise.
#[test]
fn an_undecodable_connection_management_frame_is_dropped() {
    let mut node = settled_node(name_for(1, 300), Address::new(0x80));
    let sender = Address::new(0x00);

    let nonsense = Frame::from_payload(
        Id::from_parts(Priority::LOWEST, pgn::TP_CM, Address::new(0x80), sender).unwrap(),
        [0x42, 0, 0, 0, 0, 0xCA, 0xFE, 0x00],
    );
    assert_eq!(node.on_frame(&nonsense), Event::Idle);
    assert_eq!(node.transfers_in_flight(), 0);
}

/// A Request too short to name a parameter group is handed to the application
/// rather than swallowed. The node only intercepts requests it can answer
/// itself, and it cannot answer one it cannot read.
#[test]
fn a_malformed_request_is_still_delivered_to_the_application() {
    let mut node = settled_node(name_for(1, 300), Address::new(0x80));
    let sender = Address::new(0xF9);

    let truncated = Frame::new(
        Id::from_parts(Priority::DEFAULT, pgn::REQUEST, Address::new(0x80), sender).unwrap(),
        &[0xCA, 0xFE], // Two bytes; a Request needs three.
    )
    .unwrap();

    match node.on_frame(&truncated) {
        Event::Message {
            pgn, source, data, ..
        } => {
            assert_eq!(pgn, pgn::REQUEST);
            assert_eq!(source, sender);
            assert_eq!(data, &[0xCA, 0xFE]);
        }
        other => panic!("expected the request to be delivered, got {other:?}"),
    }
}

/// A transfer at the protocol's ceiling — 1785 bytes in 255 packets — through
/// the whole node stack. The last packet is the one where a sequence counter
/// held in a `u8` would wrap, and the announcement is the one where the packet
/// count is exactly `u8::MAX`.
#[test]
fn the_largest_possible_message_survives_the_node_stack() {
    let sender = Address::new(0x00);
    let payload: [u8; 1785] = core::array::from_fn(|i| (i % 251) as u8);
    let mut node = settled_node(name_for(1, 300), Address::new(0x80));

    let mut outgoing = Outgoing::new(pgn::DM1, sender, Address::GLOBAL, &payload).unwrap();
    assert_eq!(
        outgoing.frame_count(),
        256,
        "one announcement plus 255 data packets"
    );

    let mut frames = 0;
    let mut delivered = None;
    while let Some(frame) = outgoing.next_frame() {
        frames += 1;
        if let Event::Message { pgn, data, .. } = node.on_frame(&frame) {
            assert_eq!(pgn, pgn::DM1);
            delivered = Some(data.to_vec());
        }
    }

    assert_eq!(frames, 256, "every frame must actually be produced");
    assert_eq!(
        delivered.as_deref(),
        Some(payload.as_slice()),
        "the 1785-byte ceiling must survive intact"
    );
    assert_eq!(node.transfers_in_flight(), 0);
}

// ---------------------------------------------------------------------------
// Outgoing transitions the module tests do not reach
// ---------------------------------------------------------------------------

/// Nothing a peer says can affect a message that fits in one frame. There is no
/// session to grant, complete, or abort.
#[test]
fn a_single_frame_message_ignores_every_reply() {
    let peer = Address::new(0x90);
    let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &[1, 2, 3]).unwrap();

    for cm in [
        TpCm::Cts {
            packets: 3,
            next_packet: 1,
            pgn: pgn::DM1,
        },
        TpCm::EndOfMsgAck {
            size: 21,
            packets: 3,
            pgn: pgn::DM1,
        },
        TpCm::Abort {
            reason: AbortReason::Timeout,
            pgn: pgn::DM1,
        },
    ] {
        let frame = tp_cm_frame(peer, Address::new(0x80), &cm);
        assert_eq!(tx.on_frame(&frame), Progress::Idle, "{cm:?}");
    }

    assert!(tx.next_frame().is_some(), "the one frame is still pending");
    assert!(tx.is_complete());
}

/// Regression: connection management naming a different parameter group is not
/// ours, even when it comes from exactly the ECU we are talking to.
#[test]
fn a_transfer_ignores_connection_management_for_another_parameter_group() {
    let us = Address::new(0x80);
    let peer = Address::new(0x90);
    let mut tx = Outgoing::new(pgn::DM1, us, peer, &[0; 21]).unwrap();
    tx.next_frame().expect("the RTS");

    // A CTS for the peer's own transfer must not open our window...
    let foreign_cts = tp_cm_frame(
        peer,
        us,
        &TpCm::Cts {
            packets: 3,
            next_packet: 1,
            pgn: pgn::ECU_IDENTIFICATION,
        },
    );
    assert_eq!(tx.on_frame(&foreign_cts), Progress::Idle);
    assert!(
        tx.next_frame().is_none(),
        "a CTS for another group must not release our packets"
    );

    // ...nor complete us...
    let foreign_ack = tp_cm_frame(
        peer,
        us,
        &TpCm::EndOfMsgAck {
            size: 30,
            packets: 5,
            pgn: pgn::ECU_IDENTIFICATION,
        },
    );
    assert_eq!(tx.on_frame(&foreign_ack), Progress::Idle);
    assert!(!tx.is_complete());

    // ...nor abort us.
    let foreign_abort = tp_cm_frame(
        peer,
        us,
        &TpCm::Abort {
            reason: AbortReason::Timeout,
            pgn: pgn::ECU_IDENTIFICATION,
        },
    );
    assert_eq!(tx.on_frame(&foreign_abort), Progress::Idle);

    // Our own CTS still works.
    let ours = tp_cm_frame(
        peer,
        us,
        &TpCm::Cts {
            packets: 3,
            next_packet: 1,
            pgn: pgn::DM1,
        },
    );
    assert_eq!(tx.on_frame(&ours), Progress::Ready);
    assert!(tx.next_frame().is_some());
}

/// Frames that are not connection management, and connection management that
/// does not decode, both leave a transfer where it was.
#[test]
fn unrelated_traffic_does_not_move_a_transfer_along() {
    let us = Address::new(0x80);
    let peer = Address::new(0x90);
    let mut tx = Outgoing::new(pgn::DM1, us, peer, &[0; 21]).unwrap();
    tx.next_frame().expect("the RTS");

    // A data-transfer frame from the peer: part of *its* transfer, not ours.
    let data = tp_dt_frame(peer, us, &TpDt::new(1, &[0; 7]));
    assert_eq!(tx.on_frame(&data), Progress::Idle);

    // An ordinary broadcast.
    let dm1 = Frame::from_payload(
        Id::broadcast(Priority::DEFAULT, pgn::DM1, peer),
        [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF],
    );
    assert_eq!(tx.on_frame(&dm1), Progress::Idle);

    // A TP.CM whose control byte means nothing.
    let nonsense = Frame::from_payload(
        Id::from_parts(Priority::LOWEST, pgn::TP_CM, us, peer).unwrap(),
        [0x42, 0, 0, 0, 0, 0xCA, 0xFE, 0x00],
    );
    assert_eq!(tx.on_frame(&nonsense), Progress::Idle);

    assert!(tx.next_frame().is_none(), "still waiting for a real CTS");
    assert!(!tx.is_complete());
}

/// A message the transport protocol cannot carry is refused when it is built,
/// not part-way through sending it.
#[test]
fn a_message_too_large_for_the_protocol_is_refused_up_front() {
    let source = Address::new(0x80);
    assert!(
        Outgoing::new(pgn::DM1, source, Address::GLOBAL, &[0; 1785]).is_ok(),
        "1785 bytes is the ceiling, not one past it"
    );
    assert!(
        Outgoing::new(pgn::DM1, source, Address::GLOBAL, &[0; 1786]).is_err(),
        "1786 bytes cannot be numbered by a one-byte sequence field"
    );
    assert!(
        Outgoing::new(pgn::DM1, source, Address::new(0x90), &[0; 1786]).is_err(),
        "...addressed either"
    );
}
