// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A whole ECU in one type: address claiming, reassembly, and dispatch.
//!
//! The protocol modules are deliberately separate, because a real ECU often
//! wants only some of them. But wiring them together correctly — filtering
//! frames by destination, routing transport-protocol traffic to the
//! reassembler, answering address-claim requests, remembering to send the CTS
//! the reassembler asked for — is the same every time, and easy to get subtly
//! wrong.
//!
//! [`Node`] does that wiring. Feed it every frame off the bus and it tells you
//! what to transmit and what arrived, with multi-packet messages already
//! reassembled.
//!
//! ```
//! use sae_j1939_rs::node::{Event, Node};
//! use sae_j1939_rs::{Address, Name};
//!
//! let name = Name::new().with_manufacturer_code(300).with_identity_number(1);
//! // Accept messages up to 256 bytes; track one peer at a time.
//! let mut node = Node::<256>::new(name, Address::new(0x80));
//!
//! // Announce ourselves, then wait out the contention window.
//! let claim = node.start();
//! assert_eq!(claim.id().pgn(), sae_j1939_rs::pgn::ADDRESS_CLAIMED);
//!
//! node.tick(250, |_frame| { /* transmit */ });
//! assert!(node.has_address());
//! ```
//!
//! # It is still sans-I/O
//!
//! `Node` owns no bus and no clock. You give it frames and elapsed
//! milliseconds; it gives you frames back. That keeps it testable and lets the
//! same code run on a host and a bare-metal MCU.

use crate::address_claim::{AddressClaimer, ClaimAction, ClaimState};
use crate::frame::Frame;
use crate::frame::MAX_PAYLOAD;
use crate::id::Id;
use crate::name::Name;
use crate::pgn::{self, Pgn};
use crate::request::Request;
use crate::tp::{AbortReason, Reassembler, Rx, TpCm, TpDt, Transmitter, Tx};
use crate::types::{Address, Priority, Result};

/// How long J1939-81 gives other ECUs to contest an address claim.
pub const ADDRESS_CLAIM_WINDOW_MS: u16 = 250;

/// What a [`Node`] wants after handling a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// Nothing to do.
    Idle,
    /// Put this frame on the bus.
    Transmit(Frame),
    /// A complete message arrived, single-frame or reassembled.
    Message {
        /// The parameter group carried.
        pgn: Pgn,
        /// The ECU that sent it.
        source: Address,
        /// The payload.
        data: &'a [u8],
        /// A frame the protocol requires in response — the end-of-message
        /// acknowledgement closing an RTS/CTS transfer. Transmit it if present.
        reply: Option<Frame>,
    },
}

/// What an [`Outgoing`] message wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Nothing to do — wait for the peer, or for the pacing interval.
    Idle,
    /// More frames are ready; pull them with [`Outgoing::next_frame`].
    Ready,
    /// The whole message has been sent, and acknowledged if it needed to be.
    Complete,
    /// The peer aborted the transfer.
    Aborted(AbortReason),
}

/// A message on its way out, however many frames that takes.
///
/// Sending a J1939 message is not one decision but three: does it fit in a
/// frame, is it addressed or broadcast, and if it is neither short nor
/// broadcast, who drives the handshake? `Outgoing` answers all three and hands
/// back frames.
///
/// It borrows the payload rather than copying it, so a 1785-byte message costs
/// no extra RAM — the point of the type on a microcontroller.
///
/// ```
/// use sae_j1939_rs::node::Outgoing;
/// use sae_j1939_rs::{pgn, Address};
///
/// // Eight bytes or fewer: a single frame, done.
/// let mut short = Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &[0; 8]).unwrap();
/// assert!(short.next_frame().is_some());
/// assert!(short.next_frame().is_none());
/// assert!(short.is_complete());
///
/// // Longer, and broadcast: a BAM announcement followed by data packets.
/// let mut long = Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &[0; 14]).unwrap();
/// assert!(long.needs_pacing(), "BAM packets must be spaced 50-200 ms apart");
/// assert_eq!(long.frame_count(), 3); // announcement plus two packets
/// while long.next_frame().is_some() {}
/// assert!(long.is_complete());
/// ```
///
/// A destination-specific message longer than eight bytes needs the peer's
/// permission, so feed replies back with [`Outgoing::on_frame`]:
///
/// ```
/// # use sae_j1939_rs::node::{Outgoing, Progress};
/// # use sae_j1939_rs::{pgn, Address};
/// let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), Address::new(0x90), &[0; 14]).unwrap();
/// let rts = tx.next_frame().expect("the request to send");
/// assert!(tx.next_frame().is_none(), "nothing more until the peer answers");
/// assert!(!tx.needs_pacing(), "RTS/CTS is flow-controlled, not timed");
/// # let _ = (rts, Progress::Idle);
/// ```
#[derive(Debug)]
pub struct Outgoing<'a> {
    pgn: Pgn,
    priority: Priority,
    source: Address,
    destination: Address,
    state: OutgoingState<'a>,
}

#[derive(Debug)]
enum OutgoingState<'a> {
    /// A message that fits one frame. The payload is kept rather than a built
    /// frame so that `with_priority` stays a plain field assignment.
    Single { data: &'a [u8], sent: bool },
    /// A message crossing the transport protocol.
    Multi {
        transmitter: Transmitter<'a>,
        announced: bool,
    },
}

impl<'a> Outgoing<'a> {
    /// Prepare `data` for transmission as parameter group `pgn`.
    ///
    /// Picks the mechanism for you: a single frame if it fits, a BAM if it does
    /// not and `destination` is [`Address::GLOBAL`], and an RTS/CTS handshake
    /// otherwise.
    ///
    /// Returns [`Error::InvalidMessageSize`](crate::Error::InvalidMessageSize)
    /// for a multi-frame message outside the protocol's 9..=1785 byte range, or
    /// [`Error::DestinationMismatch`](crate::Error::DestinationMismatch) if a
    /// PDU2 parameter group is addressed to a specific ECU.
    pub fn new(pgn: Pgn, source: Address, destination: Address, data: &'a [u8]) -> Result<Self> {
        let priority = Priority::DEFAULT;
        let state = if data.len() <= MAX_PAYLOAD {
            // Validate now so `next_frame` cannot fail later.
            let id = Id::from_parts(priority, pgn, destination, source)?;
            Frame::new(id, data)?;
            OutgoingState::Single { data, sent: false }
        } else if destination.is_broadcast() {
            OutgoingState::Multi {
                transmitter: Transmitter::broadcast(pgn, data)?,
                announced: false,
            }
        } else {
            OutgoingState::Multi {
                transmitter: Transmitter::addressed(pgn, data)?,
                announced: false,
            }
        };
        Ok(Outgoing {
            pgn,
            priority,
            source,
            destination,
            state,
        })
    }

    /// Send the single-frame case at a priority other than
    /// [`Priority::DEFAULT`].
    ///
    /// Transport-protocol frames always use [`Priority::LOWEST`], as J1939-21
    /// requires, so this affects only messages that fit one frame.
    #[must_use]
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Whether the caller must space frames out.
    ///
    /// True only for a BAM: J1939-21 requires 50–200 ms between broadcast data
    /// packets, and nothing acknowledges them, so a receiver on a busy bus will
    /// drop a transfer sent back to back. An RTS/CTS transfer is flow-controlled
    /// by the peer instead, and a single frame needs no pacing at all.
    pub fn needs_pacing(&self) -> bool {
        matches!(&self.state, OutgoingState::Multi { transmitter, .. }
            if self.destination.is_broadcast() && transmitter.packets() > 0)
    }

    /// How many frames this message will take in total.
    pub fn frame_count(&self) -> usize {
        match &self.state {
            OutgoingState::Single { .. } => 1,
            // The announcement plus one frame per packet.
            OutgoingState::Multi { transmitter, .. } => 1 + transmitter.packets() as usize,
        }
    }

    /// Whether everything has been sent, and acknowledged if it had to be.
    pub fn is_complete(&self) -> bool {
        match &self.state {
            OutgoingState::Single { sent, .. } => *sent,
            OutgoingState::Multi { transmitter, .. } => transmitter.is_complete(),
        }
    }

    /// The next frame to put on the bus.
    ///
    /// `None` means there is nothing to send *right now*: either the message is
    /// finished, or an RTS/CTS transfer is waiting for the peer to grant another
    /// window. Check [`Outgoing::is_complete`] to tell the two apart.
    pub fn next_frame(&mut self) -> Option<Frame> {
        let (priority, pgn, source, destination) =
            (self.priority, self.pgn, self.source, self.destination);
        match &mut self.state {
            OutgoingState::Single { data, sent } => {
                if *sent {
                    return None;
                }
                // Marked sent first: both calls below were validated in `new`,
                // and treating an impossible failure as "nothing more to send"
                // is better than hanging a caller that loops until complete.
                *sent = true;
                let id = Id::from_parts(priority, pgn, destination, source).ok()?;
                Frame::new(id, data).ok()
            }
            OutgoingState::Multi {
                transmitter,
                announced,
            } => {
                if !*announced {
                    *announced = true;
                    let id = tp_id(pgn::TP_CM, destination, source)?;
                    return Some(Frame::from_payload(id, transmitter.start().encode()));
                }
                let packet = transmitter.next_packet()?;
                let id = tp_id(pgn::TP_DT, destination, source)?;
                Some(Frame::from_payload(id, packet.encode()))
            }
        }
    }

    /// Feed back a frame received from the peer.
    ///
    /// Only connection-management frames from this message's destination matter;
    /// anything else is reported as [`Progress::Idle`] and should be handled
    /// normally.
    pub fn on_frame(&mut self, frame: &Frame) -> Progress {
        let OutgoingState::Multi { transmitter, .. } = &mut self.state else {
            return Progress::Idle;
        };
        if frame.pgn() != pgn::TP_CM || frame.source_address() != self.destination {
            return Progress::Idle;
        }
        let Ok(cm) = TpCm::decode(frame.payload()) else {
            return Progress::Idle;
        };
        match transmitter.on_tp_cm(&cm) {
            Tx::SendData => Progress::Ready,
            Tx::Complete => Progress::Complete,
            Tx::Aborted(reason) => Progress::Aborted(reason),
            Tx::Idle => Progress::Idle,
        }
    }
}

/// Transport-protocol frames are priority 7 so bulk transfers yield to control
/// traffic.
fn tp_id(group: Pgn, destination: Address, source: Address) -> Option<Id> {
    Id::from_parts(Priority::LOWEST, group, destination, source).ok()
}

/// One J1939 node: a NAME, an address, and the machinery to keep them.
///
/// `BUF` is the largest message this node will accept, and `SESSIONS` how many
/// peers may be mid-transfer at once (see [`Reassembler`]).
#[derive(Debug)]
pub struct Node<const BUF: usize, const SESSIONS: usize = 1> {
    claimer: AddressClaimer,
    reassembler: Reassembler<BUF, SESSIONS>,
    /// Milliseconds since the current claim was broadcast.
    claim_elapsed_ms: u16,
}

impl<const BUF: usize, const SESSIONS: usize> Node<BUF, SESSIONS> {
    /// Create a node that will try to claim `preferred`.
    ///
    /// Nothing goes on the bus until [`Node::start`] is called.
    pub const fn new(name: Name, preferred: Address) -> Self {
        Node {
            claimer: AddressClaimer::new(name, preferred),
            reassembler: Reassembler::new(),
            claim_elapsed_ms: 0,
        }
    }

    /// This node's NAME.
    pub const fn name(&self) -> Name {
        self.claimer.name()
    }

    /// The address currently held or being claimed.
    pub const fn address(&self) -> Address {
        self.claimer.address()
    }

    /// Where the node stands in the address-claiming protocol.
    pub const fn claim_state(&self) -> ClaimState {
        self.claimer.state()
    }

    /// Whether the node holds a usable address and may transmit freely.
    pub fn has_address(&self) -> bool {
        self.claim_state() == ClaimState::Claimed
    }

    /// Read-only access to the address claimer, for the addresses it has seen.
    pub const fn claimer(&self) -> &AddressClaimer {
        &self.claimer
    }

    /// How many multi-packet transfers are being reassembled.
    pub fn transfers_in_flight(&self) -> usize {
        self.reassembler.active_sessions()
    }

    /// Broadcast the initial address claim.
    ///
    /// Transmit the returned frame, then drive [`Node::tick`]; after
    /// [`ADDRESS_CLAIM_WINDOW_MS`] with no contest the address is held.
    pub fn start(&mut self) -> Frame {
        let claim = self.claimer.claim();
        self.claim_elapsed_ms = 0;
        address_claim_frame(claim.source, claim.name)
    }

    /// Advance the node's timers by `elapsed_ms`.
    ///
    /// This closes the address-claim contention window and expires stalled
    /// transport-protocol sessions, calling `on_transmit` for any frame that
    /// has to go out as a result (a connection abort, in practice).
    pub fn tick(&mut self, elapsed_ms: u16, mut on_transmit: impl FnMut(Frame)) {
        if self.claimer.state() == ClaimState::Claiming {
            self.claim_elapsed_ms = self.claim_elapsed_ms.saturating_add(elapsed_ms);
            if self.claim_elapsed_ms >= ADDRESS_CLAIM_WINDOW_MS {
                self.claimer.contention_window_elapsed();
            }
        }

        let source = self.claimer.address();
        self.reassembler.tick(elapsed_ms, |peer, abort| {
            if let Some(abort) = abort {
                if let Some(frame) = tp_cm_frame(source, peer, &abort) {
                    on_transmit(frame);
                }
            }
        });
    }

    /// Handle one frame off the bus.
    ///
    /// Frames addressed to another ECU are ignored. Address-claim traffic is
    /// routed to the claimer, transport-protocol traffic to the reassembler,
    /// and everything else is delivered as a [`Event::Message`].
    ///
    /// The returned payload borrows either `frame` (for a single-frame message,
    /// which costs no copy) or the node's reassembly buffer, so both must
    /// outlive the event. Handle the event before feeding in the next frame.
    pub fn on_frame<'a>(&'a mut self, frame: &'a Frame) -> Event<'a> {
        let id = frame.id();
        let source = id.source_address();
        let group = id.pgn();

        if !id.is_addressed_to(self.claimer.address()) {
            return Event::Idle;
        }

        if group == pgn::ADDRESS_CLAIMED {
            let action = self
                .claimer
                .on_address_claimed(source, Name::from_bytes(frame.payload()));
            return self.act_on_claim(action);
        }

        if group == pgn::REQUEST {
            // A request for our NAME is ours to answer; anything else is for
            // the application to decide about.
            if let Ok(request) = Request::decode(frame.data()) {
                if request.pgn == pgn::ADDRESS_CLAIMED {
                    let action = self.claimer.on_request();
                    return self.act_on_claim(action);
                }
            }
        }

        if group == pgn::TP_CM {
            return match TpCm::decode(frame.payload()) {
                // An RTS is destination-specific by definition, and a broadcast
                // one is not merely malformed but dangerous: every ECU that
                // answered it would put a CTS on the bus, turning one bad frame
                // into a storm. A broadcast transfer is announced with a BAM.
                Ok(TpCm::Rts { .. }) if id.is_broadcast() => Event::Idle,
                Ok(cm) => {
                    let address = self.claimer.address();
                    Self::lift(self.reassembler.on_tp_cm(source, &cm), address, source)
                }
                // A malformed connection-management frame is not worth aborting
                // over; the sender will time out.
                Err(_) => Event::Idle,
            };
        }

        if group == pgn::TP_DT {
            let address = self.claimer.address();
            let dt = TpDt::decode(frame.payload());
            return Self::lift(self.reassembler.on_tp_dt(source, &dt), address, source);
        }

        Event::Message {
            pgn: group,
            source,
            data: frame.data(),
            reply: None,
        }
    }

    /// Act on a Commanded Address (PGN `0x00FED8`), taking the address it
    /// names.
    ///
    /// This is network management rather than application data, but it does not
    /// happen inside [`Node::on_frame`]: the message is nine bytes, so it always
    /// arrives reassembled, and the delivered payload borrows the reassembly
    /// buffer. Handling it in place would mean copying that buffer on *every*
    /// completed message on the chance this was the one. So route it here
    /// instead — one line, and no cost to messages that are not commands:
    ///
    /// ```
    /// # use sae_j1939_rs::node::{Event, Node};
    /// # use sae_j1939_rs::{pgn, Address, Frame, Name};
    /// # fn example(node: &mut Node<256>, frame: &Frame, send: impl Fn(Frame)) {
    /// match node.on_frame(frame) {
    ///     Event::Message { pgn, data, .. } if pgn == pgn::COMMANDED_ADDRESS => {
    ///         // Copy out before the borrow ends, then act.
    ///         let mut command = [0u8; 9];
    ///         command.copy_from_slice(&data[..9]);
    ///         if let Ok(Some(claim)) = node.on_commanded_address(&command) {
    ///             send(claim); // announce the new address
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// Returns the Address Claimed frame to broadcast, or `None` if the command
    /// named a different ECU. A command naming a reserved address is rejected —
    /// see [`AddressClaimer::on_commanded_address`].
    ///
    /// The node re-enters [`ClaimState::Claiming`]: a new address has to be
    /// claimed like any other, so drive [`Node::tick`] until the window closes.
    pub fn on_commanded_address(&mut self, data: &[u8]) -> Result<Option<Frame>> {
        match self.claimer.on_commanded_address(data)? {
            ClaimAction::Announce(claim) => {
                self.claim_elapsed_ms = 0;
                Ok(Some(address_claim_frame(claim.source, claim.name)))
            }
            ClaimAction::Idle => Ok(None),
        }
    }

    /// Give up this node's address, producing the Cannot Claim Address
    /// broadcast to send.
    pub fn give_up_address(&mut self) -> Frame {
        let claim = self.claimer.give_up();
        address_claim_frame(claim.source, claim.name)
    }

    fn act_on_claim<'a>(&mut self, action: ClaimAction) -> Event<'a> {
        match action {
            ClaimAction::Idle => Event::Idle,
            ClaimAction::Announce(claim) => {
                // A fresh claim reopens the contention window.
                if self.claimer.state() == ClaimState::Claiming {
                    self.claim_elapsed_ms = 0;
                }
                Event::Transmit(address_claim_frame(claim.source, claim.name))
            }
        }
    }

    /// Turn a reassembler outcome into a node event, building any frame it asked
    /// to have sent.
    fn lift<'a>(outcome: Rx<'a>, address: Address, peer: Address) -> Event<'a> {
        match outcome {
            Rx::Idle => Event::Idle,
            Rx::Send(cm) => match tp_cm_frame(address, peer, &cm) {
                Some(frame) => Event::Transmit(frame),
                None => Event::Idle,
            },
            Rx::Message {
                pgn,
                source,
                data,
                ack,
            } => Event::Message {
                pgn,
                source,
                data,
                reply: ack.and_then(|cm| tp_cm_frame(address, peer, &cm)),
            },
        }
    }
}

/// The Address Claimed broadcast for `name` from `source`.
///
/// `source` is [`Address::NULL`] for a Cannot Claim Address message, which is
/// why the address comes from the claim rather than the node.
fn address_claim_frame(source: Address, name: Name) -> Frame {
    let id = Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, source);
    Frame::from_payload(id, name.to_bytes())
}

/// A TP.CM frame from `source` to `destination`. Transport-protocol traffic is
/// priority 7 so bulk transfers yield to control traffic.
fn tp_cm_frame(source: Address, destination: Address, cm: &TpCm) -> Option<Frame> {
    let id = Id::from_parts(Priority::LOWEST, pgn::TP_CM, destination, source).ok()?;
    Some(Frame::from_payload(id, cm.encode()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
    use crate::tp::Transmitter;

    fn name_for(identity: u32, manufacturer: u16) -> Name {
        Name::new()
            .with_identity_number(identity)
            .with_manufacturer_code(manufacturer)
    }

    fn node() -> Node<256> {
        Node::new(name_for(1, 300), Address::new(0x80))
    }

    #[test]
    fn priority_applies_to_a_single_frame_message() {
        let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &[1, 2, 3])
            .unwrap()
            .with_priority(Priority::HIGHEST);
        let frame = tx.next_frame().unwrap();
        assert_eq!(frame.id().priority(), Priority::HIGHEST);
        assert_eq!(frame.data(), &[1, 2, 3], "the payload is not disturbed");
    }

    #[test]
    fn transport_protocol_frames_ignore_the_requested_priority() {
        // J1939-21 fixes TP traffic at priority 7 so bulk transfers yield.
        let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &[0; 14])
            .unwrap()
            .with_priority(Priority::HIGHEST);
        while let Some(frame) = tx.next_frame() {
            assert_eq!(frame.id().priority(), Priority::LOWEST);
        }
    }

    #[test]
    fn a_short_message_is_one_frame_and_needs_no_pacing() {
        let mut tx =
            Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &[1, 2, 3]).unwrap();
        assert_eq!(tx.frame_count(), 1);
        assert!(!tx.needs_pacing());

        let frame = tx.next_frame().expect("one frame");
        assert_eq!(frame.pgn(), pgn::DM1);
        assert_eq!(frame.data(), &[1, 2, 3]);
        assert!(tx.is_complete());
        assert!(tx.next_frame().is_none());
    }

    #[test]
    fn a_long_broadcast_becomes_a_paced_bam() {
        let payload = [7u8; 14];
        let mut tx =
            Outgoing::new(pgn::DM1, Address::new(0x80), Address::GLOBAL, &payload).unwrap();
        assert!(tx.needs_pacing(), "a BAM has no flow control but timing");
        assert_eq!(tx.frame_count(), 3);

        let announcement = tx.next_frame().expect("the BAM");
        assert_eq!(announcement.pgn(), pgn::TP_CM);
        assert_eq!(announcement.id().priority(), Priority::LOWEST);
        assert!(matches!(
            TpCm::decode(announcement.payload()).unwrap(),
            TpCm::Bam {
                size: 14,
                packets: 2,
                ..
            }
        ));

        let mut packets = 0;
        while let Some(frame) = tx.next_frame() {
            assert_eq!(frame.pgn(), pgn::TP_DT);
            packets += 1;
        }
        assert_eq!(packets, 2);
        assert!(tx.is_complete());
    }

    /// An addressed message must wait for permission, and is not finished until
    /// the peer acknowledges it.
    #[test]
    fn a_long_addressed_message_runs_the_handshake() {
        let peer = Address::new(0x90);
        let payload = [3u8; 21];
        let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), peer, &payload).unwrap();
        assert!(!tx.needs_pacing(), "RTS/CTS is flow-controlled, not paced");

        let rts = tx.next_frame().expect("the RTS");
        assert_eq!(rts.pgn(), pgn::TP_CM);
        assert_eq!(rts.id().destination_address(), Some(peer));
        assert!(
            tx.next_frame().is_none(),
            "nothing may go out before the peer grants a window"
        );
        assert!(!tx.is_complete());

        // The peer grants everything at once.
        let cts = Frame::from_payload(
            Id::from_parts(Priority::LOWEST, pgn::TP_CM, Address::new(0x80), peer).unwrap(),
            TpCm::Cts {
                packets: 3,
                next_packet: 1,
                pgn: pgn::DM1,
            }
            .encode(),
        );
        assert_eq!(tx.on_frame(&cts), Progress::Ready);

        let mut packets = 0;
        while let Some(frame) = tx.next_frame() {
            assert_eq!(frame.pgn(), pgn::TP_DT);
            packets += 1;
        }
        assert_eq!(packets, 3);
        assert!(!tx.is_complete(), "not done until acknowledged");

        let ack = Frame::from_payload(
            Id::from_parts(Priority::LOWEST, pgn::TP_CM, Address::new(0x80), peer).unwrap(),
            TpCm::EndOfMsgAck {
                size: 21,
                packets: 3,
                pgn: pgn::DM1,
            }
            .encode(),
        );
        assert_eq!(tx.on_frame(&ack), Progress::Complete);
        assert!(tx.is_complete());
    }

    #[test]
    fn an_abort_from_the_peer_is_reported() {
        let peer = Address::new(0x90);
        let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), peer, &[0; 21]).unwrap();
        tx.next_frame();

        let abort = Frame::from_payload(
            Id::from_parts(Priority::LOWEST, pgn::TP_CM, Address::new(0x80), peer).unwrap(),
            TpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::DM1,
            }
            .encode(),
        );
        assert_eq!(
            tx.on_frame(&abort),
            Progress::Aborted(AbortReason::ResourcesUnavailable)
        );
    }

    #[test]
    fn traffic_from_other_ecus_does_not_disturb_a_transfer() {
        let peer = Address::new(0x90);
        let mut tx = Outgoing::new(pgn::DM1, Address::new(0x80), peer, &[0; 21]).unwrap();
        tx.next_frame();

        // The same CTS, but from an unrelated ECU.
        let stray = Frame::from_payload(
            Id::from_parts(
                Priority::LOWEST,
                pgn::TP_CM,
                Address::new(0x80),
                Address::new(0x17),
            )
            .unwrap(),
            TpCm::Cts {
                packets: 3,
                next_packet: 1,
                pgn: pgn::DM1,
            }
            .encode(),
        );
        assert_eq!(tx.on_frame(&stray), Progress::Idle);
        assert!(
            tx.next_frame().is_none(),
            "a stray CTS must not open our window"
        );
    }

    #[test]
    fn a_pdu2_group_cannot_be_addressed_to_one_ecu() {
        // DM1 is PDU2: broadcast only.
        assert!(Outgoing::new(pgn::DM1, Address::new(0x80), Address::new(0x90), &[0; 8]).is_err());
        // ...but the transport protocol carries it to one ECU perfectly well,
        // because the TP frames are PDU1 and the PGN travels in their payload.
        assert!(Outgoing::new(pgn::DM1, Address::new(0x80), Address::new(0x90), &[0; 21]).is_ok());
    }

    /// What one node sends, another must reassemble.
    #[test]
    fn an_outgoing_broadcast_arrives_at_a_receiving_node() {
        let sender = Address::new(0x00);
        let payload: [u8; 40] = core::array::from_fn(|i| (i * 3) as u8);

        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let mut tx = Outgoing::new(pgn::DM1, sender, Address::GLOBAL, &payload).unwrap();
        let mut delivered = None;
        while let Some(frame) = tx.next_frame() {
            if let Event::Message { pgn, data, .. } = node.on_frame(&frame) {
                assert_eq!(pgn, pgn::DM1);
                delivered = Some(data.to_vec());
            }
        }
        assert_eq!(delivered.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn claims_an_address_after_the_contention_window() {
        let mut node = node();
        assert!(!node.has_address());

        let claim = node.start();
        assert_eq!(claim.id().pgn(), pgn::ADDRESS_CLAIMED);
        assert_eq!(claim.id().source_address(), Address::new(0x80));
        assert_eq!(Name::from_bytes(claim.payload()), node.name());
        assert_eq!(node.claim_state(), ClaimState::Claiming);

        // Just short of the window: still claiming.
        node.tick(ADDRESS_CLAIM_WINDOW_MS - 1, |_| panic!("nothing to send"));
        assert!(!node.has_address());

        node.tick(1, |_| panic!("nothing to send"));
        assert!(node.has_address());
        assert_eq!(node.address(), Address::new(0x80));
    }

    #[test]
    fn answers_a_request_for_its_name() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::REQUEST,
            Address::GLOBAL,
            Address::new(0xF9),
        )
        .unwrap();
        let request = Frame::new(id, &Request::new(pgn::ADDRESS_CLAIMED).encode()).unwrap();

        match node.on_frame(&request) {
            Event::Transmit(reply) => {
                assert_eq!(reply.id().pgn(), pgn::ADDRESS_CLAIMED);
                assert_eq!(Name::from_bytes(reply.payload()), node.name());
            }
            other => panic!("expected an address claim, got {other:?}"),
        }
    }

    #[test]
    fn a_request_for_another_group_is_left_to_the_application() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::REQUEST,
            Address::new(0x80),
            Address::new(0xF9),
        )
        .unwrap();
        let request = Frame::new(id, &Request::new(pgn::DM1).encode()).unwrap();

        match node.on_frame(&request) {
            Event::Message { pgn, source, .. } => {
                assert_eq!(pgn, pgn::REQUEST);
                assert_eq!(source, Address::new(0xF9));
            }
            other => panic!("expected the request to be delivered, got {other:?}"),
        }
    }

    #[test]
    fn ignores_traffic_addressed_to_another_ecu() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::REQUEST,
            Address::new(0x17),
            Address::new(0xF9),
        )
        .unwrap();
        let request = Frame::new(id, &Request::new(pgn::ADDRESS_CLAIMED).encode()).unwrap();
        assert_eq!(node.on_frame(&request), Event::Idle);
    }

    #[test]
    fn defends_its_address_and_relocates_only_if_allowed() {
        // A fixed-address node loses and gives up.
        let mut fixed = node();
        fixed.start();
        fixed.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let winner = Name::new().with_manufacturer_code(1);
        let rival = Frame::new(
            Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, Address::new(0x80)),
            &winner.to_bytes(),
        )
        .unwrap();

        match fixed.on_frame(&rival) {
            Event::Transmit(reply) => {
                assert_eq!(
                    reply.id().source_address(),
                    Address::NULL,
                    "a displaced fixed-address node must announce Cannot Claim"
                );
            }
            other => panic!("expected a cannot-claim, got {other:?}"),
        }
        assert_eq!(fixed.claim_state(), ClaimState::CannotClaim);

        // An arbitrary-address-capable node moves instead.
        let mut flexible = Node::<256>::new(
            name_for(1, 300).with_arbitrary_address_capable(true),
            Address::new(0x80),
        );
        flexible.start();
        flexible.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});
        match flexible.on_frame(&rival) {
            Event::Transmit(reply) => {
                assert_ne!(reply.id().source_address(), Address::NULL);
                assert_ne!(reply.id().source_address(), Address::new(0x80));
            }
            other => panic!("expected a new claim, got {other:?}"),
        }
        // A new claim reopens the contention window.
        assert_eq!(flexible.claim_state(), ClaimState::Claiming);
    }

    #[test]
    fn delivers_a_single_frame_message() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let payload = [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF];
        let dm1 = Frame::new(
            Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x00)),
            &payload,
        )
        .unwrap();

        match node.on_frame(&dm1) {
            Event::Message {
                pgn,
                source,
                data,
                reply,
            } => {
                assert_eq!(pgn, pgn::DM1);
                assert_eq!(source, Address::new(0x00));
                assert_eq!(data, &payload);
                assert_eq!(reply, None);
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// The whole point of the type: a multi-packet DM1 arrives as one message,
    /// with the node having handled every transport-protocol frame itself.
    #[test]
    fn reassembles_a_multi_packet_message_without_the_caller_helping() {
        let sender = Address::new(0x00);
        let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
        let faults = [
            Dtc::new(100, 1, 2).unwrap(),
            Dtc::new(110, 0, 5).unwrap(),
            Dtc::new(1569, 31, 126).unwrap(),
        ];
        let mut payload = [0u8; 64];
        let len = diagnostics::encode(lamps, &faults, &mut payload).unwrap();

        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        // Build the wire traffic a real ECU would emit.
        let mut tx = Transmitter::broadcast(pgn::DM1, &payload[..len]).unwrap();
        let mut wire = std::vec::Vec::new();
        wire.push(
            Frame::new(
                Id::broadcast(Priority::LOWEST, pgn::TP_CM, sender),
                &tx.start().encode(),
            )
            .unwrap(),
        );
        while let Some(packet) = tx.next_packet() {
            wire.push(
                Frame::new(
                    Id::broadcast(Priority::LOWEST, pgn::TP_DT, sender),
                    &packet.encode(),
                )
                .unwrap(),
            );
        }

        let mut delivered = None;
        for frame in &wire {
            if let Event::Message { pgn, data, .. } = node.on_frame(frame) {
                assert_eq!(pgn, pgn::DM1);
                delivered = Some(data.to_vec());
            }
        }

        let delivered = delivered.expect("the node should deliver one whole message");
        let dm = diagnostics::Message::parse(&delivered).unwrap();
        assert_eq!(dm.dtcs().collect::<std::vec::Vec<_>>(), faults);
        assert_eq!(node.transfers_in_flight(), 0);
    }

    /// An RTS/CTS transfer needs the node to answer with CTS and then an
    /// end-of-message acknowledgement, unprompted.
    #[test]
    fn drives_an_rts_cts_transfer_on_the_callers_behalf() {
        let sender = Address::new(0x00);
        let payload: [u8; 30] = core::array::from_fn(|i| i as u8);

        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let mut tx = Transmitter::addressed(pgn::ECU_IDENTIFICATION, &payload).unwrap();
        let to_node = |cm: &TpCm| {
            Frame::new(
                Id::from_parts(Priority::LOWEST, pgn::TP_CM, Address::new(0x80), sender).unwrap(),
                &cm.encode(),
            )
            .unwrap()
        };
        let data_to_node = |dt: &TpDt| {
            Frame::new(
                Id::from_parts(Priority::LOWEST, pgn::TP_DT, Address::new(0x80), sender).unwrap(),
                &dt.encode(),
            )
            .unwrap()
        };

        // RTS -> the node must answer with a CTS.
        let Event::Transmit(cts) = node.on_frame(&to_node(&tx.start())) else {
            panic!("the node must answer an RTS with a CTS");
        };
        assert_eq!(cts.id().pgn(), pgn::TP_CM);
        assert_eq!(cts.id().destination_address(), Some(sender));
        let cts_cm = TpCm::decode(cts.payload()).unwrap();
        assert!(matches!(cts_cm, TpCm::Cts { .. }));

        tx.on_tp_cm(&cts_cm);
        let mut delivered = None;
        let mut acknowledged = false;
        while let Some(packet) = tx.next_packet() {
            match node.on_frame(&data_to_node(&packet)) {
                Event::Idle => {}
                Event::Transmit(frame) => {
                    // Another CTS window.
                    let cm = TpCm::decode(frame.payload()).unwrap();
                    tx.on_tp_cm(&cm);
                }
                Event::Message { data, reply, .. } => {
                    delivered = Some(data.to_vec());
                    let ack = reply.expect("an RTS/CTS transfer must be acknowledged");
                    assert!(matches!(
                        TpCm::decode(ack.payload()).unwrap(),
                        TpCm::EndOfMsgAck { .. }
                    ));
                    acknowledged = true;
                }
            }
        }

        assert_eq!(delivered.as_deref(), Some(payload.as_slice()));
        assert!(acknowledged);
    }

    #[test]
    fn expires_a_stalled_transfer_and_sends_the_abort() {
        let sender = Address::new(0x00);
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let rts = Frame::new(
            Id::from_parts(Priority::LOWEST, pgn::TP_CM, Address::new(0x80), sender).unwrap(),
            &TpCm::rts(21, pgn::DM1).unwrap().encode(),
        )
        .unwrap();
        assert!(matches!(node.on_frame(&rts), Event::Transmit(_)));
        assert_eq!(node.transfers_in_flight(), 1);

        // The sender goes quiet.
        let mut sent = std::vec::Vec::new();
        node.tick(crate::tp::T1_TIMEOUT_MS + 1, |frame| sent.push(frame));

        assert_eq!(node.transfers_in_flight(), 0);
        assert_eq!(sent.len(), 1, "a stalled RTS/CTS session must be aborted");
        assert!(matches!(
            TpCm::decode(sent[0].payload()).unwrap(),
            TpCm::Abort { .. }
        ));
    }

    /// A tool can move an ECU with a Commanded Address. The new address is not
    /// simply assumed — it has to be claimed like any other.
    #[test]
    fn a_commanded_address_moves_the_node_and_reopens_the_window() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});
        assert!(node.has_address());

        let mut command = [0u8; 9];
        command[..8].copy_from_slice(&node.name().to_bytes());
        command[8] = 0x42;

        let claim = node
            .on_commanded_address(&command)
            .unwrap()
            .expect("the node must announce its new address");
        assert_eq!(claim.id().source_address(), Address::new(0x42));
        assert_eq!(node.address(), Address::new(0x42));
        assert_eq!(
            node.claim_state(),
            ClaimState::Claiming,
            "a commanded address must be claimed, not assumed"
        );

        // The contention window restarts from the new claim.
        node.tick(ADDRESS_CLAIM_WINDOW_MS - 1, |_| {});
        assert!(!node.has_address());
        node.tick(1, |_| {});
        assert!(node.has_address());
    }

    #[test]
    fn a_commanded_address_for_another_ecu_is_ignored() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let mut command = [0u8; 9];
        command[..8].copy_from_slice(&name_for(999, 999).to_bytes());
        command[8] = 0x42;

        assert_eq!(node.on_commanded_address(&command).unwrap(), None);
        assert_eq!(node.address(), Address::new(0x80));
        assert_eq!(node.claim_state(), ClaimState::Claimed);
    }

    #[test]
    fn a_commanded_address_naming_a_reserved_address_is_refused() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let mut command = [0u8; 9];
        command[..8].copy_from_slice(&node.name().to_bytes());
        command[8] = 0xFF;

        assert!(node.on_commanded_address(&command).is_err());
        assert_eq!(node.address(), Address::new(0x80), "unchanged");
    }

    #[test]
    fn giving_up_produces_the_cannot_claim_broadcast() {
        let mut node = node();
        node.start();
        node.tick(ADDRESS_CLAIM_WINDOW_MS, |_| {});

        let frame = node.give_up_address();
        assert_eq!(frame.id().source_address(), Address::NULL);
        assert_eq!(frame.id().as_u32(), 0x18EE_FFFE);
        assert_eq!(node.claim_state(), ClaimState::CannotClaim);
    }
}
