// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A running ECU: a protocol stack bound to a bus.
//!
//! [`Bus`](crate::bus::Bus) moves frames and
//! [`Node`](sae_j1939_rs::node::Node) speaks the protocol;
//! [`Ecu`](crate::ecu::Ecu) joins them and adds the two things a host
//! program still has to do for itself — keeping the clock and splitting long
//! messages across the transport protocol.
//!
//! `Ecu` is generic over [`Bus`](crate::bus::Bus), so it is not tied to
//! SocketCAN and not tied to Linux. `Ecu::open` is the Linux shortcut that
//! binds a `SocketCan`; [`Ecu::new`](crate::ecu::Ecu::new) takes any bus,
//! including a test double.
//!
//! ```
//! use std::cell::RefCell;
//! use std::collections::VecDeque;
//! use std::io;
//!
//! use sae_j1939_host::bus::Bus;
//! use sae_j1939_host::ecu::Ecu;
//! use sae_j1939_host::sae_j1939_rs::{pgn, Address, Frame, Id, Name, Priority};
//!
//! # #[derive(Default)]
//! # struct FakeBus { incoming: RefCell<VecDeque<Frame>>, sent: RefCell<Vec<Frame>> }
//! # impl Bus for FakeBus {
//! #     fn send_frame(&self, f: &Frame) -> io::Result<()> { self.sent.borrow_mut().push(*f); Ok(()) }
//! #     fn recv_frame(&self) -> io::Result<Option<Frame>> { Ok(self.incoming.borrow_mut().pop_front()) }
//! # }
//! // Any transport that can move J1939 frames: SocketCAN, a USB adapter, a
//! // simulator, or — as here — a test double.
//! let bus = FakeBus::default();
//! bus.incoming.borrow_mut().push_back(Frame::from_payload(
//!     Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x00)),
//!     [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF],
//! ));
//!
//! let name = Name::new().with_manufacturer_code(300).with_identity_number(1);
//! let mut ecu = Ecu::<_, 1785, 4>::new(bus, name, Address::new(0x80));
//!
//! ecu.claim_address()?;
//! assert!(ecu.has_address());
//!
//! // `poll` returns None whenever the bus is quiet, so drive it in a loop
//! // rather than `while let Some(..)`, which would stop at the first gap.
//! let mut seen = None;
//! for _ in 0..4 {
//!     if let Some(message) = ecu.poll()? {
//!         seen = Some(message);
//!         break;
//!     }
//! }
//! assert_eq!(seen.unwrap().pgn, pgn::DM1);
//! # Ok::<(), std::io::Error>(())
//! ```

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use sae_j1939_rs::address_claim::ClaimState;
use sae_j1939_rs::frame::{Frame, MAX_PAYLOAD};
use sae_j1939_rs::node::{Event, Node};
use sae_j1939_rs::request::Request;
use sae_j1939_rs::tp::{TpCm, TpDt};
use sae_j1939_rs::tp::{Transmitter, Tx};
use sae_j1939_rs::{pgn, Address, Id, Name, Pgn, Priority};

use crate::bus::{Bus, Message};

/// The gap left between BAM data packets.
///
/// J1939-21 requires 50–200 ms; receivers on a busy bus drop transfers sent
/// back to back.
pub const BAM_PACKET_INTERVAL: Duration = Duration::from_millis(50);

/// How long [`Ecu::send_to`] waits for a peer to answer during a multi-packet
/// transfer before giving up.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1250);

/// How long [`Ecu::claim_address`] waits for arbitration to settle.
///
/// Generous, because losing a contest sends an arbitrary-address-capable ECU to
/// a new address and opens a fresh 250 ms window; several rounds are possible on
/// a busy bus.
pub const CLAIM_TIMEOUT: Duration = Duration::from_secs(3);

/// A J1939 ECU bound to a bus.
///
/// `BUF` is the largest message it will accept and `SESSIONS` how many peers
/// may be mid-transfer at once — a host has memory to spare, so both default
/// generously.
#[derive(Debug)]
pub struct Ecu<B: Bus, const BUF: usize = 1785, const SESSIONS: usize = 8> {
    bus: B,
    node: Node<BUF, SESSIONS>,
    /// Messages that arrived while we were busy doing something else, so that
    /// nothing is lost during a blocking handshake.
    pending: VecDeque<Message>,
    last_tick: Instant,
}

/// Bind to a Linux CAN interface.
#[cfg(target_os = "linux")]
impl<const BUF: usize, const SESSIONS: usize> Ecu<crate::transport::SocketCan, BUF, SESSIONS> {
    /// Open `interface` as an ECU called `name`, wanting address `preferred`.
    ///
    /// Nothing goes on the bus until [`Ecu::claim_address`] is called.
    ///
    /// ```no_run
    /// use sae_j1939_host::ecu::Ecu;
    /// use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name};
    ///
    /// let name = Name::new().with_manufacturer_code(300).with_identity_number(4242);
    /// let mut ecu = Ecu::open("can0", name, Address::new(0x80))?;
    ///
    /// ecu.claim_address()?;
    /// ecu.request(Address::GLOBAL, pgn::ADDRESS_CLAIMED)?;
    ///
    /// loop {
    ///     if let Some(message) = ecu.poll()? {
    ///         println!("{:#08x} from {:#04x}", message.pgn.as_u32(), message.source.as_u8());
    ///     }
    /// }
    /// # #[allow(unreachable_code)] Ok::<(), std::io::Error>(())
    /// ```
    pub fn open(interface: &str, name: Name, preferred: Address) -> io::Result<Self> {
        let socket = crate::transport::SocketCan::open(interface)?;
        socket.set_read_timeout(Duration::from_millis(50))?;
        Ok(Ecu::new(socket, name, preferred))
    }
}

impl<B: Bus, const BUF: usize, const SESSIONS: usize> Ecu<B, BUF, SESSIONS> {
    /// Build an ECU on any bus.
    ///
    /// Nothing goes on the bus until [`Ecu::claim_address`] is called.
    pub fn new(bus: B, name: Name, preferred: Address) -> Self {
        Ecu {
            bus,
            node: Node::new(name, preferred),
            pending: VecDeque::new(),
            last_tick: Instant::now(),
        }
    }

    /// The underlying bus, for anything this type does not wrap.
    pub fn bus(&self) -> &B {
        &self.bus
    }

    /// The address currently held or being claimed.
    pub fn address(&self) -> Address {
        self.node.address()
    }

    /// This ECU's NAME.
    pub fn name(&self) -> Name {
        self.node.name()
    }

    /// Whether the address has been claimed uncontested and may now be used.
    pub fn has_address(&self) -> bool {
        self.node.has_address()
    }

    /// Broadcast an address claim and settle it.
    ///
    /// Blocks through the J1939-81 contention period, handling any traffic that
    /// arrives meanwhile. A competing claim may push this ECU to a different
    /// address — in which case a fresh contention window opens and this keeps
    /// waiting — or off the bus entirely. Ordinary messages that arrive during
    /// the window are queued for [`Ecu::poll`], not discarded.
    ///
    /// Returns once the address is held or the ECU has given up; check
    /// [`Ecu::has_address`]. Gives up after [`CLAIM_TIMEOUT`] if arbitration
    /// somehow never settles.
    pub fn claim_address(&mut self) -> io::Result<()> {
        let claim = self.node.start();
        self.bus.send_frame(&claim)?;

        // Relocating restarts the contention window, so waiting a single window
        // from the *first* claim would report a still-settling ECU as failed.
        let give_up_at = Instant::now() + CLAIM_TIMEOUT;
        while Instant::now() < give_up_at {
            if self.node.has_address() || self.node.claim_state() == ClaimState::CannotClaim {
                return Ok(());
            }
            // Ordinary traffic during the contention window is queued, not
            // dropped: other ECUs are under no obligation to stay quiet while
            // this one is claiming.
            if let Some(message) = self.pump()? {
                self.pending.push_back(message);
            }
        }
        Ok(())
    }

    /// Where this ECU stands in the address-claiming protocol.
    pub fn claim_state(&self) -> ClaimState {
        self.node.claim_state()
    }

    /// Receive the next complete message, or `None` if the bus stayed quiet.
    ///
    /// Multi-packet transfers are reassembled, address-claim traffic is handled
    /// internally, and any frame the protocol requires in response has already
    /// been sent by the time this returns.
    ///
    /// **`None` means "nothing yet", not "nothing more".** It is returned
    /// whenever the read timeout expires with no traffic, so drive this in a
    /// loop — `while let Some(..)` would stop at the first quiet moment.
    pub fn poll(&mut self) -> io::Result<Option<Message>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(message));
        }
        self.pump()
    }

    /// Ask `destination` to transmit `requested`.
    ///
    /// Returns an error if this ECU has not claimed an address — see
    /// [`Ecu::broadcast`].
    pub fn request(&mut self, destination: Address, requested: Pgn) -> io::Result<()> {
        self.check_may_transmit()?;
        let id = Id::from_parts(Priority::DEFAULT, pgn::REQUEST, destination, self.address())
            .map_err(invalid_input)?;
        let frame = Frame::new(id, &Request::new(requested).encode()).map_err(invalid_input)?;
        self.bus.send_frame(&frame)
    }

    /// Broadcast `data` as parameter group `pgn`.
    ///
    /// Up to eight bytes go out as a single frame. Anything longer is announced
    /// with a BAM and pushed as data packets, paced [`BAM_PACKET_INTERVAL`]
    /// apart — so this blocks for roughly 50 ms per packet.
    ///
    /// Returns [`io::ErrorKind::NotConnected`] if this ECU has not claimed an
    /// address. J1939-81 does not allow an ECU to use an address it has not
    /// claimed, so transmitting first would put a conflicting source address on
    /// the bus. Call [`Ecu::claim_address`] and check [`Ecu::has_address`].
    pub fn broadcast(&mut self, group: Pgn, data: &[u8]) -> io::Result<()> {
        self.check_may_transmit()?;
        let source = self.address();
        if data.len() <= MAX_PAYLOAD {
            let id = Id::broadcast(Priority::DEFAULT, group, source);
            let frame = Frame::new(id, data).map_err(invalid_input)?;
            return self.bus.send_frame(&frame);
        }

        let mut tx = Transmitter::broadcast(group, data).map_err(invalid_input)?;
        self.send_tp_cm(source, Address::GLOBAL, &tx.start())?;
        while let Some(packet) = tx.next_packet() {
            std::thread::sleep(BAM_PACKET_INTERVAL);
            self.send_tp_dt(source, Address::GLOBAL, &packet)?;
        }
        Ok(())
    }

    /// Send `data` to one ECU as parameter group `pgn`.
    ///
    /// Up to eight bytes go out as a single frame. Anything longer runs the full
    /// RTS/CTS handshake, which **blocks** until the peer acknowledges or
    /// [`HANDSHAKE_TIMEOUT`] passes without an answer.
    ///
    /// Traffic that arrives during the handshake is not lost: it is handled
    /// normally and queued for the next [`Ecu::poll`].
    ///
    /// Returns [`io::ErrorKind::NotConnected`] if this ECU has not claimed an
    /// address — see [`Ecu::broadcast`].
    pub fn send_to(&mut self, destination: Address, group: Pgn, data: &[u8]) -> io::Result<()> {
        self.check_may_transmit()?;
        let source = self.address();
        if data.len() <= MAX_PAYLOAD {
            let id = Id::from_parts(Priority::DEFAULT, group, destination, source)
                .map_err(invalid_input)?;
            let frame = Frame::new(id, data).map_err(invalid_input)?;
            return self.bus.send_frame(&frame);
        }

        let mut tx = Transmitter::addressed(group, data).map_err(invalid_input)?;
        self.send_tp_cm(source, destination, &tx.start())?;

        let mut deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        while !tx.is_complete() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "no response from {:#04x} during a multi-packet transfer",
                        destination.as_u8()
                    ),
                ));
            }

            let Some(frame) = self.bus.recv_frame()? else {
                continue;
            };

            // A connection-management frame from our peer drives this transfer;
            // anything else is ordinary traffic and goes to the node.
            let is_peer_cm = frame.pgn() == pgn::TP_CM && frame.source_address() == destination;
            if !is_peer_cm {
                if let Some(message) = self.dispatch(&frame)? {
                    self.pending.push_back(message);
                }
                continue;
            }

            let Ok(cm) = TpCm::decode(frame.payload()) else {
                continue;
            };
            match tx.on_tp_cm(&cm) {
                Tx::SendData => {
                    while let Some(packet) = tx.next_packet() {
                        self.send_tp_dt(source, destination, &packet)?;
                    }
                    deadline = Instant::now() + HANDSHAKE_TIMEOUT;
                }
                Tx::Complete => break,
                Tx::Aborted(reason) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("peer aborted the transfer: {reason:?}"),
                    ))
                }
                Tx::Idle => {}
            }
        }
        Ok(())
    }

    /// J1939-81 forbids transmitting from an address this ECU has not claimed.
    fn check_may_transmit(&self) -> io::Result<()> {
        if self.node.has_address() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            match self.node.claim_state() {
                ClaimState::CannotClaim => {
                    "this ECU lost address arbitration and must stay off the bus"
                }
                _ => "no address claimed yet — call claim_address() first",
            },
        ))
    }

    /// A transport-protocol connection-management frame. TP traffic is priority
    /// 7, the lowest, so bulk transfers yield to control traffic.
    fn send_tp_cm(&self, source: Address, destination: Address, cm: &TpCm) -> io::Result<()> {
        let id = Id::from_parts(Priority::LOWEST, pgn::TP_CM, destination, source)
            .map_err(invalid_input)?;
        self.bus.send_frame(&Frame::from_payload(id, cm.encode()))
    }

    /// A transport-protocol data packet.
    fn send_tp_dt(&self, source: Address, destination: Address, dt: &TpDt) -> io::Result<()> {
        let id = Id::from_parts(Priority::LOWEST, pgn::TP_DT, destination, source)
            .map_err(invalid_input)?;
        self.bus.send_frame(&Frame::from_payload(id, dt.encode()))
    }

    /// Read one frame, dispatch it, and advance the node's timers.
    fn pump(&mut self) -> io::Result<Option<Message>> {
        let received = self.bus.recv_frame()?;

        let message = match received {
            Some(frame) => self.dispatch(&frame)?,
            None => None,
        };

        self.tick()?;
        Ok(message)
    }

    /// Feed one frame to the node and send whatever it asks for.
    fn dispatch(&mut self, frame: &Frame) -> io::Result<Option<Message>> {
        let mut outgoing: Vec<Frame> = Vec::new();
        let mut message = None;

        match self.node.on_frame(frame) {
            Event::Idle => {}
            Event::Transmit(reply) => outgoing.push(reply),
            Event::Message {
                pgn: group,
                source,
                data,
                reply,
            } => {
                outgoing.extend(reply);
                message = Some(Message {
                    pgn: group,
                    source,
                    data: data.to_vec(),
                });
            }
        }

        for frame in &outgoing {
            self.bus.send_frame(frame)?;
        }
        Ok(message)
    }

    /// Advance the node by however long has actually passed.
    ///
    /// The node counts whole milliseconds, so the sub-millisecond remainder is
    /// carried forward rather than dropped: advancing `last_tick` by only the
    /// milliseconds actually reported keeps the leftover for next time. Resetting
    /// it to `now` instead would discard the remainder on every call, and a loop
    /// spinning faster than 1 kHz — a busy bus, or a non-blocking transport —
    /// would report zero elapsed time forever and the protocol timers would
    /// never fire.
    fn tick(&mut self) -> io::Result<()> {
        let elapsed_ms = self.last_tick.elapsed().as_millis().min(u16::MAX as u128) as u16;
        if elapsed_ms == 0 {
            return Ok(());
        }
        self.last_tick += Duration::from_millis(elapsed_ms as u64);

        let mut outgoing: Vec<Frame> = Vec::new();
        self.node.tick(elapsed_ms, |frame| outgoing.push(frame));
        for frame in &outgoing {
            self.bus.send_frame(frame)?;
        }
        Ok(())
    }
}

fn invalid_input<E: ToString>(error: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use sae_j1939_rs::address_claim::ClaimState;
    use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
    use sae_j1939_rs::tp::Transmitter;
    use sae_j1939_rs::Name;

    /// A bus that replays a scripted sequence and records what was sent.
    #[derive(Debug, Default)]
    struct FakeBus {
        incoming: RefCell<VecDeque<Frame>>,
        sent: RefCell<Vec<Frame>>,
    }

    impl FakeBus {
        fn queue(&self, frame: Frame) {
            self.incoming.borrow_mut().push_back(frame);
        }

        fn sent(&self) -> Vec<Frame> {
            self.sent.borrow().clone()
        }

        fn sent_with_pgn(&self, group: Pgn) -> Vec<Frame> {
            self.sent()
                .into_iter()
                .filter(|f| f.id().pgn() == group)
                .collect()
        }
    }

    impl Bus for FakeBus {
        fn send_frame(&self, frame: &Frame) -> io::Result<()> {
            self.sent.borrow_mut().push(*frame);
            Ok(())
        }

        fn recv_frame(&self) -> io::Result<Option<Frame>> {
            Ok(self.incoming.borrow_mut().pop_front())
        }
    }

    fn name_for(identity: u32, manufacturer: u16) -> Name {
        Name::new()
            .with_identity_number(identity)
            .with_manufacturer_code(manufacturer)
    }

    fn claim_frame(source: Address, name: Name) -> Frame {
        Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, source),
            name.to_bytes(),
        )
    }

    fn ecu_on(bus: FakeBus, name: Name) -> Ecu<FakeBus, 1785, 4> {
        Ecu::new(bus, name, Address::new(0x80))
    }

    #[test]
    fn claims_an_uncontested_address() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        assert!(ecu.has_address());
        assert_eq!(ecu.address(), Address::new(0x80));
        let claims = ecu.bus().sent_with_pgn(pgn::ADDRESS_CLAIMED);
        assert_eq!(claims.len(), 1, "exactly one claim goes out");
        assert_eq!(claims[0].id().source_address(), Address::new(0x80));
    }

    /// Regression: `claim_address` used to wait one contention window from the
    /// *first* claim. Losing arbitration sends an arbitrary-address-capable ECU
    /// to a new address and opens a fresh window, so the old code returned
    /// while the node was still legitimately settling and reported failure.
    #[test]
    fn a_relocation_gets_its_own_contention_window() {
        let bus = FakeBus::default();
        // A rival with a lower manufacturer code always wins 0x80.
        bus.queue(claim_frame(
            Address::new(0x80),
            Name::new().with_manufacturer_code(1),
        ));

        let mut ecu = ecu_on(bus, name_for(1, 300).with_arbitrary_address_capable(true));
        ecu.claim_address().unwrap();

        assert!(
            ecu.has_address(),
            "the ECU relocated and must be given time to settle, not reported as failed"
        );
        assert_ne!(ecu.address(), Address::new(0x80), "it must have moved");
        assert_eq!(ecu.claim_state(), ClaimState::Claimed);

        // Two claims: the original, and the one from the new address.
        let claims = ecu.bus().sent_with_pgn(pgn::ADDRESS_CLAIMED);
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[1].id().source_address(), ecu.address());
    }

    #[test]
    fn a_fixed_address_ecu_that_loses_stops_trying() {
        let bus = FakeBus::default();
        bus.queue(claim_frame(
            Address::new(0x80),
            Name::new().with_manufacturer_code(1),
        ));

        // Not arbitrary-address-capable: nowhere to go.
        let mut ecu = ecu_on(bus, name_for(1, 300));
        ecu.claim_address().unwrap();

        assert!(!ecu.has_address());
        assert_eq!(ecu.claim_state(), ClaimState::CannotClaim);
        // It announced Cannot Claim from the null address.
        let claims = ecu.bus().sent_with_pgn(pgn::ADDRESS_CLAIMED);
        assert_eq!(claims.last().unwrap().id().source_address(), Address::NULL);
    }

    /// Regression: nothing stopped an ECU transmitting from an address it had
    /// not claimed, which J1939-81 forbids.
    #[test]
    fn transmitting_before_claiming_is_refused() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));

        for result in [
            ecu.request(Address::GLOBAL, pgn::ADDRESS_CLAIMED),
            ecu.broadcast(pgn::DM1, &[0; 8]),
            ecu.send_to(Address::new(0x90), pgn::DM1, &[0; 8]),
        ] {
            let error = result.expect_err("must refuse before an address is claimed");
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
        assert!(ecu.bus().sent().is_empty(), "nothing may reach the bus");
    }

    #[test]
    fn a_displaced_ecu_is_also_refused_and_says_why() {
        let bus = FakeBus::default();
        bus.queue(claim_frame(
            Address::new(0x80),
            Name::new().with_manufacturer_code(1),
        ));
        let mut ecu = ecu_on(bus, name_for(1, 300));
        ecu.claim_address().unwrap();
        assert_eq!(ecu.claim_state(), ClaimState::CannotClaim);

        let error = ecu.broadcast(pgn::DM1, &[0; 8]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(
            error.to_string().contains("lost address arbitration"),
            "the message should distinguish displaced from not-yet-claimed, got: {error}"
        );
    }

    /// Regression: `poll` returns `None` on a quiet bus, not at end-of-stream.
    /// `while let Some(..)` would stop at the first gap in traffic.
    #[test]
    fn poll_returning_none_does_not_mean_the_bus_is_finished() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        // Nothing queued: quiet, not finished.
        assert_eq!(ecu.poll().unwrap(), None);
        assert_eq!(ecu.poll().unwrap(), None);

        // A message arrives after those quiet polls and must still be delivered.
        ecu.bus().queue(Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x00)),
            [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF],
        ));
        let message = ecu.poll().unwrap().expect("the message must arrive");
        assert_eq!(message.pgn, pgn::DM1);
        assert_eq!(message.source, Address::new(0x00));
    }

    /// Regression: traffic arriving during the 250 ms contention window used to
    /// be read and thrown away. Other ECUs do not stay quiet while one claims.
    #[test]
    fn traffic_during_the_contention_window_is_queued_not_dropped() {
        let bus = FakeBus::default();
        bus.queue(Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x00)),
            [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF],
        ));

        let mut ecu = ecu_on(bus, name_for(1, 300));
        ecu.claim_address().unwrap();
        assert!(ecu.has_address());

        let message = ecu
            .poll()
            .unwrap()
            .expect("the message that arrived while claiming must survive");
        assert_eq!(message.pgn, pgn::DM1);
        assert_eq!(message.source, Address::new(0x00));
    }

    /// Regression: `tick` truncated elapsed time to whole milliseconds and
    /// dropped the remainder, so a loop spinning faster than 1 kHz accumulated
    /// no time at all and the protocol timers never fired.
    #[test]
    fn sub_millisecond_polling_still_advances_the_clock() {
        // A bus that never blocks makes `claim_address` spin at full speed —
        // the exact condition under which the remainder used to be lost.
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        let started = std::time::Instant::now();
        ecu.claim_address().unwrap();

        assert!(
            ecu.has_address(),
            "the contention window must elapse even when polling spins"
        );
        assert!(
            started.elapsed() < CLAIM_TIMEOUT,
            "it should settle after the contention window, not run to the cap"
        );
    }

    #[test]
    fn answers_a_request_for_its_own_name() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();
        let before = ecu.bus().sent_with_pgn(pgn::ADDRESS_CLAIMED).len();

        ecu.bus().queue(
            Frame::new(
                Id::from_parts(
                    Priority::DEFAULT,
                    pgn::REQUEST,
                    Address::GLOBAL,
                    Address::new(0xF9),
                )
                .unwrap(),
                &Request::new(pgn::ADDRESS_CLAIMED).encode(),
            )
            .unwrap(),
        );
        ecu.poll().unwrap();

        let claims = ecu.bus().sent_with_pgn(pgn::ADDRESS_CLAIMED);
        assert_eq!(claims.len(), before + 1, "the request must be answered");
        assert_eq!(
            Name::from_bytes(claims.last().unwrap().payload()),
            ecu.name()
        );
    }

    /// A multi-packet message arrives as one `Message`, with the ECU having
    /// handled every transport-protocol frame itself.
    #[test]
    fn reassembles_an_incoming_broadcast() {
        let sender = Address::new(0x00);
        let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
        let faults = [
            Dtc::new(100, 1, 2).unwrap(),
            Dtc::new(110, 0, 5).unwrap(),
            Dtc::new(1569, 31, 126).unwrap(),
        ];
        let mut payload = [0u8; 64];
        let len = diagnostics::encode(lamps, &faults, &mut payload).unwrap();

        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        let mut tx = Transmitter::broadcast(pgn::DM1, &payload[..len]).unwrap();
        ecu.bus().queue(Frame::from_payload(
            Id::broadcast(Priority::LOWEST, pgn::TP_CM, sender),
            tx.start().encode(),
        ));
        while let Some(packet) = tx.next_packet() {
            ecu.bus().queue(Frame::from_payload(
                Id::broadcast(Priority::LOWEST, pgn::TP_DT, sender),
                packet.encode(),
            ));
        }

        let mut delivered = None;
        for _ in 0..8 {
            if let Some(message) = ecu.poll().unwrap() {
                delivered = Some(message);
                break;
            }
        }

        let delivered = delivered.expect("the DM1 should reassemble into one message");
        assert_eq!(delivered.pgn, pgn::DM1);
        assert_eq!(delivered.data.len(), len);
        let dm = diagnostics::Message::parse(&delivered.data).unwrap();
        assert_eq!(dm.dtcs().collect::<Vec<_>>(), faults);
    }

    /// A short outgoing message is one frame; a long one is announced and
    /// split, with the announcement counted as its own frame.
    #[test]
    fn outgoing_messages_split_only_when_they_must() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        ecu.broadcast(pgn::DM1, &[0u8; 8]).unwrap();
        assert_eq!(ecu.bus().sent_with_pgn(pgn::DM1).len(), 1);
        assert!(ecu.bus().sent_with_pgn(pgn::TP_CM).is_empty());

        // Fourteen bytes needs a BAM and two data packets.
        ecu.broadcast(pgn::DM2, &[0u8; 14]).unwrap();
        assert!(
            ecu.bus().sent_with_pgn(pgn::DM2).is_empty(),
            "a long message travels as TP frames, not under its own PGN"
        );
        assert_eq!(ecu.bus().sent_with_pgn(pgn::TP_CM).len(), 1);
        assert_eq!(ecu.bus().sent_with_pgn(pgn::TP_DT).len(), 2);
    }

    #[test]
    fn an_addressed_transfer_times_out_when_nobody_answers() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        // No CTS will ever arrive.
        let error = ecu
            .send_to(Address::new(0x90), pgn::ECU_IDENTIFICATION, &[0u8; 30])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        // The RTS did go out before giving up.
        assert_eq!(ecu.bus().sent_with_pgn(pgn::TP_CM).len(), 1);
    }
}
