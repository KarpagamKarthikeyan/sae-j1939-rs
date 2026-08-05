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

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};

use sae_j1939_rs::address_claim::ClaimState;
use sae_j1939_rs::diagnostics::{
    self, BroadcastCommand, Dm13, Dm5, Dtc, Lamp, Lamps, Network, ObdCompliance,
};
use sae_j1939_rs::etp::{self, EtpCm, EtpDt};
use sae_j1939_rs::fault_log::FaultLog;
use sae_j1939_rs::frame::Frame;
use sae_j1939_rs::identification::SoftwareIdentification;
use sae_j1939_rs::node::{Event, Node, Outgoing, Progress};
use sae_j1939_rs::request::{Acknowledgement, Request};
use sae_j1939_rs::schedule::{Schedule, DEFAULT_SUSPEND_MS};
use sae_j1939_rs::tp::T3_TIMEOUT_MS;
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

/// How long the diagnostic readers wait for an ECU to answer.
///
/// Generous: a DM1 listing many faults arrives over the transport protocol,
/// whose data packets are paced 50 ms apart, so a long fault list legitimately
/// takes a while.
pub const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(2);

/// How many active — and separately, how many previously active — trouble codes
/// an [`Ecu`] remembers about itself.
///
/// Fixed rather than a generic parameter, because on a host there is no memory
/// pressure that would justify tuning it and every extra const parameter is one
/// more thing callers have to spell out. An ECU that needs a different bound can
/// drive [`FaultLog`] itself and transmit with [`Ecu::broadcast`].
pub const FAULT_CAPACITY: usize = 32;

/// How many periodic messages an [`Ecu`] will transmit on a schedule.
///
/// Generous: a busy engine controller broadcasts a dozen or so parameter
/// groups. Fixed rather than a generic parameter, for the same reason as
/// [`FAULT_CAPACITY`].
pub const SCHEDULE_CAPACITY: usize = 16;

/// A J1939 ECU bound to a bus.
///
/// `BUF` is the largest message it will accept and `SESSIONS` how many peers
/// may be mid-transfer at once — a host has memory to spare, so both default
/// generously.
#[derive(Debug)]
pub struct Ecu<B: Bus, const BUF: usize = 1785, const SESSIONS: usize = 8> {
    bus: B,
    node: Node<BUF, SESSIONS>,
    /// Extended transport protocol, for messages past 1785 bytes. A host has
    /// memory to spare, so this is on by default with a generous buffer; an MCU
    /// driving `Node` directly pays nothing for it.
    etp: etp::Reassembler<ETP_BUFFER, 2>,
    /// Messages that arrived while we were busy doing something else, so that
    /// nothing is lost during a blocking handshake.
    pending: VecDeque<Message>,
    /// What is wrong with *this* ECU, broadcast as DM1 and answered on request.
    faults: FaultLog<FAULT_CAPACITY>,
    /// Who else is on the bus. `Node` treats address claims as network
    /// management and never passes them up, so they are recorded on the way
    /// past — otherwise a tool could not answer the first question anyone asks
    /// of a bus, which is what is on it.
    inventory: BTreeMap<u8, Name>,
    /// What this ECU claims about emissions compliance in DM5.
    obd_compliance: ObdCompliance,
    /// What this ECU transmits on its own, and how often.
    schedule: Schedule<SCHEDULE_CAPACITY>,
    /// The payload for each scheduled message. Held here rather than in
    /// `Schedule` because the core has no allocator, and because a periodic
    /// message's payload is replaced every cycle — a copy inside the timer
    /// would be a copy that is always one cycle stale.
    payloads: BTreeMap<(u32, u8), (Vec<u8>, Priority)>,
    last_tick: Instant,
}

/// How large an extended-transport-protocol message an [`Ecu`] will accept.
///
/// ETP can carry 117 MB, which no one wants pre-allocated. 64 KiB comfortably
/// covers an ISOBUS object pool or a task data file, and a transfer larger than
/// this is refused with an abort rather than being partly accepted.
pub const ETP_BUFFER: usize = 64 * 1024;

/// An [`Ecu`] on a Linux SocketCAN interface, sized for a host.
///
/// Const-generic defaults on a struct do not apply when you call an associated
/// function, so `Ecu::open(..)` cannot infer `BUF` and `SESSIONS`. This alias
/// pins both, which is what makes [`SocketCanEcu::open`] usable without turbofish.
/// Use `Ecu::<_, BUF, SESSIONS>::open` if you want different sizes.
#[cfg(target_os = "linux")]
pub type SocketCanEcu = Ecu<crate::transport::SocketCan, 1785, 8>;

/// Bind to a Linux CAN interface.
#[cfg(target_os = "linux")]
impl<const BUF: usize, const SESSIONS: usize> Ecu<crate::transport::SocketCan, BUF, SESSIONS> {
    /// Open `interface` as an ECU called `name`, wanting address `preferred`.
    ///
    /// Nothing goes on the bus until [`Ecu::claim_address`] is called.
    ///
    /// ```no_run
    /// use sae_j1939_host::ecu::SocketCanEcu;
    /// use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name};
    ///
    /// let name = Name::new().with_manufacturer_code(300).with_identity_number(4242);
    /// // `SocketCanEcu` pins the buffer sizes; `Ecu::<_, BUF, SESSIONS>::open`
    /// // if you want different ones.
    /// let mut ecu = SocketCanEcu::open("can0", name, Address::new(0x80))?;
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
            etp: etp::Reassembler::new(),
            pending: VecDeque::new(),
            faults: FaultLog::new(),
            inventory: BTreeMap::new(),
            obd_compliance: ObdCompliance::NotIntended,
            schedule: Schedule::new(),
            payloads: BTreeMap::new(),
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

    /// How far along an extended-transport-protocol transfer from `source` is,
    /// as `(bytes received, total)`.
    ///
    /// An ETP transfer of any size takes a while — a 64 KiB object pool is over
    /// 9000 frames — so a caller may reasonably want to show progress.
    pub fn etp_progress(&self, source: Address) -> Option<(u32, u32)> {
        self.etp.progress(source)
    }

    /// How many multi-packet transfers the node is reassembling.
    pub fn transfers_in_flight(&self) -> usize {
        self.node.transfers_in_flight() + self.etp.active_sessions()
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
        self.broadcast_with_priority(group, data, Priority::DEFAULT)
    }

    /// Broadcast `data` as `group` at a chosen priority.
    ///
    /// [`Ecu::broadcast`] uses [`Priority::DEFAULT`] (6), which is right for
    /// most traffic. Continuous engine and vehicle data conventionally runs
    /// higher — a lower number wins arbitration — so that a burst of
    /// diagnostics cannot delay a control input.
    pub fn broadcast_with_priority(
        &mut self,
        group: Pgn,
        data: &[u8],
        priority: Priority,
    ) -> io::Result<()> {
        self.check_may_transmit()?;
        let mut outgoing = Outgoing::new(group, self.address(), Address::GLOBAL, data)
            .map_err(invalid_input)?
            .with_priority(priority);
        let paced = outgoing.needs_pacing();

        let mut first = true;
        while let Some(frame) = outgoing.next_frame() {
            // A BAM is not acknowledged, so J1939-21 spaces its packets instead.
            // The announcement goes out immediately; the data packets do not.
            if paced && !first {
                std::thread::sleep(BAM_PACKET_INTERVAL);
            }
            first = false;
            self.bus.send_frame(&frame)?;
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
    ///
    /// Passing [`Address::GLOBAL`] defers to [`Ecu::broadcast`]. There is no
    /// handshake to run with everybody at once, and a long message sent that way
    /// is a BAM, which has to be paced — blasting it here would put traffic on
    /// the bus that conforming receivers drop.
    pub fn send_to(&mut self, destination: Address, group: Pgn, data: &[u8]) -> io::Result<()> {
        if destination.is_broadcast() {
            return self.broadcast(group, data);
        }
        self.check_may_transmit()?;
        let mut outgoing =
            Outgoing::new(group, self.address(), destination, data).map_err(invalid_input)?;

        // Everything available right now: the whole message if it is short, or
        // the announcement if it is not.
        while let Some(frame) = outgoing.next_frame() {
            self.bus.send_frame(&frame)?;
        }

        let mut deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        while !outgoing.is_complete() {
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

            match outgoing.on_frame(&frame) {
                Progress::Ready => {
                    while let Some(packet) = outgoing.next_frame() {
                        self.bus.send_frame(&packet)?;
                    }
                    deadline = Instant::now() + HANDSHAKE_TIMEOUT;
                }
                Progress::Complete => break,
                Progress::Aborted(reason) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("peer aborted the transfer: {reason:?}"),
                    ))
                }
                // Not part of this transfer: ordinary traffic, handled normally
                // and queued rather than dropped.
                Progress::Idle => {
                    if let Some(message) = self.dispatch(&frame)? {
                        self.pending.push_back(message);
                    }
                }
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Transmitting on a schedule — what an ECU mostly does.
    // ---------------------------------------------------------------------

    /// Broadcast `data` as `group` every `period`, from now on.
    ///
    /// This is what a real ECU spends its life doing: engine speed at 20 ms,
    /// temperatures at a second, whether or not anyone asked. [`Ecu::poll`]
    /// sends them, so the application loop stays a loop over `poll`.
    ///
    /// Call it again with fresh bytes to update the value — see
    /// [`Ecu::update_periodic`], which does that without disturbing the timing.
    /// Registering the same group twice changes its rate rather than adding a
    /// second entry.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] for a period of zero or longer than
    /// [`u16::MAX`] milliseconds (about 65 seconds), or when the schedule is
    /// full — see [`SCHEDULE_CAPACITY`].
    ///
    /// Nothing is transmitted until an address is claimed, and a period shorter
    /// than the loop's own cycle time cannot be honoured; the schedule delays
    /// rather than bursting to catch up.
    ///
    /// # Keep it to eight bytes
    ///
    /// Periodic parameter groups are single-frame by design. A longer payload
    /// still works, but it goes out over the transport protocol — a broadcast
    /// one is paced 50 ms per packet, so [`Ecu::poll`] blocks for that long
    /// every period, and a period near the transfer time would leave the bus
    /// carrying nothing else.
    ///
    /// ```
    /// # use std::cell::RefCell;
    /// # use std::collections::VecDeque;
    /// # use std::io;
    /// # use std::time::Duration;
    /// # use sae_j1939_host::bus::Bus;
    /// # use sae_j1939_host::ecu::Ecu;
    /// # use sae_j1939_host::sae_j1939_rs::{pgn, Address, Frame, Name};
    /// # #[derive(Default)]
    /// # struct FakeBus { sent: RefCell<Vec<Frame>> }
    /// # impl Bus for FakeBus {
    /// #     fn send_frame(&self, f: &Frame) -> io::Result<()> { self.sent.borrow_mut().push(*f); Ok(()) }
    /// #     fn recv_frame(&self) -> io::Result<Option<Frame>> { Ok(None) }
    /// # }
    /// # let name = Name::new().with_manufacturer_code(300).with_identity_number(1);
    /// # let mut ecu = Ecu::<_, 1785, 4>::new(FakeBus::default(), name, Address::new(0x80));
    /// # ecu.claim_address()?;
    /// // Engine speed 1500 rpm, broadcast twenty times a second.
    /// let eec1 = [0xFF, 0x87, 0x96, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];
    /// ecu.broadcast_every(pgn::EEC1, &eec1, Duration::from_millis(50))?;
    ///
    /// // Each time round the control loop, publish the new value.
    /// ecu.update_periodic(pgn::EEC1, &eec1)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn broadcast_every(&mut self, group: Pgn, data: &[u8], period: Duration) -> io::Result<()> {
        self.send_every(group, Address::GLOBAL, data, period)
    }

    /// Send `data` to one ECU as `group` every `period`. See
    /// [`Ecu::broadcast_every`].
    pub fn send_every(
        &mut self,
        group: Pgn,
        destination: Address,
        data: &[u8],
        period: Duration,
    ) -> io::Result<()> {
        let period_ms = u16::try_from(period.as_millis()).map_err(|_| {
            invalid_input(format!(
                "a period of {:?} is longer than the {} ms a schedule holds",
                period,
                u16::MAX
            ))
        })?;
        self.schedule
            .send_every(group, destination, period_ms)
            .map_err(invalid_input)?;
        // Keep the priority if this group was already scheduled: changing the
        // rate should not silently reset how it arbitrates.
        let priority = self
            .payloads
            .get(&key(group, destination))
            .map_or(Priority::DEFAULT, |(_, priority)| *priority);
        self.payloads
            .insert(key(group, destination), (data.to_vec(), priority));
        Ok(())
    }

    /// Send a scheduled message at a chosen priority from now on.
    ///
    /// Scheduled messages default to [`Priority::DEFAULT`] (6). Continuous
    /// engine and vehicle data conventionally runs higher — engine speed is a
    /// control input, and a lower number wins arbitration.
    ///
    /// Returns [`io::ErrorKind::NotFound`] if the group is not scheduled.
    pub fn set_periodic_priority(
        &mut self,
        group: Pgn,
        destination: Address,
        priority: Priority,
    ) -> io::Result<()> {
        match self.payloads.get_mut(&key(group, destination)) {
            Some((_, stored)) => {
                *stored = priority;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{group} is not scheduled for transmission"),
            )),
        }
    }

    /// Replace the payload of an already-scheduled message, leaving its timing
    /// alone.
    ///
    /// The normal way to publish a new sensor reading: the value changes every
    /// cycle, the rate does not.
    ///
    /// Returns [`io::ErrorKind::NotFound`] if the group is not scheduled —
    /// silently doing nothing would leave stale values going out and look like
    /// a sensor that had stopped changing.
    pub fn update_periodic(&mut self, group: Pgn, data: &[u8]) -> io::Result<()> {
        self.update_periodic_to(group, Address::GLOBAL, data)
    }

    /// Replace the payload of a destination-specific periodic message. See
    /// [`Ecu::update_periodic`].
    pub fn update_periodic_to(
        &mut self,
        group: Pgn,
        destination: Address,
        data: &[u8],
    ) -> io::Result<()> {
        if !self.schedule.contains(group, destination) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{group} is not scheduled for transmission"),
            ));
        }
        let priority = self
            .payloads
            .get(&key(group, destination))
            .map_or(Priority::DEFAULT, |(_, priority)| *priority);
        self.payloads
            .insert(key(group, destination), (data.to_vec(), priority));
        Ok(())
    }

    /// Stop transmitting `group` periodically, returning whether it was
    /// scheduled.
    pub fn stop_periodic(&mut self, group: Pgn, destination: Address) -> bool {
        self.payloads.remove(&key(group, destination));
        self.schedule.remove(group, destination)
    }

    /// What this ECU transmits on a schedule, as `(group, destination, period)`.
    pub fn periodic(&self) -> impl Iterator<Item = (Pgn, Address, Duration)> + '_ {
        self.schedule.entries().map(|(due, period_ms)| {
            (
                due.pgn,
                due.destination,
                Duration::from_millis(period_ms as u64),
            )
        })
    }

    /// Whether periodic transmission is currently stopped by a DM13 command.
    pub fn broadcasts_suspended(&self) -> bool {
        self.schedule.is_suspended()
    }

    /// Stop periodic transmission for `timeout`, then resume automatically.
    ///
    /// Applied for you when a DM13 stop-broadcast command arrives; exposed
    /// because an application may have its own reason to go quiet.
    pub fn suspend_broadcasts(&mut self, timeout: Duration) {
        let ms = u16::try_from(timeout.as_millis()).unwrap_or(u16::MAX);
        self.schedule.suspend(ms);
    }

    /// Resume periodic transmission now.
    pub fn resume_broadcasts(&mut self) {
        self.schedule.resume();
    }

    /// Act on a DM13 stop/start broadcast command.
    ///
    /// Only the commands aimed at a network this ECU is on are obeyed:
    /// "current data link" always, and the vehicle bus, since that is what a
    /// SocketCAN interface is. A command naming only the implement bus is left
    /// alone rather than guessed at — silencing an ECU because a message meant
    /// for a different network mentioned it would be worse than ignoring it.
    ///
    /// Diagnostic messages are **not** suspended. DM13 exists so that a tool
    /// can free up bandwidth for diagnostic work; stopping the diagnostics it
    /// came for would defeat the purpose.
    fn on_dm13(&mut self, command: &Dm13) {
        for network in [Network::CurrentDataLink, Network::Vehicle] {
            match command.command(network) {
                BroadcastCommand::Stop => {
                    self.schedule.suspend(DEFAULT_SUSPEND_MS);
                    return;
                }
                BroadcastCommand::Start => {
                    self.schedule.resume();
                    return;
                }
                BroadcastCommand::Reserved | BroadcastCommand::DoNotCare => {}
            }
        }
    }

    /// Send everything the schedule says is due.
    fn send_due(&mut self) -> io::Result<()> {
        while let Some(due) = self.schedule.next_due() {
            let Some((payload, priority)) = self.payloads.get(&key(due.pgn, due.destination))
            else {
                continue;
            };
            // Clone so the send does not hold a borrow of `self.payloads`.
            // Periodic messages are single-frame in practice, so this is eight
            // bytes; correctness over saving a copy that small.
            let (payload, priority) = (payload.clone(), *priority);
            if due.destination.is_broadcast() {
                self.broadcast_with_priority(due.pgn, &payload, priority)?;
            } else {
                self.send_to(due.destination, due.pgn, &payload)?;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Reporting this ECU's own faults (J1939-73).
    // ---------------------------------------------------------------------

    /// What is currently wrong with this ECU.
    pub fn faults(&self) -> &FaultLog<FAULT_CAPACITY> {
        &self.faults
    }

    /// The fault log, to raise and clear faults directly.
    ///
    /// [`Ecu::set_fault`] and [`Ecu::clear_fault`] cover the common cases;
    /// reach for this to set flash status, or to clear the whole log.
    pub fn faults_mut(&mut self) -> &mut FaultLog<FAULT_CAPACITY> {
        &mut self.faults
    }

    /// Report a fault, lighting `lamp` until it is cleared.
    ///
    /// From here on [`Ecu::poll`] broadcasts a DM1 once a second naming this
    /// code, and answers a request for DM1 with it — no further work needed.
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the code does not fit the
    /// wire format or the log is full; see
    /// [`FaultLog::set`](sae_j1939_rs::fault_log::FaultLog::set).
    ///
    /// ```
    /// # use std::cell::RefCell;
    /// # use std::collections::VecDeque;
    /// # use std::io;
    /// # use sae_j1939_host::bus::Bus;
    /// # use sae_j1939_host::ecu::Ecu;
    /// # use sae_j1939_host::sae_j1939_rs::{Address, Frame, Name};
    /// use sae_j1939_host::sae_j1939_rs::diagnostics::Lamp;
    /// # #[derive(Default)]
    /// # struct FakeBus { sent: RefCell<Vec<Frame>> }
    /// # impl Bus for FakeBus {
    /// #     fn send_frame(&self, f: &Frame) -> io::Result<()> { self.sent.borrow_mut().push(*f); Ok(()) }
    /// #     fn recv_frame(&self) -> io::Result<Option<Frame>> { Ok(None) }
    /// # }
    /// # let name = Name::new().with_manufacturer_code(300).with_identity_number(1);
    /// # let mut ecu = Ecu::<_, 1785, 4>::new(FakeBus::default(), name, Address::new(0x80));
    /// # ecu.claim_address()?;
    /// // Oil pressure is low (SPN 100, FMI 1). Stop the engine.
    /// ecu.set_fault(100, 1, Lamp::RedStop)?;
    /// assert!(!ecu.faults().is_healthy());
    ///
    /// // Later, the pressure recovers.
    /// ecu.clear_fault(100, 1);
    /// assert!(ecu.faults().is_healthy());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_fault(&mut self, spn: u32, fmi: u8, lamp: Lamp) -> io::Result<()> {
        self.faults.set(spn, fmi, lamp).map_err(invalid_input)
    }

    /// Retire a fault whose condition has gone away, returning whether it was
    /// active. It moves to the previously active list, reported as DM2.
    pub fn clear_fault(&mut self, spn: u32, fmi: u8) -> bool {
        self.faults.clear(spn, fmi)
    }

    /// Broadcast the active fault list as DM1 now, rather than waiting for the
    /// periodic one.
    ///
    /// Two or more active faults exceed a CAN frame, so the message goes out
    /// over the transport protocol and this blocks for the BAM pacing.
    pub fn send_dm1(&mut self) -> io::Result<()> {
        let mut payload = vec![0u8; self.faults.dm1_len()];
        let len = self.faults.dm1(&mut payload).map_err(invalid_input)?;
        // DM1 is a PDU2 parameter group, so it is broadcast even when it is
        // answering one tool's request — there is no destination field to put
        // the requester in.
        self.broadcast(pgn::DM1, &payload[..len])
    }

    /// What this ECU reports for its OBD compliance level in DM5.
    ///
    /// Defaults to [`ObdCompliance::NotIntended`], which is the truth for an
    /// ECU that is not an emissions device. Set it if yours is one — the crate
    /// cannot know, and guessing would put a compliance claim on the bus that
    /// nobody stands behind.
    pub fn set_obd_compliance(&mut self, level: ObdCompliance) {
        self.obd_compliance = level;
    }

    /// Broadcast readiness and fault counts as DM5 now.
    ///
    /// The counts come from the fault log, so they cannot drift out of step
    /// with the DM1 and DM2 this ECU reports. The five monitor bytes are sent
    /// as "not available": what a monitor has completed is something only the
    /// application knows.
    pub fn send_dm5(&mut self) -> io::Result<()> {
        let readiness = Dm5::new(
            saturating_count(self.faults.active().len()),
            saturating_count(self.faults.previously_active().len()),
            self.obd_compliance,
        );
        self.broadcast(pgn::DM5, &readiness.encode())
    }

    /// Broadcast the fault history as DM2 now.
    pub fn send_dm2(&mut self) -> io::Result<()> {
        let mut payload = vec![0u8; self.faults.dm2_len()];
        let len = self.faults.dm2(&mut payload).map_err(invalid_input)?;
        self.broadcast(pgn::DM2, &payload[..len])
    }

    /// Answer a diagnostic request aimed at this ECU.
    ///
    /// Returns whether the request was one this handles, so an unhandled
    /// parameter group can still reach the application.
    fn answer_diagnostic_request(
        &mut self,
        requester: Address,
        request: &Request,
    ) -> io::Result<bool> {
        match request.pgn {
            pgn::DM1 => self.send_dm1()?,
            pgn::DM2 => self.send_dm2()?,
            pgn::DM5 => self.send_dm5()?,
            pgn::DM3 => {
                self.faults.clear_previously_active();
                self.acknowledge(requester, diagnostics::dm3::acknowledge(self.address()))?;
            }
            pgn::DM11 => {
                self.faults.clear_active();
                self.acknowledge(requester, diagnostics::dm11::acknowledge(self.address()))?;
                // Clearing the codes put the lamps out, which is worth saying
                // rather than leaving a tool to infer it from silence.
                self.send_dm1()?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Send an acknowledgement to whoever asked.
    ///
    /// Destination-specific: the requester asked, so the requester is told.
    fn acknowledge(&self, requester: Address, ack: Acknowledgement) -> io::Result<()> {
        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::ACKNOWLEDGEMENT,
            requester,
            self.node.address(),
        )
        .map_err(invalid_input)?;
        self.bus.send_frame(&Frame::from_payload(id, ack.encode()))
    }

    // ---------------------------------------------------------------------
    // Reading another ECU's diagnostics: the service-tool side.
    // ---------------------------------------------------------------------

    /// Every ECU heard claiming an address, in address order, with the NAME it
    /// claimed with.
    ///
    /// Built up from whatever has gone past — an ECU that has not spoken since
    /// this one started listening will not be here. [`Ecu::scan`] asks.
    pub fn inventory(&self) -> impl Iterator<Item = (Address, Name)> + '_ {
        self.inventory
            .iter()
            .map(|(&address, &name)| (Address::new(address), name))
    }

    /// Ask every ECU on the bus to identify itself, and listen for `duration`.
    ///
    /// A global request for Address Claimed, which each ECU answers with its
    /// NAME. Ordinary traffic arriving meanwhile is queued for [`Ecu::poll`]
    /// rather than dropped.
    ///
    /// One second is usually plenty; a busy bus with many ECUs deserves more.
    /// The result is the whole inventory, not just this scan's answers, so
    /// repeated scans accumulate.
    pub fn scan(&mut self, duration: Duration) -> io::Result<Vec<(Address, Name)>> {
        self.request(Address::GLOBAL, pgn::ADDRESS_CLAIMED)?;
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            if let Some(message) = self.pump()? {
                self.pending.push_back(message);
            }
        }
        Ok(self.inventory().collect())
    }

    /// Ask `destination` for `requested` and wait for the answer.
    ///
    /// The blocking counterpart to [`Ecu::request`], and the primitive the
    /// diagnostic readers below are built from. Traffic that arrives meanwhile
    /// is handled normally and queued for [`Ecu::poll`] rather than dropped, so
    /// this can be used on a live bus without losing anything. Messages already
    /// queued when this is called are left alone: something that arrived before
    /// the request cannot be the answer to it.
    ///
    /// A request to [`Address::GLOBAL`] returns the first answer from anyone.
    ///
    /// Returns an error if this ECU has not claimed an address — see
    /// [`Ecu::broadcast`].
    pub fn request_wait(
        &mut self,
        destination: Address,
        requested: Pgn,
        timeout: Duration,
    ) -> io::Result<Response> {
        self.request(destination, requested)?;
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let Some(message) = self.pump()? else {
                continue;
            };
            // A request to one ECU is answered by that ECU; a global one by
            // whoever gets there first.
            let from_target = destination.is_broadcast() || message.source == destination;

            if from_target && message.pgn == requested {
                return Ok(Response::Message(message));
            }
            if from_target && message.pgn == pgn::ACKNOWLEDGEMENT && message.data.len() >= 8 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&message.data[..8]);
                let ack = Acknowledgement::decode(&bytes);
                if ack.pgn == requested {
                    return Ok(Response::Acknowledged(ack));
                }
            }
            // Not what we asked for. Somebody else may still want it.
            self.pending.push_back(message);
        }
        Ok(Response::TimedOut)
    }

    /// Read the active trouble codes from `target` — a DM1 request.
    ///
    /// `Ok(None)` means the ECU did not answer within `timeout`, which on
    /// J1939 is the usual way of saying it does not support the request.
    /// [`io::ErrorKind::Unsupported`] means it answered and declined.
    ///
    /// ```
    /// # use std::cell::RefCell;
    /// # use std::collections::VecDeque;
    /// # use std::io;
    /// # use sae_j1939_host::bus::Bus;
    /// # use sae_j1939_host::ecu::Ecu;
    /// # use sae_j1939_host::sae_j1939_rs::{pgn, Address, Frame, Id, Name, Priority};
    /// use sae_j1939_host::ecu::DIAGNOSTIC_TIMEOUT;
    /// # #[derive(Default)]
    /// # struct FakeBus { incoming: RefCell<VecDeque<Frame>>, sent: RefCell<Vec<Frame>> }
    /// # impl Bus for FakeBus {
    /// #     fn send_frame(&self, f: &Frame) -> io::Result<()> { self.sent.borrow_mut().push(*f); Ok(()) }
    /// #     fn recv_frame(&self) -> io::Result<Option<Frame>> { Ok(self.incoming.borrow_mut().pop_front()) }
    /// # }
    /// # let engine = Address::new(0x00);
    /// # let name = Name::new().with_manufacturer_code(300).with_identity_number(1);
    /// # let mut tool = Ecu::<_, 1785, 4>::new(FakeBus::default(), name, Address::new(0xF9));
    /// # tool.claim_address()?;
    /// # // The engine answers with one fault: SPN 100 FMI 1, red stop lamp on.
    /// # tool.bus().incoming.borrow_mut().push_back(Frame::from_payload(
    /// #     Id::broadcast(Priority::DEFAULT, pgn::DM1, engine),
    /// #     [0x10, 0x00, 0x64, 0x00, 0x01, 0x81, 0xFF, 0xFF],
    /// # ));
    /// // `tool` is any Ecu — a SocketCAN one on Linux, a test double here.
    /// let report = tool.read_active_faults(engine, DIAGNOSTIC_TIMEOUT)?.unwrap();
    ///
    /// assert_eq!(report.dtcs.len(), 1);
    /// assert_eq!(report.dtcs[0].spn, 100);
    /// assert_eq!(report.dtcs[0].fmi, 1);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn read_active_faults(
        &mut self,
        target: Address,
        timeout: Duration,
    ) -> io::Result<Option<FaultReport>> {
        match self.request_wait(target, pgn::DM1, timeout)? {
            Response::Message(message) => Ok(Some(FaultReport::parse(&message.data)?)),
            Response::Acknowledged(ack) => refused(ack, "DM1"),
            Response::TimedOut => Ok(None),
        }
    }

    /// Read the fault history from `target` — a DM2 request. See
    /// [`Ecu::read_active_faults`].
    pub fn read_previously_active_faults(
        &mut self,
        target: Address,
        timeout: Duration,
    ) -> io::Result<Option<FaultReport>> {
        match self.request_wait(target, pgn::DM2, timeout)? {
            Response::Message(message) => Ok(Some(FaultReport::parse(&message.data)?)),
            Response::Acknowledged(ack) => refused(ack, "DM2"),
            Response::TimedOut => Ok(None),
        }
    }

    /// Read emissions readiness and fault counts from `target` — a DM5 request.
    pub fn read_readiness(
        &mut self,
        target: Address,
        timeout: Duration,
    ) -> io::Result<Option<Dm5>> {
        match self.request_wait(target, pgn::DM5, timeout)? {
            Response::Message(message) if message.data.len() >= 8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&message.data[..8]);
                Ok(Some(Dm5::decode(&bytes)))
            }
            Response::Message(message) => Err(invalid_input(format!(
                "DM5 from {} was {} bytes, not 8",
                target,
                message.data.len()
            ))),
            Response::Acknowledged(ack) => refused(ack, "DM5"),
            Response::TimedOut => Ok(None),
        }
    }

    /// Read the software version strings `target` reports about itself.
    ///
    /// The fields are `*`-delimited on the wire; this splits them and drops the
    /// leading count byte.
    pub fn read_software_identification(
        &mut self,
        target: Address,
        timeout: Duration,
    ) -> io::Result<Option<Vec<String>>> {
        match self.request_wait(target, pgn::SOFTWARE_IDENTIFICATION, timeout)? {
            Response::Message(message) => {
                let id = SoftwareIdentification::parse(&message.data).map_err(invalid_input)?;
                Ok(Some(
                    id.fields()
                        .map(|field| String::from_utf8_lossy(field).into_owned())
                        .collect(),
                ))
            }
            Response::Acknowledged(ack) => refused(ack, "software identification"),
            Response::TimedOut => Ok(None),
        }
    }

    /// Ask `target` to clear its *active* trouble codes — a DM11 request.
    ///
    /// Returns whether it confirmed. `false` means it never answered; an error
    /// means it refused, with the reason.
    ///
    /// # This is not a diagnostic step
    ///
    /// An active code is a fault happening now. Clearing it fixes nothing — the
    /// ECU sets it again if the condition persists, and if it does not, the
    /// evidence is gone. Read the codes first.
    pub fn clear_active_faults(&mut self, target: Address, timeout: Duration) -> io::Result<bool> {
        self.clear_with(target, pgn::DM11, timeout)
    }

    /// Ask `target` to clear its fault *history* — a DM3 request. See
    /// [`Ecu::clear_active_faults`].
    pub fn clear_previously_active_faults(
        &mut self,
        target: Address,
        timeout: Duration,
    ) -> io::Result<bool> {
        self.clear_with(target, pgn::DM3, timeout)
    }

    fn clear_with(&mut self, target: Address, group: Pgn, timeout: Duration) -> io::Result<bool> {
        match self.request_wait(target, group, timeout)? {
            Response::Acknowledged(ack) if ack.control.is_positive() => Ok(true),
            Response::Acknowledged(ack) => {
                refused(ack, "the clear request").map(|_: Option<()>| false)
            }
            // DM3 and DM11 carry no data of their own, so a data message in
            // reply is not an answer to this.
            Response::Message(_) | Response::TimedOut => Ok(false),
        }
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

    /// Reassemble extended-transport-protocol traffic.
    ///
    /// `Node` does not model ETP: its buffers are sized for an MCU, and a
    /// 117 MB ceiling has no place there. The host layer has memory, so it
    /// handles ETP itself and hands the finished message back looking like any
    /// other.
    ///
    /// Returns `Ok(None)` for a frame that is not ETP, so the caller can pass it
    /// on to the node.
    fn dispatch_etp(&mut self, frame: &Frame) -> io::Result<Option<Option<Message>>> {
        let group = frame.pgn();
        if group != pgn::ETP_CM && group != pgn::ETP_DT {
            return Ok(None);
        }
        if !frame.id().is_addressed_to(self.node.address()) {
            return Ok(Some(None));
        }

        let source = frame.source_address();
        let outcome = if group == pgn::ETP_CM {
            match EtpCm::decode(frame.payload()) {
                Ok(cm) => self.etp.on_etp_cm(source, &cm),
                Err(_) => return Ok(Some(None)),
            }
        } else {
            self.etp.on_etp_dt(source, &EtpDt::decode(frame.payload()))
        };

        // Copy out before the borrow of `self.etp` ends.
        let (reply, message) = match outcome {
            etp::Rx::Idle => (None, None),
            etp::Rx::Send(cm) => (Some(cm), None),
            etp::Rx::Message {
                pgn: group,
                source,
                data,
                ack,
            } => (
                Some(ack),
                Some(Message {
                    pgn: group,
                    source,
                    data: data.to_vec(),
                }),
            ),
        };

        if let Some(cm) = reply {
            self.send_etp_cm(source, &cm)?;
        }
        Ok(Some(message))
    }

    /// An ETP connection-management frame, priority 7 like the ordinary
    /// transport protocol.
    fn send_etp_cm(&self, destination: Address, cm: &EtpCm) -> io::Result<()> {
        let id = Id::from_parts(
            Priority::LOWEST,
            pgn::ETP_CM,
            destination,
            self.node.address(),
        )
        .map_err(invalid_input)?;
        self.bus.send_frame(&Frame::from_payload(id, cm.encode()))
    }

    /// Feed one frame to the node and send whatever it asks for.
    fn dispatch(&mut self, frame: &Frame) -> io::Result<Option<Message>> {
        // Record the claim before the node consumes it. A Cannot Claim
        // announcement comes from the null address and names nobody, so it is
        // not an inventory entry.
        if frame.pgn() == pgn::ADDRESS_CLAIMED && frame.source_address().is_specific() {
            self.inventory.insert(
                frame.source_address().as_u8(),
                Name::from_bytes(frame.payload()),
            );
        }

        if let Some(message) = self.dispatch_etp(frame)? {
            return Ok(message);
        }

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

        // A Commanded Address tells this ECU to move. `Node` cannot act on it
        // inside `on_frame` without copying its reassembly buffer on every
        // message, but here the payload is already owned, so wire it up and
        // spare the caller from knowing about it at all.
        if let Some(message) = &message {
            if message.pgn == pgn::COMMANDED_ADDRESS {
                if let Ok(Some(claim)) = self.node.on_commanded_address(&message.data) {
                    self.bus.send_frame(&claim)?;
                }
            }
        }

        // A tool asking this ECU about its faults. `Node` passes requests up
        // rather than answering them, because what an ECU can supply is an
        // application question — but the diagnostic groups are ones this type
        // owns the state for, so it answers them itself. The request is still
        // returned to the caller, which may want to log it.
        // A tool asking the bus to go quiet so it can work. Acted on whether
        // or not this ECU has an address: an ECU still claiming has nothing to
        // suspend, but the command is not addressed to anyone in particular
        // and refusing it would be surprising.
        if let Some(message) = &message {
            if message.pgn == pgn::DM13 && message.data.len() >= 8 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&message.data[..8]);
                let command = Dm13::decode(&bytes);
                self.on_dm13(&command);
            }
        }

        if let Some(message) = &message {
            if message.pgn == pgn::REQUEST && self.node.has_address() {
                if let Ok(request) = Request::decode(&message.data) {
                    let requester = message.source;
                    self.answer_diagnostic_request(requester, &request)?;
                }
            }
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

        // ETP uses the same T3 timeout as the ordinary protocol's handshake.
        let mut expired: Vec<(Address, EtpCm)> = Vec::new();
        self.etp.tick(elapsed_ms, T3_TIMEOUT_MS, |peer, abort| {
            expired.push((peer, abort))
        });
        for (peer, abort) in &expired {
            self.send_etp_cm(*peer, abort)?;
        }

        // The periodic DM1, once a second while anything is wrong. Held back
        // until the address is claimed: an ECU may not transmit before then,
        // and consuming the fault log's timer meanwhile would throw the report
        // away rather than delay it.
        if self.node.has_address() && self.faults.tick(elapsed_ms) {
            self.send_dm1()?;
        }

        // Everything this ECU publishes on its own. Held back until an address
        // is claimed for the same reason as the DM1: J1939-81 does not allow
        // transmitting from an address that has not been claimed.
        if self.node.has_address() {
            self.schedule.tick(elapsed_ms);
            self.send_due()?;
        }
        Ok(())
    }
}

/// What came back from [`Ecu::request_wait`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The parameter group that was asked for.
    Message(Message),
    /// The target answered with an acknowledgement instead — either confirming
    /// an action that has no data to return, such as a DM11 clear, or declining
    /// the request. Check
    /// [`AckControl::is_positive`](sae_j1939_rs::request::AckControl::is_positive).
    Acknowledged(Acknowledgement),
    /// Nothing came back in time.
    ///
    /// Not necessarily a failure: J1939 has no "unsupported" reply that ECUs
    /// are obliged to send, so silence is the usual answer to a request for a
    /// parameter group an ECU does not implement.
    TimedOut,
}

/// A fault list read from another ECU: what its lamps show, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultReport {
    /// The lamp and flash status the ECU reported.
    pub lamps: Lamps,
    /// The trouble codes. Empty when the ECU reported none — the all-zero and
    /// all-`0xFF` placeholders are filtered out, so this is only real faults.
    pub dtcs: Vec<Dtc>,
}

impl FaultReport {
    /// Whether the ECU reported nothing wrong.
    pub fn is_healthy(&self) -> bool {
        self.dtcs.is_empty()
    }

    fn parse(payload: &[u8]) -> io::Result<Self> {
        let dm = diagnostics::Message::parse(payload).map_err(invalid_input)?;
        Ok(FaultReport {
            lamps: dm.lamps(),
            dtcs: dm.dtcs().filter(|dtc| !dtc.is_no_fault()).collect(),
        })
    }
}

/// Turn a negative acknowledgement into an error carrying its reason.
fn refused<T>(ack: Acknowledgement, what: &str) -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{} declined {what}: {:?}", ack.address.as_u8(), ack.control),
    ))
}

/// DM5 gives each count a single byte. More faults than that is possible in
/// principle and reportable only as "at least 255".
fn saturating_count(count: usize) -> u8 {
    u8::try_from(count).unwrap_or(u8::MAX)
}

/// A scheduled message is identified by its group *and* its destination: the
/// same parameter group may legitimately go to two places at two rates.
fn key(group: Pgn, destination: Address) -> (u32, u8) {
    (group.as_u32(), destination.as_u8())
}

fn invalid_input<E: ToString>(error: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    use sae_j1939_rs::address_claim::ClaimState;
    use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
    use sae_j1939_rs::identification::{self, EcuIdentification};
    use sae_j1939_rs::spn::{catalogue, SpnValue};
    use sae_j1939_rs::tp::{AbortReason, TpCm, TpDt, Transmitter};
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

    /// The host layer already owns the payload, so it wires the command up
    /// without the caller needing to know the PGN exists.
    #[test]
    fn a_commanded_address_is_acted_on_without_the_caller_helping() {
        use sae_j1939_rs::tp::Transmitter;

        let tool = Address::new(0xF9);
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();
        assert_eq!(ecu.address(), Address::new(0x80));

        // Nine bytes: NAME then the address to take. It travels over the
        // transport protocol, because it does not fit one frame.
        let mut command = [0u8; 9];
        command[..8].copy_from_slice(&ecu.name().to_bytes());
        command[8] = 0x42;

        let mut tx = Transmitter::broadcast(pgn::COMMANDED_ADDRESS, &command).unwrap();
        ecu.bus().queue(Frame::from_payload(
            Id::broadcast(Priority::LOWEST, pgn::TP_CM, tool),
            tx.start().encode(),
        ));
        while let Some(packet) = tx.next_packet() {
            ecu.bus().queue(Frame::from_payload(
                Id::broadcast(Priority::LOWEST, pgn::TP_DT, tool),
                packet.encode(),
            ));
        }

        for _ in 0..8 {
            ecu.poll().unwrap();
        }

        assert_eq!(ecu.address(), Address::new(0x42), "the ECU moved");
        // ...and announced the move itself.
        let claims = ecu.bus().sent_with_pgn(pgn::ADDRESS_CLAIMED);
        assert_eq!(
            claims.last().unwrap().id().source_address(),
            Address::new(0x42)
        );
    }

    /// A 20 KiB transfer is far beyond what the ordinary transport protocol can
    /// carry, and takes a dozen extended-protocol blocks. The offset arithmetic
    /// has to hold across every one of them.
    #[test]
    fn a_large_message_arrives_over_the_extended_transport_protocol() {
        use sae_j1939_rs::etp::{self, EtpCm, EtpDt};

        let sender = Address::new(0x00);
        let payload: Vec<u8> = (0..20_000).map(|i| (i * 31 % 251) as u8).collect();

        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        let mut tx = etp::Transmitter::new(pgn::PROPRIETARY_A, &payload).unwrap();
        let to_ecu_cm = |cm: &EtpCm| {
            Frame::from_payload(
                Id::from_parts(Priority::LOWEST, pgn::ETP_CM, Address::new(0x80), sender).unwrap(),
                cm.encode(),
            )
        };
        let to_ecu_dt = |dt: &EtpDt| {
            Frame::from_payload(
                Id::from_parts(Priority::LOWEST, pgn::ETP_DT, Address::new(0x80), sender).unwrap(),
                dt.encode(),
            )
        };

        // Announce, then drive the blocks until the whole message lands.
        ecu.bus().queue(to_ecu_cm(&tx.start()));
        let mut delivered = None;
        let mut blocks = 0;
        let mut handled_replies = 0;

        'transfer: for _ in 0..40 {
            // Anything new the ECU has said drives the next block.
            let replies = ecu.bus().sent_with_pgn(pgn::ETP_CM);
            while handled_replies < replies.len() {
                let cm = EtpCm::decode(replies[handled_replies].payload()).unwrap();
                handled_replies += 1;
                if tx.on_etp_cm(&cm) == etp::Tx::SendData {
                    blocks += 1;
                    if let Some(dpo) = tx.offset() {
                        ecu.bus().queue(to_ecu_cm(&dpo));
                    }
                    while let Some(packet) = tx.next_packet() {
                        ecu.bus().queue(to_ecu_dt(&packet));
                    }
                }
            }

            // Pump unconditionally: every frame of a transfer returns None until
            // the last one, so stopping at the first None would consume one
            // frame per round.
            for _ in 0..512 {
                if let Some(message) = ecu.poll().unwrap() {
                    if message.pgn == pgn::PROPRIETARY_A {
                        delivered = Some(message.data);
                        break 'transfer;
                    }
                }
            }
        }

        assert_eq!(
            delivered.as_deref(),
            Some(payload.as_slice()),
            "the whole 20 KiB message must arrive intact"
        );
        assert!(blocks > 1, "20 KiB cannot fit one 255-packet block");
    }

    #[test]
    fn an_oversized_extended_transfer_is_refused_not_partly_accepted() {
        use sae_j1939_rs::etp::EtpCm;

        let sender = Address::new(0x00);
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        // Larger than ETP_BUFFER.
        let rts = EtpCm::rts(super::ETP_BUFFER as u32 + 1, pgn::PROPRIETARY_A).unwrap();
        ecu.bus().queue(Frame::from_payload(
            Id::from_parts(Priority::LOWEST, pgn::ETP_CM, Address::new(0x80), sender).unwrap(),
            rts.encode(),
        ));
        ecu.poll().unwrap();

        let replies = ecu.bus().sent_with_pgn(pgn::ETP_CM);
        let last = EtpCm::decode(replies.last().expect("an answer").payload()).unwrap();
        assert!(
            matches!(last, EtpCm::Abort { .. }),
            "an oversized transfer must be refused up front, got {last:?}"
        );
        assert_eq!(ecu.etp_progress(sender), None);
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

    // -----------------------------------------------------------------------
    // Scripted exchanges: one ECU, a bus that answers it
    // -----------------------------------------------------------------------

    /// A frame from `source` to `destination` carrying connection management.
    fn cm_frame(source: Address, destination: Address, cm: &TpCm) -> Frame {
        Frame::from_payload(
            Id::from_parts(Priority::LOWEST, pgn::TP_CM, destination, source).unwrap(),
            cm.encode(),
        )
    }

    /// A frame from `source` to `destination` carrying a data packet.
    fn dt_frame(source: Address, destination: Address, dt: &TpDt) -> Frame {
        Frame::from_payload(
            Id::from_parts(Priority::LOWEST, pgn::TP_DT, destination, source).unwrap(),
            dt.encode(),
        )
    }

    /// An ECU pushing a multi-packet message to a peer that is pushing one back
    /// at the same time — both transfers live on the same `send_to` call.
    ///
    /// This is where a host stack loses messages: it is blocked driving its own
    /// handshake, and everything arriving meanwhile looks like an interruption.
    /// The inbound transfer has to be answered with a CTS *and* an
    /// acknowledgement while the outbound one is still in flight, and the
    /// reassembled result has to survive until the caller asks for it.
    #[test]
    fn an_ecu_sends_and_receives_multi_packet_messages_in_one_exchange() {
        let us = Address::new(0x80);
        let peer = Address::new(0x90);
        let inbound: Vec<u8> = (0..21).map(|i| (i * 7) as u8).collect();

        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        // Script the peer's side of the exchange. It is queued after the claim
        // so that the contention window does not consume it first.
        //
        // The peer opens its own transfer before answering ours...
        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::rts(21, pgn::ECU_IDENTIFICATION).unwrap(),
        ));
        // ...then grants our window...
        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::Cts {
                packets: 3,
                next_packet: 1,
                pgn: pgn::DM1,
            },
        ));
        // ...then sends its own packets, interleaved with ours going out...
        for (i, chunk) in inbound.chunks(7).enumerate() {
            ecu.bus()
                .queue(dt_frame(peer, us, &TpDt::new(i as u8 + 1, chunk)));
        }
        // ...and finally acknowledges ours.
        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::EndOfMsgAck {
                size: 21,
                packets: 3,
                pgn: pgn::DM1,
            },
        ));

        ecu.send_to(peer, pgn::DM1, &[0xAB; 21])
            .expect("the outbound transfer must complete");

        // Our side: an RTS and three data packets went out.
        assert_eq!(
            ecu.bus().sent_with_pgn(pgn::TP_DT).len(),
            3,
            "every packet of the outbound message must be sent"
        );

        // Their side: we answered with a CTS and an end-of-message
        // acknowledgement without ever leaving `send_to`.
        let ours: Vec<TpCm> = ecu
            .bus()
            .sent_with_pgn(pgn::TP_CM)
            .iter()
            .map(|f| TpCm::decode(f.payload()).unwrap())
            .collect();
        assert!(
            ours.iter().any(|cm| matches!(
                cm,
                TpCm::Cts { pgn, .. } if *pgn == pgn::ECU_IDENTIFICATION
            )),
            "the peer's RTS must be answered even while we are mid-send, got {ours:?}"
        );
        assert!(
            ours.iter().any(|cm| matches!(
                cm,
                TpCm::EndOfMsgAck { pgn, .. } if *pgn == pgn::ECU_IDENTIFICATION
            )),
            "the peer's transfer must be acknowledged, got {ours:?}"
        );

        // And the message itself was kept, not dropped for being inconvenient.
        let delivered = ecu
            .poll()
            .unwrap()
            .expect("a message that arrived during the handshake must survive it");
        assert_eq!(delivered.pgn, pgn::ECU_IDENTIFICATION);
        assert_eq!(delivered.source, peer);
        assert_eq!(delivered.data, inbound);
    }

    /// Regression: the peer aborts a transfer of its own while ours is in
    /// flight. The abort names a different parameter group, so it is not ours,
    /// and our send must run to completion.
    #[test]
    fn a_peers_abort_of_another_group_does_not_fail_our_send() {
        let us = Address::new(0x80);
        let peer = Address::new(0x90);

        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::ECU_IDENTIFICATION,
            },
        ));
        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::Cts {
                packets: 3,
                next_packet: 1,
                pgn: pgn::DM1,
            },
        ));
        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::EndOfMsgAck {
                size: 21,
                packets: 3,
                pgn: pgn::DM1,
            },
        ));

        ecu.send_to(peer, pgn::DM1, &[0u8; 21])
            .expect("an abort naming another group must not fail our transfer");
        assert_eq!(ecu.bus().sent_with_pgn(pgn::TP_DT).len(), 3);
    }

    /// An abort that *does* name our parameter group ends the transfer, and says
    /// why. The two tests are only meaningful as a pair.
    #[test]
    fn a_peers_abort_of_our_own_group_fails_the_send() {
        let us = Address::new(0x80);
        let peer = Address::new(0x90);

        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        ecu.bus().queue(cm_frame(
            peer,
            us,
            &TpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::DM1,
            },
        ));

        let error = ecu.send_to(peer, pgn::DM1, &[0u8; 21]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            error.to_string().contains("ResourcesUnavailable"),
            "the reason belongs in the error, got: {error}"
        );
        assert!(
            ecu.bus().sent_with_pgn(pgn::TP_DT).is_empty(),
            "nothing may go out after an abort"
        );
    }

    /// Regression: `send_to(GLOBAL, ..)` is a broadcast, not a handshake.
    ///
    /// There is nobody to hand a message to "specifically" at the global
    /// address, so a long one is a BAM — and a BAM has no flow control, only
    /// pacing. Blasting the packets back to back would put traffic on the bus
    /// that conforming receivers drop, and waiting for a CTS that cannot come
    /// would fail the call outright.
    #[test]
    fn a_long_message_sent_to_the_global_address_is_paced_like_a_bam() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 300));
        ecu.claim_address().unwrap();

        let started = Instant::now();
        ecu.send_to(Address::GLOBAL, pgn::DM1, &[0u8; 14])
            .expect("a broadcast needs no acknowledgement, so it cannot time out");
        let elapsed = started.elapsed();

        let announcements = ecu.bus().sent_with_pgn(pgn::TP_CM);
        assert_eq!(announcements.len(), 1);
        assert!(
            matches!(
                TpCm::decode(announcements[0].payload()).unwrap(),
                TpCm::Bam { size: 14, .. }
            ),
            "the global address must be announced with a BAM, not an RTS"
        );
        assert_eq!(ecu.bus().sent_with_pgn(pgn::TP_DT).len(), 2);
        assert!(
            elapsed >= BAM_PACKET_INTERVAL,
            "the two data packets must be spaced, but went out in {elapsed:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Two real ECUs, one bus
    // -----------------------------------------------------------------------

    /// A two-ended in-memory bus, so two `Ecu`s can hold an actual conversation.
    ///
    /// Each end reads only what the other wrote: a CAN controller does not
    /// receive its own frames, and an ECU that heard its own address claim would
    /// contend with itself.
    #[derive(Debug, Default)]
    struct Link {
        to_a: Mutex<VecDeque<Frame>>,
        to_b: Mutex<VecDeque<Frame>>,
    }

    #[derive(Debug)]
    struct End {
        link: Arc<Link>,
        a_side: bool,
    }

    impl Bus for End {
        fn send_frame(&self, frame: &Frame) -> io::Result<()> {
            let queue = if self.a_side {
                &self.link.to_b
            } else {
                &self.link.to_a
            };
            queue.lock().unwrap().push_back(*frame);
            Ok(())
        }

        fn recv_frame(&self) -> io::Result<Option<Frame>> {
            let queue = if self.a_side {
                &self.link.to_a
            } else {
                &self.link.to_b
            };
            let frame = queue.lock().unwrap().pop_front();
            if frame.is_none() {
                // `Bus` asks implementations to block briefly rather than return
                // immediately; with two ECUs polling in one process, the
                // difference is a test versus a space heater.
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(frame)
        }
    }

    fn link_ends() -> (End, End) {
        let link = Arc::new(Link::default());
        (
            End {
                link: Arc::clone(&link),
                a_side: true,
            },
            End {
                link,
                a_side: false,
            },
        )
    }

    /// The exchange a diagnostic tool performs on every bus it is plugged into:
    /// claim an address, ask an ECU who it is, and read the answer — which is
    /// far too long for one frame and comes back over the transport protocol.
    ///
    /// Both ends are real `Ecu`s driving real sockets' worth of frames at each
    /// other, so this covers the parts the scripted tests cannot: two address
    /// claims racing, and a handshake where both sides are genuinely blocking on
    /// the other.
    #[test]
    fn two_ecus_complete_a_request_and_a_multi_packet_response() {
        const FIELDS: &[&[u8]] = &[b"PN-1234", b"SN-99", b"ENGINE BAY", b"ECM", b"ACME MOTORS"];
        let tool_address = Address::new(0x80);
        let ecu_address = Address::new(0x90);
        let patience = Duration::from_secs(10);

        let (tool_end, ecu_end) = link_ends();

        // The ECU under test: come up, answer one request, and stop.
        let responder = std::thread::spawn(move || -> io::Result<()> {
            let mut ecu = Ecu::<_, 1785, 4>::new(ecu_end, name_for(2, 200), ecu_address);
            ecu.claim_address()?;
            assert!(ecu.has_address(), "the responder never claimed an address");

            let deadline = Instant::now() + patience;
            while Instant::now() < deadline {
                let Some(message) = ecu.poll()? else { continue };
                if message.pgn != pgn::REQUEST {
                    continue;
                }
                let Ok(request) = Request::decode(&message.data) else {
                    continue;
                };
                if request.pgn != pgn::ECU_IDENTIFICATION {
                    continue;
                }

                let mut payload = [0u8; 128];
                let len = identification::encode(FIELDS, &mut payload).unwrap();
                assert!(len > 8, "identification must not fit a single frame");
                ecu.send_to(message.source, pgn::ECU_IDENTIFICATION, &payload[..len])?;
                return Ok(());
            }
            panic!("the responder never saw the request");
        });

        let mut tool = Ecu::<_, 1785, 4>::new(tool_end, name_for(1, 100), tool_address);
        tool.claim_address().unwrap();
        assert!(tool.has_address(), "the tool never claimed an address");
        assert_eq!(tool.address(), tool_address, "nobody contested 0x80");

        tool.request(ecu_address, pgn::ECU_IDENTIFICATION).unwrap();

        let deadline = Instant::now() + patience;
        let mut answer = None;
        while Instant::now() < deadline {
            if let Some(message) = tool.poll().unwrap() {
                if message.pgn == pgn::ECU_IDENTIFICATION {
                    answer = Some(message);
                    break;
                }
            }
        }

        responder
            .join()
            .expect("the responder thread panicked")
            .expect("the responder hit an I/O error");

        let answer = answer.expect("the tool never received the identification");
        assert_eq!(answer.source, ecu_address);
        let identification = EcuIdentification::new(&answer.data);
        assert_eq!(identification.field_count(), 5);
        assert_eq!(identification.part_number_str(), Some("PN-1234"));
        assert_eq!(identification.serial_number_str(), Some("SN-99"));
        assert_eq!(identification.manufacturer_name_str(), Some("ACME MOTORS"));
    }

    // -----------------------------------------------------------------------
    // Reporting this ECU's own faults.
    // -----------------------------------------------------------------------

    /// Bring an ECU up on a scripted bus, ready to transmit.
    fn claimed_ecu() -> Ecu<FakeBus, 1785, 4> {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 100));
        ecu.claim_address().unwrap();
        assert!(ecu.has_address());
        ecu
    }

    /// A Request frame from a service tool at 0xF9 to this ECU at 0x80.
    fn request_frame(requested: Pgn) -> Frame {
        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::REQUEST,
            Address::new(0x80),
            Address::new(0xF9),
        )
        .unwrap();
        Frame::new(id, &Request::new(requested).encode()).unwrap()
    }

    /// Drive `poll` for a while, so timers actually fire.
    fn run_for(ecu: &mut Ecu<FakeBus, 1785, 4>, duration: Duration) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            ecu.poll().unwrap();
        }
    }

    fn dm1_payloads(ecu: &Ecu<FakeBus, 1785, 4>) -> Vec<Vec<u8>> {
        ecu.bus()
            .sent_with_pgn(pgn::DM1)
            .into_iter()
            .map(|f| f.data().to_vec())
            .collect()
    }

    #[test]
    fn a_healthy_ecu_never_broadcasts_dm1() {
        let mut ecu = claimed_ecu();
        run_for(&mut ecu, Duration::from_millis(1200));
        assert!(
            ecu.bus().sent_with_pgn(pgn::DM1).is_empty(),
            "nothing is wrong, so there is nothing to broadcast"
        );
    }

    #[test]
    fn a_faulted_ecu_broadcasts_dm1_about_once_a_second() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();

        // The first report is prompt — a fault should not wait a second to be
        // announced when nothing has been said recently.
        run_for(&mut ecu, Duration::from_millis(50));
        assert_eq!(dm1_payloads(&ecu).len(), 1);

        // Then once per second, not once per poll.
        run_for(&mut ecu, Duration::from_millis(1100));
        let count = dm1_payloads(&ecu).len();
        assert_eq!(count, 2, "expected one more DM1, got {count} in total");
    }

    #[test]
    fn the_broadcast_dm1_carries_the_fault_and_lights_the_lamp() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        run_for(&mut ecu, Duration::from_millis(50));

        let payload = dm1_payloads(&ecu).pop().expect("no DM1 was broadcast");
        let dm = diagnostics::Message::parse(&payload).unwrap();
        assert_eq!(dm.lamps().status(Lamp::RedStop), LampStatus::On);
        assert_eq!(dm.lamps().status(Lamp::AmberWarning), LampStatus::Off);

        let dtcs: Vec<Dtc> = dm.dtcs().collect();
        assert_eq!(dtcs.len(), 1);
        assert_eq!(dtcs[0].spn, 100);
        assert_eq!(dtcs[0].fmi, 1);
    }

    #[test]
    fn clearing_the_last_fault_broadcasts_one_all_clear_then_stops() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        run_for(&mut ecu, Duration::from_millis(50));
        assert!(ecu.clear_fault(100, 1));

        run_for(&mut ecu, Duration::from_millis(1100));
        let payloads = dm1_payloads(&ecu);
        assert_eq!(payloads.len(), 2, "the fault, then the all-clear");

        let all_clear = diagnostics::Message::parse(payloads.last().unwrap()).unwrap();
        assert!(all_clear.is_fault_free());
        assert!(!all_clear.lamps().any_on(), "the lamps must go out");

        // And then nothing: silence is only meaningful after the all-clear.
        run_for(&mut ecu, Duration::from_millis(1100));
        assert_eq!(dm1_payloads(&ecu).len(), 2);
    }

    #[test]
    fn an_ecu_without_an_address_does_not_broadcast_dm1() {
        // Never claimed: J1939-81 forbids transmitting, and the report must be
        // held rather than thrown away.
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 100));
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        run_for(&mut ecu, Duration::from_millis(1200));
        assert!(ecu.bus().sent_with_pgn(pgn::DM1).is_empty());

        // Once it is on the bus, the fault is reported — not lost.
        ecu.claim_address().unwrap();
        run_for(&mut ecu, Duration::from_millis(50));
        assert_eq!(dm1_payloads(&ecu).len(), 1);
    }

    #[test]
    fn several_faults_go_out_over_the_transport_protocol() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        ecu.set_fault(110, 0, Lamp::AmberWarning).unwrap();
        ecu.set_fault(190, 16, Lamp::Protect).unwrap();
        run_for(&mut ecu, Duration::from_millis(300));

        // Fourteen bytes will not fit a frame, so it is announced with a BAM
        // and pushed as data packets — no plain DM1 frame at all.
        assert!(ecu.bus().sent_with_pgn(pgn::DM1).is_empty());
        let announcements = ecu.bus().sent_with_pgn(pgn::TP_CM);
        assert_eq!(announcements.len(), 1);
        assert_eq!(
            ecu.bus().sent_with_pgn(pgn::TP_DT).len(),
            2,
            "fourteen bytes is two data packets"
        );

        // And the announcement names DM1, so a receiver knows what is coming.
        let TpCm::Bam {
            size, pgn: group, ..
        } = TpCm::decode(announcements[0].payload()).unwrap()
        else {
            panic!("a broadcast transfer must be announced with a BAM");
        };
        assert_eq!(group, pgn::DM1);
        assert_eq!(size, 14);
    }

    #[test]
    fn a_request_for_dm1_is_answered_with_the_active_faults() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        // Drain the periodic broadcast so the next DM1 is unambiguously the
        // answer to the request.
        run_for(&mut ecu, Duration::from_millis(50));
        let before = dm1_payloads(&ecu).len();

        ecu.bus().queue(request_frame(pgn::DM1));
        ecu.poll().unwrap();

        let payloads = dm1_payloads(&ecu);
        assert_eq!(payloads.len(), before + 1, "the request went unanswered");
        let dm = diagnostics::Message::parse(payloads.last().unwrap()).unwrap();
        assert_eq!(dm.dtcs().next().unwrap().spn, 100);
    }

    #[test]
    fn a_healthy_ecu_still_answers_a_request_for_dm1() {
        // Silence would be indistinguishable from an ECU that is not there.
        let mut ecu = claimed_ecu();
        ecu.bus().queue(request_frame(pgn::DM1));
        ecu.poll().unwrap();

        let payloads = dm1_payloads(&ecu);
        assert_eq!(payloads.len(), 1);
        assert!(diagnostics::Message::parse(&payloads[0])
            .unwrap()
            .is_fault_free());
    }

    #[test]
    fn a_request_for_dm2_is_answered_with_the_history() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        ecu.clear_fault(100, 1);
        run_for(&mut ecu, Duration::from_millis(50));

        ecu.bus().queue(request_frame(pgn::DM2));
        ecu.poll().unwrap();

        let sent = ecu.bus().sent_with_pgn(pgn::DM2);
        assert_eq!(sent.len(), 1);
        let dm = diagnostics::Message::parse(sent[0].data()).unwrap();
        assert_eq!(dm.dtcs().next().unwrap().spn, 100);
        assert!(!dm.lamps().any_on(), "history lights no lamps");
    }

    #[test]
    fn dm11_clears_the_active_codes_and_is_acknowledged_to_the_requester() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        run_for(&mut ecu, Duration::from_millis(50));

        ecu.bus().queue(request_frame(pgn::DM11));
        ecu.poll().unwrap();

        assert!(ecu.faults().is_healthy(), "the codes should be gone");
        // A reset command is not evidence the fault stopped, so no history.
        assert!(ecu.faults().previously_active().is_empty());

        let acks = ecu.bus().sent_with_pgn(pgn::ACKNOWLEDGEMENT);
        assert_eq!(acks.len(), 1);
        assert_eq!(
            acks[0].id().destination_address(),
            Some(Address::new(0xF9)),
            "the requester asked, so the requester is told"
        );
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(acks[0].payload());
        let ack = Acknowledgement::decode(&bytes);
        assert!(ack.control.is_positive());
        assert_eq!(ack.pgn, pgn::DM11);

        // The lamps going out is announced rather than left to be inferred.
        let last = dm1_payloads(&ecu).pop().unwrap();
        assert!(diagnostics::Message::parse(&last).unwrap().is_fault_free());
    }

    #[test]
    fn dm3_clears_the_history_and_leaves_live_faults_alone() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        ecu.clear_fault(100, 1);
        ecu.set_fault(110, 0, Lamp::AmberWarning).unwrap();
        run_for(&mut ecu, Duration::from_millis(50));

        ecu.bus().queue(request_frame(pgn::DM3));
        ecu.poll().unwrap();

        assert!(ecu.faults().previously_active().is_empty());
        assert_eq!(ecu.faults().active().len(), 1, "DM3 spares live faults");

        let acks = ecu.bus().sent_with_pgn(pgn::ACKNOWLEDGEMENT);
        assert_eq!(acks.len(), 1);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(acks[0].payload());
        assert_eq!(Acknowledgement::decode(&bytes).pgn, pgn::DM3);
    }

    #[test]
    fn a_request_for_dm5_reports_counts_that_match_the_fault_log() {
        let mut ecu = claimed_ecu();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        ecu.set_fault(110, 0, Lamp::AmberWarning).unwrap();
        ecu.clear_fault(100, 1);
        ecu.set_fault(190, 16, Lamp::Protect).unwrap();
        run_for(&mut ecu, Duration::from_millis(300));

        ecu.bus().queue(request_frame(pgn::DM5));
        run_for(&mut ecu, Duration::from_millis(20));

        let sent = ecu.bus().sent_with_pgn(pgn::DM5);
        assert_eq!(sent.len(), 1);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(sent[0].payload());
        let readiness = diagnostics::Dm5::decode(&bytes);

        // Two active (110, 190) and one previously active (100) — the same
        // numbers the DM1 and DM2 would report, because they share a source.
        assert_eq!(readiness.active_faults, 2);
        assert_eq!(readiness.previously_active_faults, 1);
        assert_eq!(readiness.obd_compliance, ObdCompliance::NotIntended);
    }

    #[test]
    fn an_ecu_reports_the_compliance_level_it_was_given() {
        let mut ecu = claimed_ecu();
        ecu.set_obd_compliance(ObdCompliance::Other(0x14));
        ecu.bus().queue(request_frame(pgn::DM5));
        run_for(&mut ecu, Duration::from_millis(20));

        let sent = ecu.bus().sent_with_pgn(pgn::DM5);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(sent[0].payload());
        assert_eq!(
            diagnostics::Dm5::decode(&bytes).obd_compliance,
            ObdCompliance::Other(0x14)
        );
    }

    #[test]
    fn a_request_for_something_else_is_left_to_the_application() {
        let mut ecu = claimed_ecu();
        ecu.bus()
            .queue(request_frame(pgn::COMPONENT_IDENTIFICATION));

        let message = ecu.poll().unwrap().expect("the request must reach us");
        assert_eq!(message.pgn, pgn::REQUEST);
        // Not ours to answer, and specifically not answered with a wrong guess.
        assert!(ecu.bus().sent_with_pgn(pgn::DM1).is_empty());
        assert!(ecu.bus().sent_with_pgn(pgn::ACKNOWLEDGEMENT).is_empty());
    }

    // -----------------------------------------------------------------------
    // Transmitting on a schedule.
    // -----------------------------------------------------------------------

    /// A plausible EEC1 payload: 1500 rpm.
    const EEC1: [u8; 8] = [0xFF, 0x87, 0x96, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];

    #[test]
    fn an_ecu_with_nothing_scheduled_stays_quiet() {
        let mut ecu = claimed_ecu();
        run_for(&mut ecu, Duration::from_millis(300));
        assert!(ecu.bus().sent_with_pgn(pgn::EEC1).is_empty());
        assert_eq!(ecu.periodic().count(), 0);
    }

    #[test]
    fn a_scheduled_message_goes_out_at_its_own_rate() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(100))
            .unwrap();

        run_for(&mut ecu, Duration::from_millis(520));
        let sent = ecu.bus().sent_with_pgn(pgn::EEC1).len();
        // Five in half a second, allowing one either side for scheduling jitter
        // on a loaded test machine.
        assert!(
            (4..=6).contains(&sent),
            "expected about five EEC1 broadcasts, got {sent}"
        );
        assert_eq!(sent, ecu.bus().sent_with_pgn(pgn::EEC1).len());
    }

    #[test]
    fn the_scheduled_payload_is_the_one_that_goes_on_the_bus() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        run_for(&mut ecu, Duration::from_millis(60));

        let frames = ecu.bus().sent_with_pgn(pgn::EEC1);
        assert!(!frames.is_empty());
        assert_eq!(frames[0].payload(), &EEC1);
        // And it decodes to what it claims to be.
        assert_eq!(
            catalogue::ENGINE_SPEED.decode(frames[0].data()).unwrap(),
            SpnValue::Valid(1500.0)
        );
    }

    #[test]
    fn updating_the_payload_does_not_disturb_the_timing() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(50))
            .unwrap();

        // Publish a new value on every pass, the way a control loop would.
        let mut faster = EEC1;
        faster[4] = 0x5D; // a different engine speed
        let deadline = Instant::now() + Duration::from_millis(220);
        while Instant::now() < deadline {
            ecu.update_periodic(pgn::EEC1, &faster).unwrap();
            ecu.poll().unwrap();
        }

        let frames = ecu.bus().sent_with_pgn(pgn::EEC1);
        assert!(
            frames.len() >= 3,
            "updating must not stop transmission; got {}",
            frames.len()
        );
        assert_eq!(
            frames.last().unwrap().payload(),
            &faster,
            "the newest value must be the one sent"
        );
    }

    #[test]
    fn updating_something_that_is_not_scheduled_is_an_error() {
        // Silently doing nothing would leave a stale value going out, which
        // looks exactly like a sensor that stopped changing.
        let mut ecu = claimed_ecu();
        let error = ecu
            .update_periodic(pgn::EEC1, &EEC1)
            .expect_err("nothing is scheduled");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn several_groups_keep_their_separate_rates() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(50))
            .unwrap();
        ecu.broadcast_every(
            pgn::ENGINE_TEMPERATURE_1,
            &[0x50; 8],
            Duration::from_millis(500),
        )
        .unwrap();

        run_for(&mut ecu, Duration::from_millis(520));
        let fast = ecu.bus().sent_with_pgn(pgn::EEC1).len();
        let slow = ecu.bus().sent_with_pgn(pgn::ENGINE_TEMPERATURE_1).len();
        assert!(fast >= 8, "the fast group should be ~10, got {fast}");
        assert!(
            slow <= 2,
            "the slow group should be ~1, got {slow} — rates are not independent"
        );
    }

    #[test]
    fn an_ecu_without_an_address_transmits_nothing_periodic() {
        let mut ecu = ecu_on(FakeBus::default(), name_for(1, 100));
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        run_for(&mut ecu, Duration::from_millis(200));
        assert!(ecu.bus().sent_with_pgn(pgn::EEC1).is_empty());

        // ...and starts once it is on the bus.
        ecu.claim_address().unwrap();
        run_for(&mut ecu, Duration::from_millis(100));
        assert!(!ecu.bus().sent_with_pgn(pgn::EEC1).is_empty());
    }

    #[test]
    fn stopping_a_periodic_message_stops_it() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        run_for(&mut ecu, Duration::from_millis(100));
        let before = ecu.bus().sent_with_pgn(pgn::EEC1).len();
        assert!(before > 0);

        assert!(ecu.stop_periodic(pgn::EEC1, Address::GLOBAL));
        assert!(
            !ecu.stop_periodic(pgn::EEC1, Address::GLOBAL),
            "already gone"
        );
        run_for(&mut ecu, Duration::from_millis(200));
        assert_eq!(ecu.bus().sent_with_pgn(pgn::EEC1).len(), before);
    }

    #[test]
    fn the_schedule_reads_back() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(50))
            .unwrap();
        ecu.send_every(
            pgn::EEC2,
            Address::new(0x21),
            &[0u8; 8],
            Duration::from_millis(100),
        )
        .unwrap();

        let listed: Vec<_> = ecu.periodic().collect();
        assert_eq!(
            listed,
            [
                (pgn::EEC1, Address::GLOBAL, Duration::from_millis(50)),
                (pgn::EEC2, Address::new(0x21), Duration::from_millis(100)),
            ]
        );
    }

    #[test]
    fn a_period_of_zero_is_refused() {
        let mut ecu = claimed_ecu();
        let error = ecu
            .broadcast_every(pgn::EEC1, &EEC1, Duration::ZERO)
            .expect_err("every zero milliseconds means nothing");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(ecu.periodic().count(), 0);
    }

    #[test]
    fn a_period_too_long_for_the_schedule_is_refused_rather_than_truncated() {
        // Silently wrapping a two-minute period into something under a second
        // would flood the bus with the opposite of what was asked for.
        let mut ecu = claimed_ecu();
        let error = ecu
            .broadcast_every(pgn::EEC1, &EEC1, Duration::from_secs(120))
            .expect_err("longer than u16 milliseconds");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(ecu.periodic().count(), 0);
    }

    #[test]
    fn a_scheduled_message_goes_out_at_the_priority_it_was_given() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        run_for(&mut ecu, Duration::from_millis(60));
        assert_eq!(
            ecu.bus().sent_with_pgn(pgn::EEC1)[0].id().priority(),
            Priority::DEFAULT,
            "the default until told otherwise"
        );

        // Engine speed is a control input: it should win arbitration against
        // diagnostics, which means a lower priority number.
        let engine = Priority::new(3).unwrap();
        ecu.set_periodic_priority(pgn::EEC1, Address::GLOBAL, engine)
            .unwrap();
        let before = ecu.bus().sent_with_pgn(pgn::EEC1).len();
        run_for(&mut ecu, Duration::from_millis(60));

        let frames = ecu.bus().sent_with_pgn(pgn::EEC1);
        assert!(frames.len() > before);
        assert_eq!(frames.last().unwrap().id().priority(), engine);
        // ...and the identifier really is the one a receiver would see.
        assert_eq!(frames.last().unwrap().id().as_u32(), 0x0CF00480);
    }

    #[test]
    fn changing_the_rate_does_not_reset_the_priority() {
        let mut ecu = claimed_ecu();
        let engine = Priority::new(3).unwrap();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        ecu.set_periodic_priority(pgn::EEC1, Address::GLOBAL, engine)
            .unwrap();

        // Re-register at a different rate, and update the value.
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(40))
            .unwrap();
        ecu.update_periodic(pgn::EEC1, &EEC1).unwrap();

        run_for(&mut ecu, Duration::from_millis(100));
        let frames = ecu.bus().sent_with_pgn(pgn::EEC1);
        assert!(!frames.is_empty());
        assert!(frames.iter().all(|f| f.id().priority() == engine));
    }

    #[test]
    fn setting_the_priority_of_something_unscheduled_is_an_error() {
        let mut ecu = claimed_ecu();
        let error = ecu
            .set_periodic_priority(pgn::EEC1, Address::GLOBAL, Priority::new(3).unwrap())
            .expect_err("nothing is scheduled");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_one_shot_broadcast_can_choose_its_priority_too() {
        let mut ecu = claimed_ecu();
        let engine = Priority::new(3).unwrap();
        ecu.broadcast_with_priority(pgn::EEC1, &EEC1, engine)
            .unwrap();

        let frames = ecu.bus().sent_with_pgn(pgn::EEC1);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].id().priority(), engine);
    }

    /// A DM13 command frame from a tool at 0xF9.
    fn dm13_frame(command: BroadcastCommand) -> Frame {
        let dm13 = Dm13::new().with_command(Network::CurrentDataLink, command);
        Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::DM13, Address::new(0xF9)),
            dm13.encode(),
        )
    }

    #[test]
    fn dm13_stops_periodic_transmission_and_dm13_starts_it_again() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        run_for(&mut ecu, Duration::from_millis(100));
        assert!(!ecu.bus().sent_with_pgn(pgn::EEC1).is_empty());

        ecu.bus().queue(dm13_frame(BroadcastCommand::Stop));
        ecu.poll().unwrap();
        assert!(ecu.broadcasts_suspended());

        let quiet_from = ecu.bus().sent_with_pgn(pgn::EEC1).len();
        run_for(&mut ecu, Duration::from_millis(300));
        assert_eq!(
            ecu.bus().sent_with_pgn(pgn::EEC1).len(),
            quiet_from,
            "the bus must actually go quiet"
        );

        ecu.bus().queue(dm13_frame(BroadcastCommand::Start));
        ecu.poll().unwrap();
        assert!(!ecu.broadcasts_suspended());
        run_for(&mut ecu, Duration::from_millis(100));
        assert!(ecu.bus().sent_with_pgn(pgn::EEC1).len() > quiet_from);
    }

    #[test]
    fn a_dm13_that_names_no_network_this_ecu_is_on_is_left_alone() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();

        // A command aimed only at the implement bus. Silencing the vehicle bus
        // because another network was mentioned would be worse than ignoring it.
        let dm13 = Dm13::new().with_command(Network::Implement, BroadcastCommand::Stop);
        ecu.bus().queue(Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::DM13, Address::new(0xF9)),
            dm13.encode(),
        ));
        ecu.poll().unwrap();

        assert!(!ecu.broadcasts_suspended());
        run_for(&mut ecu, Duration::from_millis(100));
        assert!(!ecu.bus().sent_with_pgn(pgn::EEC1).is_empty());
    }

    #[test]
    fn diagnostics_keep_flowing_while_broadcasts_are_stopped() {
        // DM13 exists so a tool can free up bandwidth for diagnostic work.
        // Suspending the diagnostics it came for would defeat the purpose.
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();
        ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
        run_for(&mut ecu, Duration::from_millis(50));

        ecu.bus().queue(dm13_frame(BroadcastCommand::Stop));
        ecu.poll().unwrap();

        let dm1_before = dm1_payloads(&ecu).len();
        let eec1_before = ecu.bus().sent_with_pgn(pgn::EEC1).len();
        run_for(&mut ecu, Duration::from_millis(1100));

        assert_eq!(
            ecu.bus().sent_with_pgn(pgn::EEC1).len(),
            eec1_before,
            "normal broadcasts must stop"
        );
        assert!(
            dm1_payloads(&ecu).len() > dm1_before,
            "diagnostics must keep flowing"
        );
    }

    #[test]
    fn a_stop_command_expires_so_an_unplugged_tool_cannot_silence_an_ecu() {
        let mut ecu = claimed_ecu();
        ecu.broadcast_every(pgn::EEC1, &EEC1, Duration::from_millis(20))
            .unwrap();

        // Suspend for a tenth of a second rather than the DM13 default, so the
        // test does not have to wait five seconds to prove the point.
        ecu.suspend_broadcasts(Duration::from_millis(100));
        assert!(ecu.broadcasts_suspended());
        let before = ecu.bus().sent_with_pgn(pgn::EEC1).len();

        run_for(&mut ecu, Duration::from_millis(400));
        assert!(!ecu.broadcasts_suspended(), "it must expire on its own");
        assert!(
            ecu.bus().sent_with_pgn(pgn::EEC1).len() > before,
            "transmission must resume without being told to"
        );
    }

    // -----------------------------------------------------------------------
    // Reading another ECU's faults: the service-tool side.
    // -----------------------------------------------------------------------

    /// A DM1 broadcast by the engine ECU at 0x00.
    fn dm1_from_engine(lamps: Lamps, dtcs: &[Dtc]) -> Frame {
        let mut payload = [0u8; 8];
        let len = diagnostics::encode(lamps, dtcs, &mut payload).unwrap();
        assert_eq!(len, 8, "this helper only builds single-frame DM1s");
        Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x00)),
            payload,
        )
    }

    #[test]
    fn the_tool_reads_a_fault_list_back() {
        let mut tool = claimed_ecu();
        let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
        tool.bus()
            .queue(dm1_from_engine(lamps, &[Dtc::new(1569, 31, 4).unwrap()]));

        let report = tool
            .read_active_faults(Address::new(0x00), DIAGNOSTIC_TIMEOUT)
            .unwrap()
            .expect("the engine answered");

        assert_eq!(report.lamps, lamps);
        assert_eq!(report.dtcs.len(), 1);
        assert_eq!(report.dtcs[0].spn, 1569);
        assert_eq!(report.dtcs[0].occurrence_count, 4);
        assert!(!report.is_healthy());
    }

    #[test]
    fn a_fault_free_answer_reads_as_healthy_rather_than_as_a_code() {
        let mut tool = claimed_ecu();
        // The placeholder a real ECU sends when nothing is wrong.
        tool.bus()
            .queue(dm1_from_engine(Lamps::new(), &[Dtc::default()]));

        let report = tool
            .read_active_faults(Address::new(0x00), DIAGNOSTIC_TIMEOUT)
            .unwrap()
            .unwrap();
        assert!(report.is_healthy());
        assert!(report.dtcs.is_empty(), "a placeholder is not a fault");
    }

    #[test]
    fn an_ecu_that_says_nothing_reads_as_no_answer() {
        let mut tool = claimed_ecu();
        let answer = tool
            .read_active_faults(Address::new(0x00), Duration::from_millis(120))
            .unwrap();
        assert!(answer.is_none(), "silence is not a fault list");
        // And the request did go out, so this is a timeout rather than a no-op.
        assert_eq!(tool.bus().sent_with_pgn(pgn::REQUEST).len(), 1);
    }

    #[test]
    fn an_answer_from_the_wrong_ecu_is_not_mistaken_for_ours() {
        let mut tool = claimed_ecu();
        // 0x03 volunteers a DM1 while we are waiting on 0x00.
        tool.bus().queue(Frame::from_payload(
            Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x03)),
            [0x00, 0x00, 0x64, 0x00, 0x01, 0x81, 0xFF, 0xFF],
        ));

        let answer = tool
            .read_active_faults(Address::new(0x00), Duration::from_millis(120))
            .unwrap();
        assert!(answer.is_none());

        // But it was not swallowed: the application still gets to see it.
        let queued = tool.poll().unwrap().expect("the other DM1 must survive");
        assert_eq!(queued.source, Address::new(0x03));
        assert_eq!(queued.pgn, pgn::DM1);
    }

    #[test]
    fn a_refusal_is_reported_as_a_refusal_rather_than_as_silence() {
        let mut tool = claimed_ecu();
        let ack = diagnostics::dm11::refuse(
            Address::new(0x00),
            sae_j1939_rs::request::AckControl::AccessDenied,
        );
        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::ACKNOWLEDGEMENT,
            Address::new(0x80),
            Address::new(0x00),
        )
        .unwrap();
        tool.bus().queue(Frame::from_payload(id, ack.encode()));

        let error = tool
            .clear_active_faults(Address::new(0x00), DIAGNOSTIC_TIMEOUT)
            .expect_err("a denial is not success");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn a_positive_acknowledgement_confirms_the_clear() {
        let mut tool = claimed_ecu();
        let ack = diagnostics::dm3::acknowledge(Address::new(0x00));
        let id = Id::from_parts(
            Priority::DEFAULT,
            pgn::ACKNOWLEDGEMENT,
            Address::new(0x80),
            Address::new(0x00),
        )
        .unwrap();
        tool.bus().queue(Frame::from_payload(id, ack.encode()));

        assert!(tool
            .clear_previously_active_faults(Address::new(0x00), DIAGNOSTIC_TIMEOUT)
            .unwrap());
    }

    #[test]
    fn every_address_claim_heard_becomes_an_inventory_entry() {
        let mut tool = claimed_ecu();
        assert_eq!(tool.inventory().count(), 0, "nothing heard yet");

        tool.bus()
            .queue(claim_frame(Address::new(0x00), name_for(7, 700)));
        tool.bus()
            .queue(claim_frame(Address::new(0x03), name_for(8, 800)));
        run_for(&mut tool, Duration::from_millis(30));

        let inventory: Vec<_> = tool.inventory().collect();
        assert_eq!(inventory.len(), 2);
        // Address order, so a scan reads the way a bus is usually drawn.
        assert_eq!(inventory[0].0, Address::new(0x00));
        assert_eq!(inventory[0].1.manufacturer_code(), 700);
        assert_eq!(inventory[1].0, Address::new(0x03));
    }

    #[test]
    fn an_ecu_that_gave_up_is_not_an_inventory_entry() {
        let mut tool = claimed_ecu();
        // A Cannot Claim announcement comes from the null address: it says
        // somebody lost, not that anybody is there.
        tool.bus()
            .queue(claim_frame(Address::NULL, name_for(9, 900)));
        run_for(&mut tool, Duration::from_millis(30));
        assert_eq!(tool.inventory().count(), 0);
    }

    #[test]
    fn a_scan_asks_the_bus_who_is_there() {
        let mut tool = claimed_ecu();
        tool.bus()
            .queue(claim_frame(Address::new(0x21), name_for(7, 700)));

        let found = tool.scan(Duration::from_millis(60)).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Address::new(0x21));

        // It really did ask, rather than only listening.
        let requests = tool.bus().sent_with_pgn(pgn::REQUEST);
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].id().destination_address(),
            Some(Address::GLOBAL)
        );
        assert_eq!(
            Request::decode(requests[0].data()).unwrap().pgn,
            pgn::ADDRESS_CLAIMED
        );
    }

    /// The whole point of the chunk: a tool and a faulted ECU, both real, one
    /// asking and the other answering over a shared wire.
    #[test]
    fn a_tool_reads_and_clears_a_real_ecus_faults() {
        let tool_address = Address::new(0xF9);
        let ecu_address = Address::new(0x90);
        let patience = Duration::from_secs(10);

        let (tool_end, ecu_end) = link_ends();

        // An engine controller with two things wrong with it.
        let engine = std::thread::spawn(move || -> io::Result<()> {
            let mut ecu = Ecu::<_, 1785, 4>::new(ecu_end, name_for(2, 200), ecu_address);
            ecu.claim_address()?;
            assert!(ecu.has_address(), "the engine never claimed an address");
            ecu.set_fault(100, 1, Lamp::RedStop).unwrap();
            ecu.set_fault(110, 0, Lamp::AmberWarning).unwrap();

            // Just run. Everything the tool asks for is answered inside `poll`.
            let deadline = Instant::now() + patience;
            while Instant::now() < deadline && !ecu.faults().is_healthy() {
                ecu.poll()?;
            }
            assert!(
                ecu.faults().is_healthy(),
                "the tool never cleared the codes"
            );
            Ok(())
        });

        let mut tool = Ecu::<_, 1785, 4>::new(tool_end, name_for(1, 100), tool_address);
        tool.claim_address().unwrap();
        assert!(tool.has_address(), "the tool never claimed an address");

        // What is on this bus? The engine must answer the global request for
        // Address Claimed with its NAME.
        let found = tool.scan(Duration::from_secs(1)).unwrap();
        assert_eq!(found.len(), 1, "the scan should have found the engine");
        assert_eq!(found[0].0, ecu_address);
        assert_eq!(found[0].1.manufacturer_code(), 200);

        // Readiness first, the way a technician works: how many codes to expect
        // before reading them.
        let readiness = tool
            .read_readiness(ecu_address, patience)
            .unwrap()
            .expect("the engine never reported its readiness");
        assert_eq!(readiness.active_faults, 2);
        assert_eq!(readiness.previously_active_faults, 0);

        // Two faults means the answer arrives over the transport protocol.
        let report = tool
            .read_active_faults(ecu_address, patience)
            .unwrap()
            .expect("the engine never reported its faults");
        let spns: Vec<u32> = report.dtcs.iter().map(|d| d.spn).collect();
        assert_eq!(spns, [100, 110], "in the order they were raised");
        assert_eq!(report.lamps.status(Lamp::RedStop), LampStatus::On);
        assert_eq!(report.lamps.status(Lamp::AmberWarning), LampStatus::On);

        // Now clear them, and watch the ECU confirm.
        assert!(
            tool.clear_active_faults(ecu_address, patience).unwrap(),
            "the engine did not acknowledge the clear"
        );

        engine
            .join()
            .expect("the engine thread panicked")
            .expect("the engine hit an I/O error");
    }
}
