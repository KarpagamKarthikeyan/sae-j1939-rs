// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The J1939-21 Transport Protocol: multi-packet messages up to 1785 bytes.
//!
//! A CAN frame carries eight bytes. Any J1939 parameter group larger than that
//! — a DM1 with several trouble codes, an ECU identification string, a
//! commanded address — is split across numbered *data transfer* frames
//! (TP.DT), bracketed by *connection management* frames (TP.CM).
//!
//! There are two flavours, and the difference is not cosmetic:
//!
//! - **BAM** (Broadcast Announce Message) — a one-way broadcast. The sender
//!   announces the size, then pushes every packet. Nobody acknowledges, and
//!   nobody can ask for a retry. The sender **must** pace packets 50–200 ms
//!   apart (J1939-21); see [`Transmitter`].
//! - **RTS/CTS** — a destination-specific handshake. The sender offers (RTS),
//!   the receiver grants a window of packets (CTS), the sender fills it, and
//!   the receiver closes with an end-of-message acknowledgement. Either side
//!   can abort.
//!
//! Both directions are modelled here as **sans-I/O** state machines: they
//! consume and produce [`TpCm`]/[`TpDt`] messages but never touch a bus, so the
//! same code runs on a host and on a bare-metal ECU.
//!
//! # Receiving
//!
//! [`Reassembler`] is generic over the largest message it will accept, so an
//! MCU can bound its memory. Anything larger is refused with an abort rather
//! than overflowing a buffer.
//!
//! ```
//! use sae_j1939_rs::tp::{Reassembler, Rx, TpCm, TpDt};
//! use sae_j1939_rs::{pgn, Address};
//!
//! // Accept messages up to 256 bytes.
//! let mut rx = Reassembler::<256>::new();
//! let sender = Address::new(0x80);
//!
//! // A 12-byte broadcast arrives as an announcement plus two packets.
//! let announce = TpCm::bam(12, pgn::DM1).unwrap();
//! assert!(matches!(rx.on_tp_cm(sender, &announce), Rx::Idle));
//!
//! rx.on_tp_dt(sender, &TpDt::new(1, &[1, 2, 3, 4, 5, 6, 7]));
//! match rx.on_tp_dt(sender, &TpDt::new(2, &[8, 9, 10, 11, 12, 0xFF, 0xFF])) {
//!     Rx::Message { pgn, data, ack, .. } => {
//!         assert_eq!(pgn, pgn::DM1);
//!         assert_eq!(data, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
//!         assert!(ack.is_none()); // BAM is never acknowledged
//!     }
//!     other => panic!("expected a complete message, got {other:?}"),
//! }
//! ```

use crate::pgn::Pgn;
use crate::types::{Address, Error, Result};

/// Payload bytes carried by one TP.DT frame (the eighth is the sequence number).
pub const BYTES_PER_PACKET: usize = 7;

/// The smallest message the transport protocol carries. Eight bytes or fewer
/// fit in a single CAN frame and must be sent directly.
pub const MIN_MESSAGE_SIZE: u16 = 9;

/// The largest message the transport protocol can carry: 255 packets of seven
/// bytes.
pub const MAX_MESSAGE_SIZE: u16 = 1785;

/// `T1` (J1939-21): the longest gap allowed between TP.DT packets of a transfer
/// in progress, in milliseconds. A receiver that sees no packet for this long
/// should abandon the session — see [`Reassembler::tick`].
pub const T1_TIMEOUT_MS: u16 = 750;

/// `T2` (J1939-21): how long a receiver waits for the first TP.DT after sending
/// a CTS, in milliseconds.
pub const T2_TIMEOUT_MS: u16 = 1250;

/// `T3` (J1939-21): how long a sender waits for a CTS or end-of-message
/// acknowledgement, in milliseconds.
pub const T3_TIMEOUT_MS: u16 = 1250;

/// `T4` (J1939-21): how long a sender honours a "wait" CTS before giving up, in
/// milliseconds.
pub const T4_TIMEOUT_MS: u16 = 1050;

/// The number of TP.DT packets needed to carry `size` bytes.
///
/// ```
/// use sae_j1939_rs::tp::packet_count;
/// assert_eq!(packet_count(9), 2);
/// assert_eq!(packet_count(14), 2);
/// assert_eq!(packet_count(1785), 255);
/// ```
pub const fn packet_count(size: u16) -> u8 {
    ((size as usize).div_ceil(BYTES_PER_PACKET)) as u8
}

// Control bytes, J1939-21.
const CB_RTS: u8 = 0x10;
const CB_CTS: u8 = 0x11;
const CB_EOM_ACK: u8 = 0x13;
const CB_BAM: u8 = 0x20;
const CB_ABORT: u8 = 0xFF;

/// Filler for unused payload bytes, per J1939-21.
const FILL: u8 = 0xFF;

/// Why a transport-protocol session was aborted (J1939-21 connection abort
/// reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// Already in one or more connection-managed sessions and cannot support
    /// another.
    AlreadyInSession,
    /// System resources were needed for another task.
    ResourcesUnavailable,
    /// A timeout occurred and this is the connection abort to close the session.
    Timeout,
    /// A CTS was received while the data transfer was already in progress.
    UnexpectedCts,
    /// The maximum retransmit request limit was reached.
    RetransmitLimit,
    /// An unexpected data transfer packet arrived.
    UnexpectedDataPacket,
    /// A bad sequence number was received and could not be recovered.
    BadSequenceNumber,
    /// A duplicate sequence number was received and could not be recovered.
    DuplicateSequenceNumber,
    /// A reason outside the standard set, carried verbatim. `0xFF` means "no
    /// specific cause".
    Other(u8),
}

impl AbortReason {
    /// The wire byte for this reason.
    pub const fn as_u8(self) -> u8 {
        match self {
            AbortReason::AlreadyInSession => 1,
            AbortReason::ResourcesUnavailable => 2,
            AbortReason::Timeout => 3,
            AbortReason::UnexpectedCts => 4,
            AbortReason::RetransmitLimit => 5,
            AbortReason::UnexpectedDataPacket => 6,
            AbortReason::BadSequenceNumber => 7,
            AbortReason::DuplicateSequenceNumber => 8,
            AbortReason::Other(raw) => raw,
        }
    }

    /// Decode a wire byte.
    pub const fn from_u8(raw: u8) -> Self {
        match raw {
            1 => AbortReason::AlreadyInSession,
            2 => AbortReason::ResourcesUnavailable,
            3 => AbortReason::Timeout,
            4 => AbortReason::UnexpectedCts,
            5 => AbortReason::RetransmitLimit,
            6 => AbortReason::UnexpectedDataPacket,
            7 => AbortReason::BadSequenceNumber,
            8 => AbortReason::DuplicateSequenceNumber,
            other => AbortReason::Other(other),
        }
    }
}

/// A Transport Protocol Connection Management message (PGN `0x00EC00`).
///
/// Every variant is eight bytes on the wire, discriminated by the control byte
/// and carrying the PGN of the message being transported in bytes 5..8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpCm {
    /// Request To Send: the sender offers a destination-specific transfer.
    Rts {
        /// Total message size in bytes.
        size: u16,
        /// Total number of TP.DT packets.
        packets: u8,
        /// Most packets the sender will accept being asked for in one CTS.
        /// `0xFF` means no limit.
        max_packets_per_cts: u8,
        /// The parameter group being transported.
        pgn: Pgn,
    },
    /// Clear To Send: the receiver grants a window of packets.
    Cts {
        /// How many packets may be sent now. Zero tells the sender to wait.
        packets: u8,
        /// The sequence number the sender should resume from (1-based).
        next_packet: u8,
        /// The parameter group being transported.
        pgn: Pgn,
    },
    /// End Of Message Acknowledgement: the receiver has the whole message.
    EndOfMsgAck {
        /// Total message size received.
        size: u16,
        /// Total packets received.
        packets: u8,
        /// The parameter group that was transported.
        pgn: Pgn,
    },
    /// Broadcast Announce Message: the sender announces a broadcast transfer.
    Bam {
        /// Total message size in bytes.
        size: u16,
        /// Total number of TP.DT packets.
        packets: u8,
        /// The parameter group being transported.
        pgn: Pgn,
    },
    /// Connection Abort: either side tearing the session down.
    Abort {
        /// Why the session was aborted.
        reason: AbortReason,
        /// The parameter group whose transfer was abandoned.
        pgn: Pgn,
    },
}

impl TpCm {
    /// Build a BAM announcing a `size`-byte broadcast of `pgn`.
    ///
    /// Returns [`Error::InvalidMessageSize`] unless `size` is in
    /// `9..=1785` — smaller messages must be sent in a single frame.
    pub const fn bam(size: u16, pgn: Pgn) -> Result<Self> {
        if size < MIN_MESSAGE_SIZE || size > MAX_MESSAGE_SIZE {
            return Err(Error::InvalidMessageSize(size));
        }
        Ok(TpCm::Bam {
            size,
            packets: packet_count(size),
            pgn,
        })
    }

    /// Build an RTS offering a `size`-byte destination-specific transfer of
    /// `pgn`, with no limit on the CTS window.
    ///
    /// Returns [`Error::InvalidMessageSize`] unless `size` is in `9..=1785`.
    pub const fn rts(size: u16, pgn: Pgn) -> Result<Self> {
        if size < MIN_MESSAGE_SIZE || size > MAX_MESSAGE_SIZE {
            return Err(Error::InvalidMessageSize(size));
        }
        Ok(TpCm::Rts {
            size,
            packets: packet_count(size),
            max_packets_per_cts: 0xFF,
            pgn,
        })
    }

    /// The parameter group being transported.
    pub const fn pgn(&self) -> Pgn {
        match *self {
            TpCm::Rts { pgn, .. }
            | TpCm::Cts { pgn, .. }
            | TpCm::EndOfMsgAck { pgn, .. }
            | TpCm::Bam { pgn, .. }
            | TpCm::Abort { pgn, .. } => pgn,
        }
    }

    /// The control byte identifying this message on the wire.
    pub const fn control_byte(&self) -> u8 {
        match *self {
            TpCm::Rts { .. } => CB_RTS,
            TpCm::Cts { .. } => CB_CTS,
            TpCm::EndOfMsgAck { .. } => CB_EOM_ACK,
            TpCm::Bam { .. } => CB_BAM,
            TpCm::Abort { .. } => CB_ABORT,
        }
    }

    /// Encode to the eight-byte TP.CM payload.
    ///
    /// ```
    /// use sae_j1939_rs::pgn;
    /// use sae_j1939_rs::tp::TpCm;
    ///
    /// // A 12-byte BAM of DM1 (PGN 0x00FECA).
    /// let bam = TpCm::bam(12, pgn::DM1).unwrap();
    /// assert_eq!(bam.encode(), [0x20, 0x0C, 0x00, 0x02, 0xFF, 0xCA, 0xFE, 0x00]);
    /// ```
    pub const fn encode(&self) -> [u8; 8] {
        let pgn = self.pgn().as_u32();
        let (b1, b2, b3, b4) = match *self {
            TpCm::Rts {
                size,
                packets,
                max_packets_per_cts,
                ..
            } => (size as u8, (size >> 8) as u8, packets, max_packets_per_cts),
            TpCm::Cts {
                packets,
                next_packet,
                ..
            } => (packets, next_packet, FILL, FILL),
            TpCm::EndOfMsgAck { size, packets, .. } | TpCm::Bam { size, packets, .. } => {
                (size as u8, (size >> 8) as u8, packets, FILL)
            }
            TpCm::Abort { reason, .. } => (reason.as_u8(), FILL, FILL, FILL),
        };
        [
            self.control_byte(),
            b1,
            b2,
            b3,
            b4,
            pgn as u8,
            (pgn >> 8) as u8,
            (pgn >> 16) as u8,
        ]
    }

    /// Decode an eight-byte TP.CM payload.
    ///
    /// Returns [`Error::UnknownControlByte`] if the control byte is not one of
    /// the five defined by J1939-21.
    pub fn decode(data: &[u8; 8]) -> Result<Self> {
        let pgn =
            Pgn::new_masked((data[5] as u32) | ((data[6] as u32) << 8) | ((data[7] as u32) << 16));
        let size = u16::from_le_bytes([data[1], data[2]]);
        Ok(match data[0] {
            CB_RTS => TpCm::Rts {
                size,
                packets: data[3],
                max_packets_per_cts: data[4],
                pgn,
            },
            CB_CTS => TpCm::Cts {
                packets: data[1],
                next_packet: data[2],
                pgn,
            },
            CB_EOM_ACK => TpCm::EndOfMsgAck {
                size,
                packets: data[3],
                pgn,
            },
            CB_BAM => TpCm::Bam {
                size,
                packets: data[3],
                pgn,
            },
            CB_ABORT => TpCm::Abort {
                reason: AbortReason::from_u8(data[1]),
                pgn,
            },
            other => return Err(Error::UnknownControlByte(other)),
        })
    }
}

/// A Transport Protocol Data Transfer packet (PGN `0x00EB00`): a 1-based
/// sequence number followed by seven payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpDt {
    /// The 1-based packet sequence number.
    pub sequence: u8,
    /// Seven payload bytes; trailing unused bytes are `0xFF`.
    pub data: [u8; BYTES_PER_PACKET],
}

impl TpDt {
    /// Build a packet, padding `data` to seven bytes with `0xFF` and ignoring
    /// anything beyond the seventh byte.
    pub fn new(sequence: u8, data: &[u8]) -> Self {
        let mut buf = [FILL; BYTES_PER_PACKET];
        let n = data.len().min(BYTES_PER_PACKET);
        buf[..n].copy_from_slice(&data[..n]);
        TpDt {
            sequence,
            data: buf,
        }
    }

    /// Encode to the eight-byte TP.DT payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.sequence,
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
            self.data[4],
            self.data[5],
            self.data[6],
        ]
    }

    /// Decode an eight-byte TP.DT payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        TpDt {
            sequence: data[0],
            data: [
                data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ],
        }
    }
}

/// What a [`Reassembler`] wants the caller to do after a message.
#[derive(Debug, PartialEq, Eq)]
pub enum Rx<'a> {
    /// Nothing to do.
    Idle,
    /// Transmit this connection-management message back to the sender.
    Send(TpCm),
    /// A complete multi-packet message has been reassembled.
    Message {
        /// The parameter group that was transported.
        pgn: Pgn,
        /// The ECU that sent it.
        source: Address,
        /// The reassembled payload.
        data: &'a [u8],
        /// For an RTS/CTS session, the end-of-message acknowledgement to send
        /// back. `None` for a BAM, which is never acknowledged.
        ack: Option<TpCm>,
    },
}

/// The receive side of the transport protocol: reassembles BAM and RTS/CTS
/// transfers into whole messages.
///
/// `N` is the largest message this receiver will accept, in bytes. A transfer
/// announcing more than `N` is refused — with an abort for RTS/CTS, silently
/// for a BAM, which has no back-channel — so the buffer can never overflow.
///
/// `SESSIONS` is how many peers may have a transfer in flight at once, and
/// defaults to one. Each costs `N` bytes of buffer, so an MCU can keep it at one
/// while a host tracking a whole bus raises it:
///
/// ```
/// # use sae_j1939_rs::tp::Reassembler;
/// let mut node = Reassembler::<256>::new();          // one peer, 256 bytes
/// let mut tool = Reassembler::<1785, 8>::new();      // eight peers, ~14 KiB
/// # let _ = (node.is_busy(), tool.is_busy());
/// ```
///
/// Sessions are keyed by source address. A peer may only have one transfer open
/// at a time, which is what J1939-21 requires; a second concurrent request from
/// the same peer is aborted, and a request from a new peer when every slot is
/// full is refused for lack of resources.
#[derive(Debug)]
pub struct Reassembler<const N: usize, const SESSIONS: usize = 1> {
    slots: [Slot<N>; SESSIONS],
}

/// One in-flight transfer and the buffer it is filling.
#[derive(Debug, Clone, Copy)]
struct Slot<const N: usize> {
    buffer: [u8; N],
    session: Option<Session>,
}

impl<const N: usize> Slot<N> {
    const EMPTY: Self = Slot {
        buffer: [0; N],
        session: None,
    };
}

#[derive(Debug, Clone, Copy)]
struct Session {
    source: Address,
    pgn: Pgn,
    size: u16,
    packets: u8,
    /// The sequence number expected next (1-based).
    next_sequence: u8,
    /// Packets still expected in the window granted by the last CTS.
    window_remaining: u8,
    /// The most packets the sender will accept being asked for in one CTS.
    /// Carried for the life of the session so every window respects it, not
    /// just the first.
    max_packets_per_cts: u8,
    /// BAM sessions are broadcast: no CTS, no acknowledgement, no abort.
    broadcast: bool,
    /// Milliseconds since this session last made progress, accumulated by
    /// [`Reassembler::tick`].
    idle_ms: u16,
}

impl<const N: usize, const SESSIONS: usize> Default for Reassembler<N, SESSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const SESSIONS: usize> Reassembler<N, SESSIONS> {
    /// Create an idle reassembler.
    pub const fn new() -> Self {
        Reassembler {
            slots: [Slot::EMPTY; SESSIONS],
        }
    }

    /// Whether any transfer is currently in progress.
    pub fn is_busy(&self) -> bool {
        self.slots.iter().any(|slot| slot.session.is_some())
    }

    /// How many transfers are in flight.
    pub fn active_sessions(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.session.is_some())
            .count()
    }

    /// Whether `source` has a transfer in progress.
    pub fn is_receiving_from(&self, source: Address) -> bool {
        self.slot_of(source).is_some()
    }

    /// Abandon every session in progress.
    ///
    /// Call this when sessions time out — J1939-21 allows 750 ms between packets
    /// (`T1`). Timing lives with the caller, which owns the clock. To drop a
    /// single stalled peer, use [`Reassembler::abandon`].
    pub fn reset(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.session = None;
        }
    }

    /// Abandon the session with `source`, if any, and report whether there was
    /// one.
    pub fn abandon(&mut self, source: Address) -> bool {
        match self.slot_of(source) {
            Some(index) => {
                self.slots[index].session = None;
                true
            }
            None => false,
        }
    }

    /// Handle an incoming TP.CM addressed to this ECU.
    ///
    /// [`TpCm::Cts`] and [`TpCm::EndOfMsgAck`] belong to the *sending* side and
    /// are reported as [`Rx::Idle`] here; feed them to a [`Transmitter`].
    pub fn on_tp_cm(&mut self, source: Address, cm: &TpCm) -> Rx<'_> {
        match *cm {
            TpCm::Bam { size, packets, pgn } => {
                // A BAM has no back-channel: an unacceptable announcement can
                // only be dropped.
                if !valid_announcement(size, packets) || size as usize > N {
                    self.abandon(source);
                    return Rx::Idle;
                }
                let Some(index) = self.slot_for(source) else {
                    // Every slot is busy and none belongs to this sender.
                    return Rx::Idle;
                };
                // A BAM is pushed without permission, so there is no window limit.
                self.begin(index, source, pgn, size, packets, true, packets, 0);
                Rx::Idle
            }
            TpCm::Rts {
                size,
                packets,
                max_packets_per_cts,
                pgn,
            } => {
                if !valid_announcement(size, packets) {
                    return Rx::Send(TpCm::Abort {
                        reason: AbortReason::Other(FILL),
                        pgn,
                    });
                }
                if size as usize > N {
                    return Rx::Send(TpCm::Abort {
                        reason: AbortReason::ResourcesUnavailable,
                        pgn,
                    });
                }
                // One connection-managed session per peer, per J1939-21.
                if let Some(index) = self.slot_of(source) {
                    if self.slots[index].session.is_some_and(|s| !s.broadcast) {
                        return Rx::Send(TpCm::Abort {
                            reason: AbortReason::AlreadyInSession,
                            pgn,
                        });
                    }
                }
                let Some(index) = self.slot_for(source) else {
                    // No buffer free for a new peer.
                    return Rx::Send(TpCm::Abort {
                        reason: AbortReason::ResourcesUnavailable,
                        pgn,
                    });
                };
                // Grant as much of the transfer as the sender will allow at once.
                let window = grant_window(packets, max_packets_per_cts);
                self.begin(
                    index,
                    source,
                    pgn,
                    size,
                    packets,
                    false,
                    window,
                    max_packets_per_cts,
                );
                Rx::Send(TpCm::Cts {
                    packets: window,
                    next_packet: 1,
                    pgn,
                })
            }
            TpCm::Abort { .. } => {
                self.abandon(source);
                Rx::Idle
            }
            // Sender-side messages; not ours to act on.
            TpCm::Cts { .. } | TpCm::EndOfMsgAck { .. } => Rx::Idle,
        }
    }

    /// Handle an incoming TP.DT packet addressed to this ECU.
    pub fn on_tp_dt(&mut self, source: Address, dt: &TpDt) -> Rx<'_> {
        // No announcement preceded this packet, or it belongs to a peer we are
        // not tracking.
        let Some(index) = self.slot_of(source) else {
            return Rx::Idle;
        };
        let mut session = match self.slots[index].session {
            Some(session) => session,
            None => return Rx::Idle,
        };

        if dt.sequence != session.next_sequence {
            // Out of order. A BAM cannot be recovered, so drop it; an RTS/CTS
            // session is aborted so the sender learns immediately.
            self.slots[index].session = None;
            return if session.broadcast {
                Rx::Idle
            } else {
                Rx::Send(TpCm::Abort {
                    reason: AbortReason::BadSequenceNumber,
                    pgn: session.pgn,
                })
            };
        }

        // Copy this packet's slice of the message, clamped to the announced size.
        let offset = (dt.sequence as usize - 1) * BYTES_PER_PACKET;
        let end = (offset + BYTES_PER_PACKET).min(session.size as usize);
        self.slots[index].buffer[offset..end].copy_from_slice(&dt.data[..end - offset]);

        // Check for completion *before* advancing: a 255-packet transfer is the
        // protocol maximum, and `next_sequence` would overflow past it.
        if dt.sequence == session.packets {
            // Clear the session before handing out the payload so the slot is
            // immediately ready for the next transfer.
            self.slots[index].session = None;
            let ack = (!session.broadcast).then_some(TpCm::EndOfMsgAck {
                size: session.size,
                packets: session.packets,
                pgn: session.pgn,
            });
            return Rx::Message {
                pgn: session.pgn,
                source: session.source,
                data: &self.slots[index].buffer[..session.size as usize],
                ack,
            };
        }

        session.next_sequence += 1;
        session.window_remaining = session.window_remaining.saturating_sub(1);
        session.idle_ms = 0;
        self.slots[index].session = Some(session);

        if !session.broadcast && session.window_remaining == 0 {
            // The granted window is used up; open the next one, still within
            // the limit the sender stated in its RTS.
            let remaining = session.packets - session.next_sequence + 1;
            let window = grant_window(remaining, session.max_packets_per_cts);
            if let Some(active) = self.slots[index].session.as_mut() {
                active.window_remaining = window;
            }
            return Rx::Send(TpCm::Cts {
                packets: window,
                next_packet: session.next_sequence,
                pgn: session.pgn,
            });
        }
        Rx::Idle
    }

    /// Advance every session's idle timer by `elapsed_ms`, abandoning any that
    /// has gone quiet for longer than [`T1_TIMEOUT_MS`].
    ///
    /// This type owns no clock — call this from whatever timer you already
    /// have, passing the milliseconds since the last call. `on_timeout` is
    /// invoked once per abandoned session with the peer's address and, for a
    /// destination-specific transfer, the [`TpCm::Abort`] to send back. A
    /// broadcast has no back-channel, so it yields `None`.
    ///
    /// ```
    /// use sae_j1939_rs::tp::{Reassembler, TpCm, T1_TIMEOUT_MS};
    /// use sae_j1939_rs::{pgn, Address};
    ///
    /// let peer = Address::new(0x80);
    /// let mut rx = Reassembler::<256>::new();
    /// rx.on_tp_cm(peer, &TpCm::rts(21, pgn::DM1).unwrap());
    ///
    /// // The sender goes quiet. After T1 the session is dropped.
    /// let mut dropped = None;
    /// rx.tick(T1_TIMEOUT_MS + 1, |address, abort| dropped = Some((address, abort)));
    ///
    /// let (address, abort) = dropped.expect("the stalled session should time out");
    /// assert_eq!(address, peer);
    /// assert!(matches!(abort, Some(TpCm::Abort { .. })));
    /// assert!(!rx.is_busy());
    /// ```
    pub fn tick(&mut self, elapsed_ms: u16, on_timeout: impl FnMut(Address, Option<TpCm>)) {
        self.tick_with_timeout(elapsed_ms, T1_TIMEOUT_MS, on_timeout)
    }

    /// [`Reassembler::tick`] with a timeout of your choosing, for buses that
    /// deviate from `T1`.
    pub fn tick_with_timeout(
        &mut self,
        elapsed_ms: u16,
        timeout_ms: u16,
        mut on_timeout: impl FnMut(Address, Option<TpCm>),
    ) {
        for slot in self.slots.iter_mut() {
            let Some(session) = slot.session.as_mut() else {
                continue;
            };
            session.idle_ms = session.idle_ms.saturating_add(elapsed_ms);
            if session.idle_ms <= timeout_ms {
                continue;
            }
            let abort = (!session.broadcast).then_some(TpCm::Abort {
                reason: AbortReason::Timeout,
                pgn: session.pgn,
            });
            let source = session.source;
            slot.session = None;
            on_timeout(source, abort);
        }
    }

    /// The slot holding `source`'s session, if it has one.
    fn slot_of(&self, source: Address) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.session.is_some_and(|s| s.source == source))
    }

    /// The slot to start a transfer from `source` in: its existing one, or the
    /// first free slot.
    fn slot_for(&self, source: Address) -> Option<usize> {
        self.slot_of(source)
            .or_else(|| self.slots.iter().position(|slot| slot.session.is_none()))
    }

    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        index: usize,
        source: Address,
        pgn: Pgn,
        size: u16,
        packets: u8,
        broadcast: bool,
        window: u8,
        max_packets_per_cts: u8,
    ) {
        self.slots[index].session = Some(Session {
            source,
            pgn,
            size,
            packets,
            next_sequence: 1,
            window_remaining: window,
            max_packets_per_cts,
            broadcast,
            idle_ms: 0,
        });
    }
}

/// An announcement is coherent only if the size is in range and the packet
/// count matches it exactly.
const fn valid_announcement(size: u16, packets: u8) -> bool {
    size >= MIN_MESSAGE_SIZE && size <= MAX_MESSAGE_SIZE && packets == packet_count(size)
}

/// How many packets to ask for in one CTS, respecting the sender's limit.
const fn grant_window(packets: u8, max_packets_per_cts: u8) -> u8 {
    // 0 and 0xFF both mean "no limit stated".
    if max_packets_per_cts == 0 || max_packets_per_cts == 0xFF {
        packets
    } else if max_packets_per_cts < packets {
        max_packets_per_cts
    } else {
        packets
    }
}

/// What a [`Transmitter`] wants the caller to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    /// Nothing to do; wait for the peer.
    Idle,
    /// The peer granted a window — pull packets with
    /// [`Transmitter::next_packet`] and send them.
    SendData,
    /// The receiver acknowledged the whole message.
    Complete,
    /// The peer aborted the transfer.
    Aborted(AbortReason),
}

/// The send side of the transport protocol: splits a message into TP.DT
/// packets, driving either a BAM broadcast or an RTS/CTS handshake.
///
/// The transmitter borrows the payload rather than copying it, so a large
/// message costs no extra RAM on an MCU.
///
/// ```
/// use sae_j1939_rs::tp::{TpCm, Transmitter, Tx};
/// use sae_j1939_rs::{pgn, Address};
///
/// let payload: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
/// let mut tx = Transmitter::broadcast(pgn::DM1, &payload).unwrap();
///
/// // Announce, then push every packet — pacing them 50–200 ms apart.
/// let announce = tx.start();
/// assert!(matches!(announce, TpCm::Bam { size: 12, packets: 2, .. }));
/// assert_eq!(tx.next_packet().unwrap().sequence, 1);
/// assert_eq!(tx.next_packet().unwrap().sequence, 2);
/// assert!(tx.next_packet().is_none());
/// assert!(tx.is_complete());
/// ```
#[derive(Debug)]
pub struct Transmitter<'a> {
    pgn: Pgn,
    data: &'a [u8],
    packets: u8,
    /// The 1-based sequence number to send next. Held as a `u16` so that
    /// advancing past the 255th (and final possible) packet cannot overflow.
    next_sequence: u16,
    /// Packets still allowed in the current window.
    window_remaining: u8,
    broadcast: bool,
    complete: bool,
    /// The per-CTS limit advertised in our RTS.
    max_packets_per_cts: u8,
}

impl<'a> Transmitter<'a> {
    /// Prepare a BAM broadcast of `data` as parameter group `pgn`.
    ///
    /// Returns [`Error::InvalidMessageSize`] unless `data` is 9..=1785 bytes.
    ///
    /// **Pacing matters.** J1939-21 requires 50–200 ms between BAM data
    /// packets; receivers on a busy bus will drop the transfer if you send them
    /// back to back. This type is sans-I/O and owns no clock, so the delay is
    /// the caller's responsibility.
    pub fn broadcast(pgn: Pgn, data: &'a [u8]) -> Result<Self> {
        Self::build(pgn, data, true)
    }

    /// Prepare a destination-specific RTS/CTS transfer of `data` as parameter
    /// group `pgn`.
    ///
    /// Returns [`Error::InvalidMessageSize`] unless `data` is 9..=1785 bytes.
    pub fn addressed(pgn: Pgn, data: &'a [u8]) -> Result<Self> {
        Self::build(pgn, data, false)
    }

    fn build(pgn: Pgn, data: &'a [u8], broadcast: bool) -> Result<Self> {
        let size = data.len();
        if size < MIN_MESSAGE_SIZE as usize || size > MAX_MESSAGE_SIZE as usize {
            return Err(Error::InvalidMessageSize(size.min(u16::MAX as usize) as u16));
        }
        let packets = packet_count(size as u16);
        Ok(Transmitter {
            pgn,
            data,
            packets,
            next_sequence: 1,
            // A BAM is sent without waiting for permission.
            window_remaining: if broadcast { packets } else { 0 },
            broadcast,
            complete: false,
            max_packets_per_cts: 0xFF,
        })
    }

    /// Limit how many packets the receiver may ask for in a single CTS.
    ///
    /// Advertised in the RTS. Use this when the sender cannot keep a large
    /// window full — a slow flash read, say. `0xFF` (the default) means no
    /// limit. Has no effect on a broadcast, which has no CTS at all.
    #[must_use]
    pub const fn with_max_packets_per_cts(mut self, max: u8) -> Self {
        self.max_packets_per_cts = max;
        self
    }

    /// The announcement to send first: a BAM, or an RTS awaiting a CTS.
    pub fn start(&self) -> TpCm {
        let size = self.data.len() as u16;
        if self.broadcast {
            TpCm::Bam {
                size,
                packets: self.packets,
                pgn: self.pgn,
            }
        } else {
            TpCm::Rts {
                size,
                packets: self.packets,
                max_packets_per_cts: self.max_packets_per_cts,
                pgn: self.pgn,
            }
        }
    }

    /// The total number of TP.DT packets this transfer needs.
    pub const fn packets(&self) -> u8 {
        self.packets
    }

    /// Whether every packet has been produced and (for RTS/CTS) acknowledged.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Handle a TP.CM from the receiver.
    pub fn on_tp_cm(&mut self, cm: &TpCm) -> Tx {
        match *cm {
            TpCm::Cts {
                packets,
                next_packet,
                ..
            } => {
                if packets == 0 {
                    // A zero-packet CTS is the receiver asking us to hold.
                    return Tx::Idle;
                }
                if next_packet == 0 || next_packet > self.packets {
                    return Tx::Idle;
                }
                self.next_sequence = next_packet as u16;
                self.window_remaining = packets.min(self.packets - next_packet + 1);
                Tx::SendData
            }
            TpCm::EndOfMsgAck { .. } => {
                self.complete = true;
                Tx::Complete
            }
            TpCm::Abort { reason, .. } => Tx::Aborted(reason),
            TpCm::Rts { .. } | TpCm::Bam { .. } => Tx::Idle,
        }
    }

    /// The next TP.DT packet to send, or `None` when the current window is
    /// exhausted (wait for a CTS) or the message is fully sent.
    pub fn next_packet(&mut self) -> Option<TpDt> {
        if self.window_remaining == 0 || self.next_sequence > self.packets as u16 {
            return None;
        }
        let sequence = self.next_sequence;
        let offset = (sequence as usize - 1) * BYTES_PER_PACKET;
        let end = (offset + BYTES_PER_PACKET).min(self.data.len());
        let packet = TpDt::new(sequence as u8, &self.data[offset..end]);

        self.next_sequence += 1;
        self.window_remaining -= 1;
        // A broadcast is finished the moment the last packet is out; an RTS/CTS
        // transfer is finished only once acknowledged.
        if self.broadcast && self.next_sequence > self.packets as u16 {
            self.complete = true;
        }
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgn;

    const SENDER: Address = Address::new(0x80);

    /// The BAM control byte and layout, checked against the byte sequence the
    /// Open-SAE-J1939 C reference builds: control byte, size little-endian,
    /// packet count, 0xFF filler, then the PGN little-endian.
    #[test]
    fn encodes_connection_management_messages() {
        assert_eq!(
            TpCm::bam(12, pgn::DM1).unwrap().encode(),
            [0x20, 0x0C, 0x00, 0x02, 0xFF, 0xCA, 0xFE, 0x00]
        );
        assert_eq!(
            TpCm::rts(1785, pgn::DM1).unwrap().encode(),
            [0x10, 0xF9, 0x06, 0xFF, 0xFF, 0xCA, 0xFE, 0x00]
        );
        assert_eq!(
            TpCm::Cts {
                packets: 2,
                next_packet: 1,
                pgn: pgn::DM1,
            }
            .encode(),
            [0x11, 0x02, 0x01, 0xFF, 0xFF, 0xCA, 0xFE, 0x00]
        );
        assert_eq!(
            TpCm::EndOfMsgAck {
                size: 12,
                packets: 2,
                pgn: pgn::DM1,
            }
            .encode(),
            [0x13, 0x0C, 0x00, 0x02, 0xFF, 0xCA, 0xFE, 0x00]
        );
        assert_eq!(
            TpCm::Abort {
                reason: AbortReason::Timeout,
                pgn: pgn::DM1,
            }
            .encode(),
            [0xFF, 0x03, 0xFF, 0xFF, 0xFF, 0xCA, 0xFE, 0x00]
        );
    }

    #[test]
    fn connection_management_round_trips() {
        let messages = [
            TpCm::bam(12, pgn::DM1).unwrap(),
            TpCm::rts(1785, pgn::COMMANDED_ADDRESS).unwrap(),
            TpCm::Cts {
                packets: 5,
                next_packet: 3,
                pgn: pgn::DM1,
            },
            TpCm::EndOfMsgAck {
                size: 30,
                packets: 5,
                pgn: pgn::ECU_IDENTIFICATION,
            },
            TpCm::Abort {
                reason: AbortReason::BadSequenceNumber,
                pgn: pgn::DM1,
            },
        ];
        for message in messages {
            assert_eq!(TpCm::decode(&message.encode()).unwrap(), message);
        }
    }

    #[test]
    fn rejects_unknown_control_bytes() {
        let bytes = [0x42, 0, 0, 0, 0, 0xCA, 0xFE, 0x00];
        assert_eq!(TpCm::decode(&bytes), Err(Error::UnknownControlByte(0x42)));
    }

    #[test]
    fn rejects_sizes_outside_the_protocol_range() {
        // Eight bytes fits a single frame; the transport protocol must not be used.
        assert_eq!(TpCm::bam(8, pgn::DM1), Err(Error::InvalidMessageSize(8)));
        assert_eq!(
            TpCm::rts(1786, pgn::DM1),
            Err(Error::InvalidMessageSize(1786))
        );
        assert!(TpCm::bam(9, pgn::DM1).is_ok());
        assert!(TpCm::rts(1785, pgn::DM1).is_ok());
    }

    #[test]
    fn data_packets_round_trip_and_pad_with_filler() {
        let dt = TpDt::new(3, &[1, 2, 3]);
        assert_eq!(dt.encode(), [3, 1, 2, 3, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(TpDt::decode(&dt.encode()), dt);
    }

    #[test]
    fn packet_counts_round_up() {
        assert_eq!(packet_count(9), 2);
        assert_eq!(packet_count(14), 2);
        assert_eq!(packet_count(15), 3);
        assert_eq!(packet_count(MAX_MESSAGE_SIZE), 255);
    }

    /// Split a payload into the packets a real sender would put on the bus.
    fn packets_for(payload: &[u8]) -> impl Iterator<Item = TpDt> + '_ {
        payload
            .chunks(BYTES_PER_PACKET)
            .enumerate()
            .map(|(i, chunk)| TpDt::new(i as u8 + 1, chunk))
    }

    #[test]
    fn reassembles_a_bam_broadcast() {
        let payload: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut rx = Reassembler::<256>::new();

        assert_eq!(
            rx.on_tp_cm(SENDER, &TpCm::bam(12, pgn::DM1).unwrap()),
            Rx::Idle
        );
        assert!(rx.is_busy());

        let mut packets = packets_for(&payload);
        assert_eq!(rx.on_tp_dt(SENDER, &packets.next().unwrap()), Rx::Idle);
        match rx.on_tp_dt(SENDER, &packets.next().unwrap()) {
            Rx::Message {
                pgn,
                source,
                data,
                ack,
            } => {
                assert_eq!(pgn, pgn::DM1);
                assert_eq!(source, SENDER);
                assert_eq!(data, &payload);
                // A broadcast is never acknowledged.
                assert_eq!(ack, None);
            }
            other => panic!("expected a message, got {other:?}"),
        }
        assert!(!rx.is_busy(), "session should be released on completion");
    }

    #[test]
    fn reassembles_an_rts_cts_transfer_at_the_maximum_size() {
        // The largest message the protocol allows: 255 packets, 1785 bytes.
        let payload: [u8; 1785] = core::array::from_fn(|i| i as u8);
        let mut rx = Reassembler::<1785>::new();

        let cts = rx.on_tp_cm(SENDER, &TpCm::rts(1785, pgn::COMMANDED_ADDRESS).unwrap());
        assert_eq!(
            cts,
            Rx::Send(TpCm::Cts {
                packets: 255,
                next_packet: 1,
                pgn: pgn::COMMANDED_ADDRESS,
            })
        );

        let mut packets = packets_for(&payload).collect::<std::vec::Vec<_>>();
        let last = packets.pop().unwrap();
        for packet in &packets {
            assert_eq!(rx.on_tp_dt(SENDER, packet), Rx::Idle);
        }
        match rx.on_tp_dt(SENDER, &last) {
            Rx::Message { data, ack, .. } => {
                assert_eq!(data.len(), 1785);
                assert_eq!(data, &payload);
                assert_eq!(
                    ack,
                    Some(TpCm::EndOfMsgAck {
                        size: 1785,
                        packets: 255,
                        pgn: pgn::COMMANDED_ADDRESS,
                    })
                );
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// A sender that says "at most two packets per CTS" must be obeyed on
    /// *every* window, not only the first — otherwise a slow sender is flooded.
    #[test]
    fn every_cts_window_respects_the_senders_limit() {
        let mut rx = Reassembler::<256>::new();
        // 35 bytes = 5 packets, but the sender will only take 2 at a time.
        let rts = TpCm::Rts {
            size: 35,
            packets: 5,
            max_packets_per_cts: 2,
            pgn: pgn::DM1,
        };
        assert_eq!(
            rx.on_tp_cm(SENDER, &rts),
            Rx::Send(TpCm::Cts {
                packets: 2,
                next_packet: 1,
                pgn: pgn::DM1,
            })
        );

        // Fill the first window; the second CTS must also ask for only 2.
        assert_eq!(rx.on_tp_dt(SENDER, &TpDt::new(1, &[0; 7])), Rx::Idle);
        assert_eq!(
            rx.on_tp_dt(SENDER, &TpDt::new(2, &[0; 7])),
            Rx::Send(TpCm::Cts {
                packets: 2,
                next_packet: 3,
                pgn: pgn::DM1,
            })
        );

        // And the last window shrinks to the single remaining packet.
        assert_eq!(rx.on_tp_dt(SENDER, &TpDt::new(3, &[0; 7])), Rx::Idle);
        assert_eq!(
            rx.on_tp_dt(SENDER, &TpDt::new(4, &[0; 7])),
            Rx::Send(TpCm::Cts {
                packets: 1,
                next_packet: 5,
                pgn: pgn::DM1,
            })
        );
        assert!(matches!(
            rx.on_tp_dt(SENDER, &TpDt::new(5, &[0; 7])),
            Rx::Message { .. }
        ));
    }

    #[test]
    fn refuses_a_transfer_larger_than_the_receive_buffer() {
        // This ECU only has room for 64 bytes.
        let mut rx = Reassembler::<64>::new();

        // RTS gets an explicit abort so the sender stops immediately...
        assert_eq!(
            rx.on_tp_cm(SENDER, &TpCm::rts(200, pgn::DM1).unwrap()),
            Rx::Send(TpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::DM1,
            })
        );
        assert!(!rx.is_busy());

        // ...a BAM has no back-channel, so it can only be dropped.
        assert_eq!(
            rx.on_tp_cm(SENDER, &TpCm::bam(200, pgn::DM1).unwrap()),
            Rx::Idle
        );
        assert!(!rx.is_busy());
    }

    #[test]
    fn aborts_on_an_out_of_order_packet() {
        let mut rx = Reassembler::<64>::new();
        rx.on_tp_cm(SENDER, &TpCm::rts(21, pgn::DM1).unwrap());

        assert_eq!(rx.on_tp_dt(SENDER, &TpDt::new(1, &[0; 7])), Rx::Idle);
        // Packet 3 arrives where packet 2 was expected.
        assert_eq!(
            rx.on_tp_dt(SENDER, &TpDt::new(3, &[0; 7])),
            Rx::Send(TpCm::Abort {
                reason: AbortReason::BadSequenceNumber,
                pgn: pgn::DM1,
            })
        );
        assert!(!rx.is_busy());
    }

    #[test]
    fn drops_an_out_of_order_broadcast_without_aborting() {
        let mut rx = Reassembler::<64>::new();
        rx.on_tp_cm(SENDER, &TpCm::bam(21, pgn::DM1).unwrap());
        rx.on_tp_dt(SENDER, &TpDt::new(1, &[0; 7]));
        // Nothing to send back on a broadcast — the session is simply dropped.
        assert_eq!(rx.on_tp_dt(SENDER, &TpDt::new(3, &[0; 7])), Rx::Idle);
        assert!(!rx.is_busy());
    }

    #[test]
    fn rejects_an_incoherent_announcement() {
        let mut rx = Reassembler::<256>::new();
        // 12 bytes needs 2 packets, not 5.
        let lying = TpCm::Bam {
            size: 12,
            packets: 5,
            pgn: pgn::DM1,
        };
        assert_eq!(rx.on_tp_cm(SENDER, &lying), Rx::Idle);
        assert!(!rx.is_busy());
    }

    /// J1939-21 allows a peer only one connection-managed session at a time.
    #[test]
    fn refuses_a_second_session_from_the_same_peer() {
        let mut rx = Reassembler::<256, 4>::new();
        rx.on_tp_cm(SENDER, &TpCm::rts(21, pgn::DM1).unwrap());

        assert_eq!(
            rx.on_tp_cm(SENDER, &TpCm::rts(21, pgn::DM2).unwrap()),
            Rx::Send(TpCm::Abort {
                reason: AbortReason::AlreadyInSession,
                pgn: pgn::DM2,
            })
        );
    }

    /// A new peer arriving with no slot free is short of resources, which is a
    /// different failure from the same peer opening a second session.
    #[test]
    fn refuses_a_new_peer_when_every_slot_is_occupied() {
        let mut rx = Reassembler::<256>::new(); // one slot
        rx.on_tp_cm(SENDER, &TpCm::rts(21, pgn::DM1).unwrap());

        assert_eq!(
            rx.on_tp_cm(Address::new(0x91), &TpCm::rts(21, pgn::DM2).unwrap()),
            Rx::Send(TpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::DM2,
            })
        );
        assert_eq!(rx.active_sessions(), 1);
    }

    /// Two ECUs broadcasting at the same time is routine on a busy bus. Their
    /// packets interleave, and both messages must survive intact.
    #[test]
    fn concurrent_transfers_from_different_peers_do_not_corrupt_each_other() {
        let alice = Address::new(0x80);
        let bob = Address::new(0x91);
        let alice_payload: [u8; 14] = [0xA0; 14];
        let bob_payload: [u8; 14] = [0xB0; 14];

        let mut rx = Reassembler::<256, 4>::new();
        rx.on_tp_cm(alice, &TpCm::bam(14, pgn::DM1).unwrap());
        rx.on_tp_cm(bob, &TpCm::bam(14, pgn::DM2).unwrap());
        assert_eq!(rx.active_sessions(), 2);
        assert!(rx.is_receiving_from(alice));
        assert!(rx.is_receiving_from(bob));

        let alice_packets: std::vec::Vec<TpDt> = packets_for(&alice_payload).collect();
        let bob_packets: std::vec::Vec<TpDt> = packets_for(&bob_payload).collect();

        // Fully interleaved: A1, B1, A2, B2.
        assert_eq!(rx.on_tp_dt(alice, &alice_packets[0]), Rx::Idle);
        assert_eq!(rx.on_tp_dt(bob, &bob_packets[0]), Rx::Idle);

        match rx.on_tp_dt(alice, &alice_packets[1]) {
            Rx::Message {
                pgn, source, data, ..
            } => {
                assert_eq!(pgn, pgn::DM1);
                assert_eq!(source, alice);
                assert_eq!(data, &alice_payload);
            }
            other => panic!("expected Alice's message, got {other:?}"),
        }
        match rx.on_tp_dt(bob, &bob_packets[1]) {
            Rx::Message {
                pgn, source, data, ..
            } => {
                assert_eq!(pgn, pgn::DM2);
                assert_eq!(source, bob);
                assert_eq!(data, &bob_payload);
            }
            other => panic!("expected Bob's message, got {other:?}"),
        }
        assert_eq!(rx.active_sessions(), 0);
    }

    #[test]
    fn a_session_survives_until_the_timeout_then_expires() {
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(SENDER, &TpCm::bam(21, pgn::DM1).unwrap());

        // Just under T1: still alive.
        let mut expired = std::vec::Vec::new();
        rx.tick(T1_TIMEOUT_MS - 1, |address, abort| {
            expired.push((address, abort))
        });
        assert!(rx.is_busy());
        assert!(expired.is_empty());

        // A packet arrives, resetting the idle timer.
        rx.on_tp_dt(SENDER, &TpDt::new(1, &[0; 7]));
        rx.tick(T1_TIMEOUT_MS - 1, |address, abort| {
            expired.push((address, abort))
        });
        assert!(rx.is_busy(), "a packet must restart the clock");
        assert!(expired.is_empty());

        // Then silence past T1.
        rx.tick(2, |address, abort| expired.push((address, abort)));
        assert!(!rx.is_busy());
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, SENDER);
        // A broadcast has nobody to tell.
        assert_eq!(expired[0].1, None);
    }

    #[test]
    fn a_timed_out_addressed_session_yields_an_abort_to_send() {
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(SENDER, &TpCm::rts(21, pgn::DM1).unwrap());

        let mut expired = std::vec::Vec::new();
        rx.tick(T1_TIMEOUT_MS + 1, |address, abort| {
            expired.push((address, abort))
        });
        assert_eq!(
            expired,
            [(
                SENDER,
                Some(TpCm::Abort {
                    reason: AbortReason::Timeout,
                    pgn: pgn::DM1,
                })
            )]
        );
    }

    #[test]
    fn a_timeout_expires_only_the_stalled_peer() {
        let alice = Address::new(0x80);
        let bob = Address::new(0x91);
        let mut rx = Reassembler::<256, 4>::new();
        rx.on_tp_cm(alice, &TpCm::bam(21, pgn::DM1).unwrap());

        // Alice idles while Bob starts later and keeps sending.
        rx.tick(T1_TIMEOUT_MS - 1, |_, _| {});
        rx.on_tp_cm(bob, &TpCm::bam(21, pgn::DM2).unwrap());

        let mut expired = std::vec::Vec::new();
        rx.tick(2, |address, _| expired.push(address));
        assert_eq!(expired, [alice], "only the stalled session expires");
        assert!(rx.is_receiving_from(bob));
        assert_eq!(rx.active_sessions(), 1);
    }

    #[test]
    fn abandoning_one_peer_leaves_the_others_alone() {
        let alice = Address::new(0x80);
        let bob = Address::new(0x91);

        let mut rx = Reassembler::<256, 4>::new();
        rx.on_tp_cm(alice, &TpCm::bam(14, pgn::DM1).unwrap());
        rx.on_tp_cm(bob, &TpCm::bam(14, pgn::DM2).unwrap());

        assert!(rx.abandon(alice));
        assert!(!rx.abandon(alice), "already gone");
        assert!(!rx.is_receiving_from(alice));
        assert!(
            rx.is_receiving_from(bob),
            "Bob's transfer must be untouched"
        );
        assert_eq!(rx.active_sessions(), 1);

        rx.reset();
        assert_eq!(rx.active_sessions(), 0);
    }

    #[test]
    fn ignores_stray_packets_from_another_ecu() {
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(SENDER, &TpCm::bam(14, pgn::DM1).unwrap());
        // A packet from an unrelated ECU must not disturb our session.
        assert_eq!(
            rx.on_tp_dt(Address::new(0x91), &TpDt::new(1, &[0; 7])),
            Rx::Idle
        );
        assert!(rx.is_busy());
    }

    #[test]
    fn an_abort_releases_the_session() {
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(SENDER, &TpCm::rts(21, pgn::DM1).unwrap());
        assert!(rx.is_busy());
        rx.on_tp_cm(
            SENDER,
            &TpCm::Abort {
                reason: AbortReason::Timeout,
                pgn: pgn::DM1,
            },
        );
        assert!(!rx.is_busy());
    }

    #[test]
    fn transmitter_rejects_sizes_outside_the_protocol_range() {
        assert!(Transmitter::broadcast(pgn::DM1, &[0; 8]).is_err());
        assert!(Transmitter::broadcast(pgn::DM1, &[0; 9]).is_ok());
        assert!(Transmitter::addressed(pgn::DM1, &[0; 1785]).is_ok());
        assert!(Transmitter::addressed(pgn::DM1, &[0; 1786]).is_err());
    }

    #[test]
    fn transmitter_pads_the_final_packet() {
        let payload: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut tx = Transmitter::broadcast(pgn::DM1, &payload).unwrap();
        assert!(matches!(
            tx.start(),
            TpCm::Bam {
                size: 9,
                packets: 2,
                ..
            }
        ));
        assert_eq!(tx.next_packet().unwrap().encode(), [1, 1, 2, 3, 4, 5, 6, 7]);
        // Five unused bytes in the last packet are filled with 0xFF.
        assert_eq!(
            tx.next_packet().unwrap().encode(),
            [2, 8, 9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert!(tx.next_packet().is_none());
        assert!(tx.is_complete());
    }

    #[test]
    fn transmitter_waits_for_a_cts_before_sending() {
        let payload: [u8; 21] = [7; 21];
        let mut tx = Transmitter::addressed(pgn::DM1, &payload).unwrap();
        assert!(matches!(
            tx.start(),
            TpCm::Rts {
                size: 21,
                packets: 3,
                ..
            }
        ));

        // Nothing may go out before the receiver grants a window.
        assert!(tx.next_packet().is_none());

        // A window of two packets.
        assert_eq!(
            tx.on_tp_cm(&TpCm::Cts {
                packets: 2,
                next_packet: 1,
                pgn: pgn::DM1
            }),
            Tx::SendData
        );
        assert_eq!(tx.next_packet().unwrap().sequence, 1);
        assert_eq!(tx.next_packet().unwrap().sequence, 2);
        assert!(tx.next_packet().is_none(), "window exhausted");

        // The receiver opens the next window.
        assert_eq!(
            tx.on_tp_cm(&TpCm::Cts {
                packets: 1,
                next_packet: 3,
                pgn: pgn::DM1
            }),
            Tx::SendData
        );
        assert_eq!(tx.next_packet().unwrap().sequence, 3);

        // Only the acknowledgement completes an RTS/CTS transfer.
        assert!(!tx.is_complete());
        assert_eq!(
            tx.on_tp_cm(&TpCm::EndOfMsgAck {
                size: 21,
                packets: 3,
                pgn: pgn::DM1
            }),
            Tx::Complete
        );
        assert!(tx.is_complete());
    }

    #[test]
    fn transmitter_reports_an_abort() {
        let mut tx = Transmitter::addressed(pgn::DM1, &[0; 21]).unwrap();
        assert_eq!(
            tx.on_tp_cm(&TpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::DM1,
            }),
            Tx::Aborted(AbortReason::ResourcesUnavailable)
        );
    }

    /// The two halves must agree: drive a real transmitter into a real
    /// reassembler and get the original bytes back.
    #[test]
    fn transmitter_and_reassembler_interoperate() {
        for size in [9usize, 14, 15, 100, 700, 1785] {
            let payload: std::vec::Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
            let mut tx = Transmitter::addressed(pgn::DM1, &payload).unwrap();
            let mut rx = Reassembler::<1785>::new();

            // RTS -> CTS
            let mut response = match rx.on_tp_cm(SENDER, &tx.start()) {
                Rx::Send(cm) => Some(cm),
                other => panic!("expected a CTS, got {other:?}"),
            };

            let mut delivered = None;
            'transfer: while let Some(cm) = response.take() {
                assert_eq!(tx.on_tp_cm(&cm), Tx::SendData);
                while let Some(packet) = tx.next_packet() {
                    match rx.on_tp_dt(SENDER, &packet) {
                        Rx::Idle => {}
                        Rx::Send(cm) => response = Some(cm),
                        Rx::Message { data, ack, .. } => {
                            delivered = Some(data.to_vec());
                            assert!(ack.is_some());
                            break 'transfer;
                        }
                    }
                }
            }

            assert_eq!(
                delivered.as_deref(),
                Some(payload.as_slice()),
                "round trip of a {size}-byte message"
            );
        }
    }
}
