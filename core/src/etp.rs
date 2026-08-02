// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Extended Transport Protocol: messages beyond 1785 bytes.
//!
//! [`crate::tp`] tops out at 1785 bytes, because its packet counter is a single
//! byte. That is enough for a diagnostic message and nowhere near enough for an
//! ISOBUS object pool or a task data file, which routinely run to tens or
//! hundreds of kilobytes. ETP carries up to **117,440,505 bytes**.
//!
//! It works like RTS/CTS with one addition. The sequence number in a data
//! packet is still one byte, so it cannot address a packet a million deep.
//! Instead the sender precedes each block with a **Data Packet Offset**, and the
//! sequence numbers that follow are relative to it:
//!
//! ```text
//! absolute packet = offset + sequence
//! ```
//!
//! That is the whole trick, and the whole hazard: a receiver that ignores the
//! offset writes every block over the first one.
//!
//! ```text
//! sender                                        receiver
//!   |-- ETP.CM RTS (total size) ------------------->|
//!   |<------------------- ETP.CM CTS (n, from p) ---|
//!   |-- ETP.CM DPO (n, offset) -------------------->|
//!   |-- ETP.DT seq 1..n --------------------------->|
//!   |<------------------- ETP.CM CTS (next block) --|
//!   |                       ...                     |
//!   |<------------------- ETP.CM EOMA --------------|
//! ```
//!
//! ```
//! use sae_j1939_rs::etp::{EtpCm, Reassembler, Rx};
//! use sae_j1939_rs::{pgn, Address};
//!
//! // A receiver that will accept up to 8 KiB.
//! let mut rx = Reassembler::<8192>::new();
//! let sender = Address::new(0x80);
//!
//! // 4000 bytes is beyond what the ordinary transport protocol can carry.
//! let announce = EtpCm::rts(4000, pgn::PROPRIETARY_A).unwrap();
//! assert!(matches!(rx.on_etp_cm(sender, &announce), Rx::Send(EtpCm::Cts { .. })));
//! ```
//!
//! # Unverified against hardware
//!
//! Every other wire format in this crate was cross-checked against the
//! MIT-licensed Open-SAE-J1939 C implementation. That implementation does not
//! cover ETP, so this module is built from the structure J1939-21 and
//! ISO 11783-3 describe, and has not been checked against a real device. Treat
//! it as the least-proven part of the crate and please report anything that
//! disagrees with your hardware.

use crate::pgn::Pgn;
use crate::tp::{AbortReason, BYTES_PER_PACKET};
use crate::types::{Address, Error, Result};

/// The smallest message ETP carries. Anything at or below
/// [`tp::MAX_MESSAGE_SIZE`](crate::tp::MAX_MESSAGE_SIZE) belongs to the ordinary
/// transport protocol.
pub const MIN_MESSAGE_SIZE: u32 = 1786;

/// The largest message ETP can carry: `0xFF_FFFF` packets of seven bytes.
pub const MAX_MESSAGE_SIZE: u32 = 0x00FF_FFFF * BYTES_PER_PACKET as u32;

/// The most packets one block can hold, because a data packet's sequence number
/// is a single byte.
pub const MAX_PACKETS_PER_BLOCK: u8 = 255;

// Control bytes, J1939-21.
const CB_RTS: u8 = 20;
const CB_CTS: u8 = 21;
const CB_DPO: u8 = 22;
const CB_EOMA: u8 = 23;
const CB_ABORT: u8 = 255;

/// Filler for unused payload bytes.
const FILL: u8 = 0xFF;

/// The number of packets needed to carry `size` bytes.
///
/// Saturates at [`MAX_MESSAGE_SIZE`], for the same reason
/// [`tp::packet_count`](crate::tp::packet_count) does: zero would read as "no
/// packets needed".
pub const fn packet_count(size: u32) -> u32 {
    if size > MAX_MESSAGE_SIZE {
        return 0x00FF_FFFF;
    }
    (size as usize).div_ceil(BYTES_PER_PACKET) as u32
}

/// An Extended Transport Protocol connection-management message (PGN
/// `0x00C800`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtpCm {
    /// Request To Send: the sender offers a transfer of `size` bytes.
    Rts {
        /// Total message size in bytes.
        size: u32,
        /// The parameter group being transported.
        pgn: Pgn,
    },
    /// Clear To Send: the receiver grants a block, starting at an absolute
    /// packet number.
    Cts {
        /// How many packets may be sent in this block.
        packets: u8,
        /// The absolute packet number the block starts at (1-based).
        next_packet: u32,
        /// The parameter group being transported.
        pgn: Pgn,
    },
    /// Data Packet Offset: what the sequence numbers in the next block are
    /// relative to.
    Dpo {
        /// How many packets the offset applies to.
        packets: u8,
        /// The offset added to each following sequence number.
        offset: u32,
        /// The parameter group being transported.
        pgn: Pgn,
    },
    /// End Of Message Acknowledgement.
    Eoma {
        /// Total message size received.
        size: u32,
        /// The parameter group that was transported.
        pgn: Pgn,
    },
    /// Connection Abort.
    Abort {
        /// Why the session was abandoned.
        reason: AbortReason,
        /// The parameter group whose transfer was abandoned.
        pgn: Pgn,
    },
}

impl EtpCm {
    /// Build an RTS offering a `size`-byte transfer.
    ///
    /// Returns [`Error::InvalidMessageSize`] unless `size` is in
    /// `1786..=117_440_505`. Smaller messages belong to [`crate::tp`].
    pub const fn rts(size: u32, pgn: Pgn) -> Result<Self> {
        if size < MIN_MESSAGE_SIZE || size > MAX_MESSAGE_SIZE {
            // The error carries a u16; report the ceiling rather than truncate.
            return Err(Error::InvalidMessageSize(if size > u16::MAX as u32 {
                u16::MAX
            } else {
                size as u16
            }));
        }
        Ok(EtpCm::Rts { size, pgn })
    }

    /// The parameter group being transported.
    pub const fn pgn(&self) -> Pgn {
        match *self {
            EtpCm::Rts { pgn, .. }
            | EtpCm::Cts { pgn, .. }
            | EtpCm::Dpo { pgn, .. }
            | EtpCm::Eoma { pgn, .. }
            | EtpCm::Abort { pgn, .. } => pgn,
        }
    }

    /// The control byte identifying this message on the wire.
    pub const fn control_byte(&self) -> u8 {
        match *self {
            EtpCm::Rts { .. } => CB_RTS,
            EtpCm::Cts { .. } => CB_CTS,
            EtpCm::Dpo { .. } => CB_DPO,
            EtpCm::Eoma { .. } => CB_EOMA,
            EtpCm::Abort { .. } => CB_ABORT,
        }
    }

    /// Encode to the eight-byte payload.
    ///
    /// ```
    /// use sae_j1939_rs::etp::EtpCm;
    /// use sae_j1939_rs::pgn;
    ///
    /// // RTS carries a four-byte size where TP carries two.
    /// let rts = EtpCm::rts(4000, pgn::PROPRIETARY_A).unwrap();
    /// assert_eq!(rts.encode(), [20, 0xA0, 0x0F, 0x00, 0x00, 0x00, 0xEF, 0x00]);
    /// ```
    pub const fn encode(&self) -> [u8; 8] {
        let pgn = self.pgn().as_u32();
        let body = match *self {
            EtpCm::Rts { size, .. } | EtpCm::Eoma { size, .. } => [
                size as u8,
                (size >> 8) as u8,
                (size >> 16) as u8,
                (size >> 24) as u8,
            ],
            EtpCm::Cts {
                packets,
                next_packet,
                ..
            } => [
                packets,
                next_packet as u8,
                (next_packet >> 8) as u8,
                (next_packet >> 16) as u8,
            ],
            EtpCm::Dpo {
                packets, offset, ..
            } => [
                packets,
                offset as u8,
                (offset >> 8) as u8,
                (offset >> 16) as u8,
            ],
            EtpCm::Abort { reason, .. } => [reason.as_u8(), FILL, FILL, FILL],
        };
        [
            self.control_byte(),
            body[0],
            body[1],
            body[2],
            body[3],
            pgn as u8,
            (pgn >> 8) as u8,
            (pgn >> 16) as u8,
        ]
    }

    /// Decode an eight-byte payload.
    ///
    /// Returns [`Error::UnknownControlByte`] for a control byte J1939-21 does
    /// not define for ETP.
    pub fn decode(data: &[u8; 8]) -> Result<Self> {
        let pgn =
            Pgn::new_masked((data[5] as u32) | ((data[6] as u32) << 8) | ((data[7] as u32) << 16));
        let four = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let three = (data[2] as u32) | ((data[3] as u32) << 8) | ((data[4] as u32) << 16);

        Ok(match data[0] {
            CB_RTS => EtpCm::Rts { size: four, pgn },
            CB_CTS => EtpCm::Cts {
                packets: data[1],
                next_packet: three,
                pgn,
            },
            CB_DPO => EtpCm::Dpo {
                packets: data[1],
                offset: three,
                pgn,
            },
            CB_EOMA => EtpCm::Eoma { size: four, pgn },
            CB_ABORT => EtpCm::Abort {
                reason: AbortReason::from_u8(data[1]),
                pgn,
            },
            other => return Err(Error::UnknownControlByte(other)),
        })
    }
}

/// An Extended Transport Protocol data packet (PGN `0x00C700`).
///
/// The sequence number is relative to the last [`EtpCm::Dpo`], not absolute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtpDt {
    /// The 1-based sequence number *within the current block*.
    pub sequence: u8,
    /// Seven payload bytes; trailing unused bytes are `0xFF`.
    pub data: [u8; BYTES_PER_PACKET],
}

impl EtpDt {
    /// Build a packet, padding `data` to seven bytes with `0xFF`.
    pub fn new(sequence: u8, data: &[u8]) -> Self {
        let mut buf = [FILL; BYTES_PER_PACKET];
        let n = data.len().min(BYTES_PER_PACKET);
        buf[..n].copy_from_slice(&data[..n]);
        EtpDt {
            sequence,
            data: buf,
        }
    }

    /// Encode to the eight-byte payload.
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

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        EtpDt {
            sequence: data[0],
            data: [
                data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ],
        }
    }
}

/// What a [`Reassembler`] wants the caller to do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Rx<'a> {
    /// Nothing to do.
    Idle,
    /// Transmit this connection-management message back to the sender.
    Send(EtpCm),
    /// A complete message has been reassembled.
    Message {
        /// The parameter group that was transported.
        pgn: Pgn,
        /// The ECU that sent it.
        source: Address,
        /// The reassembled payload.
        data: &'a [u8],
        /// The end-of-message acknowledgement to send back.
        ack: EtpCm,
    },
}

/// The receive side of the Extended Transport Protocol.
///
/// `N` is the largest message this receiver accepts. Unlike [`crate::tp`], where
/// the protocol ceiling of 1785 bytes is a plausible buffer, an ETP buffer is a
/// real memory decision: a transfer may be 117 MB, and refusing early is the
/// point of the parameter.
#[derive(Debug)]
pub struct Reassembler<const N: usize, const SESSIONS: usize = 1> {
    slots: [Slot<N>; SESSIONS],
}

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
    size: u32,
    packets: u32,
    /// The absolute packet number the current block starts at.
    block_start: u32,
    /// Packets granted in the current block.
    block_packets: u8,
    /// The offset the sender declared for the current block, if it has.
    offset: Option<u32>,
    /// The sequence number expected next, within the block.
    next_sequence: u8,
    /// Milliseconds since this session last made progress.
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

    /// Whether any transfer is in progress.
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

    /// How far along `source`'s transfer is, in bytes received.
    ///
    /// An ETP transfer can take minutes; a caller may reasonably want to show
    /// progress.
    pub fn progress(&self, source: Address) -> Option<(u32, u32)> {
        let index = self.slot_of(source)?;
        let session = self.slots[index].session?;
        let received = session.block_start.saturating_sub(1) * BYTES_PER_PACKET as u32;
        Some((received.min(session.size), session.size))
    }

    /// Abandon the session with `source`, reporting whether there was one.
    pub fn abandon(&mut self, source: Address) -> bool {
        match self.slot_of(source) {
            Some(index) => {
                self.slots[index].session = None;
                true
            }
            None => false,
        }
    }

    /// Abandon every session.
    pub fn reset(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.session = None;
        }
    }

    /// Expire sessions that have gone quiet longer than `timeout_ms`.
    ///
    /// Same shape as [`tp::Reassembler::tick`](crate::tp::Reassembler::tick):
    /// the caller supplies elapsed time, because this owns no clock.
    pub fn tick(
        &mut self,
        elapsed_ms: u16,
        timeout_ms: u16,
        mut on_timeout: impl FnMut(Address, EtpCm),
    ) {
        for slot in self.slots.iter_mut() {
            let Some(session) = slot.session.as_mut() else {
                continue;
            };
            session.idle_ms = session.idle_ms.saturating_add(elapsed_ms);
            if session.idle_ms <= timeout_ms {
                continue;
            }
            let abort = EtpCm::Abort {
                reason: AbortReason::Timeout,
                pgn: session.pgn,
            };
            let source = session.source;
            slot.session = None;
            on_timeout(source, abort);
        }
    }

    /// Handle an incoming ETP.CM addressed to this ECU.
    pub fn on_etp_cm(&mut self, source: Address, cm: &EtpCm) -> Rx<'_> {
        match *cm {
            EtpCm::Rts { size, pgn } => {
                if !(MIN_MESSAGE_SIZE..=MAX_MESSAGE_SIZE).contains(&size) {
                    return Rx::Send(EtpCm::Abort {
                        reason: AbortReason::Other(FILL),
                        pgn,
                    });
                }
                if size as usize > N {
                    return Rx::Send(EtpCm::Abort {
                        reason: AbortReason::ResourcesUnavailable,
                        pgn,
                    });
                }
                if self.slot_of(source).is_some() {
                    return Rx::Send(EtpCm::Abort {
                        reason: AbortReason::AlreadyInSession,
                        pgn,
                    });
                }
                let Some(index) = self.free_slot() else {
                    return Rx::Send(EtpCm::Abort {
                        reason: AbortReason::ResourcesUnavailable,
                        pgn,
                    });
                };

                let packets = packet_count(size);
                let block = block_size(packets, 1);
                self.slots[index].session = Some(Session {
                    source,
                    pgn,
                    size,
                    packets,
                    block_start: 1,
                    block_packets: block,
                    offset: None,
                    next_sequence: 1,
                    idle_ms: 0,
                });
                Rx::Send(EtpCm::Cts {
                    packets: block,
                    next_packet: 1,
                    pgn,
                })
            }
            EtpCm::Dpo {
                packets, offset, ..
            } => {
                let Some(index) = self.slot_of(source) else {
                    return Rx::Idle;
                };
                if let Some(session) = self.slots[index].session.as_mut() {
                    // The offset is what the following sequence numbers are
                    // relative to. Accepting one that does not match the block
                    // we granted would scatter data through the buffer.
                    if offset + 1 != session.block_start || packets != session.block_packets {
                        let pgn = session.pgn;
                        self.slots[index].session = None;
                        return Rx::Send(EtpCm::Abort {
                            reason: AbortReason::UnexpectedDataPacket,
                            pgn,
                        });
                    }
                    session.offset = Some(offset);
                    session.next_sequence = 1;
                    session.idle_ms = 0;
                }
                Rx::Idle
            }
            EtpCm::Abort { pgn, .. } => {
                if let Some(index) = self.slot_of(source) {
                    if self.slots[index].session.is_some_and(|s| s.pgn == pgn) {
                        self.slots[index].session = None;
                    }
                }
                Rx::Idle
            }
            // Sender-side messages.
            EtpCm::Cts { .. } | EtpCm::Eoma { .. } => Rx::Idle,
        }
    }

    /// Handle an incoming ETP.DT packet addressed to this ECU.
    pub fn on_etp_dt(&mut self, source: Address, dt: &EtpDt) -> Rx<'_> {
        let Some(index) = self.slot_of(source) else {
            return Rx::Idle;
        };
        let Some(mut session) = self.slots[index].session else {
            return Rx::Idle;
        };

        // Data before the offset that gives it meaning cannot be placed.
        let Some(offset) = session.offset else {
            self.slots[index].session = None;
            return Rx::Send(EtpCm::Abort {
                reason: AbortReason::UnexpectedDataPacket,
                pgn: session.pgn,
            });
        };

        if dt.sequence != session.next_sequence {
            let pgn = session.pgn;
            let reason = if dt.sequence < session.next_sequence {
                AbortReason::DuplicateSequenceNumber
            } else {
                AbortReason::BadSequenceNumber
            };
            self.slots[index].session = None;
            return Rx::Send(EtpCm::Abort { reason, pgn });
        }

        // This is the offset's whole purpose: a one-byte sequence number can
        // only address 255 packets, so the block's position comes from the DPO.
        let absolute = offset + dt.sequence as u32;
        let start = (absolute as usize - 1) * BYTES_PER_PACKET;
        let end = (start + BYTES_PER_PACKET).min(session.size as usize);
        if start >= end {
            let pgn = session.pgn;
            self.slots[index].session = None;
            return Rx::Send(EtpCm::Abort {
                reason: AbortReason::BadSequenceNumber,
                pgn,
            });
        }
        self.slots[index].buffer[start..end].copy_from_slice(&dt.data[..end - start]);
        session.idle_ms = 0;

        if absolute >= session.packets {
            // The whole message has arrived.
            self.slots[index].session = None;
            return Rx::Message {
                pgn: session.pgn,
                source: session.source,
                data: &self.slots[index].buffer[..session.size as usize],
                ack: EtpCm::Eoma {
                    size: session.size,
                    pgn: session.pgn,
                },
            };
        }

        if dt.sequence >= session.block_packets {
            // The block is full; open the next one.
            let next_start = session.block_start + session.block_packets as u32;
            let remaining = session.packets - next_start + 1;
            let block = block_size(remaining, next_start);
            session.block_start = next_start;
            session.block_packets = block;
            session.offset = None;
            session.next_sequence = 1;
            self.slots[index].session = Some(session);
            return Rx::Send(EtpCm::Cts {
                packets: block,
                next_packet: next_start,
                pgn: session.pgn,
            });
        }

        session.next_sequence += 1;
        self.slots[index].session = Some(session);
        Rx::Idle
    }

    fn slot_of(&self, source: Address) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.session.is_some_and(|s| s.source == source))
    }

    fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|slot| slot.session.is_none())
    }
}

/// How many packets to grant, capped by what a one-byte sequence can address.
const fn block_size(remaining: u32, _from: u32) -> u8 {
    if remaining > MAX_PACKETS_PER_BLOCK as u32 {
        MAX_PACKETS_PER_BLOCK
    } else {
        remaining as u8
    }
}

/// What a [`Transmitter`] wants the caller to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    /// Nothing to do; wait for the peer.
    Idle,
    /// The peer granted a block — pull frames with
    /// [`Transmitter::next_packet`].
    SendData,
    /// The receiver acknowledged the whole message.
    Complete,
    /// The peer aborted the transfer.
    Aborted(AbortReason),
}

/// The send side of the Extended Transport Protocol.
///
/// Borrows the payload, which for ETP is the difference between sending a
/// 100 KiB object pool and having nowhere to put a copy of it.
#[derive(Debug)]
pub struct Transmitter<'a> {
    pgn: Pgn,
    data: &'a [u8],
    packets: u32,
    /// The absolute packet number the current block starts at.
    block_start: u32,
    /// Packets granted in the current block.
    block_packets: u8,
    /// Whether the offset for the current block has been emitted.
    offset_sent: bool,
    /// The next sequence number within the block.
    next_sequence: u16,
    complete: bool,
}

impl<'a> Transmitter<'a> {
    /// Prepare `data` for transmission as parameter group `pgn`.
    ///
    /// Returns [`Error::InvalidMessageSize`] unless `data` is 1786..=117,440,505
    /// bytes. Smaller messages belong to [`crate::tp`].
    pub fn new(pgn: Pgn, data: &'a [u8]) -> Result<Self> {
        let size = data.len() as u64;
        if size < MIN_MESSAGE_SIZE as u64 || size > MAX_MESSAGE_SIZE as u64 {
            return Err(Error::InvalidMessageSize(if size > u16::MAX as u64 {
                u16::MAX
            } else {
                size as u16
            }));
        }
        Ok(Transmitter {
            pgn,
            data,
            packets: packet_count(size as u32),
            block_start: 1,
            block_packets: 0,
            offset_sent: false,
            next_sequence: 1,
            complete: false,
        })
    }

    /// The announcement to send first.
    pub fn start(&self) -> EtpCm {
        EtpCm::Rts {
            size: self.data.len() as u32,
            pgn: self.pgn,
        }
    }

    /// The total number of data packets this transfer needs.
    pub const fn packets(&self) -> u32 {
        self.packets
    }

    /// Whether the message has been sent and acknowledged.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// The Data Packet Offset for the current block, if it has not been sent.
    ///
    /// Send this *before* the block's data packets. Their sequence numbers are
    /// relative to it, so a receiver cannot place them without it.
    pub fn offset(&mut self) -> Option<EtpCm> {
        if self.offset_sent || self.block_packets == 0 {
            return None;
        }
        self.offset_sent = true;
        Some(EtpCm::Dpo {
            packets: self.block_packets,
            offset: self.block_start - 1,
            pgn: self.pgn,
        })
    }

    /// Handle an ETP.CM from the receiver.
    pub fn on_etp_cm(&mut self, cm: &EtpCm) -> Tx {
        if cm.pgn() != self.pgn {
            return Tx::Idle;
        }
        match *cm {
            EtpCm::Cts {
                packets,
                next_packet,
                ..
            } => {
                if packets == 0 || next_packet == 0 || next_packet > self.packets {
                    return Tx::Idle;
                }
                let remaining = self.packets - next_packet + 1;
                self.block_start = next_packet;
                self.block_packets = block_size(remaining, next_packet).min(packets);
                self.offset_sent = false;
                self.next_sequence = 1;
                Tx::SendData
            }
            EtpCm::Eoma { .. } => {
                self.complete = true;
                Tx::Complete
            }
            EtpCm::Abort { reason, .. } => Tx::Aborted(reason),
            EtpCm::Rts { .. } | EtpCm::Dpo { .. } => Tx::Idle,
        }
    }

    /// The next data packet in the current block.
    ///
    /// `None` means the block is finished; wait for the next CTS. Send
    /// [`Transmitter::offset`] before the first packet of each block.
    pub fn next_packet(&mut self) -> Option<EtpDt> {
        if self.block_packets == 0 || self.next_sequence > self.block_packets as u16 {
            return None;
        }
        let absolute = self.block_start + self.next_sequence as u32 - 1;
        if absolute > self.packets {
            return None;
        }
        let start = (absolute as usize - 1) * BYTES_PER_PACKET;
        let end = (start + BYTES_PER_PACKET).min(self.data.len());
        let packet = EtpDt::new(self.next_sequence as u8, &self.data[start..end]);
        self.next_sequence += 1;
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgn;

    const SENDER: Address = Address::new(0x80);

    #[test]
    fn control_messages_round_trip() {
        let messages = [
            EtpCm::rts(4000, pgn::PROPRIETARY_A).unwrap(),
            EtpCm::rts(MAX_MESSAGE_SIZE, pgn::PROPRIETARY_A).unwrap(),
            EtpCm::Cts {
                packets: 255,
                next_packet: 0x00FF_FFFF,
                pgn: pgn::PROPRIETARY_A,
            },
            EtpCm::Dpo {
                packets: 200,
                offset: 0x00AB_CDEF,
                pgn: pgn::PROPRIETARY_A,
            },
            EtpCm::Eoma {
                size: 4000,
                pgn: pgn::PROPRIETARY_A,
            },
            EtpCm::Abort {
                reason: AbortReason::Timeout,
                pgn: pgn::PROPRIETARY_A,
            },
        ];
        for message in messages {
            assert_eq!(EtpCm::decode(&message.encode()).unwrap(), message);
        }
    }

    /// The RTS size field is four bytes wide, where the ordinary transport
    /// protocol's is two — that widening is the whole point of ETP.
    #[test]
    fn the_size_field_spans_four_bytes() {
        let rts = EtpCm::rts(0x0102_0304, pgn::PROPRIETARY_A).unwrap();
        assert_eq!(rts.encode()[1..5], [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(
            EtpCm::decode(&rts.encode()).unwrap(),
            EtpCm::Rts {
                size: 0x0102_0304,
                pgn: pgn::PROPRIETARY_A
            }
        );
    }

    #[test]
    fn sizes_outside_the_protocol_range_are_refused() {
        // 1785 is the ordinary transport protocol's job.
        assert!(EtpCm::rts(1785, pgn::PROPRIETARY_A).is_err());
        assert!(EtpCm::rts(MIN_MESSAGE_SIZE, pgn::PROPRIETARY_A).is_ok());
        assert!(EtpCm::rts(MAX_MESSAGE_SIZE + 1, pgn::PROPRIETARY_A).is_err());
        assert!(Transmitter::new(pgn::PROPRIETARY_A, &[0; 1785]).is_err());
    }

    #[test]
    fn packet_counts_saturate_rather_than_wrap() {
        assert_eq!(packet_count(1786), 256);
        assert_eq!(packet_count(MAX_MESSAGE_SIZE), 0x00FF_FFFF);
        assert_eq!(packet_count(MAX_MESSAGE_SIZE + 1), 0x00FF_FFFF);
        assert_eq!(packet_count(u32::MAX), 0x00FF_FFFF);
    }

    #[test]
    fn rejects_unknown_control_bytes() {
        assert_eq!(
            EtpCm::decode(&[0x42, 0, 0, 0, 0, 0xEF, 0x00, 0x00]),
            Err(Error::UnknownControlByte(0x42))
        );
        // A TP control byte is not an ETP one.
        assert!(EtpCm::decode(&[0x10, 0, 0, 0, 0, 0xEF, 0x00, 0x00]).is_err());
    }

    /// Data before the offset that gives it meaning cannot be placed anywhere.
    #[test]
    fn data_before_an_offset_is_refused() {
        let mut rx = Reassembler::<8192>::new();
        rx.on_etp_cm(SENDER, &EtpCm::rts(2000, pgn::PROPRIETARY_A).unwrap());

        assert_eq!(
            rx.on_etp_dt(SENDER, &EtpDt::new(1, &[0; 7])),
            Rx::Send(EtpCm::Abort {
                reason: AbortReason::UnexpectedDataPacket,
                pgn: pgn::PROPRIETARY_A,
            })
        );
        assert!(!rx.is_busy());
    }

    /// An offset that does not match the block just granted would scatter data
    /// through the buffer.
    #[test]
    fn an_offset_that_does_not_match_the_granted_block_is_refused() {
        let mut rx = Reassembler::<8192>::new();
        rx.on_etp_cm(SENDER, &EtpCm::rts(2000, pgn::PROPRIETARY_A).unwrap());

        assert_eq!(
            rx.on_etp_cm(
                SENDER,
                &EtpCm::Dpo {
                    packets: 255,
                    offset: 500, // we granted a block starting at packet 1
                    pgn: pgn::PROPRIETARY_A,
                }
            ),
            Rx::Send(EtpCm::Abort {
                reason: AbortReason::UnexpectedDataPacket,
                pgn: pgn::PROPRIETARY_A,
            })
        );
        assert!(!rx.is_busy());
    }

    #[test]
    fn refuses_a_transfer_larger_than_the_buffer() {
        let mut rx = Reassembler::<2048>::new();
        assert_eq!(
            rx.on_etp_cm(SENDER, &EtpCm::rts(100_000, pgn::PROPRIETARY_A).unwrap()),
            Rx::Send(EtpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::PROPRIETARY_A,
            })
        );
        assert!(!rx.is_busy());
    }

    /// Drive a real transmitter into a real reassembler across several blocks,
    /// which is where the offset arithmetic either works or does not.
    fn round_trip(size: usize) {
        let payload: std::vec::Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let mut tx = Transmitter::new(pgn::PROPRIETARY_A, &payload).unwrap();
        let mut rx = Reassembler::<200_000>::new();

        let mut response = match rx.on_etp_cm(SENDER, &tx.start()) {
            Rx::Send(cm) => Some(cm),
            other => panic!("expected a CTS, got {other:?}"),
        };

        let mut delivered = None;
        let mut blocks = 0;
        'transfer: while let Some(cm) = response.take() {
            assert_eq!(tx.on_etp_cm(&cm), Tx::SendData);
            blocks += 1;

            // The offset must go out before the block's data.
            let dpo = tx.offset().expect("every block needs an offset");
            assert_eq!(rx.on_etp_cm(SENDER, &dpo), Rx::Idle);

            while let Some(packet) = tx.next_packet() {
                match rx.on_etp_dt(SENDER, &packet) {
                    Rx::Idle => {}
                    Rx::Send(next) => response = Some(next),
                    Rx::Message { data, ack, .. } => {
                        delivered = Some(data.to_vec());
                        assert_eq!(tx.on_etp_cm(&ack), Tx::Complete);
                        break 'transfer;
                    }
                }
            }
        }

        assert_eq!(
            delivered.as_deref(),
            Some(payload.as_slice()),
            "round trip of {size} bytes"
        );
        assert!(tx.is_complete());
        if size > 255 * 7 {
            assert!(blocks > 1, "{size} bytes must take more than one block");
        }
    }

    #[test]
    fn a_single_block_transfer_round_trips() {
        // 1786 bytes is 256 packets — just past what one 255-packet block holds,
        // so even the smallest ETP message needs two.
        round_trip(1786);
    }

    #[test]
    fn a_multi_block_transfer_round_trips() {
        // 20 KiB is 2926 packets: a dozen blocks, so the offset arithmetic is
        // exercised repeatedly rather than once.
        round_trip(20_000);
    }

    #[test]
    fn transfers_round_trip_at_block_boundaries() {
        // Exactly one block, one block plus a byte, exactly two blocks.
        for size in [1786, 1799, 255 * 7 * 2, 255 * 7 * 2 + 1, 100_000] {
            round_trip(size);
        }
    }

    #[test]
    fn out_of_order_packets_abort_with_distinct_reasons() {
        let expect = |sequence: u8, reason: AbortReason| {
            let mut rx = Reassembler::<8192>::new();
            rx.on_etp_cm(SENDER, &EtpCm::rts(2000, pgn::PROPRIETARY_A).unwrap());
            rx.on_etp_cm(
                SENDER,
                &EtpCm::Dpo {
                    packets: 255,
                    offset: 0,
                    pgn: pgn::PROPRIETARY_A,
                },
            );
            rx.on_etp_dt(SENDER, &EtpDt::new(1, &[0; 7]));
            rx.on_etp_dt(SENDER, &EtpDt::new(2, &[0; 7]));
            match rx.on_etp_dt(SENDER, &EtpDt::new(sequence, &[0; 7])) {
                Rx::Send(EtpCm::Abort { reason: got, .. }) => assert_eq!(got, reason),
                other => panic!("expected an abort, got {other:?}"),
            }
        };
        expect(2, AbortReason::DuplicateSequenceNumber);
        expect(5, AbortReason::BadSequenceNumber);
    }

    #[test]
    fn progress_is_reportable_during_a_long_transfer() {
        let mut rx = Reassembler::<200_000>::new();
        rx.on_etp_cm(SENDER, &EtpCm::rts(20_000, pgn::PROPRIETARY_A).unwrap());
        assert_eq!(rx.progress(SENDER), Some((0, 20_000)));

        rx.on_etp_cm(
            SENDER,
            &EtpCm::Dpo {
                packets: 255,
                offset: 0,
                pgn: pgn::PROPRIETARY_A,
            },
        );
        for sequence in 1..=255u8 {
            rx.on_etp_dt(SENDER, &EtpDt::new(sequence, &[0; 7]));
        }
        // The first block is done: 255 packets of seven bytes.
        assert_eq!(rx.progress(SENDER), Some((255 * 7, 20_000)));
        assert_eq!(rx.progress(Address::new(0x91)), None);
    }

    #[test]
    fn a_stalled_transfer_times_out() {
        let mut rx = Reassembler::<8192>::new();
        rx.on_etp_cm(SENDER, &EtpCm::rts(2000, pgn::PROPRIETARY_A).unwrap());

        let mut expired = std::vec::Vec::new();
        rx.tick(1300, 1250, |peer, abort| expired.push((peer, abort)));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, SENDER);
        assert!(matches!(expired[0].1, EtpCm::Abort { .. }));
        assert!(!rx.is_busy());
    }

    #[test]
    fn concurrent_transfers_from_different_peers_stay_separate() {
        let alice = Address::new(0x80);
        let bob = Address::new(0x91);
        let mut rx = Reassembler::<8192, 2>::new();

        assert!(matches!(
            rx.on_etp_cm(alice, &EtpCm::rts(2000, pgn::PROPRIETARY_A).unwrap()),
            Rx::Send(EtpCm::Cts { .. })
        ));
        assert!(matches!(
            rx.on_etp_cm(bob, &EtpCm::rts(3000, pgn::PROPRIETARY_A).unwrap()),
            Rx::Send(EtpCm::Cts { .. })
        ));
        assert_eq!(rx.active_sessions(), 2);

        // A third peer finds no slot.
        assert_eq!(
            rx.on_etp_cm(
                Address::new(0x17),
                &EtpCm::rts(2000, pgn::PROPRIETARY_A).unwrap()
            ),
            Rx::Send(EtpCm::Abort {
                reason: AbortReason::ResourcesUnavailable,
                pgn: pgn::PROPRIETARY_A,
            })
        );

        assert!(rx.abandon(alice));
        assert!(rx.is_receiving_from(bob));
    }

    #[test]
    fn a_transmitter_ignores_traffic_for_another_group() {
        let payload = [0u8; 2000];
        let mut tx = Transmitter::new(pgn::PROPRIETARY_A, &payload).unwrap();
        tx.start();

        assert_eq!(
            tx.on_etp_cm(&EtpCm::Cts {
                packets: 10,
                next_packet: 1,
                pgn: pgn::DM1,
            }),
            Tx::Idle
        );
        assert!(tx.next_packet().is_none(), "the block must stay shut");
        assert!(tx.offset().is_none());
    }
}
