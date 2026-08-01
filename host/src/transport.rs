// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux SocketCAN transport for `sae-j1939-rs`.
//!
//! Bridges the J1939 core codecs to a Linux SocketCAN interface. The
//! [`socketcan`] crate's [`CanFrame`](socketcan::CanFrame) implements the
//! [`embedded-can`] traits, so the core's frame helpers
//! ([`sae_j1939_rs::can`]) turn identifiers and payloads straight into
//! bus traffic.
//!
//! [`embedded-can`]: https://docs.rs/embedded-can
//!
//! [`SocketCan::open`](crate::transport::SocketCan::open) binds a named
//! interface (e.g. `"can0"`, or `"vcan0"` for a virtual bus). This is the raw
//! J1939 frame layer: [`SocketCan::send`](crate::transport::SocketCan::send),
//! [`SocketCan::recv`](crate::transport::SocketCan::recv), and
//! [`SocketCan::request`](crate::transport::SocketCan::request). Higher-level
//! services (transport protocol reassembly, address claiming, diagnostics) land
//! here as the core stack grows.
//!
//! Note that this is a plain `SOCK_RAW` CAN socket, not the Linux kernel's
//! `CAN_J1939` protocol family: reassembly and address management belong to the
//! portable core so that the same logic runs on a bare-metal ECU.
//!
//! [`socketcan`]: https://docs.rs/socketcan

use std::io;
use std::time::Duration;

use socketcan::{CanFrame, CanSocket, Socket};

use sae_j1939_rs::can::{decode, encode};
use sae_j1939_rs::frame::Frame;
use sae_j1939_rs::tp::{Reassembler, Rx, TpCm, TpDt, MAX_MESSAGE_SIZE};

/// How many peers may have a multi-packet transfer in flight at once.
///
/// A host has memory to spare, so this is generous: several ECUs broadcasting
/// diagnostics at the same time is routine on a busy bus, and a transfer that
/// gets no slot is refused rather than corrupting another.
pub const CONCURRENT_TRANSFERS: usize = 8;
use sae_j1939_rs::{pgn, Address, Id, Pgn, Priority};

use crate::bus::Bus;

pub use crate::bus::Message;

/// A J1939 transport over a Linux SocketCAN interface.
#[derive(Debug)]
pub struct SocketCan {
    socket: CanSocket,
    reassembler: Reassembler<{ MAX_MESSAGE_SIZE as usize }, CONCURRENT_TRANSFERS>,
}

impl SocketCan {
    /// Open the named CAN interface (e.g. `"can0"` or `"vcan0"`).
    pub fn open(interface: &str) -> io::Result<Self> {
        Ok(Self {
            socket: CanSocket::open(interface)?,
            reassembler: Reassembler::new(),
        })
    }

    /// Set a read timeout, so [`SocketCan::recv`] fails with a timeout error
    /// rather than blocking forever.
    pub fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Put the socket into (non-)blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    /// Transmit `data` on the J1939 identifier `id` as an extended data frame.
    pub fn send(&self, id: Id, data: &[u8]) -> io::Result<()> {
        let frame = Frame::new(id, data).map_err(invalid_input)?;
        self.send_frame(&frame)
    }

    /// Transmit an already-built J1939 [`Frame`].
    pub fn send_frame(&self, frame: &Frame) -> io::Result<()> {
        let raw: CanFrame = encode(frame).ok_or_else(|| {
            invalid_input(format!(
                "frame with id {:#010x} cannot be encoded",
                frame.id().as_u32()
            ))
        })?;
        self.socket.write_frame(&raw)
    }

    /// Receive the next J1939 frame.
    ///
    /// Non-J1939 traffic sharing the bus (11-bit standard identifier frames,
    /// remote frames, and SocketCAN error frames) is skipped, so this returns
    /// only frames the stack can interpret. Blocks until one arrives, or until
    /// the read timeout set by [`SocketCan::set_read_timeout`] expires.
    pub fn recv(&self) -> io::Result<Frame> {
        loop {
            let raw = self.socket.read_frame()?;
            // Error and remote frames carry no J1939 payload; a standard
            // identifier is not J1939 at all (it may be CANopen on a shared bus).
            if let CanFrame::Data(_) = raw {
                if let Some(frame) = decode(&raw) {
                    return Ok(frame);
                }
            }
        }
    }

    /// Send a J1939 Request (PGN `0x00EA00`) asking `destination` for `requested`.
    ///
    /// Pass [`Address::GLOBAL`] as `destination` to ask every ECU on the bus —
    /// the usual way to discover who is present, by requesting
    /// [`pgn::ADDRESS_CLAIMED`].
    ///
    /// The payload is the requested PGN as three little-endian bytes, per
    /// J1939-21.
    pub fn request(&self, source: Address, destination: Address, requested: Pgn) -> io::Result<()> {
        let id = Id::from_parts(Priority::DEFAULT, pgn::REQUEST, destination, source)
            .map_err(invalid_input)?;
        let bytes = requested.as_u32().to_le_bytes();
        self.send(id, &bytes[..3])
    }
}

impl SocketCan {
    /// Receive the next complete J1939 *message*, transparently reassembling
    /// multi-packet transfers.
    ///
    /// Single-frame parameter groups are returned as they arrive. Transport
    /// protocol traffic (BAM and RTS/CTS) is fed to a reassembler, and this
    /// call blocks until a whole message is available — sending the CTS and
    /// end-of-message acknowledgements an RTS/CTS transfer needs along the way.
    ///
    /// Up to [`CONCURRENT_TRANSFERS`] peers may be mid-transfer at once, so
    /// interleaved broadcasts from different ECUs are reassembled independently
    /// rather than corrupting one another.
    ///
    /// `this_ecu` is the address of the local node: TP frames addressed
    /// elsewhere are ignored, and it is used as the source address of any
    /// acknowledgement sent back.
    ///
    /// The TP.CM and TP.DT frames themselves are never returned — only the
    /// message they carry.
    pub fn recv_message(&mut self, this_ecu: Address) -> io::Result<Message> {
        loop {
            let frame = self.recv()?;
            let id = frame.id();
            let source = frame.source_address();
            let pgn = frame.pgn();

            // Transport protocol frames not meant for us are none of our business.
            if (pgn == pgn::TP_CM || pgn == pgn::TP_DT) && !id.is_addressed_to(this_ecu) {
                continue;
            }

            let outcome = if pgn == pgn::TP_CM {
                match TpCm::decode(frame.payload()) {
                    Ok(cm) => self.reassembler.on_tp_cm(source, &cm),
                    // A malformed TP.CM is not fatal to the bus; skip it.
                    Err(_) => continue,
                }
            } else if pgn == pgn::TP_DT {
                self.reassembler
                    .on_tp_dt(source, &TpDt::decode(frame.payload()))
            } else {
                return Ok(Message {
                    pgn,
                    source,
                    data: frame.data().to_vec(),
                });
            };

            // Copy out what the reassembler produced before the borrow ends.
            let (reply, message) = match outcome {
                Rx::Idle => (None, None),
                Rx::Send(cm) => (Some(cm), None),
                Rx::Message {
                    pgn,
                    source,
                    data,
                    ack,
                } => (
                    ack,
                    Some(Message {
                        pgn,
                        source,
                        data: data.to_vec(),
                    }),
                ),
            };

            if let Some(cm) = reply {
                self.send_tp_cm(this_ecu, source, &cm)?;
            }
            if let Some(message) = message {
                return Ok(message);
            }
        }
    }

    /// Send a transport-protocol connection-management message to `destination`.
    ///
    /// TP.CM uses priority 7, the lowest, so bulk transfers yield to control
    /// traffic on a busy bus.
    pub fn send_tp_cm(&self, source: Address, destination: Address, cm: &TpCm) -> io::Result<()> {
        let id = Id::from_parts(Priority::LOWEST, pgn::TP_CM, destination, source)
            .map_err(invalid_input)?;
        self.send(id, &cm.encode())
    }

    /// How many multi-packet transfers are currently being reassembled.
    pub fn transfers_in_flight(&self) -> usize {
        self.reassembler.active_sessions()
    }

    /// Abandon the partially received transfer from `source`, if any.
    ///
    /// Use this when a peer goes quiet mid-transfer: J1939-21 allows 750 ms
    /// between packets, and this type owns no timer.
    pub fn abandon_transfer(&mut self, source: Address) -> bool {
        self.reassembler.abandon(source)
    }

    /// Send a transport-protocol data packet to `destination`.
    pub fn send_tp_dt(&self, source: Address, destination: Address, dt: &TpDt) -> io::Result<()> {
        let id = Id::from_parts(Priority::LOWEST, pgn::TP_DT, destination, source)
            .map_err(invalid_input)?;
        self.send(id, &dt.encode())
    }
}

impl Bus for SocketCan {
    fn send_frame(&self, frame: &Frame) -> io::Result<()> {
        SocketCan::send_frame(self, frame)
    }

    fn recv_frame(&self) -> io::Result<Option<Frame>> {
        match self.recv() {
            Ok(frame) => Ok(Some(frame)),
            // A quiet bus is not a failure; both kinds surface here depending on
            // whether the socket is blocking or non-blocking.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

fn invalid_input<E: ToString>(error: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
