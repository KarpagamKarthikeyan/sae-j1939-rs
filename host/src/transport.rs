// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux SocketCAN transport for `sae-j1939-rs`.
//!
//! This is the frame layer and nothing more: open an interface, put frames on
//! it, take frames off it. It implements [`Bus`](crate::bus::Bus), so
//! [`Ecu`](crate::ecu::Ecu) can drive a whole protocol stack over it.
//!
//! Everything above frames — reassembly, address claiming, diagnostics — lives
//! in the portable core, so that the same logic runs unchanged on a bare-metal
//! ECU. Keeping it out of here also means there is only ever *one*
//! implementation of each protocol rule to get right.
//!
//! ```no_run
//! use sae_j1939_host::transport::SocketCan;
//! use sae_j1939_host::sae_j1939_rs::{pgn, Address, Id, Priority};
//!
//! let bus = SocketCan::open("can0")?;
//!
//! // Raw frames in and out.
//! let id = Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x80));
//! bus.send(id, &[0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF])?;
//! let frame = bus.recv()?;
//! println!("PGN {:#08x}", frame.pgn().as_u32());
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! For anything beyond single frames, hand the socket to
//! [`Ecu::new`](crate::ecu::Ecu::new) — or use
//! [`Ecu::open`](crate::ecu::Ecu::open), which does both steps.
//!
//! Note that this is a plain `SOCK_RAW` CAN socket, not the Linux kernel's
//! `CAN_J1939` protocol family. The kernel module implements the transport
//! protocol itself; doing it in the core instead is what lets the same code run
//! on a microcontroller.
//!
//! [`socketcan`]: https://docs.rs/socketcan

use std::io;
use std::time::Duration;

use socketcan::{CanFrame, CanSocket, Socket};

use sae_j1939_rs::can::{decode, encode};
use sae_j1939_rs::frame::Frame;
use sae_j1939_rs::Id;

use crate::bus::Bus;

pub use crate::bus::Message;

/// A J1939 frame transport over a Linux SocketCAN interface.
#[derive(Debug)]
pub struct SocketCan {
    socket: CanSocket,
}

impl SocketCan {
    /// Open the named CAN interface (e.g. `"can0"` or `"vcan0"`).
    ///
    /// The socket starts with no read timeout, so [`SocketCan::recv`] blocks
    /// indefinitely. [`Ecu::open`](crate::ecu::Ecu::open) sets a 50 ms timeout;
    /// set one yourself with [`SocketCan::set_read_timeout`] if you are driving
    /// the socket directly.
    pub fn open(interface: &str) -> io::Result<Self> {
        Ok(Self {
            socket: CanSocket::open(interface)?,
        })
    }

    /// Set a read timeout, so [`SocketCan::recv`] fails with a timeout error
    /// rather than blocking forever.
    ///
    /// [`Bus::recv_frame`] turns that timeout into `Ok(None)`.
    pub fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Put the socket into (non-)blocking mode.
    ///
    /// A non-blocking socket makes [`Ecu`](crate::ecu::Ecu)'s poll loop a busy
    /// wait; prefer a short [`read timeout`](SocketCan::set_read_timeout).
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
    /// Traffic the stack cannot interpret is skipped rather than returned:
    /// remote frames and SocketCAN error frames carry no J1939 payload, and an
    /// 11-bit standard identifier is not J1939 at all — it may be CANopen
    /// sharing the bus.
    ///
    /// Blocks until a frame arrives, or until the read timeout set by
    /// [`SocketCan::set_read_timeout`] expires.
    pub fn recv(&self) -> io::Result<Frame> {
        loop {
            let raw = self.socket.read_frame()?;
            if let CanFrame::Data(_) = raw {
                if let Some(frame) = decode(&raw) {
                    return Ok(frame);
                }
            }
        }
    }
}

impl Bus for SocketCan {
    fn send_frame(&self, frame: &Frame) -> io::Result<()> {
        SocketCan::send_frame(self, frame)
    }

    fn recv_frame(&self) -> io::Result<Option<Frame>> {
        match self.recv() {
            Ok(frame) => Ok(Some(frame)),
            // A quiet bus is not a failure; which kind surfaces depends on
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
