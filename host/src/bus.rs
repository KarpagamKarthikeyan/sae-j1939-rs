// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The transport boundary: what [`Ecu`](crate::ecu::Ecu) needs from a CAN bus.
//!
//! [`Bus`](crate::bus::Bus) is deliberately tiny — send a frame, try to receive
//! one. Everything else the stack does is protocol logic, and protocol logic
//! should not depend on which CAN library is underneath.
//!
//! `SocketCan` implements it on Linux. Anything else that can move J1939 frames
//! can too: a USB adapter's SDK, a simulator, a recorded log being replayed, or
//! a test double.
//!
//! ```
//! use std::cell::RefCell;
//! use std::collections::VecDeque;
//! use std::io;
//!
//! use sae_j1939_host::bus::Bus;
//! use sae_j1939_host::sae_j1939_rs::Frame;
//!
//! /// A bus that plays back a script and records what was sent.
//! #[derive(Default)]
//! struct Playback {
//!     incoming: RefCell<VecDeque<Frame>>,
//!     sent: RefCell<Vec<Frame>>,
//! }
//!
//! impl Bus for Playback {
//!     fn send_frame(&self, frame: &Frame) -> io::Result<()> {
//!         self.sent.borrow_mut().push(*frame);
//!         Ok(())
//!     }
//!
//!     fn recv_frame(&self) -> io::Result<Option<Frame>> {
//!         Ok(self.incoming.borrow_mut().pop_front())
//!     }
//! }
//! ```

use std::io;

use sae_j1939_rs::{Address, Frame, Pgn};

/// A whole J1939 message, however many CAN frames it took to arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The parameter group carried.
    pub pgn: Pgn,
    /// The ECU that sent it.
    pub source: Address,
    /// The payload: up to eight bytes for a single frame, up to 1785 for a
    /// transport-protocol transfer.
    pub data: Vec<u8>,
}

/// Something that can carry J1939 frames.
///
/// Both methods take `&self` so a bus can be shared; implementations that need
/// interior mutability should use a `RefCell` or a lock.
pub trait Bus {
    /// Put a frame on the bus.
    fn send_frame(&self, frame: &Frame) -> io::Result<()>;

    /// Take the next frame off the bus.
    ///
    /// Returns `Ok(None)` when nothing arrived before the implementation's read
    /// timeout — a quiet bus is not an error. Non-J1939 traffic (11-bit
    /// identifiers, remote frames, error frames) should be skipped rather than
    /// returned.
    ///
    /// **Implementations should block for a short interval** — tens of
    /// milliseconds — rather than returning immediately.
    /// [`Ecu`](crate::ecu::Ecu) polls in a loop, so a bus that never blocks
    /// turns that loop into a busy wait. `SocketCan` uses a 50 ms read timeout
    /// for this reason.
    fn recv_frame(&self) -> io::Result<Option<Frame>>;
}

impl<B: Bus + ?Sized> Bus for &B {
    fn send_frame(&self, frame: &Frame) -> io::Result<()> {
        (**self).send_frame(frame)
    }

    fn recv_frame(&self) -> io::Result<Option<Frame>> {
        (**self).recv_frame()
    }
}
