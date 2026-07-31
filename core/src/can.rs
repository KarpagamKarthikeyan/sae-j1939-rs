// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bridging J1939 frames to the [`embedded_can`] traits.
//!
//! This is the *CAN driver* boundary, not the J1939 transport protocol — that
//! lives in [`crate::tp`]. In `canopen-rs`, the companion project, the same
//! helpers live in its `transport` module; the shape is deliberately identical
//! so the two can converge on shared code.
//!
//! The protocol modules speak in [`Id`]s and payloads; a CAN controller speaks
//! in [`embedded_can::Frame`]s. These helpers convert between the two, so any
//! driver implementing the `embedded-can` traits — a bare-metal HAL or a host
//! SocketCAN socket alike — can carry J1939 traffic.
//!
//! J1939 uses only the 29-bit extended identifier, so [`j1939_id`] returns
//! `None` for a standard-identifier frame. (This is the mirror image of the
//! CANopen predefined connection set, which uses only 11-bit identifiers, so
//! the two stacks can share a physical bus without colliding.)
//!
//! ```
//! # use sae_j1939_rs::can::{frame_from, j1939_id};
//! # use sae_j1939_rs::{pgn, Address, Id, Priority};
//! # fn example<F: embedded_can::Frame>(bus_send: impl Fn(&F), bus_recv: impl Fn() -> F) {
//! // Request the Address Claimed PGN from every ECU on the bus.
//! let id = Id::broadcast(Priority::DEFAULT, pgn::REQUEST, Address::new(0x80));
//! let request = pgn::ADDRESS_CLAIMED.as_u32().to_le_bytes();
//! let frame: F = frame_from(id, &request[..3]).unwrap();
//! bus_send(&frame);
//!
//! // Later, pull a frame off the bus and recover its J1939 identifier.
//! let reply = bus_recv();
//! if let Some(id) = j1939_id(&reply) {
//!     if id.pgn() == pgn::ADDRESS_CLAIMED {
//!         // dispatch reply.data() to the network management layer
//!     }
//! }
//! # }
//! ```

use embedded_can::{ExtendedId, Frame, Id as CanId};

use crate::frame::Frame as J1939Frame;
use crate::id::Id;

/// Build an extended CAN frame carrying `data` on the J1939 identifier `id`.
///
/// Returns `None` if `data` is longer than the frame can hold or the driver's
/// frame constructor rejects it.
pub fn frame_from<F: Frame>(id: Id, data: &[u8]) -> Option<F> {
    F::new(ExtendedId::new(id.as_u32())?, data)
}

/// The J1939 identifier of a received frame.
///
/// Returns `None` for a frame with an 11-bit standard identifier, which J1939
/// does not use.
pub fn j1939_id<F: Frame>(frame: &F) -> Option<Id> {
    match frame.id() {
        CanId::Extended(id) => Id::new(id.as_raw()).ok(),
        CanId::Standard(_) => None,
    }
}

/// Decode a received CAN frame into a J1939 [`Frame`](crate::frame::Frame).
///
/// Returns `None` if the frame is not an extended-identifier data frame, or if
/// its payload exceeds eight bytes.
pub fn decode<F: Frame>(frame: &F) -> Option<J1939Frame> {
    let id = j1939_id(frame)?;
    J1939Frame::new(id, frame.data()).ok()
}

/// Encode a J1939 [`Frame`](crate::frame::Frame) as a driver CAN frame.
pub fn encode<F: Frame>(frame: &J1939Frame) -> Option<F> {
    frame_from(frame.id(), frame.data())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgn;
    use crate::types::Address;
    use heapless::Vec;

    /// A minimal in-memory [`Frame`] for exercising the helpers.
    #[derive(Debug)]
    struct MockFrame {
        id: CanId,
        data: Vec<u8, 8>,
    }

    impl Frame for MockFrame {
        fn new(id: impl Into<CanId>, data: &[u8]) -> Option<Self> {
            let mut buf = Vec::new();
            buf.extend_from_slice(data).ok()?;
            Some(Self {
                id: id.into(),
                data: buf,
            })
        }

        fn new_remote(_id: impl Into<CanId>, _dlc: usize) -> Option<Self> {
            None
        }

        fn is_extended(&self) -> bool {
            matches!(self.id, CanId::Extended(_))
        }

        fn is_remote_frame(&self) -> bool {
            false
        }

        fn id(&self) -> CanId {
            self.id
        }

        fn dlc(&self) -> usize {
            self.data.len()
        }

        fn data(&self) -> &[u8] {
            &self.data
        }
    }

    #[test]
    fn round_trips_identifier_and_data() {
        let id = Id::new(0x18EEFF80).unwrap();
        let frame: MockFrame = frame_from(id, &[0x64, 0x00, 0x2C, 0x01]).unwrap();
        assert_eq!(j1939_id(&frame), Some(id));
        assert_eq!(frame.data(), &[0x64, 0x00, 0x2C, 0x01]);
        assert!(frame.is_extended());
    }

    #[test]
    fn decodes_into_a_j1939_frame() {
        let id = Id::new(0x18FECA80).unwrap();
        let raw: MockFrame = frame_from(id, &[0xFF; 8]).unwrap();
        let decoded = decode(&raw).unwrap();
        assert_eq!(decoded.pgn(), pgn::DM1);
        assert_eq!(decoded.source_address(), Address::new(0x80));

        let reencoded: MockFrame = encode(&decoded).unwrap();
        assert_eq!(j1939_id(&reencoded), Some(id));
    }

    #[test]
    fn standard_identifier_frames_are_not_j1939() {
        use embedded_can::StandardId;
        let frame = MockFrame {
            id: CanId::Standard(StandardId::new(0x581).unwrap()),
            data: Vec::new(),
        };
        assert_eq!(j1939_id(&frame), None);
        assert_eq!(decode(&frame), None);
    }
}
