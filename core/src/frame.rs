// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A single J1939 CAN frame: a decoded [`Id`] and up to eight payload bytes.

use crate::id::Id;
use crate::types::{Error, Result};

/// The maximum payload of a single classic CAN frame.
pub const MAX_PAYLOAD: usize = 8;

/// The value J1939 specifies for unused payload bytes.
const FILL: u8 = 0xFF;

/// One J1939 frame — a decoded identifier plus its payload.
///
/// This is the unit the protocol layers consume and produce. Messages longer
/// than eight bytes are carried by the transport protocol (J1939-21) as a
/// sequence of these; see the roadmap in the crate documentation.
///
/// ```
/// use sae_j1939_rs::{pgn, Address, Frame, Id};
///
/// let frame = Frame::new(Id::new(0x18EEFF80).unwrap(), &[0x00; 8]).unwrap();
/// assert_eq!(frame.pgn(), pgn::ADDRESS_CLAIMED);
/// assert_eq!(frame.source_address(), Address::new(0x80));
/// assert_eq!(frame.data().len(), 8);
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    id: Id,
    data: [u8; MAX_PAYLOAD],
    len: u8,
}

/// Prints in the `candump` format every CAN engineer reads: `18FECA80#04002B`.
///
/// A frame logged by this crate can therefore be replayed with `cansend`
/// verbatim, and traffic captured with `candump` compared against it by eye.
impl core::fmt::Display for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}#", self.id)?;
        for byte in self.data() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Frame({self})")
    }
}

impl Frame {
    /// Build a frame from an identifier and payload.
    ///
    /// Returns [`Error::ShortPayload`] — with `expected` set to
    /// [`MAX_PAYLOAD`] — if `data` is longer than a classic CAN frame can
    /// carry.
    pub fn new(id: Id, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::ShortPayload {
                expected: MAX_PAYLOAD,
                actual: data.len(),
            });
        }
        // J1939 fills unused payload bytes with 0xFF, not zero, so `payload()`
        // reads back the way the parameter group codecs expect.
        let mut buf = [FILL; MAX_PAYLOAD];
        buf[..data.len()].copy_from_slice(data);
        Ok(Frame {
            id,
            data: buf,
            len: data.len() as u8,
        })
    }

    /// Build a frame from an identifier and a full eight-byte payload.
    ///
    /// Infallible, unlike [`Frame::new`]: a payload of exactly [`MAX_PAYLOAD`]
    /// bytes always fits. Most J1939 parameter groups encode to exactly eight
    /// bytes, so this is the common case.
    pub const fn from_payload(id: Id, data: [u8; MAX_PAYLOAD]) -> Self {
        Frame {
            id,
            data,
            len: MAX_PAYLOAD as u8,
        }
    }

    /// The frame's identifier.
    pub const fn id(&self) -> Id {
        self.id
    }

    /// The parameter group this frame carries.
    pub const fn pgn(&self) -> crate::pgn::Pgn {
        self.id.pgn()
    }

    /// The address of the ECU that sent this frame.
    pub const fn source_address(&self) -> crate::types::Address {
        self.id.source_address()
    }

    /// The payload, trimmed to the frame's data length.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    /// The full eight-byte payload, padded with `0xFF`.
    ///
    /// Convenient for the fixed-width parameter-group codecs, which are defined
    /// over all eight bytes. J1939 specifies `0xFF` for unused bytes, so a short
    /// frame reads back exactly as a conforming sender would have transmitted it.
    pub const fn payload(&self) -> &[u8; MAX_PAYLOAD] {
        &self.data
    }

    /// The frame's data length code.
    pub const fn dlc(&self) -> usize {
        self.len as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgn;
    use crate::types::Address;

    #[test]
    fn exposes_identifier_fields() {
        let frame = Frame::new(Id::new(0x18FECA80).unwrap(), &[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(frame.pgn(), pgn::DM1);
        assert_eq!(frame.source_address(), Address::new(0x80));
        assert_eq!(frame.data(), &[0x01, 0x02, 0x03]);
        assert_eq!(frame.dlc(), 3);
        // Unused bytes read back as J1939's 0xFF filler, not zero.
        assert_eq!(
            frame.payload(),
            &[0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // ...but `data()` is still trimmed to what was actually supplied.
        assert_eq!(frame.data(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn a_full_payload_needs_no_fallible_constructor() {
        let id = Id::new(0x18FECA80).unwrap();
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let frame = Frame::from_payload(id, bytes);
        assert_eq!(frame.dlc(), 8);
        assert_eq!(frame.data(), &bytes);
        assert_eq!(Frame::new(id, &bytes).unwrap(), frame);
    }

    /// A logged frame must be replayable with `cansend` verbatim.
    #[test]
    fn frames_print_in_candump_format() {
        extern crate std;
        use std::format;

        let id = Id::new(0x18FECA80).unwrap();
        let frame = Frame::new(id, &[0x04, 0x00, 0x2B, 0x01, 0x04, 0x83]).unwrap();
        assert_eq!(format!("{frame}"), "18FECA80#04002B010483");
        assert_eq!(format!("{frame:?}"), "Frame(18FECA80#04002B010483)");

        // The trailing 0xFF filler is not part of the frame, so it is not shown.
        let short = Frame::new(id, &[0x01]).unwrap();
        assert_eq!(format!("{short}"), "18FECA80#01");
    }

    #[test]
    fn rejects_payloads_beyond_eight_bytes() {
        let id = Id::new(0x18FECA80).unwrap();
        assert!(Frame::new(id, &[0u8; 8]).is_ok());
        assert_eq!(
            Frame::new(id, &[0u8; 9]),
            Err(Error::ShortPayload {
                expected: 8,
                actual: 9
            })
        );
    }
}
