// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! J1939-21 Request and Acknowledgement.
//!
//! The **Request** parameter group (`0x00EA00`) is how one ECU asks another —
//! or the whole bus — to transmit a parameter group. Its payload is just the
//! requested PGN, three bytes little-endian. Requesting
//! [`pgn::ADDRESS_CLAIMED`](crate::pgn::ADDRESS_CLAIMED) from
//! [`Address::GLOBAL`] is the standard way to discover who is on the bus.
//!
//! The **Acknowledgement** parameter group (`0x00E800`) is the reply an ECU
//! sends when it cannot honour a request — or, for some parameter groups, to
//! confirm that it did.
//!
//! ```
//! use sae_j1939_rs::pgn;
//! use sae_j1939_rs::request::{AckControl, Acknowledgement, Request};
//!
//! // Ask for the software identification PGN.
//! let request = Request::new(pgn::SOFTWARE_IDENTIFICATION);
//! assert_eq!(request.encode(), [0xDA, 0xFE, 0x00]);
//!
//! // The other ECU does not implement it.
//! let nack = Acknowledgement::negative(pgn::SOFTWARE_IDENTIFICATION);
//! assert_eq!(nack.control, AckControl::NotSupported);
//! ```

use crate::pgn::Pgn;
use crate::types::{Address, Error, Result};

/// Bytes in a Request payload: the requested PGN, little-endian.
pub const REQUEST_LEN: usize = 3;

/// Filler for unused payload bytes, per J1939-21.
const FILL: u8 = 0xFF;

/// A request for another ECU to transmit a parameter group.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The parameter group being asked for.
    pub pgn: Pgn,
}

impl Request {
    /// Ask for `pgn`.
    pub const fn new(pgn: Pgn) -> Self {
        Request { pgn }
    }

    /// Encode to the three-byte payload.
    ///
    /// J1939-21 defines the Request payload as exactly three bytes; a frame
    /// carrying it therefore has a data length of 3, not 8.
    pub const fn encode(&self) -> [u8; REQUEST_LEN] {
        let pgn = self.pgn.as_u32();
        [pgn as u8, (pgn >> 8) as u8, (pgn >> 16) as u8]
    }

    /// Decode a Request payload.
    ///
    /// Accepts any slice of at least three bytes, so a request padded out to a
    /// full eight-byte frame — which some ECUs send — parses correctly.
    ///
    /// Returns [`Error::ShortPayload`] if fewer than three bytes are supplied.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < REQUEST_LEN {
            return Err(Error::ShortPayload {
                expected: REQUEST_LEN,
                actual: data.len(),
            });
        }
        Ok(Request {
            pgn: Pgn::new_masked(
                (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16),
            ),
        })
    }
}

/// The control byte of an [`Acknowledgement`]: how the request was received.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckControl {
    /// Positive acknowledgement — the parameter group is supported and the
    /// request was honoured.
    Acknowledged,
    /// Negative acknowledgement — this ECU does not support the parameter group.
    NotSupported,
    /// The parameter group is supported, but the requester may not have it.
    AccessDenied,
    /// The parameter group is supported, but this ECU is busy and cannot
    /// respond now.
    Busy,
    /// A control byte outside the four J1939-21 defines.
    Other(u8),
}

impl AckControl {
    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            AckControl::Acknowledged => 0,
            AckControl::NotSupported => 1,
            AckControl::AccessDenied => 2,
            AckControl::Busy => 3,
            AckControl::Other(raw) => raw,
        }
    }

    /// Decode a wire byte.
    pub const fn from_u8(raw: u8) -> Self {
        match raw {
            0 => AckControl::Acknowledged,
            1 => AckControl::NotSupported,
            2 => AckControl::AccessDenied,
            3 => AckControl::Busy,
            other => AckControl::Other(other),
        }
    }

    /// Whether this is the positive acknowledgement.
    pub const fn is_positive(self) -> bool {
        matches!(self, AckControl::Acknowledged)
    }
}

/// A reply to a [`Request`], reporting whether it could be honoured.
///
/// ```text
/// byte 0    control byte
/// byte 1    group function value (why, when the control byte says no)
/// bytes 2-3 reserved (0xFF)
/// byte 4    address of the ECU that is acknowledging
/// bytes 5-7 the PGN being acknowledged, little-endian
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acknowledgement {
    /// How the request was received.
    pub control: AckControl,
    /// A group-specific reason code qualifying `control`. `0xFF` means no
    /// specific cause.
    pub group_function: u8,
    /// The address of the ECU sending this acknowledgement.
    pub address: Address,
    /// The parameter group being acknowledged.
    pub pgn: Pgn,
}

impl Acknowledgement {
    /// A positive acknowledgement for `pgn`.
    pub const fn positive(pgn: Pgn, address: Address) -> Self {
        Acknowledgement {
            control: AckControl::Acknowledged,
            group_function: FILL,
            address,
            pgn,
        }
    }

    /// A negative acknowledgement: this ECU does not support `pgn`.
    ///
    /// The address field is left as [`Address::NULL`]; set it if the responding
    /// ECU has claimed one.
    pub const fn negative(pgn: Pgn) -> Self {
        Acknowledgement {
            control: AckControl::NotSupported,
            group_function: FILL,
            address: Address::NULL,
            pgn,
        }
    }

    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        let pgn = self.pgn.as_u32();
        [
            self.control.as_u8(),
            self.group_function,
            FILL,
            FILL,
            self.address.as_u8(),
            pgn as u8,
            (pgn >> 8) as u8,
            (pgn >> 16) as u8,
        ]
    }

    /// Decode an eight-byte Acknowledgement payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        Acknowledgement {
            control: AckControl::from_u8(data[0]),
            group_function: data[1],
            address: Address::new(data[4]),
            pgn: Pgn::new_masked(
                (data[5] as u32) | ((data[6] as u32) << 8) | ((data[7] as u32) << 16),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgn;

    #[test]
    fn request_encodes_the_pgn_little_endian() {
        // The C reference sends exactly these three bytes for a PGN request.
        assert_eq!(
            Request::new(pgn::ADDRESS_CLAIMED).encode(),
            [0x00, 0xEE, 0x00]
        );
        assert_eq!(Request::new(pgn::DM1).encode(), [0xCA, 0xFE, 0x00]);
        assert_eq!(
            Request::new(pgn::SOFTWARE_IDENTIFICATION).encode(),
            [0xDA, 0xFE, 0x00]
        );
    }

    #[test]
    fn request_round_trips() {
        for pgn in [
            pgn::ADDRESS_CLAIMED,
            pgn::DM1,
            pgn::DM2,
            pgn::ECU_IDENTIFICATION,
            pgn::COMPONENT_IDENTIFICATION,
        ] {
            assert_eq!(
                Request::decode(&Request::new(pgn).encode()).unwrap().pgn,
                pgn
            );
        }
    }

    #[test]
    fn request_tolerates_a_padded_frame() {
        // Some ECUs pad the three-byte request out to a full frame.
        let padded = [0xCA, 0xFE, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(Request::decode(&padded).unwrap().pgn, pgn::DM1);
    }

    #[test]
    fn request_rejects_a_short_payload() {
        assert_eq!(
            Request::decode(&[0xCA, 0xFE]),
            Err(Error::ShortPayload {
                expected: 3,
                actual: 2
            })
        );
    }

    /// A PDU1 request names the parameter group only; the destination lives in
    /// the CAN identifier, not the payload.
    #[test]
    fn requesting_a_pdu1_group_carries_a_zero_low_byte() {
        let request = Request::new(pgn::REQUEST);
        assert_eq!(request.encode(), [0x00, 0xEA, 0x00]);
    }

    #[test]
    fn acknowledgement_matches_the_reference_byte_layout() {
        let ack = Acknowledgement {
            control: AckControl::NotSupported,
            group_function: 0xFF,
            address: Address::new(0x80),
            pgn: pgn::DM1,
        };
        // control, group function, two reserved, address, then the PGN.
        assert_eq!(
            ack.encode(),
            [0x01, 0xFF, 0xFF, 0xFF, 0x80, 0xCA, 0xFE, 0x00]
        );
        assert_eq!(Acknowledgement::decode(&ack.encode()), ack);
    }

    #[test]
    fn control_bytes_round_trip_including_unknown_values() {
        for raw in 0u8..=255 {
            assert_eq!(AckControl::from_u8(raw).as_u8(), raw);
        }
        assert!(AckControl::Acknowledged.is_positive());
        assert!(!AckControl::Busy.is_positive());
        assert_eq!(AckControl::from_u8(9), AckControl::Other(9));
    }

    #[test]
    fn constructors_produce_the_expected_control_bytes() {
        let positive = Acknowledgement::positive(pgn::DM1, Address::new(0x80));
        assert_eq!(positive.encode()[0], 0);
        assert!(positive.control.is_positive());

        let negative = Acknowledgement::negative(pgn::DM1);
        assert_eq!(negative.encode()[0], 1);
        assert_eq!(negative.address, Address::NULL);
    }
}
