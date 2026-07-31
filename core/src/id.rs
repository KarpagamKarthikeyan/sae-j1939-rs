// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The 29-bit J1939 CAN identifier.
//!
//! J1939 runs exclusively on CAN extended frames and gives every bit of the
//! 29-bit identifier a meaning:
//!
//! ```text
//! bit 28 .. 26   25    24    23 .......... 16   15 .......... 8   7 ......... 0
//!  Priority     EDP    DP    PDU Format (PF)    PDU Specific     Source Address
//!                            \______________ PGN ____________/
//! ```
//!
//! [`Id`] decodes and encodes that layout. The subtlety it hides is the PDU
//! specific byte: for a PDU1 (destination-specific) parameter group it is the
//! **destination address**, and for a PDU2 (broadcast) one it is a **group
//! extension** belonging to the PGN. See [`crate::pgn`] for that split.
//!
//! ```
//! use sae_j1939_rs::{pgn, Address, Id, Priority};
//!
//! // An Address Claimed broadcast from ECU 0x80.
//! let id = Id::new(0x18EEFF80).unwrap();
//! assert_eq!(id.priority(), Priority::DEFAULT);
//! assert_eq!(id.pgn(), pgn::ADDRESS_CLAIMED);
//! assert_eq!(id.source_address(), Address::new(0x80));
//! assert_eq!(id.destination_address(), Some(Address::GLOBAL));
//!
//! // ... and back again.
//! let rebuilt =
//!     Id::from_parts(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, Address::GLOBAL, Address::new(0x80))
//!         .unwrap();
//! assert_eq!(rebuilt, id);
//! ```

use crate::pgn::{self, Pgn};
use crate::types::{Address, Error, Priority, Result};

/// The largest valid 29-bit extended CAN identifier.
pub const MAX: u32 = 0x1FFF_FFFF;

const PRIORITY_SHIFT: u32 = 26;
const PGN_SHIFT: u32 = 8;

/// A decoded 29-bit J1939 CAN identifier.
///
/// Construct one from the wire with [`Id::new`], or from its components with
/// [`Id::from_parts`] / [`Id::broadcast`]. The struct stores the raw identifier
/// and decodes fields on access, so it is [`Copy`] and free of hidden state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id {
    raw: u32,
}

impl Id {
    /// Decode a raw 29-bit extended CAN identifier.
    ///
    /// Returns [`Error::InvalidId`] if `raw` does not fit in 29 bits.
    ///
    /// ```
    /// use sae_j1939_rs::Id;
    /// assert!(Id::new(0x1CECFF00).is_ok());
    /// assert!(Id::new(0x2000_0000).is_err());
    /// ```
    pub const fn new(raw: u32) -> Result<Self> {
        if raw > MAX {
            Err(Error::InvalidId(raw))
        } else {
            Ok(Id { raw })
        }
    }

    /// Decode a raw identifier, masking it to 29 bits.
    ///
    /// For decoding paths where the value already came out of an extended CAN
    /// frame and cannot be out of range.
    pub const fn new_masked(raw: u32) -> Self {
        Id { raw: raw & MAX }
    }

    /// Assemble an identifier from its components.
    ///
    /// For a PDU1 (destination-specific) `pgn`, `destination` is written into
    /// the PDU specific byte; pass [`Address::GLOBAL`] to broadcast.
    ///
    /// For a PDU2 (broadcast) `pgn`, the PDU specific byte is the group
    /// extension and already part of the PGN, so `destination` must be
    /// [`Address::GLOBAL`] — anything else returns
    /// [`Error::DestinationMismatch`] rather than silently corrupting the PGN.
    ///
    /// ```
    /// use sae_j1939_rs::{pgn, Address, Error, Id, Priority};
    ///
    /// // PDU1 Request from 0x80 to 0x90.
    /// let req =
    ///     Id::from_parts(Priority::DEFAULT, pgn::REQUEST, Address::new(0x90), Address::new(0x80))
    ///         .unwrap();
    /// assert_eq!(req.as_u32(), 0x18EA9080);
    ///
    /// // PDU2 cannot be addressed to a specific ECU.
    /// let bad = Id::from_parts(Priority::DEFAULT, pgn::DM1, Address::new(0x90), Address::new(0x80));
    /// assert_eq!(bad, Err(Error::DestinationMismatch));
    /// ```
    pub const fn from_parts(
        priority: Priority,
        pgn: Pgn,
        destination: Address,
        source: Address,
    ) -> Result<Self> {
        if pgn.is_pdu2() && !destination.is_broadcast() {
            return Err(Error::DestinationMismatch);
        }
        // For PDU1 the PGN's low byte is guaranteed zero (see `Pgn::new`), so
        // OR-ing the destination in cannot disturb the PGN. For PDU2 the
        // destination is global and contributes nothing.
        let ps = if pgn.is_pdu1() {
            destination.as_u8() as u32
        } else {
            0
        };
        let raw = ((priority.as_u8() as u32) << PRIORITY_SHIFT)
            | (pgn.as_u32() << PGN_SHIFT)
            | (ps << PGN_SHIFT)
            | (source.as_u8() as u32);
        Ok(Id { raw })
    }

    /// Assemble a broadcast identifier: [`Id::from_parts`] with
    /// [`Address::GLOBAL`] as the destination.
    ///
    /// Valid for both PDU1 and PDU2 parameter groups.
    pub const fn broadcast(priority: Priority, pgn: Pgn, source: Address) -> Self {
        match Id::from_parts(priority, pgn, Address::GLOBAL, source) {
            Ok(id) => id,
            // Unreachable: a global destination is accepted by both PDU formats.
            Err(_) => Id { raw: 0 },
        }
    }

    /// The raw 29-bit identifier.
    pub const fn as_u32(self) -> u32 {
        self.raw
    }

    /// The 3-bit message priority (bits 28..26).
    pub const fn priority(self) -> Priority {
        Priority::new_saturating(((self.raw >> PRIORITY_SHIFT) & 0x7) as u8)
    }

    /// The parameter group this identifier names.
    ///
    /// For PDU1 the PDU specific byte is excluded (it is the destination
    /// address); for PDU2 it is included as the group extension.
    pub const fn pgn(self) -> Pgn {
        Pgn::new_masked((self.raw >> PGN_SHIFT) & pgn::MAX)
    }

    /// The source address: which ECU sent this frame (bits 7..0).
    pub const fn source_address(self) -> Address {
        Address::new(self.raw as u8)
    }

    /// The destination address, for a PDU1 (destination-specific) frame.
    ///
    /// Returns `None` for PDU2, where the same byte is a group extension and
    /// the message is inherently a broadcast.
    pub const fn destination_address(self) -> Option<Address> {
        if self.is_pdu1() {
            Some(Address::new(self.pdu_specific()))
        } else {
            None
        }
    }

    /// The raw PDU specific byte (bits 15..8), whatever its meaning.
    pub const fn pdu_specific(self) -> u8 {
        (self.raw >> PGN_SHIFT) as u8
    }

    /// The PDU format byte (bits 23..16).
    pub const fn pdu_format(self) -> u8 {
        (self.raw >> 16) as u8
    }

    /// The Data Page bit (bit 24).
    pub const fn data_page(self) -> bool {
        (self.raw >> 24) & 1 == 1
    }

    /// The Extended Data Page bit (bit 25).
    pub const fn extended_data_page(self) -> bool {
        (self.raw >> 25) & 1 == 1
    }

    /// Whether this frame uses PDU1 (destination-specific) addressing.
    pub const fn is_pdu1(self) -> bool {
        self.pdu_format() < pgn::PDU2_FORMAT_MIN
    }

    /// Whether this frame uses PDU2 (broadcast) addressing.
    pub const fn is_pdu2(self) -> bool {
        !self.is_pdu1()
    }

    /// Whether this frame is a broadcast: a PDU2 frame, or a PDU1 frame
    /// addressed to [`Address::GLOBAL`].
    pub const fn is_broadcast(self) -> bool {
        match self.destination_address() {
            Some(destination) => destination.is_broadcast(),
            None => true,
        }
    }

    /// Whether an ECU at `address` should process this frame — that is, whether
    /// it is broadcast or addressed specifically to `address`.
    ///
    /// This is the receive filter every J1939 ECU applies before dispatching.
    ///
    /// ```
    /// use sae_j1939_rs::{Address, Id};
    ///
    /// let to_0x90 = Id::new(0x18EA9080).unwrap();     // Request, 0x80 -> 0x90
    /// assert!(to_0x90.is_addressed_to(Address::new(0x90)));
    /// assert!(!to_0x90.is_addressed_to(Address::new(0x91)));
    ///
    /// let dm1 = Id::new(0x18FECA80).unwrap();         // DM1: PDU2, broadcast
    /// assert!(dm1.is_addressed_to(Address::new(0x91)));
    /// ```
    pub const fn is_addressed_to(self, address: Address) -> bool {
        match self.destination_address() {
            Some(destination) => {
                destination.is_broadcast() || destination.as_u8() == address.as_u8()
            }
            None => true,
        }
    }
}

impl From<Id> for u32 {
    fn from(id: Id) -> Self {
        id.raw
    }
}

impl TryFrom<u32> for Id {
    type Error = Error;

    fn try_from(raw: u32) -> Result<Self> {
        Id::new(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identifiers taken from the MIT-licensed Open-SAE-J1939 C reference, which
    /// builds each of these literally (e.g. `0x18EEFF << 8 | SA` for Address
    /// Claimed) and dispatches on the decoded bytes in
    /// `Open_SAE_J1939_Listen_For_Messages`. Decoding them is the ground truth
    /// for this module.
    #[test]
    fn decodes_reference_identifiers() {
        struct Vector {
            raw: u32,
            what: &'static str,
            priority: u8,
            pgn: Pgn,
            destination: Option<u8>,
            source: u8,
        }

        let vectors = [
            Vector {
                raw: 0x18EEFF80,
                what: "Address Claimed, broadcast from 0x80",
                priority: 6,
                pgn: pgn::ADDRESS_CLAIMED,
                destination: Some(0xFF),
                source: 0x80,
            },
            Vector {
                raw: 0x18EEFFFE,
                what: "Address Not Claimed (null source address)",
                priority: 6,
                pgn: pgn::ADDRESS_CLAIMED,
                destination: Some(0xFF),
                source: 0xFE,
            },
            Vector {
                raw: 0x18EA9080,
                what: "Request, 0x80 -> 0x90",
                priority: 6,
                pgn: pgn::REQUEST,
                destination: Some(0x90),
                source: 0x80,
            },
            Vector {
                raw: 0x18E89080,
                what: "Acknowledgement, 0x80 -> 0x90",
                priority: 6,
                pgn: pgn::ACKNOWLEDGEMENT,
                destination: Some(0x90),
                source: 0x80,
            },
            Vector {
                raw: 0x1CEC9080,
                what: "TP.CM, 0x80 -> 0x90",
                priority: 7,
                pgn: pgn::TP_CM,
                destination: Some(0x90),
                source: 0x80,
            },
            Vector {
                raw: 0x1CEBFF80,
                what: "TP.DT (BAM), broadcast from 0x80",
                priority: 7,
                pgn: pgn::TP_DT,
                destination: Some(0xFF),
                source: 0x80,
            },
            Vector {
                raw: 0x18FECA80,
                what: "DM1, PDU2 broadcast from 0x80",
                priority: 6,
                pgn: pgn::DM1,
                destination: None,
                source: 0x80,
            },
            Vector {
                raw: 0x18FECB80,
                what: "DM2, PDU2 broadcast from 0x80",
                priority: 6,
                pgn: pgn::DM2,
                destination: None,
                source: 0x80,
            },
            Vector {
                raw: 0x18D99080,
                what: "DM14 memory request, 0x80 -> 0x90",
                priority: 6,
                pgn: pgn::DM14,
                destination: Some(0x90),
                source: 0x80,
            },
            Vector {
                raw: 0x18FDC580,
                what: "ECU Identification, PDU2 broadcast from 0x80",
                priority: 6,
                pgn: pgn::ECU_IDENTIFICATION,
                destination: None,
                source: 0x80,
            },
            Vector {
                raw: 0x14EF2380,
                what: "Proprietary A, priority 5, 0x80 -> 0x23",
                priority: 5,
                pgn: pgn::PROPRIETARY_A,
                destination: Some(0x23),
                source: 0x80,
            },
        ];

        for v in vectors {
            let id = Id::new(v.raw).unwrap_or_else(|_| panic!("{} should decode", v.what));
            assert_eq!(id.priority().as_u8(), v.priority, "priority of {}", v.what);
            assert_eq!(id.pgn(), v.pgn, "pgn of {}", v.what);
            assert_eq!(
                id.destination_address().map(Address::as_u8),
                v.destination,
                "destination of {}",
                v.what
            );
            assert_eq!(
                id.source_address().as_u8(),
                v.source,
                "source of {}",
                v.what
            );
        }
    }

    /// Every reference identifier must survive a decode/encode round trip.
    #[test]
    fn round_trips_reference_identifiers() {
        for raw in [
            0x18EEFF80u32,
            0x18EEFFFE,
            0x18EA9080,
            0x18E89080,
            0x1CEC9080,
            0x1CEBFF80,
            0x18FECA80,
            0x18FDC580,
            0x14EF2380,
            0x0CFE3080, // ISO 11783 auxiliary valve command 0, priority 3
        ] {
            let id = Id::new(raw).unwrap();
            let destination = id.destination_address().unwrap_or(Address::GLOBAL);
            let rebuilt =
                Id::from_parts(id.priority(), id.pgn(), destination, id.source_address()).unwrap();
            assert_eq!(rebuilt.as_u32(), raw, "round trip of {raw:#010x}");
        }
    }

    #[test]
    fn rejects_identifiers_wider_than_29_bits() {
        assert!(Id::new(MAX).is_ok());
        assert_eq!(Id::new(MAX + 1), Err(Error::InvalidId(MAX + 1)));
        // Masking keeps only the low 29 bits.
        assert_eq!(Id::new_masked(0xFFFF_FFFF).as_u32(), MAX);
    }

    #[test]
    fn pdu2_rejects_a_specific_destination() {
        assert_eq!(
            Id::from_parts(
                Priority::DEFAULT,
                pgn::DM1,
                Address::new(0x90),
                Address::new(0x80)
            ),
            Err(Error::DestinationMismatch)
        );
        // Broadcast is the only legal PDU2 destination.
        assert_eq!(
            Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x80)).as_u32(),
            0x18FECA80
        );
    }

    #[test]
    fn broadcast_classification_covers_both_pdu_formats() {
        assert!(Id::new(0x18EEFF80).unwrap().is_broadcast()); // PDU1 to 0xFF
        assert!(!Id::new(0x18EA9080).unwrap().is_broadcast()); // PDU1 to 0x90
        assert!(Id::new(0x18FECA80).unwrap().is_broadcast()); // PDU2
    }

    #[test]
    fn receive_filter_matches_the_reference_dispatch_rule() {
        let this_ecu = Address::new(0x90);

        // Addressed to us, addressed elsewhere, and broadcast.
        assert!(Id::new(0x18EA9080).unwrap().is_addressed_to(this_ecu));
        assert!(!Id::new(0x18EA8180).unwrap().is_addressed_to(this_ecu));
        assert!(Id::new(0x18EAFF80).unwrap().is_addressed_to(this_ecu));

        // A PDU2 broadcast reaches every ECU.
        assert!(Id::new(0x18FECA80).unwrap().is_addressed_to(this_ecu));
    }

    #[test]
    fn decodes_the_data_page_bits() {
        // DP set: PF 0xF0 on data page 1.
        let id = Id::new(0x19F04080).unwrap();
        assert!(id.data_page());
        assert!(!id.extended_data_page());
        assert_eq!(id.pgn().as_u32(), 0x0001_F040);
    }
}
