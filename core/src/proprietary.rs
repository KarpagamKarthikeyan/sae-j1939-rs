// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proprietary A and B: manufacturer-specific parameter groups.
//!
//! J1939 reserves space for traffic the standard does not define, and on a real
//! vehicle a large share of the bus is exactly that. There are two kinds:
//!
//! - **Proprietary A** (`0x00EF00`) — PDU1, so it is *addressed* to one ECU.
//!   There is only one such PGN; the destination lives in the identifier.
//! - **Proprietary B** (`0x00FF00`–`0x00FFFF`) — PDU2, so it is *broadcast*.
//!   The group extension gives 256 distinct PGNs to allocate as you like.
//!
//! The contents are entirely up to the manufacturer, so this module does not
//! try to interpret them. What it does is get the addressing right — which of
//! the two to use, and which PGNs are legal — because that is the part people
//! get wrong.
//!
//! ```
//! use sae_j1939_rs::proprietary::{self, ProprietaryB};
//! use sae_j1939_rs::{Address, Priority};
//!
//! // Addressed: a message for ECU 0x90 only.
//! let to_one = proprietary::addressed_id(Priority::DEFAULT, Address::new(0x90), Address::new(0x80))
//!     .unwrap();
//! assert_eq!(to_one.destination_address(), Some(Address::new(0x90)));
//!
//! // Broadcast: proprietary group 0x42, seen by everyone.
//! let group = ProprietaryB::new(0x42);
//! let to_all = proprietary::broadcast_id(Priority::DEFAULT, group, Address::new(0x80));
//! assert_eq!(to_all.pgn().as_u32(), 0x00FF42);
//! ```
//!
//! Payloads longer than eight bytes are sent over the transport protocol like
//! any other parameter group — see [`crate::tp`].

use crate::id::Id;
use crate::pgn::{self, Pgn};
use crate::types::{Address, Priority, Result};

/// One of the 256 Proprietary B broadcast parameter groups.
///
/// Identified by its group extension: `ProprietaryB::new(0x42)` is PGN
/// `0x00FF42`. Because the type can only name PGNs inside the reserved range,
/// it is impossible to accidentally collide with a standard parameter group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProprietaryB {
    group_extension: u8,
    data_page: bool,
}

impl ProprietaryB {
    /// The proprietary group with this group extension, on data page 0.
    pub const fn new(group_extension: u8) -> Self {
        ProprietaryB {
            group_extension,
            data_page: false,
        }
    }

    /// The same group extension on data page 1 — the widely used mirror range.
    pub const fn on_data_page_1(group_extension: u8) -> Self {
        ProprietaryB {
            group_extension,
            data_page: true,
        }
    }

    /// Recognise a PGN as Proprietary B, on either data page.
    ///
    /// Returns `None` for any PGN outside the reserved ranges.
    ///
    /// **On an ISOBUS network, check the ISO 11783 allocations first.** The
    /// auxiliary valve measured position block (`0x00FF20`–`0x00FF2F`) sits
    /// inside the Proprietary B range, so this method will happily classify a
    /// valve position report as manufacturer-specific — see
    /// [`ValveNumber::from_measured_position_pgn`](crate::iso11783::ValveNumber::from_measured_position_pgn).
    ///
    /// ```
    /// use sae_j1939_rs::proprietary::ProprietaryB;
    /// use sae_j1939_rs::{pgn, Pgn};
    ///
    /// let group = ProprietaryB::from_pgn(Pgn::new(0x00FF42).unwrap()).unwrap();
    /// assert_eq!(group.group_extension(), 0x42);
    /// assert!(ProprietaryB::from_pgn(pgn::DM1).is_none());
    /// ```
    pub const fn from_pgn(pgn: Pgn) -> Option<Self> {
        let raw = pgn.as_u32();
        if raw >= crate::pgn::PROPRIETARY_B_START.as_u32()
            && raw <= crate::pgn::PROPRIETARY_B_END.as_u32()
        {
            Some(ProprietaryB::new(raw as u8))
        } else if raw >= crate::pgn::PROPRIETARY_B2_START.as_u32()
            && raw <= crate::pgn::PROPRIETARY_B2_END.as_u32()
        {
            Some(ProprietaryB::on_data_page_1(raw as u8))
        } else {
            None
        }
    }

    /// The group extension distinguishing this group from the other 255.
    pub const fn group_extension(self) -> u8 {
        self.group_extension
    }

    /// Whether this group sits on the data-page-1 mirror range.
    pub const fn is_data_page_1(self) -> bool {
        self.data_page
    }

    /// The parameter group number.
    pub const fn pgn(self) -> Pgn {
        let base = if self.data_page {
            crate::pgn::PROPRIETARY_B2_START.as_u32()
        } else {
            crate::pgn::PROPRIETARY_B_START.as_u32()
        };
        Pgn::new_masked(base | self.group_extension as u32)
    }
}

impl From<ProprietaryB> for Pgn {
    fn from(group: ProprietaryB) -> Pgn {
        group.pgn()
    }
}

/// The identifier for a Proprietary A message from `source` to `destination`.
///
/// Proprietary A is destination-specific. Pass [`Address::GLOBAL`] to broadcast
/// it, though [`ProprietaryB`] is the better choice for traffic meant for
/// everyone.
///
/// Returns an error only if the addressing is impossible, which cannot happen
/// for this PGN — it is `Result` for symmetry with [`Id::from_parts`].
pub fn addressed_id(priority: Priority, destination: Address, source: Address) -> Result<Id> {
    Id::from_parts(priority, pgn::PROPRIETARY_A, destination, source)
}

/// The identifier for a Proprietary B broadcast of `group` from `source`.
pub const fn broadcast_id(priority: Priority, group: ProprietaryB, source: Address) -> Id {
    Id::broadcast(priority, group.pgn(), source)
}

/// Whether a PGN is proprietary at all, of either kind.
///
/// Carries the same ISOBUS caveat as [`ProprietaryB::from_pgn`]: part of the
/// Proprietary B range is allocated to ISO 11783 valve messages.
pub const fn is_proprietary(pgn_value: Pgn) -> bool {
    pgn_value.as_u32() == pgn::PROPRIETARY_A.as_u32() || ProprietaryB::from_pgn(pgn_value).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proprietary_b_maps_to_its_pgn_and_back() {
        for extension in [0x00u8, 0x01, 0x42, 0xFE, 0xFF] {
            let group = ProprietaryB::new(extension);
            assert_eq!(group.pgn().as_u32(), 0x00FF00 | extension as u32);
            assert_eq!(ProprietaryB::from_pgn(group.pgn()), Some(group));
            assert_eq!(group.group_extension(), extension);
            assert!(!group.is_data_page_1());
        }
    }

    #[test]
    fn the_data_page_1_mirror_is_recognised_and_kept_distinct() {
        let page0 = ProprietaryB::new(0x42);
        let page1 = ProprietaryB::on_data_page_1(0x42);

        assert_eq!(page0.pgn().as_u32(), 0x00FF42);
        assert_eq!(page1.pgn().as_u32(), 0x01FF42);
        assert_ne!(page0, page1, "the two pages are different groups");
        assert!(page1.is_data_page_1());
        assert_eq!(ProprietaryB::from_pgn(page1.pgn()), Some(page1));
    }

    #[test]
    fn standard_parameter_groups_are_not_proprietary_b() {
        for standard in [pgn::DM1, pgn::DM2, pgn::REQUEST, pgn::ADDRESS_CLAIMED] {
            assert_eq!(ProprietaryB::from_pgn(standard), None);
        }
        // The boundaries: 0x00FEFF is the last standard PGN before the range.
        assert_eq!(ProprietaryB::from_pgn(Pgn::new(0x00FEFF).unwrap()), None);
        assert!(ProprietaryB::from_pgn(Pgn::new(0x00FF00).unwrap()).is_some());
        assert!(ProprietaryB::from_pgn(Pgn::new(0x00FFFF).unwrap()).is_some());
        assert_eq!(ProprietaryB::from_pgn(Pgn::new(0x010000).unwrap()), None);
    }

    #[test]
    fn proprietary_b_is_always_a_broadcast() {
        let id = broadcast_id(
            Priority::DEFAULT,
            ProprietaryB::new(0x42),
            Address::new(0x80),
        );
        assert_eq!(id.pgn().as_u32(), 0x00FF42);
        assert_eq!(id.source_address(), Address::new(0x80));
        assert!(id.is_pdu2(), "the Proprietary B range is PDU2");
        assert!(id.is_broadcast());
        // PDU2 carries no destination: the group extension occupies that byte.
        assert_eq!(id.destination_address(), None);
    }

    #[test]
    fn proprietary_a_is_addressed_to_one_ecu() {
        let id = addressed_id(Priority::DEFAULT, Address::new(0x90), Address::new(0x80)).unwrap();
        assert_eq!(id.as_u32(), 0x18EF9080);
        assert_eq!(id.pgn(), pgn::PROPRIETARY_A);
        assert_eq!(id.destination_address(), Some(Address::new(0x90)));
        assert!(id.is_addressed_to(Address::new(0x90)));
        assert!(!id.is_addressed_to(Address::new(0x91)));
    }

    #[test]
    fn proprietary_a_can_be_broadcast_when_asked() {
        let id = addressed_id(Priority::DEFAULT, Address::GLOBAL, Address::new(0x80)).unwrap();
        assert!(id.is_broadcast());
        assert_eq!(id.destination_address(), Some(Address::GLOBAL));
    }

    #[test]
    fn classifies_both_kinds_of_proprietary_traffic() {
        assert!(is_proprietary(pgn::PROPRIETARY_A));
        assert!(is_proprietary(ProprietaryB::new(0x42).pgn()));
        assert!(is_proprietary(ProprietaryB::on_data_page_1(0x42).pgn()));
        assert!(!is_proprietary(pgn::DM1));
        assert!(!is_proprietary(pgn::REQUEST));
    }

    /// A proprietary payload longer than a frame rides the transport protocol
    /// exactly like a standard parameter group.
    #[test]
    fn a_long_proprietary_b_message_goes_over_the_transport_protocol() {
        use crate::tp::{Reassembler, Rx, Transmitter};

        let group = ProprietaryB::new(0x42);
        let payload: [u8; 40] = core::array::from_fn(|i| (i * 5) as u8);
        let sender = Address::new(0x80);

        let mut tx = Transmitter::broadcast(group.pgn(), &payload).unwrap();
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(sender, &tx.start());

        let mut received = None;
        while let Some(packet) = tx.next_packet() {
            if let Rx::Message { pgn, data, .. } = rx.on_tp_dt(sender, &packet) {
                assert_eq!(ProprietaryB::from_pgn(pgn), Some(group));
                received = Some(data.to_vec());
            }
        }
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }
}
