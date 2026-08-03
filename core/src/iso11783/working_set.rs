// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Working sets (ISO 11783-7): declaring that several ECUs are one implement.
//!
//! A seed drill is not one control unit. It might be a main controller, a
//! metering controller, and a section controller — three ECUs, three addresses,
//! three NAMEs. To a task controller they must appear as **one implement**, or
//! it would offer the operator three unrelated devices.
//!
//! A **working set** is that grouping. One ECU is the *master* and announces how
//! many members the set has; the rest are members, and the master's Address
//! Claimed identifies the whole set.
//!
//! ```
//! use sae_j1939_rs::iso11783::working_set::WorkingSetMaster;
//!
//! // A three-ECU implement: the master plus two more.
//! let announce = WorkingSetMaster::new(3).unwrap();
//! assert_eq!(announce.members, 3);
//! assert_eq!(WorkingSetMaster::decode(&announce.encode()).unwrap(), announce);
//! ```
//!
//! The member ECUs then announce themselves with Working Set Member messages,
//! which carry a NAME each. This module models the master message; a member's
//! NAME is an ordinary [`Name`](crate::Name), so it needs no separate type.
//!
//! # Verification status
//!
//! Built from the structure ISO 11783-7 describes, not cross-checked against the
//! Open-SAE-J1939 C reference, which does not cover working sets.

use crate::pgn::Pgn;
use crate::types::{Error, Result};

/// Working Set Master (ISO 11783-7).
pub const WORKING_SET_MASTER: Pgn = Pgn::new_masked(0x00FE0D);

/// Working Set Member (ISO 11783-7).
pub const WORKING_SET_MEMBER: Pgn = Pgn::new_masked(0x00FE0C);

/// The most ECUs one working set can contain.
pub const MAX_MEMBERS: u8 = 255;

/// Filler for the reserved tail.
const FILL: u8 = 0xFF;

/// The message declaring how many ECUs form this implement.
///
/// ```text
/// byte 0    number of working set members, including the master
/// bytes 1-7 reserved
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkingSetMaster {
    /// How many ECUs are in the set, the master included.
    pub members: u8,
}

impl WorkingSetMaster {
    /// Declare a working set of `members` ECUs.
    ///
    /// Returns [`Error::ValueOutOfRange`] for zero: a set always contains at
    /// least its own master, so zero is not "no members" but a malformed
    /// message, and a task controller reading it would have nothing to attach
    /// the implement's functions to.
    pub const fn new(members: u8) -> Result<Self> {
        if members == 0 {
            return Err(Error::ValueOutOfRange {
                field: "working set members",
                value: 0,
            });
        }
        Ok(WorkingSetMaster { members })
    }

    /// A working set of one: an implement that is a single ECU.
    pub const fn single() -> Self {
        WorkingSetMaster { members: 1 }
    }

    /// How many members follow the master.
    pub const fn followers(&self) -> u8 {
        self.members.saturating_sub(1)
    }

    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [self.members, FILL, FILL, FILL, FILL, FILL, FILL, FILL]
    }

    /// Decode an eight-byte payload.
    ///
    /// Returns [`Error::ValueOutOfRange`] if the count is zero — see
    /// [`WorkingSetMaster::new`].
    pub const fn decode(data: &[u8; 8]) -> Result<Self> {
        Self::new(data[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_working_set_always_contains_its_master() {
        // Zero is not "no members" — the master is itself a member, so zero is
        // a malformed message.
        assert_eq!(
            WorkingSetMaster::new(0),
            Err(Error::ValueOutOfRange {
                field: "working set members",
                value: 0
            })
        );
        assert_eq!(
            WorkingSetMaster::decode(&[0; 8]),
            Err(Error::ValueOutOfRange {
                field: "working set members",
                value: 0
            })
        );
        assert_eq!(WorkingSetMaster::single().members, 1);
        assert_eq!(WorkingSetMaster::single().followers(), 0);
    }

    #[test]
    fn every_member_count_round_trips() {
        for members in 1..=MAX_MEMBERS {
            let message = WorkingSetMaster::new(members).unwrap();
            let bytes = message.encode();
            assert_eq!(bytes[0], members);
            assert_eq!(&bytes[1..], &[FILL; 7], "the tail is reserved");
            assert_eq!(WorkingSetMaster::decode(&bytes).unwrap(), message);
            assert_eq!(message.followers(), members - 1);
        }
    }

    #[test]
    fn the_master_and_member_groups_are_distinct() {
        assert_ne!(WORKING_SET_MASTER, WORKING_SET_MEMBER);
        assert_eq!(WORKING_SET_MASTER.as_u32(), 0x00FE0D);
        assert_eq!(WORKING_SET_MEMBER.as_u32(), 0x00FE0C);
        // Both are PDU2, so both are broadcast.
        assert!(WORKING_SET_MASTER.is_pdu2());
        assert!(WORKING_SET_MEMBER.is_pdu2());
    }
}
