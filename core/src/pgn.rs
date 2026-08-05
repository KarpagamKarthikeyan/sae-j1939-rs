// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parameter Group Numbers (PGNs).
//!
//! A PGN is the 18-bit label that identifies *what* a J1939 message carries.
//! It is not a flat number: it is assembled from four fields of the CAN
//! identifier, and the PDU format determines whether the last of them belongs
//! to the PGN at all.
//!
//! ```text
//! bit  17    16    15 .......... 8    7 ........... 0
//!     EDP    DP    PDU Format (PF)    PDU Specific (PS)
//! ```
//!
//! - **PF `0x00..=0xEF`** — *PDU1*, destination-specific. The PS byte is the
//!   destination address and is **not** part of the PGN, so the PGN's low byte
//!   is always zero (e.g. Request is `0x00EA00`, never `0x00EAnn`).
//! - **PF `0xF0..=0xFF`** — *PDU2*, broadcast. The PS byte is a *group
//!   extension* and **is** part of the PGN (e.g. `0x00FECA` is DM1).
//!
//! That asymmetry is the single most common source of J1939 decoding bugs, so
//! [`Pgn`] enforces it: constructing a PDU1 PGN masks the low byte off,
//! [`Pgn::group_extension`] only ever returns a value for PDU2, and
//! [`Id::destination_address`](crate::Id::destination_address) only ever
//! returns one for PDU1.
//!
//! ```
//! use sae_j1939_rs::{pgn, Pgn};
//!
//! // PDU1: destination-specific, low byte is not part of the PGN.
//! assert!(pgn::REQUEST.is_pdu1());
//! assert_eq!(pgn::REQUEST.as_u32(), 0x00EA00);
//!
//! // PDU2: broadcast, the group extension is part of the PGN.
//! assert!(pgn::DM1.is_pdu2());
//! assert_eq!(pgn::DM1.group_extension(), Some(0xCA));
//! ```

use crate::types::{Error, Result};

/// The largest valid PGN value (18 bits).
pub const MAX: u32 = 0x0003_FFFF;

/// The lowest PDU format value that selects PDU2 (broadcast) addressing.
pub const PDU2_FORMAT_MIN: u8 = 0xF0;

/// A Parameter Group Number: the 18-bit identifier of a J1939 parameter group.
///
/// A `Pgn` is always *normalised*: for a PDU1 (destination-specific) parameter
/// group the PDU-specific byte is cleared, because it carries the destination
/// address rather than part of the group's identity. Build one from a raw value
/// with [`Pgn::new`], or use the constants in [`crate::pgn`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pgn(u32);

/// Prints both forms, because J1939 documentation uses both: `0x00FECA (65226)`.
impl core::fmt::Display for Pgn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#08X} ({})", self.0, self.0)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Pgn {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{=u32:#08x}", self.0)
    }
}

impl core::fmt::Debug for Pgn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pgn({:#08X})", self.0)
    }
}

impl Pgn {
    /// Build a PGN from a raw 18-bit value.
    ///
    /// If the value names a PDU1 parameter group, the PDU-specific byte is
    /// cleared, so `Pgn::new(0x00EA80)` and `Pgn::new(0x00EA00)` are equal —
    /// both are the Request PGN, addressed to different ECUs.
    ///
    /// Returns [`Error::InvalidPgn`] if `raw` exceeds 18 bits.
    ///
    /// ```
    /// use sae_j1939_rs::{pgn, Pgn};
    ///
    /// // PDU1: the destination byte is normalised away.
    /// assert_eq!(Pgn::new(0x00EA80).unwrap(), pgn::REQUEST);
    /// // PDU2: the group extension is significant.
    /// assert_ne!(Pgn::new(0x00FECB).unwrap(), pgn::DM1);
    /// assert!(Pgn::new(0x0004_0000).is_err());
    /// ```
    pub const fn new(raw: u32) -> Result<Self> {
        if raw > MAX {
            Err(Error::InvalidPgn(raw))
        } else {
            Ok(Pgn(normalise(raw)))
        }
    }

    /// Build a PGN from a raw value, masking it to 18 bits.
    ///
    /// Intended for `const` definitions and for decoding paths where the value
    /// has already been masked out of a valid identifier.
    pub const fn new_masked(raw: u32) -> Self {
        Pgn(normalise(raw & MAX))
    }

    /// The raw 18-bit PGN value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// The Extended Data Page (EDP) bit, bit 17.
    pub const fn extended_data_page(self) -> bool {
        (self.0 >> 17) & 1 == 1
    }

    /// The Data Page (DP) bit, bit 16.
    pub const fn data_page(self) -> bool {
        (self.0 >> 16) & 1 == 1
    }

    /// The PDU Format (PF) byte, bits 15..8.
    pub const fn pdu_format(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// Whether this is a PDU1 (destination-specific) parameter group.
    pub const fn is_pdu1(self) -> bool {
        self.pdu_format() < PDU2_FORMAT_MIN
    }

    /// Whether this is a PDU2 (broadcast) parameter group.
    pub const fn is_pdu2(self) -> bool {
        !self.is_pdu1()
    }

    /// The group extension byte for a PDU2 parameter group.
    ///
    /// Returns `None` for PDU1, where the corresponding byte is the destination
    /// address rather than part of the PGN.
    pub const fn group_extension(self) -> Option<u8> {
        if self.is_pdu2() {
            Some(self.0 as u8)
        } else {
            None
        }
    }

    /// Whether this PGN falls in the Proprietary B range (`0x00FF00..=0x00FFFF`,
    /// or the widely used data-page-1 mirror `0x01FF00..=0x01FFFF`).
    pub const fn is_proprietary_b(self) -> bool {
        let raw = self.0;
        (raw >= PROPRIETARY_B_START.0 && raw <= PROPRIETARY_B_END.0)
            || (raw >= PROPRIETARY_B2_START.0 && raw <= PROPRIETARY_B2_END.0)
    }
}

/// Clear the PDU-specific byte of a PDU1 PGN, leaving PDU2 PGNs untouched.
const fn normalise(raw: u32) -> u32 {
    if ((raw >> 8) as u8) < PDU2_FORMAT_MIN {
        raw & 0x0003_FF00
    } else {
        raw
    }
}

impl From<Pgn> for u32 {
    fn from(pgn: Pgn) -> Self {
        pgn.0
    }
}

impl TryFrom<u32> for Pgn {
    type Error = Error;

    fn try_from(raw: u32) -> Result<Self> {
        Pgn::new(raw)
    }
}

// ---------------------------------------------------------------------------
// Well-known parameter groups
// ---------------------------------------------------------------------------

/// Request (J1939-21). PDU1 — ask another ECU (or all of them) for a PGN.
pub const REQUEST: Pgn = Pgn::new_masked(0x00EA00);

/// Acknowledgement (J1939-21). PDU1 — ACK/NACK for a request.
pub const ACKNOWLEDGEMENT: Pgn = Pgn::new_masked(0x00E800);

/// Transport Protocol — Connection Management (J1939-21): RTS/CTS/EOM/BAM/Abort.
pub const TP_CM: Pgn = Pgn::new_masked(0x00EC00);

/// Transport Protocol — Data Transfer (J1939-21): the numbered data packets.
pub const TP_DT: Pgn = Pgn::new_masked(0x00EB00);

/// Extended Transport Protocol — Connection Management (J1939-21): messages
/// beyond the 1785 bytes [`TP_CM`] can announce.
pub const ETP_CM: Pgn = Pgn::new_masked(0x00C800);

/// Extended Transport Protocol — Data Transfer (J1939-21).
pub const ETP_DT: Pgn = Pgn::new_masked(0x00C700);

/// Address Claimed (J1939-81) — an ECU announcing its NAME and address.
pub const ADDRESS_CLAIMED: Pgn = Pgn::new_masked(0x00EE00);

/// Commanded Address (J1939-81) — instruct an ECU to take a given address.
pub const COMMANDED_ADDRESS: Pgn = Pgn::new_masked(0x00FED8);

/// Proprietary A (J1939-21) — manufacturer-specific, destination-specific.
pub const PROPRIETARY_A: Pgn = Pgn::new_masked(0x00EF00);

/// First PGN of the Proprietary B broadcast range.
pub const PROPRIETARY_B_START: Pgn = Pgn::new_masked(0x00FF00);

/// Last PGN of the Proprietary B broadcast range.
pub const PROPRIETARY_B_END: Pgn = Pgn::new_masked(0x00FFFF);

/// First PGN of the data-page-1 mirror of the Proprietary B range.
///
/// Not defined by the standard, but common enough in the field that decoders
/// have to recognise it.
pub const PROPRIETARY_B2_START: Pgn = Pgn::new_masked(0x01FF00);

/// Last PGN of the data-page-1 mirror of the Proprietary B range.
pub const PROPRIETARY_B2_END: Pgn = Pgn::new_masked(0x01FFFF);

/// DM1 (J1939-73) — active diagnostic trouble codes.
pub const DM1: Pgn = Pgn::new_masked(0x00FECA);

/// DM2 (J1939-73) — previously active diagnostic trouble codes.
pub const DM2: Pgn = Pgn::new_masked(0x00FECB);

/// DM3 (J1939-73) — clear previously active DTCs.
pub const DM3: Pgn = Pgn::new_masked(0x00FECC);

/// DM4 (J1939-73) — freeze frame parameters: the conditions when a fault set.
///
/// The PGN only. The freeze frame payload is a variable-length structure whose
/// contents depend on the ECU, and this crate does not model it — see the
/// [`diagnostics`](crate::diagnostics) module documentation.
pub const DM4: Pgn = Pgn::new_masked(0x00FECD);

/// DM5 (J1939-73) — diagnostic readiness: fault counts and monitor status.
pub const DM5: Pgn = Pgn::new_masked(0x00FECE);

/// DM6 (J1939-73) — pending diagnostic trouble codes.
pub const DM6: Pgn = Pgn::new_masked(0x00FECF);

/// DM11 (J1939-73) — clear active diagnostic trouble codes.
pub const DM11: Pgn = Pgn::new_masked(0x00FED3);

/// DM12 (J1939-73) — emissions-related active diagnostic trouble codes.
pub const DM12: Pgn = Pgn::new_masked(0x00FED4);

/// DM13 (J1939-73) — stop/start broadcast, used to quieten the bus.
pub const DM13: Pgn = Pgn::new_masked(0x00DF00);

/// DM23 (J1939-73) — previously active emissions-related trouble codes.
pub const DM23: Pgn = Pgn::new_masked(0x00FDB5);

/// DM27 (J1939-73) — all pending diagnostic trouble codes.
pub const DM27: Pgn = Pgn::new_masked(0x00FD82);

/// DM14 (J1939-73) — memory access request.
pub const DM14: Pgn = Pgn::new_masked(0x00D900);

/// DM15 (J1939-73) — memory access response.
pub const DM15: Pgn = Pgn::new_masked(0x00D800);

/// DM16 (J1939-73) — binary data transfer.
pub const DM16: Pgn = Pgn::new_masked(0x00D700);

/// Software Identification (J1939-71).
pub const SOFTWARE_IDENTIFICATION: Pgn = Pgn::new_masked(0x00FEDA);

/// ECU Identification (J1939-71).
pub const ECU_IDENTIFICATION: Pgn = Pgn::new_masked(0x00FDC5);

/// Component Identification (J1939-71).
pub const COMPONENT_IDENTIFICATION: Pgn = Pgn::new_masked(0x00FEEB);

// ---------------------------------------------------------------------------
// Application-layer parameter groups (J1939-71).
//
// These are the ones this crate already decodes — every constant here is the
// group behind an entry in `spn::catalogue`, so each is exercised by a test
// that reads a real payload rather than merely asserting its own number back.
// The full J1939-71 list runs to hundreds; it is sold rather than published,
// and `host`'s DBC parser is the way to bring in the rest.
// ---------------------------------------------------------------------------

/// Electronic Engine Controller 1 (EEC1) — engine speed and torque.
///
/// Broadcast fast: engine speed is a control input, and 20 ms is the usual rate.
pub const EEC1: Pgn = Pgn::new_masked(0x00F004);

/// Electronic Engine Controller 2 (EEC2) — pedal position and engine load.
pub const EEC2: Pgn = Pgn::new_masked(0x00F003);

/// Engine Temperature 1 (ET1) — coolant, fuel, and oil temperatures.
pub const ENGINE_TEMPERATURE_1: Pgn = Pgn::new_masked(0x00FEEE);

/// Engine Fluid Level/Pressure 1 (EFL/P1) — oil pressure and level.
pub const ENGINE_FLUID_LEVEL_PRESSURE_1: Pgn = Pgn::new_masked(0x00FEEF);

/// Fuel Economy, liquid (LFE) — fuel rate and economy.
pub const FUEL_ECONOMY: Pgn = Pgn::new_masked(0x00FEF2);

/// Cruise Control/Vehicle Speed 1 (CCVS1) — wheel-based vehicle speed.
pub const CRUISE_CONTROL_VEHICLE_SPEED: Pgn = Pgn::new_masked(0x00FEF1);

/// Vehicle Electrical Power 1 (VEP1) — battery potential.
pub const VEHICLE_ELECTRICAL_POWER: Pgn = Pgn::new_masked(0x00FEF7);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_application_groups_are_broadcast_and_distinct() {
        let groups = [
            ("EEC1", EEC1, 0x00F004),
            ("EEC2", EEC2, 0x00F003),
            ("ET1", ENGINE_TEMPERATURE_1, 0x00FEEE),
            ("EFL/P1", ENGINE_FLUID_LEVEL_PRESSURE_1, 0x00FEEF),
            ("LFE", FUEL_ECONOMY, 0x00FEF2),
            ("CCVS1", CRUISE_CONTROL_VEHICLE_SPEED, 0x00FEF1),
            ("VEP1", VEHICLE_ELECTRICAL_POWER, 0x00FEF7),
        ];

        for (name, pgn, raw) in groups {
            assert_eq!(pgn.as_u32(), raw, "{name}");
            // Every one is PDU2, which is what makes them broadcast parameter
            // groups rather than something addressed to a single ECU. A typo
            // landing in the PDU1 range would silently normalise its low byte
            // away and quietly become a different group.
            assert!(pgn.is_pdu2(), "{name} must be a broadcast group");
            assert!(pgn.group_extension().is_some(), "{name}");
        }

        for (i, (name, pgn, _)) in groups.iter().enumerate() {
            for (other_name, other, _) in &groups[..i] {
                assert_ne!(pgn, other, "{name} collides with {other_name}");
            }
        }
    }

    #[test]
    fn pdu1_normalises_away_the_destination_byte() {
        // 0xEA is PDU1: the low byte is a destination address, not PGN identity.
        let addressed = Pgn::new(0x00EA80).unwrap();
        assert_eq!(addressed, REQUEST);
        assert_eq!(addressed.as_u32(), 0x00EA00);
        assert!(addressed.is_pdu1());
        assert_eq!(addressed.group_extension(), None);
    }

    #[test]
    fn pdu2_keeps_the_group_extension() {
        // 0xFE is PDU2: the low byte distinguishes DM1 from DM2.
        assert!(DM1.is_pdu2());
        assert_eq!(DM1.as_u32(), 0x00FECA);
        assert_eq!(DM1.group_extension(), Some(0xCA));
        assert_ne!(DM1, DM2);
    }

    #[test]
    fn pdu_boundary_is_at_0xf0() {
        // 0xEF is the last PDU1 format, 0xF0 the first PDU2 one.
        assert!(Pgn::new(0x00EF00).unwrap().is_pdu1());
        assert!(Pgn::new(0x00F000).unwrap().is_pdu2());
    }

    #[test]
    fn decodes_data_page_bits() {
        let dp = Pgn::new(0x0001_F000).unwrap();
        assert!(dp.data_page());
        assert!(!dp.extended_data_page());

        let edp = Pgn::new(0x0002_F000).unwrap();
        assert!(!edp.data_page());
        assert!(edp.extended_data_page());
    }

    #[test]
    fn rejects_values_beyond_18_bits() {
        assert_eq!(Pgn::new(MAX + 1), Err(Error::InvalidPgn(MAX + 1)));
        assert!(Pgn::new(MAX).is_ok());
    }

    #[test]
    fn recognises_the_proprietary_b_ranges() {
        assert!(PROPRIETARY_B_START.is_proprietary_b());
        assert!(PROPRIETARY_B_END.is_proprietary_b());
        assert!(Pgn::new(0x01FF42).unwrap().is_proprietary_b());
        assert!(!DM1.is_proprietary_b());
    }
}
