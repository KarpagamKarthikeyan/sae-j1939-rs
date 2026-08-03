// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hydraulic valves (ISO 11783-7).
//!
//! The messages a tractor and a mounted implement exchange to move hydraulic
//! cylinders.
//!
//! A tractor has up to **16 auxiliary valves**, and each gets its own PGN in
//! three blocks:
//!
//! | Message | PGN range | Direction |
//! |---------|-----------|-----------|
//! | Auxiliary valve command | `0x00FE30`–`0x00FE3F` | implement → tractor |
//! | Auxiliary valve estimated flow | `0x00FE10`–`0x00FE1F` | tractor → implement |
//! | Auxiliary valve measured position | `0x00FF20`–`0x00FF2F` | tractor → implement |
//!
//! Plus a single **general purpose valve** with a command (`0x00C400`) and an
//! estimated flow (`0x00C600`) that carry extended, higher-resolution flow
//! figures.
//!
//! [`ValveNumber`] does the fiddly part — mapping a valve to its three PGNs and
//! back — so a decoder can recognise "auxiliary valve 5 estimated flow" without
//! open-coding arithmetic on PGN values.
//!
//! ```
//! use sae_j1939_rs::iso11783::{AuxiliaryValveCommand, FailSafeMode, ValveNumber, ValveState};
//!
//! let valve = ValveNumber::new(3).unwrap();
//! assert_eq!(valve.command_pgn().as_u32(), 0x00FE33);
//!
//! // Extend valve 3 at 40% of standard flow.
//! let command = AuxiliaryValveCommand {
//!     standard_flow: 40,
//!     valve_state: ValveState::Extend,
//!     fail_safe_mode: FailSafeMode::Blocked,
//! };
//! assert_eq!(AuxiliaryValveCommand::decode(&command.encode()), command);
//! ```
//!
//! # Safety
//!
//! These messages move hydraulics on real machinery. A malformed or mistimed
//! valve command can drive an implement into the ground, a person, or itself.
//! Nothing here validates that a command is *sensible* for your machine — that
//! judgement belongs to the implement controller, and it should fail safe.

use crate::id::Id;
use crate::pgn::Pgn;
use crate::types::{Address, Error, Priority, Result};

/// The highest auxiliary valve number: ISO 11783 defines 16, numbered 0–15.
pub const MAX_VALVE_NUMBER: u8 = 15;

/// First PGN of the auxiliary valve command block.
pub const AUX_VALVE_COMMAND_BASE: u32 = 0x00FE30;

/// First PGN of the auxiliary valve estimated flow block.
pub const AUX_VALVE_ESTIMATED_FLOW_BASE: u32 = 0x00FE10;

/// First PGN of the auxiliary valve measured position block.
///
/// Note this block sits *inside* the Proprietary B range
/// (`0x00FF00`–`0x00FFFF`). On an ISOBUS network these sixteen PGNs are
/// allocated to measured position, so a decoder must check for them before
/// treating a PGN in that range as manufacturer-specific.
pub const AUX_VALVE_MEASURED_POSITION_BASE: u32 = 0x00FF20;

/// The general purpose valve command PGN.
pub const GENERAL_PURPOSE_VALVE_COMMAND: Pgn = Pgn::new_masked(0x00C400);

/// The general purpose valve estimated flow PGN.
pub const GENERAL_PURPOSE_VALVE_ESTIMATED_FLOW: Pgn = Pgn::new_masked(0x00C600);

/// Valve messages are control traffic and use priority 3.
pub const VALVE_PRIORITY: Priority = Priority::CONTROL;

/// The value ISO 11783 uses for an unused `limit` field.
pub const LIMIT_NOT_USED: u8 = 0x7;

/// Filler for reserved bytes.
const FILL: u8 = 0xFF;

/// What a hydraulic valve is doing, or being told to do.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValveState {
    /// Holding position.
    #[default]
    Neutral,
    /// Extending the cylinder.
    Extend,
    /// Retracting the cylinder.
    Retract,
    /// Floating — the cylinder follows external forces.
    Floating,
    /// Initialising.
    Initialisation,
    /// In error.
    Error,
    /// A state outside the defined set (4 bits).
    Other(u8),
}

impl ValveState {
    /// The 4-bit wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            ValveState::Neutral => 0x0,
            ValveState::Extend => 0x1,
            ValveState::Retract => 0x2,
            ValveState::Floating => 0x3,
            ValveState::Initialisation => 0xA,
            ValveState::Error => 0xE,
            ValveState::Other(raw) => raw & 0x0F,
        }
    }

    /// Decode the 4-bit wire value.
    pub const fn from_u8(raw: u8) -> Self {
        match raw & 0x0F {
            0x0 => ValveState::Neutral,
            0x1 => ValveState::Extend,
            0x2 => ValveState::Retract,
            0x3 => ValveState::Floating,
            0xA => ValveState::Initialisation,
            0xE => ValveState::Error,
            other => ValveState::Other(other),
        }
    }

    /// Whether this state moves the cylinder.
    pub const fn is_moving(self) -> bool {
        matches!(self, ValveState::Extend | ValveState::Retract)
    }
}

/// What the valve should do if communication is lost.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailSafeMode {
    /// Block the valve, holding its current position.
    #[default]
    Blocked,
    /// Activate fail-safe handling: return to neutral.
    Activated,
    /// A mode outside the defined set (2 bits).
    Other(u8),
}

impl FailSafeMode {
    /// The 2-bit wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            FailSafeMode::Blocked => 0,
            FailSafeMode::Activated => 1,
            FailSafeMode::Other(raw) => raw & 0b11,
        }
    }

    /// Decode the 2-bit wire value.
    pub const fn from_u8(raw: u8) -> Self {
        match raw & 0b11 {
            0 => FailSafeMode::Blocked,
            1 => FailSafeMode::Activated,
            other => FailSafeMode::Other(other),
        }
    }
}

/// One of the sixteen auxiliary valves, and the PGNs that address it.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValveNumber(u8);

impl ValveNumber {
    /// The valve with this number.
    ///
    /// Returns [`Error::ValueOutOfRange`] above [`MAX_VALVE_NUMBER`].
    pub const fn new(number: u8) -> Result<Self> {
        if number > MAX_VALVE_NUMBER {
            return Err(Error::ValueOutOfRange {
                field: "valve number",
                value: number as u32,
            });
        }
        Ok(ValveNumber(number))
    }

    /// The valve number, 0–15.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The PGN carrying commands *to* this valve.
    pub const fn command_pgn(self) -> Pgn {
        Pgn::new_masked(AUX_VALVE_COMMAND_BASE + self.0 as u32)
    }

    /// The PGN carrying this valve's estimated flow.
    pub const fn estimated_flow_pgn(self) -> Pgn {
        Pgn::new_masked(AUX_VALVE_ESTIMATED_FLOW_BASE + self.0 as u32)
    }

    /// The PGN carrying this valve's measured position.
    pub const fn measured_position_pgn(self) -> Pgn {
        Pgn::new_masked(AUX_VALVE_MEASURED_POSITION_BASE + self.0 as u32)
    }

    /// Which valve a command PGN addresses, if it is one.
    pub const fn from_command_pgn(pgn: Pgn) -> Option<Self> {
        Self::from_block(pgn, AUX_VALVE_COMMAND_BASE)
    }

    /// Which valve an estimated flow PGN reports on, if it is one.
    pub const fn from_estimated_flow_pgn(pgn: Pgn) -> Option<Self> {
        Self::from_block(pgn, AUX_VALVE_ESTIMATED_FLOW_BASE)
    }

    /// Which valve a measured position PGN reports on, if it is one.
    pub const fn from_measured_position_pgn(pgn: Pgn) -> Option<Self> {
        Self::from_block(pgn, AUX_VALVE_MEASURED_POSITION_BASE)
    }

    const fn from_block(pgn: Pgn, base: u32) -> Option<Self> {
        let raw = pgn.as_u32();
        if raw >= base && raw <= base + MAX_VALVE_NUMBER as u32 {
            Some(ValveNumber((raw - base) as u8))
        } else {
            None
        }
    }

    /// The identifier for a broadcast about this valve on `pgn`, from `source`.
    ///
    /// All three auxiliary valve blocks are PDU2, so they are broadcast.
    pub const fn broadcast_id(pgn: Pgn, source: Address) -> Id {
        Id::broadcast(VALVE_PRIORITY, pgn, source)
    }
}

/// Pack the byte shared by the command and estimated-flow messages: a 2-bit
/// fail-safe mode, two reserved bits, and a 4-bit valve state.
const fn pack_mode_and_state(fail_safe_mode: FailSafeMode, valve_state: ValveState) -> u8 {
    (fail_safe_mode.as_u8() << 6) | (0b11 << 4) | valve_state.as_u8()
}

/// A command to one auxiliary valve (`0x00FE30`–`0x00FE3F`).
///
/// ```text
/// byte 0    standard flow, percent
/// byte 1    reserved
/// byte 2    fail-safe mode (2 bits) | reserved (2) | valve state (4)
/// bytes 3-7 reserved
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuxiliaryValveCommand {
    /// Commanded flow as a percentage of the valve's standard flow.
    pub standard_flow: u8,
    /// What the valve should do.
    pub valve_state: ValveState,
    /// What to do if communication is lost.
    pub fail_safe_mode: FailSafeMode,
}

impl AuxiliaryValveCommand {
    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.standard_flow,
            FILL,
            pack_mode_and_state(self.fail_safe_mode, self.valve_state),
            FILL,
            FILL,
            FILL,
            FILL,
            FILL,
        ]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        AuxiliaryValveCommand {
            standard_flow: data[0],
            valve_state: ValveState::from_u8(data[2]),
            fail_safe_mode: FailSafeMode::from_u8(data[2] >> 6),
        }
    }
}

/// An auxiliary valve's estimated flow (`0x00FE10`–`0x00FE1F`).
///
/// ```text
/// byte 0    extend estimated flow, percent
/// byte 1    retract estimated flow, percent
/// byte 2    fail-safe mode (2 bits) | reserved (2) | valve state (4)
/// byte 3    limit (top 3 bits)
/// bytes 4-7 reserved
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxiliaryValveEstimatedFlow {
    /// Estimated flow while extending, percent.
    pub extend_flow: u8,
    /// Estimated flow while retracting, percent.
    pub retract_flow: u8,
    /// What the valve is doing.
    pub valve_state: ValveState,
    /// The configured fail-safe behaviour.
    pub fail_safe_mode: FailSafeMode,
    /// Which limit, if any, the valve is up against (3 bits).
    /// [`LIMIT_NOT_USED`] when not reported.
    pub limit: u8,
}

impl Default for AuxiliaryValveEstimatedFlow {
    fn default() -> Self {
        AuxiliaryValveEstimatedFlow {
            extend_flow: 0,
            retract_flow: 0,
            valve_state: ValveState::Neutral,
            fail_safe_mode: FailSafeMode::Blocked,
            limit: LIMIT_NOT_USED,
        }
    }
}

impl AuxiliaryValveEstimatedFlow {
    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.extend_flow,
            self.retract_flow,
            pack_mode_and_state(self.fail_safe_mode, self.valve_state),
            (self.limit & 0b111) << 5,
            FILL,
            FILL,
            FILL,
            FILL,
        ]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        AuxiliaryValveEstimatedFlow {
            extend_flow: data[0],
            retract_flow: data[1],
            valve_state: ValveState::from_u8(data[2]),
            fail_safe_mode: FailSafeMode::from_u8(data[2] >> 6),
            limit: data[3] >> 5,
        }
    }
}

/// An auxiliary valve's measured position (`0x00FF20`–`0x00FF2F`).
///
/// ```text
/// bytes 0-1 measured position, percent, little-endian
/// byte 2    reserved (top 4 bits) | valve state (4)
/// bytes 3-4 measured position, micrometres, little-endian
/// bytes 5-7 reserved
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuxiliaryValveMeasuredPosition {
    /// Position as a percentage of travel.
    pub position_percent: u16,
    /// Position in micrometres.
    pub position_micrometres: u16,
    /// What the valve is doing.
    pub valve_state: ValveState,
}

impl AuxiliaryValveMeasuredPosition {
    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.position_percent as u8,
            (self.position_percent >> 8) as u8,
            0xF0 | self.valve_state.as_u8(),
            self.position_micrometres as u8,
            (self.position_micrometres >> 8) as u8,
            FILL,
            FILL,
            FILL,
        ]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        AuxiliaryValveMeasuredPosition {
            position_percent: u16::from_le_bytes([data[0], data[1]]),
            position_micrometres: u16::from_le_bytes([data[3], data[4]]),
            valve_state: ValveState::from_u8(data[2]),
        }
    }
}

/// A command to the general purpose valve (`0x00C400`).
///
/// Like [`AuxiliaryValveCommand`], but with an extra 16-bit extended flow field
/// for finer control.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GeneralPurposeValveCommand {
    /// Commanded flow as a percentage of standard flow.
    pub standard_flow: u8,
    /// Commanded flow at extended resolution.
    pub extended_flow: u16,
    /// What the valve should do.
    pub valve_state: ValveState,
    /// What to do if communication is lost.
    pub fail_safe_mode: FailSafeMode,
}

impl GeneralPurposeValveCommand {
    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.standard_flow,
            FILL,
            pack_mode_and_state(self.fail_safe_mode, self.valve_state),
            self.extended_flow as u8,
            (self.extended_flow >> 8) as u8,
            FILL,
            FILL,
            FILL,
        ]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        GeneralPurposeValveCommand {
            standard_flow: data[0],
            extended_flow: u16::from_le_bytes([data[3], data[4]]),
            valve_state: ValveState::from_u8(data[2]),
            fail_safe_mode: FailSafeMode::from_u8(data[2] >> 6),
        }
    }
}

/// The general purpose valve's estimated flow (`0x00C600`).
///
/// Carries both the percentage figures of an auxiliary valve and 16-bit
/// extended values, filling all eight bytes.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralPurposeValveEstimatedFlow {
    /// Estimated flow while extending, percent.
    pub extend_flow: u8,
    /// Estimated flow while retracting, percent.
    pub retract_flow: u8,
    /// Estimated flow while extending, extended resolution.
    pub extend_flow_extended: u16,
    /// Estimated flow while retracting, extended resolution.
    pub retract_flow_extended: u16,
    /// What the valve is doing.
    pub valve_state: ValveState,
    /// The configured fail-safe behaviour.
    pub fail_safe_mode: FailSafeMode,
    /// Which limit, if any, the valve is up against (3 bits).
    pub limit: u8,
}

impl Default for GeneralPurposeValveEstimatedFlow {
    fn default() -> Self {
        GeneralPurposeValveEstimatedFlow {
            extend_flow: 0,
            retract_flow: 0,
            extend_flow_extended: 0,
            retract_flow_extended: 0,
            valve_state: ValveState::Neutral,
            fail_safe_mode: FailSafeMode::Blocked,
            limit: LIMIT_NOT_USED,
        }
    }
}

impl GeneralPurposeValveEstimatedFlow {
    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.extend_flow,
            self.retract_flow,
            pack_mode_and_state(self.fail_safe_mode, self.valve_state),
            (self.limit & 0b111) << 5,
            self.extend_flow_extended as u8,
            (self.extend_flow_extended >> 8) as u8,
            self.retract_flow_extended as u8,
            (self.retract_flow_extended >> 8) as u8,
        ]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        GeneralPurposeValveEstimatedFlow {
            extend_flow: data[0],
            retract_flow: data[1],
            extend_flow_extended: u16::from_le_bytes([data[4], data[5]]),
            retract_flow_extended: u16::from_le_bytes([data[6], data[7]]),
            valve_state: ValveState::from_u8(data[2]),
            fail_safe_mode: FailSafeMode::from_u8(data[2] >> 6),
            limit: data[3] >> 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valve_numbers_map_to_all_three_pgn_blocks() {
        for number in 0..=MAX_VALVE_NUMBER {
            let valve = ValveNumber::new(number).unwrap();
            assert_eq!(valve.command_pgn().as_u32(), 0x00FE30 + number as u32);
            assert_eq!(
                valve.estimated_flow_pgn().as_u32(),
                0x00FE10 + number as u32
            );
            assert_eq!(
                valve.measured_position_pgn().as_u32(),
                0x00FF20 + number as u32
            );

            assert_eq!(
                ValveNumber::from_command_pgn(valve.command_pgn()),
                Some(valve)
            );
            assert_eq!(
                ValveNumber::from_estimated_flow_pgn(valve.estimated_flow_pgn()),
                Some(valve)
            );
            assert_eq!(
                ValveNumber::from_measured_position_pgn(valve.measured_position_pgn()),
                Some(valve)
            );
        }
    }

    #[test]
    fn valve_numbers_stop_at_fifteen() {
        assert!(ValveNumber::new(15).is_ok());
        assert_eq!(
            ValveNumber::new(16),
            Err(Error::ValueOutOfRange {
                field: "valve number",
                value: 16
            })
        );
    }

    /// Each block is exactly sixteen PGNs wide; the one past the end belongs to
    /// something else.
    #[test]
    fn the_pgn_blocks_do_not_overrun() {
        assert!(ValveNumber::from_command_pgn(Pgn::new(0x00FE2F).unwrap()).is_none());
        assert!(ValveNumber::from_command_pgn(Pgn::new(0x00FE40).unwrap()).is_none());
        assert!(ValveNumber::from_estimated_flow_pgn(Pgn::new(0x00FE0F).unwrap()).is_none());
        assert!(ValveNumber::from_estimated_flow_pgn(Pgn::new(0x00FE20).unwrap()).is_none());
        assert!(ValveNumber::from_measured_position_pgn(Pgn::new(0x00FF1F).unwrap()).is_none());
        assert!(ValveNumber::from_measured_position_pgn(Pgn::new(0x00FF30).unwrap()).is_none());
    }

    /// The estimated flow block and the command block must not be confused —
    /// they are adjacent in PGN space and both PDU2.
    #[test]
    fn the_blocks_do_not_alias_each_other() {
        let valve = ValveNumber::new(0).unwrap();
        assert!(ValveNumber::from_command_pgn(valve.estimated_flow_pgn()).is_none());
        assert!(ValveNumber::from_estimated_flow_pgn(valve.command_pgn()).is_none());
        assert!(ValveNumber::from_measured_position_pgn(valve.command_pgn()).is_none());
    }

    /// The measured position block sits inside the Proprietary B range, so a
    /// decoder has to check ISOBUS allocations first.
    #[test]
    fn measured_position_overlaps_the_proprietary_b_range() {
        let valve = ValveNumber::new(5).unwrap();
        let pgn = valve.measured_position_pgn();
        assert!(
            pgn.is_proprietary_b(),
            "0x00FF25 falls in the Proprietary B range — this is expected, and \
             why ISOBUS decoders must check valve PGNs before proprietary ones"
        );
        assert_eq!(ValveNumber::from_measured_position_pgn(pgn), Some(valve));
    }

    #[test]
    fn auxiliary_command_matches_the_reference_layout() {
        let command = AuxiliaryValveCommand {
            standard_flow: 40,
            valve_state: ValveState::Extend,
            fail_safe_mode: FailSafeMode::Blocked,
        };
        // byte 2 = fail-safe << 6 | 0b11 << 4 | state
        assert_eq!(
            command.encode(),
            [40, 0xFF, 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(AuxiliaryValveCommand::decode(&command.encode()), command);
    }

    #[test]
    fn every_valve_state_round_trips() {
        for state in [
            ValveState::Neutral,
            ValveState::Extend,
            ValveState::Retract,
            ValveState::Floating,
            ValveState::Initialisation,
            ValveState::Error,
            ValveState::Other(0x7),
        ] {
            let command = AuxiliaryValveCommand {
                standard_flow: 0,
                valve_state: state,
                fail_safe_mode: FailSafeMode::Activated,
            };
            let decoded = AuxiliaryValveCommand::decode(&command.encode());
            assert_eq!(decoded.valve_state, state);
            assert_eq!(decoded.fail_safe_mode, FailSafeMode::Activated);
        }
        assert!(ValveState::Extend.is_moving());
        assert!(ValveState::Retract.is_moving());
        assert!(!ValveState::Neutral.is_moving());
        assert!(!ValveState::Error.is_moving());
    }

    /// The reserved bits between fail-safe mode and valve state must stay set,
    /// and must not bleed into either neighbour.
    #[test]
    fn reserved_bits_do_not_disturb_their_neighbours() {
        let command = AuxiliaryValveCommand {
            standard_flow: 0,
            valve_state: ValveState::Error,
            fail_safe_mode: FailSafeMode::Activated,
        };
        let byte = command.encode()[2];
        assert_eq!(byte & 0b0011_0000, 0b0011_0000, "reserved bits stay set");
        assert_eq!(byte >> 6, 1, "fail-safe mode intact");
        assert_eq!(byte & 0x0F, 0xE, "valve state intact");
    }

    #[test]
    fn auxiliary_estimated_flow_round_trips() {
        let flow = AuxiliaryValveEstimatedFlow {
            extend_flow: 75,
            retract_flow: 30,
            valve_state: ValveState::Retract,
            fail_safe_mode: FailSafeMode::Activated,
            limit: LIMIT_NOT_USED,
        };
        let bytes = flow.encode();
        assert_eq!(bytes[0], 75);
        assert_eq!(bytes[1], 30);
        assert_eq!(bytes[3] >> 5, LIMIT_NOT_USED, "limit rides the top 3 bits");
        assert_eq!(AuxiliaryValveEstimatedFlow::decode(&bytes), flow);
    }

    #[test]
    fn measured_position_round_trips_both_scales() {
        let position = AuxiliaryValveMeasuredPosition {
            position_percent: 6400,
            position_micrometres: 51_234,
            valve_state: ValveState::Floating,
        };
        let bytes = position.encode();
        // The top nibble of byte 2 is reserved and set.
        assert_eq!(bytes[2] & 0xF0, 0xF0);
        assert_eq!(bytes[2] & 0x0F, 0x3);
        assert_eq!(AuxiliaryValveMeasuredPosition::decode(&bytes), position);
    }

    #[test]
    fn general_purpose_command_carries_the_extended_flow() {
        let command = GeneralPurposeValveCommand {
            standard_flow: 55,
            extended_flow: 0xBEEF,
            valve_state: ValveState::Extend,
            fail_safe_mode: FailSafeMode::Blocked,
        };
        let bytes = command.encode();
        assert_eq!(bytes[3], 0xEF, "extended flow is little-endian");
        assert_eq!(bytes[4], 0xBE);
        assert_eq!(GeneralPurposeValveCommand::decode(&bytes), command);
    }

    #[test]
    fn general_purpose_estimated_flow_fills_all_eight_bytes() {
        let flow = GeneralPurposeValveEstimatedFlow {
            extend_flow: 80,
            retract_flow: 20,
            extend_flow_extended: 0x1234,
            retract_flow_extended: 0x5678,
            valve_state: ValveState::Extend,
            fail_safe_mode: FailSafeMode::Blocked,
            limit: 2,
        };
        let bytes = flow.encode();
        assert_eq!(&bytes[4..], &[0x34, 0x12, 0x78, 0x56]);
        assert_eq!(GeneralPurposeValveEstimatedFlow::decode(&bytes), flow);
    }

    #[test]
    fn defaults_are_a_safe_resting_state() {
        // A default command must not move anything.
        let command = AuxiliaryValveCommand::default();
        assert_eq!(command.valve_state, ValveState::Neutral);
        assert!(!command.valve_state.is_moving());
        assert_eq!(command.standard_flow, 0);

        // Unreported limits default to "not used", not to zero (a real limit).
        assert_eq!(AuxiliaryValveEstimatedFlow::default().limit, LIMIT_NOT_USED);
        assert_eq!(
            GeneralPurposeValveEstimatedFlow::default().limit,
            LIMIT_NOT_USED
        );
    }

    #[test]
    fn valve_traffic_is_a_priority_3_broadcast() {
        let valve = ValveNumber::new(3).unwrap();
        let id = ValveNumber::broadcast_id(valve.command_pgn(), Address::new(0x80));
        // The C reference builds these identifiers with a 0x0C prefix: priority 3.
        assert_eq!(id.as_u32(), 0x0CFE3380);
        assert_eq!(id.priority(), Priority::CONTROL);
        assert!(id.is_broadcast());
        assert_eq!(ValveNumber::from_command_pgn(id.pgn()), Some(valve));
    }
}
