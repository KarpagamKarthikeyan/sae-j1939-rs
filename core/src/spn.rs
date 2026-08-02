// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Suspect Parameter Numbers: turning payload bytes into engineering units.
//!
//! A PGN says *which* message arrived; an **SPN** says which parameter sits
//! where inside it, how wide it is, and how to scale it. Engine speed is not
//! "bytes 4 and 5" — it is a 16-bit little-endian field scaled by 0.125 rpm per
//! bit.
//!
//! ```
//! use sae_j1939_rs::spn::{catalogue, SpnValue};
//!
//! // Electronic Engine Controller 1, engine turning at 800 rpm.
//! let payload = [0xFF, 0xFF, 0xFF, 0x00, 0x19, 0xFF, 0xFF, 0xFF];
//! assert_eq!(catalogue::ENGINE_SPEED.decode(&payload), Ok(SpnValue::Valid(800.0)));
//! ```
//!
//! # Not every value is a value
//!
//! This is the part that bites people. J1939 reserves the top of every
//! parameter's range for status: a one-byte parameter reading `0xFF` means
//! *not available*, and `0xFE` means *error* — not 255 of whatever the unit is.
//! A naive decoder reports a failed coolant sensor as 215 °C.
//!
//! [`Spn::decode`] returns an [`SpnValue`], so those cases are impossible to
//! read as measurements by accident:
//!
//! ```
//! use sae_j1939_rs::spn::{catalogue, SpnValue};
//!
//! // The coolant sensor is disconnected: byte 1 reads 0xFF.
//! let payload = [0xFF; 8];
//! assert_eq!(catalogue::ENGINE_COOLANT_TEMPERATURE.decode(&payload), Ok(SpnValue::NotAvailable));
//!
//! // ...and 0xFE is a sensor fault, not -40 + 254 degrees.
//! let payload = [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
//! assert_eq!(catalogue::ENGINE_COOLANT_TEMPERATURE.decode(&payload), Ok(SpnValue::Error));
//! ```
//!
//! # Bit numbering
//!
//! SAE documents positions as `byte.bit`, both 1-based, with bit 1 the least
//! significant. [`bit_position`] converts that notation directly, so a
//! definition can be transcribed from a datasheet without off-by-one arithmetic.
//!
//! # About [`catalogue`]
//!
//! The catalogue is a **starter set** of widely published parameters, not a
//! complete database — the full parameter list runs to thousands of entries and
//! lives in the SAE J1939-71 document. Verify any definition against your own
//! documentation before relying on it in production, and please open an issue if
//! one disagrees with your hardware.

use crate::types::{Error, Result};

/// The widest parameter this module extracts.
pub const MAX_BIT_LENGTH: u16 = 32;

/// Convert SAE `byte.bit` notation — both 1-based, bit 1 least significant —
/// into a 0-based bit offset from the start of the payload.
///
/// ```
/// use sae_j1939_rs::spn::bit_position;
///
/// assert_eq!(bit_position(1, 1), 0);   // the very first bit
/// assert_eq!(bit_position(1, 8), 7);   // ...and the last bit of byte 1
/// assert_eq!(bit_position(2, 1), 8);   // byte 2 starts here
/// assert_eq!(bit_position(2, 3), 10);  // two bits into byte 2
/// assert_eq!(bit_position(4, 1), 24);  // engine speed starts at byte 4
/// ```
pub const fn bit_position(byte: u16, bit: u16) -> u16 {
    (byte - 1) * 8 + (bit - 1)
}

/// A decoded parameter, or the reason there is no measurement.
///
/// The variants that are not [`SpnValue::Valid`] are J1939's in-band status
/// codes, which occupy the top of every parameter's range.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpnValue {
    /// A real measurement, scaled into the parameter's unit.
    Valid(f32),
    /// The sending ECU reports a fault with this parameter.
    Error,
    /// The sending ECU does not support or cannot supply this parameter.
    NotAvailable,
    /// The raw value falls in a range J1939 reserves.
    Reserved,
}

impl SpnValue {
    /// The measurement, or `None` for any of the status codes.
    pub const fn value(self) -> Option<f32> {
        match self {
            SpnValue::Valid(value) => Some(value),
            _ => None,
        }
    }

    /// Whether this is a real measurement.
    pub const fn is_valid(self) -> bool {
        matches!(self, SpnValue::Valid(_))
    }
}

/// The raw field, before scaling, classified against J1939's reserved ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawValue {
    /// A usable raw field.
    Valid(u32),
    /// The error indicator.
    Error,
    /// The not-available indicator.
    NotAvailable,
    /// A reserved range.
    Reserved,
}

/// Where a parameter lives inside a payload, and how to scale it.
///
/// Build one with [`Spn::new`], or take a ready-made definition from
/// [`catalogue`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spn {
    /// The SPN number assigned by SAE.
    pub number: u32,
    /// A short human-readable name.
    pub name: &'static str,
    /// 0-based bit offset from the start of the payload — see [`bit_position`].
    pub start_bit: u16,
    /// Field width in bits, at most [`MAX_BIT_LENGTH`].
    pub bit_length: u16,
    /// Units per bit.
    pub resolution: f32,
    /// Added after scaling.
    pub offset: f32,
    /// The unit the scaled value is in.
    pub unit: &'static str,
}

impl Spn {
    /// Define a parameter.
    ///
    /// `start_bit` is 0-based; use [`bit_position`] to convert SAE `byte.bit`
    /// notation.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        number: u32,
        name: &'static str,
        start_bit: u16,
        bit_length: u16,
        resolution: f32,
        offset: f32,
        unit: &'static str,
    ) -> Self {
        Spn {
            number,
            name,
            start_bit,
            bit_length,
            resolution,
            offset,
            unit,
        }
    }

    /// How many payload bytes this parameter needs to be present.
    pub const fn required_len(&self) -> usize {
        (self.start_bit as usize + self.bit_length as usize).div_ceil(8)
    }

    /// Pull the raw field out of `data`, classified against J1939's reserved
    /// ranges but not scaled.
    ///
    /// Returns [`Error::ShortPayload`] if the payload does not reach the field,
    /// or [`Error::ValueOutOfRange`] if the definition is wider than
    /// [`MAX_BIT_LENGTH`].
    pub fn extract(&self, data: &[u8]) -> Result<RawValue> {
        if self.bit_length == 0 || self.bit_length > MAX_BIT_LENGTH {
            return Err(Error::ValueOutOfRange {
                field: "spn bit_length",
                value: self.bit_length as u32,
            });
        }
        let needed = self.required_len();
        if data.len() < needed {
            return Err(Error::ShortPayload {
                expected: needed,
                actual: data.len(),
            });
        }

        // J1939 packs parameters least-significant-bit first, with the payload's
        // first byte lowest — so a multi-byte field reads little-endian.
        let mut raw: u32 = 0;
        for i in 0..self.bit_length {
            let index = (self.start_bit + i) as usize;
            let bit = (data[index / 8] >> (index % 8)) & 1;
            raw |= (bit as u32) << i;
        }
        Ok(classify(raw, self.bit_length))
    }

    /// Pull the field out of `data` and scale it into the parameter's unit.
    ///
    /// ```
    /// use sae_j1939_rs::spn::{catalogue, SpnValue};
    ///
    /// // Coolant at 90 °C: the raw byte is 90 + 40, because the offset is -40.
    /// let payload = [130, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    /// let value = catalogue::ENGINE_COOLANT_TEMPERATURE.decode(&payload).unwrap();
    /// assert_eq!(value, SpnValue::Valid(90.0));
    /// ```
    pub fn decode(&self, data: &[u8]) -> Result<SpnValue> {
        Ok(match self.extract(data)? {
            RawValue::Valid(raw) => SpnValue::Valid(raw as f32 * self.resolution + self.offset),
            RawValue::Error => SpnValue::Error,
            RawValue::NotAvailable => SpnValue::NotAvailable,
            RawValue::Reserved => SpnValue::Reserved,
        })
    }
}

/// Classify a raw field against the reserved values at the top of a parameter's
/// range, without a [`Spn`] to hand.
///
/// Useful when the parameter's geometry comes from somewhere other than a
/// compile-time definition — a DBC file loaded at runtime, for instance. The
/// reserved-range rules are J1939's, not a property of how the field was
/// described, so they should not be reimplemented per source.
///
/// ```
/// use sae_j1939_rs::spn::{classify, RawValue};
///
/// assert_eq!(classify(200, 8), RawValue::Valid(200));
/// assert_eq!(classify(0xFE, 8), RawValue::Error);
/// assert_eq!(classify(0xFF, 8), RawValue::NotAvailable);
/// ```
///
/// The universal rule is that the **highest** value of a field means *not
/// available* and the one below it means *error*. On top of that, J1939-71
/// documents a reserved band for the widths it tabulates:
///
/// | Width | Valid | Reserved | Error | Not available |
/// |-------|-------|----------|-------|---------------|
/// | 1 bit | both values | — | — | — |
/// | 2 bits | `0`–`1` | — | `2` | `3` |
/// | 4 bits | `0x0`–`0xA` | `0xB`–`0xD` | `0xE` | `0xF` |
/// | 8 bits | `0x00`–`0xFA` | `0xFB`–`0xFD` | `0xFE` | `0xFF` |
/// | > 8 bits | top byte `≤ 0xFA` | top byte `0xFB`–`0xFD` | top byte `0xFE` | top byte `0xFF` |
///
/// Widths the standard does not tabulate — 3, and 5 through 7 — get the general
/// top-two rule with no reserved band, since there is no documented one to
/// apply. Such fields are rare; a 1-bit field is the only case with no room for
/// status at all, so both its values are measurements.
pub const fn classify(raw: u32, bit_length: u16) -> RawValue {
    match bit_length {
        // No room for status codes.
        1 => RawValue::Valid(raw),
        2 => match raw {
            0 | 1 => RawValue::Valid(raw),
            2 => RawValue::Error,
            _ => RawValue::NotAvailable,
        },
        4 => match raw {
            0x0..=0xA => RawValue::Valid(raw),
            0xB..=0xD => RawValue::Reserved,
            0xE => RawValue::Error,
            _ => RawValue::NotAvailable,
        },
        8 => match raw {
            0x00..=0xFA => RawValue::Valid(raw),
            0xFB..=0xFD => RawValue::Reserved,
            0xFE => RawValue::Error,
            _ => RawValue::NotAvailable,
        },
        // Widths the standard does not tabulate: the top two values only.
        3 | 5..=7 => {
            let max = (1u32 << bit_length) - 1;
            if raw == max {
                RawValue::NotAvailable
            } else if raw == max - 1 {
                RawValue::Error
            } else {
                RawValue::Valid(raw)
            }
        }
        // Wider fields are classified by their most significant byte, so a
        // 16-bit parameter is unavailable across all of 0xFF00..=0xFFFF.
        _ => {
            let top = raw >> (bit_length - 8);
            match top {
                0x00..=0xFA => RawValue::Valid(raw),
                0xFB..=0xFD => RawValue::Reserved,
                0xFE => RawValue::Error,
                _ => RawValue::NotAvailable,
            }
        }
    }
}

/// A starter set of widely published parameter definitions.
///
/// These cover the parameters most often wanted from a running engine. They are
/// **not** a complete database — see the note in the [module
/// documentation](self#about-catalogue) — and each carries the PGN it belongs
/// to in its doc comment, because an SPN is only meaningful inside its own
/// parameter group.
pub mod catalogue {
    use super::{bit_position, Spn};

    /// SPN 190 — Engine Speed. Electronic Engine Controller 1 (`0x00F004`).
    pub const ENGINE_SPEED: Spn = Spn::new(
        190,
        "Engine Speed",
        bit_position(4, 1),
        16,
        0.125,
        0.0,
        "rpm",
    );

    /// SPN 513 — Actual Engine Percent Torque. EEC1 (`0x00F004`).
    pub const ACTUAL_ENGINE_PERCENT_TORQUE: Spn = Spn::new(
        513,
        "Actual Engine Percent Torque",
        bit_position(3, 1),
        8,
        1.0,
        -125.0,
        "%",
    );

    /// SPN 512 — Driver's Demand Engine Percent Torque. EEC1 (`0x00F004`).
    pub const DRIVERS_DEMAND_ENGINE_PERCENT_TORQUE: Spn = Spn::new(
        512,
        "Driver's Demand Engine Percent Torque",
        bit_position(2, 1),
        8,
        1.0,
        -125.0,
        "%",
    );

    /// SPN 91 — Accelerator Pedal Position 1. EEC2 (`0x00F003`).
    pub const ACCELERATOR_PEDAL_POSITION: Spn = Spn::new(
        91,
        "Accelerator Pedal Position 1",
        bit_position(2, 1),
        8,
        0.4,
        0.0,
        "%",
    );

    /// SPN 92 — Engine Percent Load At Current Speed. EEC2 (`0x00F003`).
    pub const ENGINE_PERCENT_LOAD: Spn = Spn::new(
        92,
        "Engine Percent Load At Current Speed",
        bit_position(3, 1),
        8,
        1.0,
        0.0,
        "%",
    );

    /// SPN 110 — Engine Coolant Temperature. Engine Temperature 1 (`0x00FEEE`).
    pub const ENGINE_COOLANT_TEMPERATURE: Spn = Spn::new(
        110,
        "Engine Coolant Temperature",
        bit_position(1, 1),
        8,
        1.0,
        -40.0,
        "°C",
    );

    /// SPN 174 — Engine Fuel Temperature 1. Engine Temperature 1 (`0x00FEEE`).
    pub const ENGINE_FUEL_TEMPERATURE: Spn = Spn::new(
        174,
        "Engine Fuel Temperature 1",
        bit_position(2, 1),
        8,
        1.0,
        -40.0,
        "°C",
    );

    /// SPN 175 — Engine Oil Temperature 1. Engine Temperature 1 (`0x00FEEE`).
    pub const ENGINE_OIL_TEMPERATURE: Spn = Spn::new(
        175,
        "Engine Oil Temperature 1",
        bit_position(3, 1),
        16,
        0.031_25,
        -273.0,
        "°C",
    );

    /// SPN 100 — Engine Oil Pressure. Engine Fluid Level/Pressure 1 (`0x00FEEF`).
    pub const ENGINE_OIL_PRESSURE: Spn = Spn::new(
        100,
        "Engine Oil Pressure",
        bit_position(4, 1),
        8,
        4.0,
        0.0,
        "kPa",
    );

    /// SPN 98 — Engine Oil Level. Engine Fluid Level/Pressure 1 (`0x00FEEF`).
    pub const ENGINE_OIL_LEVEL: Spn =
        Spn::new(98, "Engine Oil Level", bit_position(3, 1), 8, 0.4, 0.0, "%");

    /// SPN 183 — Engine Fuel Rate. Fuel Economy (`0x00FEF2`).
    pub const ENGINE_FUEL_RATE: Spn = Spn::new(
        183,
        "Engine Fuel Rate",
        bit_position(1, 1),
        16,
        0.05,
        0.0,
        "L/h",
    );

    /// SPN 84 — Wheel-Based Vehicle Speed. Cruise Control/Vehicle Speed
    /// (`0x00FEF1`).
    pub const WHEEL_BASED_VEHICLE_SPEED: Spn = Spn::new(
        84,
        "Wheel-Based Vehicle Speed",
        bit_position(2, 1),
        16,
        1.0 / 256.0,
        0.0,
        "km/h",
    );

    /// SPN 168 — Battery Potential (Power Input 1). Vehicle Electrical Power 1
    /// (`0x00FEF7`).
    pub const BATTERY_POTENTIAL: Spn = Spn::new(
        168,
        "Battery Potential",
        bit_position(5, 1),
        16,
        0.05,
        0.0,
        "V",
    );

    /// Every definition in the catalogue, for iterating or building a lookup.
    pub const ALL: [Spn; 13] = [
        ENGINE_SPEED,
        ACTUAL_ENGINE_PERCENT_TORQUE,
        DRIVERS_DEMAND_ENGINE_PERCENT_TORQUE,
        ACCELERATOR_PEDAL_POSITION,
        ENGINE_PERCENT_LOAD,
        ENGINE_COOLANT_TEMPERATURE,
        ENGINE_FUEL_TEMPERATURE,
        ENGINE_OIL_TEMPERATURE,
        ENGINE_OIL_PRESSURE,
        ENGINE_OIL_LEVEL,
        ENGINE_FUEL_RATE,
        WHEEL_BASED_VEHICLE_SPEED,
        BATTERY_POTENTIAL,
    ];
}

#[cfg(test)]
mod tests {
    use super::catalogue::*;
    use super::*;

    #[test]
    fn sae_byte_bit_notation_converts_to_offsets() {
        assert_eq!(bit_position(1, 1), 0);
        assert_eq!(bit_position(1, 8), 7);
        assert_eq!(bit_position(2, 1), 8);
        assert_eq!(bit_position(4, 1), 24);
        assert_eq!(bit_position(8, 8), 63);
    }

    #[test]
    fn extracts_a_multi_byte_field_little_endian() {
        // Engine speed 800 rpm = 6400 raw at 0.125 rpm/bit = 0x1900.
        let payload = [0xFF, 0xFF, 0xFF, 0x00, 0x19, 0xFF, 0xFF, 0xFF];
        assert_eq!(ENGINE_SPEED.extract(&payload), Ok(RawValue::Valid(6400)));
        assert_eq!(ENGINE_SPEED.decode(&payload), Ok(SpnValue::Valid(800.0)));
    }

    #[test]
    fn applies_resolution_and_offset() {
        // Coolant temperature has a -40 offset at 1 °C/bit.
        let payload = [130, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE.decode(&payload),
            Ok(SpnValue::Valid(90.0))
        );

        // Zero raw is a real reading of -40 °C, not "no data".
        let payload = [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE.decode(&payload),
            Ok(SpnValue::Valid(-40.0))
        );
    }

    /// The failure this module exists to prevent: reading a status code as a
    /// measurement.
    #[test]
    fn status_codes_are_never_reported_as_measurements() {
        let not_available = [0xFF; 8];
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE.decode(&not_available),
            Ok(SpnValue::NotAvailable)
        );
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE
                .decode(&not_available)
                .unwrap()
                .value(),
            None,
            "a disconnected sensor must not read as 215 °C"
        );

        let error = [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE.decode(&error),
            Ok(SpnValue::Error)
        );

        let reserved = [0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE.decode(&reserved),
            Ok(SpnValue::Reserved)
        );

        // 0xFA is the last valid raw byte.
        let highest_valid = [0xFA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            ENGINE_COOLANT_TEMPERATURE.decode(&highest_valid),
            Ok(SpnValue::Valid(210.0))
        );
    }

    /// A 16-bit parameter is unavailable across its whole top byte, not only at
    /// `0xFFFF`.
    #[test]
    fn wide_fields_are_classified_by_their_top_byte() {
        let mut payload = [0xFFu8; 8];

        payload[3] = 0x00;
        payload[4] = 0xFF;
        assert_eq!(ENGINE_SPEED.decode(&payload), Ok(SpnValue::NotAvailable));

        payload[4] = 0xFE;
        assert_eq!(ENGINE_SPEED.decode(&payload), Ok(SpnValue::Error));

        payload[4] = 0xFC;
        assert_eq!(ENGINE_SPEED.decode(&payload), Ok(SpnValue::Reserved));

        // 0xFAFF is the top of the valid range.
        payload[3] = 0xFF;
        payload[4] = 0xFA;
        assert!(ENGINE_SPEED.decode(&payload).unwrap().is_valid());
    }

    #[test]
    fn narrow_fields_use_their_own_reserved_ranges() {
        // A 2-bit field: 0 and 1 valid, 2 error, 3 not available.
        let two_bit = Spn::new(0, "test", 0, 2, 1.0, 0.0, "");
        assert_eq!(two_bit.extract(&[0b00]), Ok(RawValue::Valid(0)));
        assert_eq!(two_bit.extract(&[0b01]), Ok(RawValue::Valid(1)));
        assert_eq!(two_bit.extract(&[0b10]), Ok(RawValue::Error));
        assert_eq!(two_bit.extract(&[0b11]), Ok(RawValue::NotAvailable));

        // A 4-bit field tops out at 0xA.
        let four_bit = Spn::new(0, "test", 0, 4, 1.0, 0.0, "");
        assert_eq!(four_bit.extract(&[0x0A]), Ok(RawValue::Valid(0x0A)));
        assert_eq!(four_bit.extract(&[0x0C]), Ok(RawValue::Reserved));
        assert_eq!(four_bit.extract(&[0x0E]), Ok(RawValue::Error));
        assert_eq!(four_bit.extract(&[0x0F]), Ok(RawValue::NotAvailable));

        // A 1-bit field has no room for status codes; both values are real.
        let one_bit = Spn::new(0, "test", 0, 1, 1.0, 0.0, "");
        assert_eq!(one_bit.extract(&[0]), Ok(RawValue::Valid(0)));
        assert_eq!(one_bit.extract(&[1]), Ok(RawValue::Valid(1)));

        // Widths the standard does not tabulate still reserve their top two
        // values, so an all-ones field is never a measurement.
        let three_bit = Spn::new(0, "test", 0, 3, 1.0, 0.0, "");
        assert_eq!(three_bit.extract(&[0b101]), Ok(RawValue::Valid(5)));
        assert_eq!(three_bit.extract(&[0b110]), Ok(RawValue::Error));
        assert_eq!(three_bit.extract(&[0b111]), Ok(RawValue::NotAvailable));

        let six_bit = Spn::new(0, "test", 0, 6, 1.0, 0.0, "");
        assert_eq!(six_bit.extract(&[60]), Ok(RawValue::Valid(60)));
        assert_eq!(six_bit.extract(&[62]), Ok(RawValue::Error));
        assert_eq!(six_bit.extract(&[63]), Ok(RawValue::NotAvailable));
    }

    #[test]
    fn extracts_fields_that_straddle_a_byte_boundary() {
        // Four bits starting at bit 6: two from byte 0, two from byte 1.
        let spn = Spn::new(0, "test", 6, 4, 1.0, 0.0, "");
        // byte 0 = 0b1100_0000 -> bits 6,7 = 1,1;  byte 1 = 0b0000_0001 -> bit 0 = 1
        assert_eq!(
            spn.extract(&[0b1100_0000, 0b0000_0001]),
            Ok(RawValue::Valid(0b0111))
        );
    }

    #[test]
    fn rejects_a_payload_that_does_not_reach_the_field() {
        assert_eq!(ENGINE_SPEED.required_len(), 5);
        assert_eq!(
            ENGINE_SPEED.extract(&[0; 4]),
            Err(Error::ShortPayload {
                expected: 5,
                actual: 4
            })
        );
        assert!(ENGINE_SPEED.extract(&[0; 5]).is_ok());
    }

    #[test]
    fn rejects_an_impossible_definition() {
        let too_wide = Spn::new(0, "test", 0, 33, 1.0, 0.0, "");
        assert_eq!(
            too_wide.extract(&[0; 8]),
            Err(Error::ValueOutOfRange {
                field: "spn bit_length",
                value: 33
            })
        );
        let zero_width = Spn::new(0, "test", 0, 0, 1.0, 0.0, "");
        assert!(zero_width.extract(&[0; 8]).is_err());
    }

    #[test]
    fn every_catalogue_entry_fits_a_single_frame() {
        for spn in catalogue::ALL {
            assert!(
                spn.required_len() <= 8,
                "{} ({}) needs {} bytes",
                spn.name,
                spn.number,
                spn.required_len()
            );
            assert!(spn.bit_length > 0 && spn.bit_length <= MAX_BIT_LENGTH);
            // Every entry must decode an all-0xFF frame as unavailable.
            assert_eq!(
                spn.decode(&[0xFF; 8]),
                Ok(SpnValue::NotAvailable),
                "{} should read as not available",
                spn.name
            );
        }
    }

    #[test]
    fn catalogue_numbers_are_unique() {
        let all = catalogue::ALL;
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a.number, b.number, "duplicate SPN {}", a.number);
            }
        }
    }

    /// A realistic EEC1 frame decoded field by field.
    #[test]
    fn decodes_a_realistic_engine_controller_frame() {
        // EEC1: driver demand 10%, actual torque 25%, engine 1500 rpm.
        // Torque fields carry a -125 offset, so 10% is raw 135.
        let mut payload = [0xFFu8; 8];
        payload[1] = 135; // driver's demand: 10%
        payload[2] = 150; // actual torque: 25%
        let raw_speed = (1500.0f32 / 0.125) as u16; // 12000
        payload[3] = raw_speed as u8;
        payload[4] = (raw_speed >> 8) as u8;

        assert_eq!(
            DRIVERS_DEMAND_ENGINE_PERCENT_TORQUE.decode(&payload),
            Ok(SpnValue::Valid(10.0))
        );
        assert_eq!(
            ACTUAL_ENGINE_PERCENT_TORQUE.decode(&payload),
            Ok(SpnValue::Valid(25.0))
        );
        assert_eq!(ENGINE_SPEED.decode(&payload), Ok(SpnValue::Valid(1500.0)));
    }
}
