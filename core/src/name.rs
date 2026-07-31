// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The J1939-81 NAME: the 64-bit identity of an ECU.
//!
//! Every ECU on a J1939 bus has a NAME — a 64-bit value describing what the
//! device *is*, independent of the 8-bit address it currently holds. It packs
//! nine fields:
//!
//! ```text
//! bit 63       Arbitrary Address Capable  (1)
//! bits 62..60  Industry Group             (3)
//! bits 59..56  Vehicle System Instance    (4)
//! bits 55..49  Vehicle System             (7)
//! bit 48       Reserved                   (1)
//! bits 47..40  Function                   (8)
//! bits 39..35  Function Instance          (5)
//! bits 34..32  ECU Instance               (3)
//! bits 31..21  Manufacturer Code          (11)
//! bits 20..0   Identity Number            (21)
//! ```
//!
//! The layout is not arbitrary: a NAME is compared **as a 64-bit integer** to
//! settle address contention, and the fields are ordered so that the most
//! significant ones dominate. A numerically **lower** NAME wins. Because the
//! identity number sits in the least significant bits, two otherwise identical
//! ECUs from the same manufacturer are still separated by serial number — so
//! arbitration always terminates. See [`crate::address_claim`].
//!
//! ```
//! use sae_j1939_rs::Name;
//!
//! let name = Name::new()
//!     .with_identity_number(100)
//!     .with_manufacturer_code(300)
//!     .with_function(0x87)         // vehicle dynamic stability control module
//!     .with_industry_group(2)      // construction
//!     .with_arbitrary_address_capable(true);
//!
//! // NAMEs round-trip through the eight bytes of an Address Claimed message.
//! assert_eq!(Name::from_bytes(&name.to_bytes()), name);
//! ```

/// The 64-bit J1939-81 NAME identifying an ECU.
///
/// Build one with [`Name::new`] and the `with_*` methods; every field is
/// masked to its bit width, so an out-of-range value cannot corrupt its
/// neighbours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Name(u64);

macro_rules! name_field {
    (
        $(#[$meta:meta])*
        $get:ident / $with:ident, $ty:ty, shift = $shift:expr, bits = $bits:expr
    ) => {
        $(#[$meta])*
        pub const fn $get(self) -> $ty {
            ((self.0 >> $shift) & ((1u64 << $bits) - 1)) as $ty
        }

        $(#[$meta])*
        ///
        /// The value is masked to the field's width.
        #[must_use]
        pub const fn $with(self, value: $ty) -> Self {
            let mask = ((1u64 << $bits) - 1) << $shift;
            Name((self.0 & !mask) | (((value as u64) << $shift) & mask))
        }
    };
}

impl Name {
    /// An all-zero NAME. Every field is unset; fill it in with the `with_*`
    /// methods.
    ///
    /// Note that an all-zero NAME is numerically the lowest possible, and so
    /// would win every arbitration — set at least a manufacturer code and
    /// identity number before putting a device on a real bus.
    pub const fn new() -> Self {
        Name(0)
    }

    /// Wrap a raw 64-bit NAME.
    pub const fn from_u64(raw: u64) -> Self {
        Name(raw)
    }

    /// The raw 64-bit NAME, as compared during address arbitration.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    name_field! {
        /// The device's serial number, unique within a manufacturer and
        /// function (21 bits).
        identity_number / with_identity_number, u32, shift = 0, bits = 21
    }

    name_field! {
        /// The manufacturer's code, assigned by SAE (11 bits).
        manufacturer_code / with_manufacturer_code, u16, shift = 21, bits = 11
    }

    name_field! {
        /// Which instance of this ECU within the vehicle system (3 bits).
        ecu_instance / with_ecu_instance, u8, shift = 32, bits = 3
    }

    name_field! {
        /// Which instance of this function within the ECU (5 bits).
        function_instance / with_function_instance, u8, shift = 35, bits = 5
    }

    name_field! {
        /// What the device does — engine, transmission, brakes (8 bits).
        function / with_function, u8, shift = 40, bits = 8
    }

    name_field! {
        /// The vehicle system this device belongs to (7 bits).
        vehicle_system / with_vehicle_system, u8, shift = 49, bits = 7
    }

    name_field! {
        /// Which instance of that vehicle system (4 bits).
        vehicle_system_instance / with_vehicle_system_instance, u8, shift = 56, bits = 4
    }

    name_field! {
        /// The industry the device is built for (3 bits) — see the
        /// [`industry_group`] module for the defined codes.
        industry_group / with_industry_group, u8, shift = 60, bits = 3
    }

    /// Whether this ECU may pick a different address if it loses arbitration.
    ///
    /// An ECU that is *not* arbitrary-address-capable has no fallback: losing
    /// contention forces it off the bus with a Cannot Claim Address message.
    pub const fn arbitrary_address_capable(self) -> bool {
        (self.0 >> 63) & 1 == 1
    }

    /// Set whether this ECU may pick a different address if it loses
    /// arbitration.
    #[must_use]
    pub const fn with_arbitrary_address_capable(self, capable: bool) -> Self {
        let mask = 1u64 << 63;
        if capable {
            Name(self.0 | mask)
        } else {
            Name(self.0 & !mask)
        }
    }

    /// Encode to the eight-byte payload of an Address Claimed message.
    ///
    /// The NAME goes on the wire little-endian, least significant byte first.
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Decode from the eight-byte payload of an Address Claimed message.
    pub const fn from_bytes(data: &[u8; 8]) -> Self {
        Name(u64::from_le_bytes(*data))
    }

    /// Whether this NAME wins address arbitration against `other`.
    ///
    /// J1939-81 resolves contention by numeric comparison: the lower NAME
    /// keeps the address.
    pub const fn wins_arbitration_against(self, other: Name) -> bool {
        self.0 < other.0
    }
}

/// Industry group codes (J1939-81), the top-level classification in a NAME.
pub mod industry_group {
    /// Global — applies across industries.
    pub const GLOBAL: u8 = 0;
    /// On-highway equipment: trucks and buses.
    pub const ON_HIGHWAY: u8 = 1;
    /// Agricultural and forestry equipment.
    pub const AGRICULTURAL_AND_FORESTRY: u8 = 2;
    /// Construction equipment.
    pub const CONSTRUCTION: u8 = 3;
    /// Marine equipment.
    pub const MARINE: u8 = 4;
    /// Industrial process control, stationary generators.
    pub const INDUSTRIAL_PROCESS_CONTROL: u8 = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field must survive a set/get cycle at its maximum value without
    /// disturbing its neighbours — the classic bit-packing failure.
    #[test]
    fn fields_are_independent_at_their_maximum_values() {
        let name = Name::new()
            .with_identity_number(0x1F_FFFF) // 21 bits
            .with_manufacturer_code(0x7FF) // 11 bits
            .with_ecu_instance(0x7) // 3 bits
            .with_function_instance(0x1F) // 5 bits
            .with_function(0xFF) // 8 bits
            .with_vehicle_system(0x7F) // 7 bits
            .with_vehicle_system_instance(0xF) // 4 bits
            .with_industry_group(0x7) // 3 bits
            .with_arbitrary_address_capable(true);

        assert_eq!(name.identity_number(), 0x1F_FFFF);
        assert_eq!(name.manufacturer_code(), 0x7FF);
        assert_eq!(name.ecu_instance(), 0x7);
        assert_eq!(name.function_instance(), 0x1F);
        assert_eq!(name.function(), 0xFF);
        assert_eq!(name.vehicle_system(), 0x7F);
        assert_eq!(name.vehicle_system_instance(), 0xF);
        assert_eq!(name.industry_group(), 0x7);
        assert!(name.arbitrary_address_capable());

        // Bit 48 is reserved and must stay clear.
        assert_eq!(name.as_u64() & (1 << 48), 0, "reserved bit must be zero");
    }

    #[test]
    fn out_of_range_values_are_masked_not_bled_into_neighbours() {
        // 0xFFFF does not fit the 11-bit manufacturer code.
        let name = Name::new()
            .with_identity_number(1)
            .with_manufacturer_code(0xFFFF)
            .with_ecu_instance(2);
        assert_eq!(name.manufacturer_code(), 0x7FF);
        assert_eq!(name.identity_number(), 1, "neighbour below is intact");
        assert_eq!(name.ecu_instance(), 2, "neighbour above is intact");
    }

    #[test]
    fn setting_a_field_twice_replaces_rather_than_ors() {
        let name = Name::new().with_function(0xFF).with_function(0x01);
        assert_eq!(name.function(), 0x01);
    }

    /// The NAME from the Open-SAE-J1939 "Address Claimed" example, field for
    /// field: identity 100, manufacturer 300, function instance 10, ECU
    /// instance 2, function `0x87` (VDC module), vehicle system 100, industry
    /// group 3 (construction), vehicle system instance 10, not
    /// arbitrary-address-capable.
    #[test]
    fn matches_the_reference_bit_packing() {
        let name = Name::new()
            .with_identity_number(100)
            .with_manufacturer_code(300)
            .with_function_instance(10)
            .with_ecu_instance(2)
            .with_function(0x87)
            .with_vehicle_system(100)
            .with_arbitrary_address_capable(false)
            .with_industry_group(industry_group::CONSTRUCTION)
            .with_vehicle_system_instance(10);

        // The C reference packs the same nine fields into these eight bytes:
        //   data[0..2] = identity number (21 bits, low)
        //   data[2]    = identity high 5 bits | manufacturer code low 3 bits
        //   data[3]    = manufacturer code >> 3
        //   data[4]    = function instance << 3 | ECU instance
        //   data[5]    = function
        //   data[6]    = vehicle system << 1
        //   data[7]    = arbitrary << 7 | industry group << 4 | vehicle system instance
        let bytes = name.to_bytes();
        assert_eq!(bytes[0], 100u32 as u8);
        assert_eq!(bytes[1], (100u32 >> 8) as u8);
        assert_eq!(bytes[2], ((100u32 >> 16) as u8) | ((300u16 << 5) as u8));
        assert_eq!(bytes[3], (300u16 >> 3) as u8);
        assert_eq!(bytes[4], (10u8 << 3) | 2);
        assert_eq!(bytes[5], 0x87);
        assert_eq!(bytes[6], 100u8 << 1);
        // Bit 7 is `arbitrary address capable`, left clear for this NAME.
        assert_eq!(bytes[7], (industry_group::CONSTRUCTION << 4) | 10);

        assert_eq!(Name::from_bytes(&bytes), name);
    }

    #[test]
    fn arbitration_prefers_the_numerically_lower_name() {
        let low = Name::new().with_identity_number(1);
        let high = Name::new().with_identity_number(2);
        assert!(low.wins_arbitration_against(high));
        assert!(!high.wins_arbitration_against(low));
        assert!(!low.wins_arbitration_against(low), "a tie is not a win");

        // Arbitrary-address-capable sets the top bit, so such an ECU always
        // loses to one that is not — which is what makes it the party that moves.
        let fixed = Name::new().with_manufacturer_code(2000);
        let flexible = Name::new()
            .with_manufacturer_code(1)
            .with_arbitrary_address_capable(true);
        assert!(fixed.wins_arbitration_against(flexible));
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let name = Name::from_u64(0x8123_4567_89AB_CDEF);
        assert_eq!(Name::from_bytes(&name.to_bytes()), name);
        assert_eq!(name.to_bytes()[0], 0xEF, "little-endian on the wire");
    }
}
