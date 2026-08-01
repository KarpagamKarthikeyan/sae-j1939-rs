// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core J1939 value types: [`Address`], [`Priority`], and the crate [`Error`].

use core::fmt;

/// The result of a fallible J1939 operation.
pub type Result<T> = core::result::Result<T, Error>;

/// An error produced by the J1939 codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A CAN identifier did not fit the 29-bit extended range.
    InvalidId(u32),
    /// A PGN did not fit the 18-bit parameter group number range.
    InvalidPgn(u32),
    /// A priority was outside the 3-bit range `0..=7`.
    InvalidPriority(u8),
    /// A destination address was supplied for a PDU2 (broadcast-only) PGN, or
    /// omitted for a PDU1 (destination-specific) one.
    DestinationMismatch,
    /// A frame's payload was shorter than the parameter group requires.
    ShortPayload {
        /// Bytes the parameter group requires.
        expected: usize,
        /// Bytes actually present.
        actual: usize,
    },
    /// A transport-protocol message size was outside the range the protocol
    /// carries (9..=1785 bytes). Messages of eight bytes or fewer must be sent
    /// in a single CAN frame.
    InvalidMessageSize(u16),
    /// A transport-protocol connection-management message carried a control
    /// byte that J1939-21 does not define.
    UnknownControlByte(u8),
    /// A diagnostic trouble code field was out of range: the SPN exceeds 19
    /// bits, the FMI exceeds 5, or the occurrence count exceeds 7.
    InvalidDtc,
    /// A field was too large for the bit width the wire format gives it.
    ValueOutOfRange {
        /// The name of the field that overflowed.
        field: &'static str,
        /// The value that did not fit.
        value: u32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidId(raw) => {
                write!(f, "{raw:#x} is not a valid 29-bit CAN identifier")
            }
            Error::InvalidPgn(raw) => write!(f, "{raw:#x} is not a valid 18-bit PGN"),
            Error::InvalidPriority(p) => write!(f, "priority {p} exceeds the 3-bit range 0..=7"),
            Error::DestinationMismatch => {
                f.write_str("destination address does not match the PGN's PDU format")
            }
            Error::ShortPayload { expected, actual } => {
                write!(
                    f,
                    "payload too short: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidMessageSize(size) => write!(
                f,
                "{size} bytes is outside the transport protocol range of 9..=1785"
            ),
            Error::UnknownControlByte(byte) => {
                write!(f, "{byte:#04x} is not a defined TP.CM control byte")
            }
            Error::InvalidDtc => f.write_str("diagnostic trouble code field out of range"),
            Error::ValueOutOfRange { field, value } => {
                write!(f, "{value} does not fit the {field} field")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A J1939 node address: the 8-bit source or destination address of an ECU.
///
/// Addresses `0..=253` identify a specific ECU. Two values are reserved by
/// J1939-81:
///
/// - [`Address::NULL`] (`0xFE`) — the "cannot claim an address" source address,
///   used by an ECU that has lost address arbitration.
/// - [`Address::GLOBAL`] (`0xFF`) — the global (broadcast) destination address.
///
/// ```
/// use sae_j1939_rs::Address;
///
/// let ecu = Address::new(0x80);
/// assert!(ecu.is_specific());
/// assert!(Address::GLOBAL.is_broadcast());
/// assert!(!Address::NULL.is_specific());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(u8);

/// Prints as hex, naming the two reserved values: `0x80`, `0xFF (global)`,
/// `0xFE (null)`.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04X}", self.0)?;
        match self.0 {
            0xFF => f.write_str(" (global)"),
            0xFE => f.write_str(" (null)"),
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({:#04X}", self.0)?;
        match self.0 {
            0xFF => f.write_str(" global)"),
            0xFE => f.write_str(" null)"),
            _ => f.write_str(")"),
        }
    }
}

impl Address {
    /// The null address (`0xFE`), used when an ECU cannot claim an address.
    pub const NULL: Address = Address(0xFE);

    /// The global (broadcast) destination address (`0xFF`).
    pub const GLOBAL: Address = Address(0xFF);

    /// Wrap a raw address byte.
    ///
    /// Every one of the 256 byte values is a legal address field on the wire —
    /// `0xFE` and `0xFF` simply carry the reserved meanings above — so this is
    /// infallible. Use [`Address::is_specific`] to test for a real ECU.
    pub const fn new(address: u8) -> Self {
        Address(address)
    }

    /// The raw address byte.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Whether this address identifies a specific ECU (`0..=253`).
    pub const fn is_specific(self) -> bool {
        self.0 < 0xFE
    }

    /// Whether this is the global (broadcast) address `0xFF`.
    pub const fn is_broadcast(self) -> bool {
        self.0 == Address::GLOBAL.0
    }

    /// Whether this is the null address `0xFE`.
    pub const fn is_null(self) -> bool {
        self.0 == Address::NULL.0
    }
}

impl From<u8> for Address {
    fn from(address: u8) -> Self {
        Address(address)
    }
}

impl From<Address> for u8 {
    fn from(address: Address) -> Self {
        address.0
    }
}

/// A J1939 message priority: the 3-bit field in bits 28..26 of the CAN
/// identifier, where `0` is the highest priority and `7` the lowest.
///
/// ```
/// use sae_j1939_rs::Priority;
///
/// assert_eq!(Priority::DEFAULT.as_u8(), 6);
/// assert!(Priority::new(8).is_err());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Priority(u8);

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Priority({})", self.0)
    }
}

impl Priority {
    /// The highest priority (`0`).
    pub const HIGHEST: Priority = Priority(0);

    /// The default priority for most parameter groups (`6`).
    pub const DEFAULT: Priority = Priority(6);

    /// The lowest priority (`7`).
    pub const LOWEST: Priority = Priority(7);

    /// The priority used for control-oriented parameter groups (`3`).
    pub const CONTROL: Priority = Priority(3);

    /// Build a priority from a raw value.
    ///
    /// Returns [`Error::InvalidPriority`] if `priority` exceeds `7`.
    pub const fn new(priority: u8) -> Result<Self> {
        if priority > 7 {
            Err(Error::InvalidPriority(priority))
        } else {
            Ok(Priority(priority))
        }
    }

    /// Build a priority, saturating anything above `7` to [`Priority::LOWEST`].
    ///
    /// Useful in `const` contexts and when decoding, where the source value is
    /// already masked to three bits and cannot be out of range.
    pub const fn new_saturating(priority: u8) -> Self {
        if priority > 7 {
            Priority::LOWEST
        } else {
            Priority(priority)
        }
    }

    /// The raw 3-bit priority value.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl Default for Priority {
    fn default() -> Self {
        Priority::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_addresses_classify_correctly() {
        assert!(Address::new(0x00).is_specific());
        assert!(Address::new(0xFD).is_specific());
        assert!(!Address::NULL.is_specific());
        assert!(Address::NULL.is_null());
        assert!(!Address::NULL.is_broadcast());
        assert!(Address::GLOBAL.is_broadcast());
        assert!(!Address::GLOBAL.is_specific());
    }

    #[test]
    fn addresses_print_in_hex_and_name_the_reserved_values() {
        extern crate std;
        use std::format;

        assert_eq!(format!("{}", Address::new(0x80)), "0x80");
        assert_eq!(format!("{}", Address::GLOBAL), "0xFF (global)");
        assert_eq!(format!("{}", Address::NULL), "0xFE (null)");
        assert_eq!(format!("{:?}", Address::new(0x80)), "Address(0x80)");
        assert_eq!(format!("{:?}", Address::GLOBAL), "Address(0xFF global)");
    }

    #[test]
    fn priority_rejects_out_of_range() {
        assert_eq!(Priority::new(7).unwrap(), Priority::LOWEST);
        assert_eq!(Priority::new(8), Err(Error::InvalidPriority(8)));
        assert_eq!(Priority::new_saturating(200), Priority::LOWEST);
    }
}
