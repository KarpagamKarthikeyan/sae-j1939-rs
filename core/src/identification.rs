// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! J1939-71 identification: who and what an ECU says it is.
//!
//! Three parameter groups let a tool interrogate a device:
//!
//! - **Software Identification** (`0x00FEDA`) — firmware versions. A leading
//!   count byte, then the fields.
//! - **ECU Identification** (`0x00FDC5`) — part number, serial number,
//!   location, type, manufacturer.
//! - **Component Identification** (`0x00FEEB`) — make, model, serial number,
//!   unit number.
//!
//! All three carry **ASCII fields terminated by an asterisk** (`*`). Each is
//! normally longer than eight bytes, so they arrive over the transport protocol
//! ([`crate::tp`]) in response to a [`Request`](crate::Request).
//!
//! ```
//! use sae_j1939_rs::identification::EcuIdentification;
//!
//! let payload = b"PN-1234*SN-99*ENGINE BAY*ECM*ACME MOTORS*";
//! let ecu = EcuIdentification::new(payload);
//!
//! assert_eq!(ecu.part_number_str(), Some("PN-1234"));
//! assert_eq!(ecu.serial_number_str(), Some("SN-99"));
//! assert_eq!(ecu.manufacturer_name_str(), Some("ACME MOTORS"));
//! ```
//!
//! # A note on the wire format
//!
//! J1939-71 specifies asterisk-delimited fields, and that is what real
//! diagnostic tools emit and expect. (The Open-SAE-J1939 C reference stores
//! these as fixed-width parallel arrays instead — a simplification local to
//! that library, not the standard, so this module follows the specification.)

use crate::types::{Error, Result};

/// The byte that terminates each field: ASCII `*`.
pub const DELIMITER: u8 = b'*';

/// An iterator over the asterisk-delimited fields of an identification message.
///
/// A field is the run of bytes before each `*`. Trailing bytes with no
/// terminating delimiter — which some devices emit on the last field — are
/// yielded as a final field rather than discarded.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone)]
pub struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Fields<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        match self.rest.iter().position(|&byte| byte == DELIMITER) {
            Some(index) => {
                let field = &self.rest[..index];
                self.rest = &self.rest[index + 1..];
                Some(field)
            }
            None => {
                // An unterminated trailing field.
                let field = self.rest;
                self.rest = &[];
                Some(field)
            }
        }
    }
}

/// Split an identification payload into its asterisk-delimited fields.
pub fn fields(data: &[u8]) -> Fields<'_> {
    Fields { rest: data }
}

/// The `index`-th field, or `None` if the payload has fewer.
pub fn field(data: &[u8], index: usize) -> Option<&[u8]> {
    fields(data).nth(index)
}

/// The `index`-th field as a string, or `None` if it is absent or not UTF-8.
///
/// J1939-71 fields are ASCII, which is valid UTF-8, so this succeeds for any
/// conforming device.
pub fn field_str(data: &[u8], index: usize) -> Option<&str> {
    core::str::from_utf8(field(data, index)?).ok()
}

/// Build an identification payload: each field followed by a `*`.
///
/// Returns the number of bytes written, or [`Error::ShortPayload`] if `out` is
/// too small.
///
/// ```
/// use sae_j1939_rs::identification::{encode, fields};
///
/// let mut buf = [0u8; 64];
/// let len = encode(&[b"ACME".as_slice(), b"MODEL-7", b"SN-1234"], &mut buf).unwrap();
/// assert_eq!(&buf[..len], b"ACME*MODEL-7*SN-1234*");
/// assert_eq!(fields(&buf[..len]).count(), 3);
/// ```
pub fn encode(values: &[&[u8]], out: &mut [u8]) -> Result<usize> {
    let needed: usize = values.iter().map(|value| value.len() + 1).sum();
    if out.len() < needed {
        return Err(Error::ShortPayload {
            expected: needed,
            actual: out.len(),
        });
    }
    let mut written = 0;
    for value in values {
        out[written..written + value.len()].copy_from_slice(value);
        written += value.len();
        out[written] = DELIMITER;
        written += 1;
    }
    Ok(written)
}

/// Generate a borrowing wrapper with named accessors over delimited fields.
macro_rules! identification {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($index:literal => $accessor:ident / $accessor_str:ident: $doc:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<'a> {
            data: &'a [u8],
        }

        impl<'a> $name<'a> {
            /// Wrap an identification payload.
            ///
            /// Nothing is validated up front: a device that omits trailing
            /// fields is common, and the accessors simply return `None` for
            /// what is missing.
            pub const fn new(data: &'a [u8]) -> Self {
                $name { data }
            }

            /// The raw payload.
            pub const fn as_bytes(&self) -> &'a [u8] {
                self.data
            }

            /// Every field, in order.
            pub fn fields(&self) -> Fields<'a> {
                fields(self.data)
            }

            /// How many fields the payload actually carries.
            pub fn field_count(&self) -> usize {
                self.fields().count()
            }

            $(
                #[doc = $doc]
                pub fn $accessor(&self) -> Option<&'a [u8]> {
                    field(self.data, $index)
                }

                #[doc = $doc]
                ///
                /// As a string, or `None` if absent or not valid UTF-8.
                pub fn $accessor_str(&self) -> Option<&'a str> {
                    field_str(self.data, $index)
                }
            )+
        }
    };
}

identification! {
    /// ECU Identification (PGN `0x00FDC5`): what this control unit is.
    EcuIdentification {
        0 => part_number / part_number_str: "The ECU part number.",
        1 => serial_number / serial_number_str: "The ECU serial number.",
        2 => location / location_str: "Where the ECU is mounted.",
        3 => ecu_type / ecu_type_str: "The ECU type.",
        4 => manufacturer_name / manufacturer_name_str: "The manufacturer's name.",
    }
}

identification! {
    /// Component Identification (PGN `0x00FEEB`): the component an ECU controls.
    ComponentIdentification {
        0 => make / make_str: "The component make.",
        1 => model / model_str: "The component model.",
        2 => serial_number / serial_number_str: "The component serial number.",
        3 => unit_number / unit_number_str: "The component unit (or product) number.",
    }
}

/// Software Identification (PGN `0x00FEDA`): the firmware versions an ECU runs.
///
/// Unlike the other two, this payload begins with a **count byte** giving the
/// number of fields that follow.
///
/// ```
/// use sae_j1939_rs::identification::SoftwareIdentification;
///
/// let payload = b"\x02BOOT-1.0*APP-2.4.1*";
/// let software = SoftwareIdentification::parse(payload).unwrap();
///
/// assert_eq!(software.declared_field_count(), 2);
/// assert_eq!(software.field_str(0), Some("BOOT-1.0"));
/// assert_eq!(software.field_str(1), Some("APP-2.4.1"));
/// assert!(software.count_is_consistent());
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareIdentification<'a> {
    declared: u8,
    data: &'a [u8],
}

impl<'a> SoftwareIdentification<'a> {
    /// Parse a Software Identification payload, consuming the leading count
    /// byte.
    ///
    /// Returns [`Error::ShortPayload`] if the payload is empty.
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let Some((&declared, rest)) = payload.split_first() else {
            return Err(Error::ShortPayload {
                expected: 1,
                actual: 0,
            });
        };
        Ok(SoftwareIdentification {
            declared,
            data: rest,
        })
    }

    /// The field count the message claims.
    pub const fn declared_field_count(&self) -> u8 {
        self.declared
    }

    /// The number of fields actually present.
    pub fn field_count(&self) -> usize {
        self.fields().count()
    }

    /// Whether the declared count matches what the payload carries.
    ///
    /// Worth checking before trusting a device: a mismatch means the message
    /// was truncated or the device is buggy.
    pub fn count_is_consistent(&self) -> bool {
        self.field_count() == self.declared as usize
    }

    /// Every field, in order.
    pub fn fields(&self) -> Fields<'a> {
        fields(self.data)
    }

    /// The `index`-th field.
    pub fn field(&self, index: usize) -> Option<&'a [u8]> {
        field(self.data, index)
    }

    /// The `index`-th field as a string.
    pub fn field_str(&self, index: usize) -> Option<&'a str> {
        field_str(self.data, index)
    }

    /// Encode a Software Identification payload: a count byte followed by the
    /// delimited fields.
    ///
    /// Returns [`Error::ShortPayload`] if `out` is too small, or
    /// [`Error::ValueOutOfRange`] if more than 255 fields are supplied.
    pub fn encode(values: &[&[u8]], out: &mut [u8]) -> Result<usize> {
        if values.len() > u8::MAX as usize {
            return Err(Error::ValueOutOfRange {
                field: "software identification field count",
                value: values.len() as u32,
            });
        }
        if out.is_empty() {
            return Err(Error::ShortPayload {
                expected: 1,
                actual: 0,
            });
        }
        out[0] = values.len() as u8;
        Ok(1 + encode(values, &mut out[1..])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_delimited_fields() {
        let collected: std::vec::Vec<&[u8]> = fields(b"A*BB*CCC*").collect();
        assert_eq!(collected, [b"A".as_slice(), b"BB", b"CCC"]);
    }

    #[test]
    fn a_trailing_field_without_a_delimiter_is_still_a_field() {
        // Some devices omit the final asterisk.
        let collected: std::vec::Vec<&[u8]> = fields(b"A*BB").collect();
        assert_eq!(collected, [b"A".as_slice(), b"BB"]);
    }

    #[test]
    fn empty_fields_are_preserved() {
        // "**" is two empty fields, not zero.
        let collected: std::vec::Vec<&[u8]> = fields(b"**").collect();
        assert_eq!(collected, [b"".as_slice(), b""]);
        // A field may be empty in the middle of a message.
        let collected: std::vec::Vec<&[u8]> = fields(b"A**C*").collect();
        assert_eq!(collected, [b"A".as_slice(), b"", b"C"]);
    }

    #[test]
    fn an_empty_payload_has_no_fields() {
        assert_eq!(fields(b"").count(), 0);
        assert_eq!(field(b"", 0), None);
    }

    #[test]
    fn ecu_identification_maps_fields_to_names() {
        let payload = b"PN-1234*SN-99*ENGINE BAY*ECM*ACME MOTORS*";
        let ecu = EcuIdentification::new(payload);

        assert_eq!(ecu.field_count(), 5);
        assert_eq!(ecu.part_number_str(), Some("PN-1234"));
        assert_eq!(ecu.serial_number_str(), Some("SN-99"));
        assert_eq!(ecu.location_str(), Some("ENGINE BAY"));
        assert_eq!(ecu.ecu_type_str(), Some("ECM"));
        assert_eq!(ecu.manufacturer_name_str(), Some("ACME MOTORS"));
        assert_eq!(ecu.part_number(), Some(b"PN-1234".as_slice()));
    }

    #[test]
    fn missing_trailing_fields_read_as_none() {
        // A device that only reports the first two fields.
        let ecu = EcuIdentification::new(b"PN-1234*SN-99*");
        assert_eq!(ecu.part_number_str(), Some("PN-1234"));
        assert_eq!(ecu.location(), None);
        assert_eq!(ecu.manufacturer_name(), None);
        assert_eq!(ecu.field_count(), 2);
    }

    #[test]
    fn component_identification_maps_fields_to_names() {
        let component = ComponentIdentification::new(b"CUMMINS*ISX15*79000123*UN-4*");
        assert_eq!(component.make_str(), Some("CUMMINS"));
        assert_eq!(component.model_str(), Some("ISX15"));
        assert_eq!(component.serial_number_str(), Some("79000123"));
        assert_eq!(component.unit_number_str(), Some("UN-4"));
    }

    #[test]
    fn non_utf8_fields_read_as_none_but_bytes_survive() {
        let payload = [0xFF, 0xFE, DELIMITER];
        let ecu = EcuIdentification::new(&payload);
        assert_eq!(ecu.part_number(), Some([0xFF, 0xFE].as_slice()));
        assert_eq!(ecu.part_number_str(), None, "invalid UTF-8 is not a string");
    }

    #[test]
    fn software_identification_consumes_the_count_byte() {
        let software = SoftwareIdentification::parse(b"\x02BOOT-1.0*APP-2.4.1*").unwrap();
        assert_eq!(software.declared_field_count(), 2);
        assert_eq!(software.field_count(), 2);
        assert!(software.count_is_consistent());
        assert_eq!(software.field_str(0), Some("BOOT-1.0"));
        assert_eq!(software.field_str(1), Some("APP-2.4.1"));
        assert_eq!(software.field(2), None);
    }

    #[test]
    fn software_identification_detects_a_lying_count() {
        // Claims five fields, carries two.
        let software = SoftwareIdentification::parse(b"\x05BOOT*APP*").unwrap();
        assert_eq!(software.declared_field_count(), 5);
        assert_eq!(software.field_count(), 2);
        assert!(!software.count_is_consistent());
    }

    #[test]
    fn software_identification_rejects_an_empty_payload() {
        assert_eq!(
            SoftwareIdentification::parse(b""),
            Err(Error::ShortPayload {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn encoding_round_trips() {
        let values: [&[u8]; 3] = [b"ACME", b"MODEL-7", b"SN-1234"];
        let mut buf = [0u8; 64];
        let len = encode(&values, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"ACME*MODEL-7*SN-1234*");

        let collected: std::vec::Vec<&[u8]> = fields(&buf[..len]).collect();
        assert_eq!(collected, values);
    }

    #[test]
    fn software_encoding_round_trips_with_its_count_byte() {
        let values: [&[u8]; 2] = [b"BOOT-1.0", b"APP-2.4.1"];
        let mut buf = [0u8; 64];
        let len = SoftwareIdentification::encode(&values, &mut buf).unwrap();
        assert_eq!(buf[0], 2, "count byte leads the payload");

        let parsed = SoftwareIdentification::parse(&buf[..len]).unwrap();
        assert!(parsed.count_is_consistent());
        assert_eq!(parsed.field_str(1), Some("APP-2.4.1"));
    }

    #[test]
    fn encoding_rejects_an_undersized_buffer() {
        let values: [&[u8]; 1] = [b"ACME"];
        let mut small = [0u8; 4]; // needs 5: four bytes plus the delimiter
        assert_eq!(
            encode(&values, &mut small),
            Err(Error::ShortPayload {
                expected: 5,
                actual: 4
            })
        );
    }

    /// Identification messages exceed a CAN frame, which is why they are
    /// requested and answered over the transport protocol.
    #[test]
    fn an_ecu_identification_survives_a_bam_round_trip() {
        use crate::pgn;
        use crate::tp::{Reassembler, Rx, Transmitter};
        use crate::types::Address;

        let values: [&[u8]; 5] = [b"PN-1234", b"SN-99", b"ENGINE BAY", b"ECM", b"ACME MOTORS"];
        let mut payload = [0u8; 128];
        let len = encode(&values, &mut payload).unwrap();
        assert!(len > 8, "identification must not fit a single frame");

        let ecu_address = Address::new(0x80);
        let mut tx = Transmitter::broadcast(pgn::ECU_IDENTIFICATION, &payload[..len]).unwrap();
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(ecu_address, &tx.start());

        let mut received = None;
        while let Some(packet) = tx.next_packet() {
            if let Rx::Message { pgn, data, .. } = rx.on_tp_dt(ecu_address, &packet) {
                assert_eq!(pgn, pgn::ECU_IDENTIFICATION);
                received = Some(data.to_vec());
            }
        }

        let received = received.expect("the identification should reassemble");
        let ecu = EcuIdentification::new(&received);
        assert_eq!(ecu.part_number_str(), Some("PN-1234"));
        assert_eq!(ecu.manufacturer_name_str(), Some("ACME MOTORS"));
    }
}
