// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The task controller (ISO 11783-10): process data.
//!
//! A **task controller** is the thing on a tractor that runs a field job: it
//! knows the prescription map, logs what was applied, and tells the implement
//! what to do. Everything it exchanges with an implement travels in one
//! parameter group — **Process Data**, PGN `0x00CB00` — and every message in it
//! has the same eight-byte shape:
//!
//! ```text
//! byte 0    element number bits 3..0 (high nibble) | command (low nibble)
//! byte 1    element number bits 11..4
//! bytes 2-3 DDI — which quantity this is, 16-bit little-endian
//! bytes 4-7 value, 32-bit little-endian, signed
//! ```
//!
//! Three fields answer three questions: the **element** is *which part of the
//! implement* (boom section 7, hopper 2), the **DDI** is *what quantity*
//! (application rate, working width), and the **command** is *what to do about
//! it* (tell me, here it is, tell me when it changes).
//!
//! ```
//! use sae_j1939_rs::iso11783::task_controller::{ddi, Command, ProcessData};
//!
//! // "Implement, what is section 7's actual application rate?"
//! let request = ProcessData::new(Command::RequestValue, 7, ddi::ACTUAL_MASS_PER_AREA_RATE, 0)
//!     .unwrap();
//! assert_eq!(ProcessData::decode(&request.encode()), request);
//!
//! // The implement answers with the same element and DDI, a different command.
//! let reply = ProcessData::new(Command::Value, 7, ddi::ACTUAL_MASS_PER_AREA_RATE, 12_500)
//!     .unwrap();
//! assert_eq!(reply.value, 12_500);
//! ```
//!
//! # Before any of that: the device descriptor
//!
//! An implement first uploads a **device descriptor object pool**, describing
//! every element and DDI it supports. That structure runs to tens of kilobytes,
//! which is more than [`crate::tp`] can carry — it is the reason
//! [`crate::etp`] exists. See [`DeviceDescriptor`].
//!
//! # Verification status
//!
//! Built from the structure ISO 11783-10 describes, not cross-checked against
//! the Open-SAE-J1939 C reference, which does not cover the task controller.
//! The DDI list is a small selection of well-known identifiers; the full data
//! dictionary is ISO 11783-11 and runs to hundreds of entries.

use crate::pgn::Pgn;
use crate::types::{Error, Result};

/// Process Data (ISO 11783-10): everything a task controller and an implement
/// say to each other.
pub const PROCESS_DATA: Pgn = Pgn::new_masked(0x00CB00);

/// The largest element number: the field is 12 bits.
pub const MAX_ELEMENT: u16 = 0x0FFF;

/// The element number that means "the device itself" rather than one of its
/// parts.
pub const DEVICE_ELEMENT: u16 = 0;

/// What a [`ProcessData`] message is asking for or reporting.
///
/// The low nibble of byte 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Technical capabilities: version and supported options.
    TechnicalCapabilities,
    /// A chunk of the device descriptor object pool.
    DeviceDescriptor,
    /// "Send me this value."
    RequestValue,
    /// "Here is this value." Also used to set one on the implement.
    Value,
    /// "Report this value every so many milliseconds."
    MeasurementTimeInterval,
    /// "Report this value every so many millimetres travelled."
    MeasurementDistanceInterval,
    /// "Report when this value falls below the threshold."
    MeasurementMinimumThreshold,
    /// "Report when this value rises above the threshold."
    MeasurementMaximumThreshold,
    /// "Report when this value changes by more than the threshold."
    MeasurementChangeThreshold,
    /// Hand control of a value to another ECU on the bus.
    PeerControlAssignment,
    /// Set a value and acknowledge that it was set.
    SetValueAndAcknowledge,
    /// A command outside the set this module models (4 bits).
    Other(u8),
}

impl Command {
    /// The 4-bit wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            Command::TechnicalCapabilities => 0,
            Command::DeviceDescriptor => 1,
            Command::RequestValue => 2,
            Command::Value => 3,
            Command::MeasurementTimeInterval => 4,
            Command::MeasurementDistanceInterval => 5,
            Command::MeasurementMinimumThreshold => 6,
            Command::MeasurementMaximumThreshold => 7,
            Command::MeasurementChangeThreshold => 8,
            Command::PeerControlAssignment => 9,
            Command::SetValueAndAcknowledge => 10,
            Command::Other(raw) => raw & 0x0F,
        }
    }

    /// Decode the 4-bit wire value.
    pub const fn from_u8(raw: u8) -> Self {
        match raw & 0x0F {
            0 => Command::TechnicalCapabilities,
            1 => Command::DeviceDescriptor,
            2 => Command::RequestValue,
            3 => Command::Value,
            4 => Command::MeasurementTimeInterval,
            5 => Command::MeasurementDistanceInterval,
            6 => Command::MeasurementMinimumThreshold,
            7 => Command::MeasurementMaximumThreshold,
            8 => Command::MeasurementChangeThreshold,
            9 => Command::PeerControlAssignment,
            10 => Command::SetValueAndAcknowledge,
            other => Command::Other(other),
        }
    }

    /// Whether this command sets up periodic or conditional reporting, rather
    /// than asking once.
    ///
    /// These four are why a task controller does not have to poll: it says once
    /// what it wants to hear about, and the implement volunteers it thereafter.
    pub const fn is_measurement_trigger(self) -> bool {
        matches!(
            self,
            Command::MeasurementTimeInterval
                | Command::MeasurementDistanceInterval
                | Command::MeasurementMinimumThreshold
                | Command::MeasurementMaximumThreshold
                | Command::MeasurementChangeThreshold
        )
    }
}

/// A Data Dictionary Identifier: *which quantity* a message is about.
///
/// ISO 11783-11 assigns these. The [`ddi`] module names a few common ones; the
/// full dictionary runs to hundreds, so treat these as a starting point and use
/// [`Ddi::new`] for anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ddi(u16);

impl Ddi {
    /// The identifier with this number.
    pub const fn new(number: u16) -> Self {
        Ddi(number)
    }

    /// The raw identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Whether this is in the proprietary range, where the meaning is the
    /// manufacturer's rather than the standard's.
    pub const fn is_proprietary(self) -> bool {
        self.0 >= 0xDFFF
    }
}

impl core::fmt::Display for Ddi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DDI {}", self.0)
    }
}

/// A selection of well-known Data Dictionary Identifiers.
///
/// Not the full ISO 11783-11 dictionary — that runs to hundreds of entries and
/// is revised regularly. These are the ones a sprayer or spreader task uses
/// most; build others with [`Ddi::new`].
pub mod ddi {
    use super::Ddi;

    /// Setpoint volume per area application rate (DDI 1), in mm³/m².
    pub const SETPOINT_VOLUME_PER_AREA_RATE: Ddi = Ddi::new(1);
    /// Actual volume per area application rate (DDI 2), in mm³/m².
    pub const ACTUAL_VOLUME_PER_AREA_RATE: Ddi = Ddi::new(2);
    /// Setpoint mass per area application rate (DDI 5), in mg/m².
    pub const SETPOINT_MASS_PER_AREA_RATE: Ddi = Ddi::new(5);
    /// Actual mass per area application rate (DDI 6), in mg/m².
    pub const ACTUAL_MASS_PER_AREA_RATE: Ddi = Ddi::new(6);
    /// Setpoint count per area application rate (DDI 9), per m².
    pub const SETPOINT_COUNT_PER_AREA_RATE: Ddi = Ddi::new(9);
    /// Actual count per area application rate (DDI 10), per m².
    pub const ACTUAL_COUNT_PER_AREA_RATE: Ddi = Ddi::new(10);
    /// Actual working width (DDI 67), in mm.
    pub const ACTUAL_WORKING_WIDTH: Ddi = Ddi::new(67);
    /// Setpoint working width (DDI 68), in mm.
    pub const SETPOINT_WORKING_WIDTH: Ddi = Ddi::new(68);
    /// Section control state (DDI 141).
    pub const SECTION_CONTROL_STATE: Ddi = Ddi::new(141);
    /// Actual work state (DDI 141 family): whether the implement is working.
    pub const ACTUAL_WORK_STATE: Ddi = Ddi::new(142);
    /// Total area worked (DDI 116), in m².
    pub const TOTAL_AREA: Ddi = Ddi::new(116);
    /// Effective total distance (DDI 117), in mm.
    pub const EFFECTIVE_TOTAL_DISTANCE: Ddi = Ddi::new(117);
    /// The request-default-process-data identifier (DDI 0xDFFF), which asks for
    /// everything the element supports rather than one quantity.
    pub const REQUEST_DEFAULT_PROCESS_DATA: Ddi = Ddi::new(0xDFFF);
}

/// One Process Data message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessData {
    /// What to do about the value.
    pub command: Command,
    /// Which part of the implement this concerns (12 bits).
    ///
    /// [`DEVICE_ELEMENT`] means the device as a whole.
    pub element: u16,
    /// Which quantity.
    pub ddi: Ddi,
    /// The value, signed. What it means depends entirely on the DDI — a rate, a
    /// width in millimetres, a state, an interval.
    pub value: i32,
}

impl ProcessData {
    /// Build a Process Data message.
    ///
    /// Returns [`Error::ValueOutOfRange`] if `element` exceeds
    /// [`MAX_ELEMENT`], since the field is 12 bits and a larger number would
    /// silently address a different element.
    pub const fn new(command: Command, element: u16, ddi: Ddi, value: i32) -> Result<Self> {
        if element > MAX_ELEMENT {
            return Err(Error::ValueOutOfRange {
                field: "process data element",
                value: element as u32,
            });
        }
        Ok(ProcessData {
            command,
            element,
            ddi,
            value,
        })
    }

    /// Ask an element for a value.
    pub const fn request(element: u16, ddi: Ddi) -> Result<Self> {
        Self::new(Command::RequestValue, element, ddi, 0)
    }

    /// Report a value for an element.
    pub const fn report(element: u16, ddi: Ddi, value: i32) -> Result<Self> {
        Self::new(Command::Value, element, ddi, value)
    }

    /// Encode to the eight-byte payload.
    ///
    /// ```
    /// use sae_j1939_rs::iso11783::task_controller::{ddi, Command, ProcessData};
    ///
    /// // Element 7, DDI 6, value 12500.
    /// let message = ProcessData::new(Command::Value, 7, ddi::ACTUAL_MASS_PER_AREA_RATE, 12_500)
    ///     .unwrap();
    /// let bytes = message.encode();
    /// assert_eq!(bytes[0], (7 << 4) | 3, "element low nibble, then the command");
    /// assert_eq!(bytes[1], 0, "element high bits");
    /// assert_eq!(&bytes[2..4], &[6, 0], "DDI, little-endian");
    /// assert_eq!(&bytes[4..], &12_500i32.to_le_bytes());
    /// ```
    pub const fn encode(&self) -> [u8; 8] {
        let value = self.value.to_le_bytes();
        [
            ((self.element as u8 & 0x0F) << 4) | self.command.as_u8(),
            (self.element >> 4) as u8,
            self.ddi.as_u16() as u8,
            (self.ddi.as_u16() >> 8) as u8,
            value[0],
            value[1],
            value[2],
            value[3],
        ]
    }

    /// Decode an eight-byte payload.
    ///
    /// Infallible: every byte pattern is a valid message. The element field is
    /// 12 bits wide on the wire, so it cannot overflow coming in.
    pub const fn decode(data: &[u8; 8]) -> Self {
        ProcessData {
            command: Command::from_u8(data[0]),
            element: ((data[0] >> 4) as u16) | ((data[1] as u16) << 4),
            ddi: Ddi::new((data[2] as u16) | ((data[3] as u16) << 8)),
            value: i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        }
    }
}

/// The device descriptor object pool: what an implement can do.
///
/// Before a task controller can ask for anything, the implement uploads a
/// structure listing every element it has and every DDI each supports. That
/// structure is large — tens of kilobytes for a section-controlled sprayer —
/// which is precisely why the extended transport protocol exists.
///
/// This type does not parse the pool's internal object format, which is a
/// substantial binary structure in its own right. What it does is get the
/// transfer right: the pool is sent as [`Command::DeviceDescriptor`] process
/// data over [`crate::etp`], and this reports whether a given payload needs
/// that.
///
/// ```
/// use sae_j1939_rs::iso11783::task_controller::DeviceDescriptor;
///
/// // A realistic pool is far past what the ordinary transport protocol carries.
/// assert!(DeviceDescriptor::needs_extended_transport(40_000));
/// assert!(!DeviceDescriptor::needs_extended_transport(500));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDescriptor;

impl DeviceDescriptor {
    /// Whether a pool of this size needs [`crate::etp`] rather than
    /// [`crate::tp`].
    ///
    /// The boundary is the ordinary protocol's 1785-byte ceiling. A real object
    /// pool is almost always past it, which is the practical reason ISOBUS
    /// requires the extended protocol at all.
    pub const fn needs_extended_transport(size: usize) -> bool {
        size > crate::tp::MAX_MESSAGE_SIZE as usize
    }

    /// The process data message announcing a device descriptor transfer.
    pub const fn announcement(element: u16, size: u32) -> Result<ProcessData> {
        ProcessData::new(Command::DeviceDescriptor, element, Ddi::new(0), size as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_element_field_spans_two_bytes() {
        // 12 bits: the low nibble shares byte 0 with the command, the rest is
        // byte 1. Getting the split wrong addresses a different part of the
        // implement, which is the kind of mistake that applies fertiliser to the
        // wrong section.
        for element in [0u16, 1, 0x0F, 0x10, 0xFF, 0x100, MAX_ELEMENT] {
            let message =
                ProcessData::new(Command::Value, element, ddi::ACTUAL_WORKING_WIDTH, 0).unwrap();
            let decoded = ProcessData::decode(&message.encode());
            assert_eq!(decoded.element, element, "element {element:#x}");
            assert_eq!(decoded.command, Command::Value, "element {element:#x}");
        }
    }

    #[test]
    fn an_element_beyond_twelve_bits_is_refused() {
        assert_eq!(
            ProcessData::new(
                Command::Value,
                MAX_ELEMENT + 1,
                ddi::ACTUAL_WORKING_WIDTH,
                0
            ),
            Err(Error::ValueOutOfRange {
                field: "process data element",
                value: 0x1000
            })
        );
        assert!(
            ProcessData::new(Command::Value, MAX_ELEMENT, ddi::ACTUAL_WORKING_WIDTH, 0).is_ok()
        );
    }

    #[test]
    fn every_command_round_trips_alongside_its_element() {
        let commands = [
            Command::TechnicalCapabilities,
            Command::DeviceDescriptor,
            Command::RequestValue,
            Command::Value,
            Command::MeasurementTimeInterval,
            Command::MeasurementDistanceInterval,
            Command::MeasurementMinimumThreshold,
            Command::MeasurementMaximumThreshold,
            Command::MeasurementChangeThreshold,
            Command::PeerControlAssignment,
            Command::SetValueAndAcknowledge,
            Command::Other(0x0F),
        ];
        for command in commands {
            for element in [0u16, 7, 0x0F, 0xABC] {
                let message =
                    ProcessData::new(command, element, ddi::ACTUAL_MASS_PER_AREA_RATE, -1).unwrap();
                let decoded = ProcessData::decode(&message.encode());
                assert_eq!(decoded.command, command);
                assert_eq!(decoded.element, element);
            }
            assert_eq!(Command::from_u8(command.as_u8()), command);
        }
    }

    /// A value is signed: a rate correction or a position offset can be
    /// negative, and reading one as unsigned would be a very large number.
    #[test]
    fn values_round_trip_across_the_signed_range() {
        for value in [0i32, 1, -1, i32::MAX, i32::MIN, 12_500, -12_500] {
            let message =
                ProcessData::new(Command::Value, 3, ddi::ACTUAL_VOLUME_PER_AREA_RATE, value)
                    .unwrap();
            assert_eq!(ProcessData::decode(&message.encode()).value, value);
        }
    }

    #[test]
    fn ddis_round_trip_across_the_whole_range() {
        for number in [0u16, 1, 6, 255, 256, 0xDFFF, 0xFFFF] {
            let ddi = Ddi::new(number);
            let message = ProcessData::new(Command::Value, 1, ddi, 0).unwrap();
            assert_eq!(ProcessData::decode(&message.encode()).ddi, ddi);
            assert_eq!(ddi.as_u16(), number);
        }
        assert!(!ddi::ACTUAL_MASS_PER_AREA_RATE.is_proprietary());
        assert!(ddi::REQUEST_DEFAULT_PROCESS_DATA.is_proprietary());
    }

    /// The measurement triggers are what let a task controller stop polling.
    #[test]
    fn measurement_triggers_are_distinguishable() {
        for command in [
            Command::MeasurementTimeInterval,
            Command::MeasurementDistanceInterval,
            Command::MeasurementMinimumThreshold,
            Command::MeasurementMaximumThreshold,
            Command::MeasurementChangeThreshold,
        ] {
            assert!(command.is_measurement_trigger(), "{command:?}");
        }
        for command in [
            Command::RequestValue,
            Command::Value,
            Command::DeviceDescriptor,
            Command::SetValueAndAcknowledge,
        ] {
            assert!(!command.is_measurement_trigger(), "{command:?}");
        }
    }

    /// A request and its answer differ only in the command and the value, which
    /// is what lets an implement match one to the other.
    #[test]
    fn a_request_and_its_answer_share_element_and_ddi() {
        let request = ProcessData::request(7, ddi::ACTUAL_MASS_PER_AREA_RATE).unwrap();
        let answer = ProcessData::report(7, ddi::ACTUAL_MASS_PER_AREA_RATE, 12_500).unwrap();

        assert_eq!(request.command, Command::RequestValue);
        assert_eq!(answer.command, Command::Value);
        assert_eq!(request.element, answer.element);
        assert_eq!(request.ddi, answer.ddi);
        assert_eq!(request.value, 0);
        assert_eq!(answer.value, 12_500);
    }

    #[test]
    fn a_device_descriptor_needs_the_extended_protocol() {
        assert!(!DeviceDescriptor::needs_extended_transport(8));
        assert!(!DeviceDescriptor::needs_extended_transport(1785));
        assert!(DeviceDescriptor::needs_extended_transport(1786));
        assert!(DeviceDescriptor::needs_extended_transport(40_000));

        let announce = DeviceDescriptor::announcement(DEVICE_ELEMENT, 40_000).unwrap();
        assert_eq!(announce.command, Command::DeviceDescriptor);
        assert_eq!(announce.value, 40_000);
    }

    /// The whole point of ETP, end to end: a 40 KiB object pool travels from an
    /// implement to a task controller and arrives intact.
    #[test]
    fn an_object_pool_crosses_the_bus_over_the_extended_protocol() {
        use crate::etp::{EtpCm, Reassembler, Rx, Transmitter, Tx};
        use crate::pgn;
        use crate::types::Address;

        let implement = Address::new(0x80);
        // A plausible pool: 40 KiB of structured bytes.
        let pool: std::vec::Vec<u8> = (0..40_000).map(|i| (i * 17 % 253) as u8).collect();
        assert!(DeviceDescriptor::needs_extended_transport(pool.len()));

        let mut tx = Transmitter::new(pgn::PROPRIETARY_A, &pool).unwrap();
        let mut rx = Reassembler::<65_536>::new();

        let mut response = match rx.on_etp_cm(implement, &tx.start()) {
            Rx::Send(cm) => Some(cm),
            other => panic!("expected a CTS, got {other:?}"),
        };

        let mut delivered = None;
        'transfer: while let Some(cm) = response.take() {
            assert_eq!(tx.on_etp_cm(&cm), Tx::SendData);
            let dpo = tx.offset().expect("each block needs its offset");
            rx.on_etp_cm(implement, &dpo);

            while let Some(packet) = tx.next_packet() {
                match rx.on_etp_dt(implement, &packet) {
                    Rx::Idle => {}
                    Rx::Send(next) => response = Some(next),
                    Rx::Message { data, ack, .. } => {
                        delivered = Some(data.to_vec());
                        assert!(matches!(ack, EtpCm::Eoma { .. }));
                        break 'transfer;
                    }
                }
            }
        }

        assert_eq!(
            delivered.as_deref(),
            Some(pool.as_slice()),
            "a 40 KiB object pool must arrive intact"
        );
    }
}
