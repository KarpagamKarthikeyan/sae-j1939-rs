// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! J1939-73 memory access: DM14, DM15, and DM16.
//!
//! These three parameter groups form the read/write protocol a tool uses to
//! reach an ECU's flash, EEPROM, or variables — the basis of calibration and
//! bootloading.
//!
//! - **DM14** (`0x00D900`) — the *request*: read or write this many bytes at
//!   this address, with a security key.
//! - **DM15** (`0x00D800`) — the *response*: proceed, busy, completed, or
//!   failed, plus a seed for the next key.
//! - **DM16** (`0x00D700`) — the *data*: the bytes themselves.
//!
//! A transfer is a conversation: DM14 request → DM15 response → DM16 data →
//! DM15 confirmation. Anything longer than seven data bytes travels over the
//! transport protocol ([`crate::tp`]).
//!
//! ```
//! use sae_j1939_rs::memory_access::{pointer_extension, Dm14, MemoryCommand, PointerType};
//!
//! // Ask to read 16 bytes from EEPROM at 0x1000.
//! let request = Dm14::new(16, MemoryCommand::Read, 0x1000)
//!     .unwrap()
//!     .with_pointer_extension(pointer_extension::EEPROM)
//!     .with_key(0xFFFF);
//!
//! // Naming a memory space makes the extension a selector, not address bits.
//! assert_eq!(request.pointer_type, PointerType::ExtensionIsCommand);
//! assert_eq!(Dm14::decode(&request.encode()), request);
//! ```
//!
//! # A caution
//!
//! Memory access writes to a live ECU. The security-key exchange in DM14/DM15
//! is deliberately weak by modern standards — it is an interlock against
//! accidents, not an authentication mechanism. Treat a bus that carries these
//! messages as a trusted network.

use crate::types::{Error, Result};

/// The largest byte count DM14/DM15 can express: the field is 11 bits.
pub const MAX_BYTE_COUNT: u16 = 0x07FF;

/// The largest memory pointer DM14 can express: the field is 24 bits.
pub const MAX_POINTER: u32 = 0x00FF_FFFF;

/// The largest EDC parameter DM15 can express: the field is 24 bits.
pub const MAX_EDC_PARAMETER: u32 = 0x00FF_FFFF;

/// What a [`Dm14`] asks the ECU to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryCommand {
    /// Erase the addressed region.
    Erase,
    /// Read from the addressed region.
    Read,
    /// Write to the addressed region.
    Write,
    /// Ask for the status of an operation in progress.
    StatusRequest,
    /// Report that the operation finished.
    OperationCompleted,
    /// Report that the operation failed.
    OperationFailed,
    /// Enter the boot loader.
    BootLoad,
    /// Generate an error-detection code.
    EdcpGeneration,
}

impl MemoryCommand {
    /// The 3-bit wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            MemoryCommand::Erase => 0,
            MemoryCommand::Read => 1,
            MemoryCommand::Write => 2,
            MemoryCommand::StatusRequest => 3,
            MemoryCommand::OperationCompleted => 4,
            MemoryCommand::OperationFailed => 5,
            MemoryCommand::BootLoad => 6,
            MemoryCommand::EdcpGeneration => 7,
        }
    }

    /// Decode the 3-bit wire value. Only the low three bits are considered, so
    /// this is total — every input maps to a command.
    pub const fn from_u8(raw: u8) -> Self {
        match raw & 0b111 {
            0 => MemoryCommand::Erase,
            1 => MemoryCommand::Read,
            2 => MemoryCommand::Write,
            3 => MemoryCommand::StatusRequest,
            4 => MemoryCommand::OperationCompleted,
            5 => MemoryCommand::OperationFailed,
            6 => MemoryCommand::BootLoad,
            _ => MemoryCommand::EdcpGeneration,
        }
    }
}

/// How the pointer and pointer extension of a [`Dm14`] combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PointerType {
    /// The extension is the high-order part of the address: a 32-bit pointer
    /// split across the two fields.
    #[default]
    JoinWithExtension,
    /// The extension is a command selecting *which* memory space the pointer
    /// addresses — see [`pointer_extension`].
    ExtensionIsCommand,
}

impl PointerType {
    const fn as_bit(self) -> u8 {
        match self {
            PointerType::JoinWithExtension => 0,
            PointerType::ExtensionIsCommand => 1,
        }
    }

    const fn from_bit(bit: u8) -> Self {
        if bit & 1 == 1 {
            PointerType::ExtensionIsCommand
        } else {
            PointerType::JoinWithExtension
        }
    }
}

/// Pointer extension values that name a memory space, used when
/// [`PointerType::ExtensionIsCommand`] is set.
pub mod pointer_extension {
    /// Flash memory.
    pub const FLASH: u8 = 0;
    /// EEPROM.
    pub const EEPROM: u8 = 1;
    /// Program variables in RAM.
    pub const VARIABLE: u8 = 2;
}

/// Well-known DM14 key values.
pub mod key {
    /// No key is available or required.
    pub const NONE: u16 = 0xFFFF;
}

/// DM14 — a memory access request.
///
/// ```text
/// byte 0    byte count, low 8 bits
/// byte 1    byte count bits 10..8 (top 3) | reserved | pointer type | command (3 bits) | reserved
/// bytes 2-4 pointer, little-endian
/// byte 5    pointer extension
/// bytes 6-7 key, little-endian
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dm14 {
    /// How many bytes are being requested (11 bits).
    pub requested_bytes: u16,
    /// What to do.
    pub command: MemoryCommand,
    /// How `pointer` and `pointer_extension` combine.
    pub pointer_type: PointerType,
    /// The memory address (24 bits).
    pub pointer: u32,
    /// The high-order address bits, or a memory-space selector — see
    /// [`pointer_type`](Dm14::pointer_type).
    pub pointer_extension: u8,
    /// The security key. [`key::NONE`] when none is required.
    pub key: u16,
}

impl Dm14 {
    /// Build a request for `requested_bytes` at `pointer`.
    ///
    /// Returns [`Error::ValueOutOfRange`] if `requested_bytes` exceeds
    /// [`MAX_BYTE_COUNT`] or `pointer` exceeds [`MAX_POINTER`].
    pub const fn new(requested_bytes: u16, command: MemoryCommand, pointer: u32) -> Result<Self> {
        if requested_bytes > MAX_BYTE_COUNT {
            return Err(Error::ValueOutOfRange {
                field: "requested_bytes",
                value: requested_bytes as u32,
            });
        }
        if pointer > MAX_POINTER {
            return Err(Error::ValueOutOfRange {
                field: "pointer",
                value: pointer,
            });
        }
        Ok(Dm14 {
            requested_bytes,
            command,
            pointer_type: PointerType::JoinWithExtension,
            pointer,
            pointer_extension: 0,
            key: key::NONE,
        })
    }

    /// Set the pointer extension, and mark it as a memory-space selector.
    #[must_use]
    pub const fn with_pointer_extension(mut self, extension: u8) -> Self {
        self.pointer_extension = extension;
        self.pointer_type = PointerType::ExtensionIsCommand;
        self
    }

    /// Set the security key.
    #[must_use]
    pub const fn with_key(mut self, key: u16) -> Self {
        self.key = key;
        self
    }

    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.requested_bytes as u8,
            pack_count_and_command(
                self.requested_bytes,
                self.pointer_type.as_bit(),
                self.command.as_u8(),
            ),
            self.pointer as u8,
            (self.pointer >> 8) as u8,
            (self.pointer >> 16) as u8,
            self.pointer_extension,
            self.key as u8,
            (self.key >> 8) as u8,
        ]
    }

    /// Decode an eight-byte DM14 payload.
    ///
    /// Infallible: every byte pattern is a valid DM14, because the reserved
    /// bits carry no meaning, every 3-bit command is defined, and the count and
    /// pointer fields cannot overflow their widths coming off the wire.
    pub const fn decode(data: &[u8; 8]) -> Self {
        Dm14 {
            requested_bytes: unpack_count(data[0], data[1]),
            command: MemoryCommand::from_u8(data[1] >> 1),
            pointer_type: PointerType::from_bit(data[1] >> 4),
            pointer: (data[2] as u32) | ((data[3] as u32) << 8) | ((data[4] as u32) << 16),
            pointer_extension: data[5],
            key: u16::from_le_bytes([data[6], data[7]]),
        }
    }
}

/// The status an ECU reports in a [`Dm15`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryStatus {
    /// Go ahead with the requested operation.
    Proceed,
    /// Busy; try again later.
    Busy,
    /// The operation finished successfully.
    OperationCompleted,
    /// The operation failed.
    OperationFailed,
    /// A status outside the set J1939-73 defines (3 bits).
    Other(u8),
}

impl MemoryStatus {
    /// The 3-bit wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            MemoryStatus::Proceed => 0,
            MemoryStatus::Busy => 1,
            MemoryStatus::OperationCompleted => 4,
            MemoryStatus::OperationFailed => 5,
            MemoryStatus::Other(raw) => raw & 0b111,
        }
    }

    /// Decode the 3-bit wire value.
    pub const fn from_u8(raw: u8) -> Self {
        match raw & 0b111 {
            0 => MemoryStatus::Proceed,
            1 => MemoryStatus::Busy,
            4 => MemoryStatus::OperationCompleted,
            5 => MemoryStatus::OperationFailed,
            other => MemoryStatus::Other(other),
        }
    }
}

/// Well-known DM15 seed values.
pub mod seed {
    /// No further keys are needed for this process.
    pub const NO_MORE_KEYS_NEEDED: u16 = 0x0000;
    /// A long key is required.
    pub const USE_LONG_KEY: u16 = 0x0001;
    /// No key is used at all.
    pub const NO_KEY_USED: u16 = 0xFFFF;
}

/// DM15 — the response to a [`Dm14`].
///
/// The byte layout mirrors DM14: an 11-bit count split across bytes 0 and 1,
/// the 3-bit status where DM14 has its command, a 24-bit parameter, an
/// extension byte, and a 16-bit seed where DM14 has its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dm15 {
    /// How many bytes the ECU will allow (11 bits).
    pub allowed_bytes: u16,
    /// How the request was received.
    pub status: MemoryStatus,
    /// A status or error code qualifying `status` (24 bits).
    pub edc_parameter: u32,
    /// How to interpret `edc_parameter`.
    pub edcp_extension: u8,
    /// The seed for the next key, or one of the [`seed`] constants.
    pub seed: u16,
}

impl Dm15 {
    /// Build a response allowing `allowed_bytes`.
    ///
    /// Returns [`Error::ValueOutOfRange`] if `allowed_bytes` exceeds
    /// [`MAX_BYTE_COUNT`].
    pub const fn new(allowed_bytes: u16, status: MemoryStatus) -> Result<Self> {
        if allowed_bytes > MAX_BYTE_COUNT {
            return Err(Error::ValueOutOfRange {
                field: "allowed_bytes",
                value: allowed_bytes as u32,
            });
        }
        Ok(Dm15 {
            allowed_bytes,
            status,
            edc_parameter: 0,
            edcp_extension: 0xFF,
            seed: seed::NO_KEY_USED,
        })
    }

    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.allowed_bytes as u8,
            // DM15 has no pointer-type bit; that position is reserved and set.
            pack_count_and_command(self.allowed_bytes, 1, self.status.as_u8()),
            self.edc_parameter as u8,
            (self.edc_parameter >> 8) as u8,
            (self.edc_parameter >> 16) as u8,
            self.edcp_extension,
            self.seed as u8,
            (self.seed >> 8) as u8,
        ]
    }

    /// Decode an eight-byte DM15 payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        Dm15 {
            allowed_bytes: unpack_count(data[0], data[1]),
            status: MemoryStatus::from_u8(data[1] >> 1),
            edc_parameter: (data[2] as u32) | ((data[3] as u32) << 8) | ((data[4] as u32) << 16),
            edcp_extension: data[5],
            seed: u16::from_le_bytes([data[6], data[7]]),
        }
    }
}

/// Byte 1 of DM14/DM15: the count's top three bits, a reserved bit, the
/// pointer-type (or reserved) bit, a 3-bit command, and a trailing reserved bit.
const fn pack_count_and_command(count: u16, type_bit: u8, command: u8) -> u8 {
    (((count >> 3) as u8) & 0xE0) | ((type_bit & 1) << 4) | ((command & 0b111) << 1) | 1
}

/// Recover the 11-bit count from bytes 0 and 1.
const fn unpack_count(low: u8, packed: u8) -> u16 {
    (((packed & 0xE0) as u16) << 3) | low as u16
}

/// DM16 — a binary data transfer, borrowing its payload.
///
/// ```text
/// byte 0    number of data bytes that follow
/// byte 1+   the data
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dm16<'a> {
    data: &'a [u8],
}

impl<'a> Dm16<'a> {
    /// The most bytes one DM16 can carry: the count field is a single byte.
    pub const MAX_DATA: usize = 255;

    /// Wrap `data` for transmission.
    ///
    /// Returns [`Error::ValueOutOfRange`] if `data` exceeds
    /// [`MAX_DATA`](Dm16::MAX_DATA).
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() > Self::MAX_DATA {
            return Err(Error::ValueOutOfRange {
                field: "dm16 data length",
                value: data.len() as u32,
            });
        }
        Ok(Dm16 { data })
    }

    /// The bytes carried.
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The encoded length: one count byte plus the data, padded out to a full
    /// CAN frame when it fits in one.
    pub fn encoded_len(&self) -> usize {
        (1 + self.data.len()).max(8)
    }

    /// Parse a DM16 payload.
    ///
    /// The leading count byte is authoritative: trailing filler beyond it — the
    /// `0xFF` padding of a single frame — is not part of the data.
    ///
    /// Returns [`Error::ShortPayload`] if the payload is empty, or if it
    /// declares more bytes than it actually carries.
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let Some((&count, rest)) = payload.split_first() else {
            return Err(Error::ShortPayload {
                expected: 1,
                actual: 0,
            });
        };
        let count = count as usize;
        if rest.len() < count {
            return Err(Error::ShortPayload {
                expected: count + 1,
                actual: payload.len(),
            });
        }
        Ok(Dm16 {
            data: &rest[..count],
        })
    }

    /// Encode into `out`, returning how many bytes were written.
    ///
    /// A short transfer is padded to eight bytes with `0xFF` so it fills a CAN
    /// frame; a longer one is `1 + data.len()` bytes and must go over the
    /// transport protocol.
    ///
    /// Returns [`Error::ShortPayload`] if `out` is too small.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize> {
        let len = self.encoded_len();
        if out.len() < len {
            return Err(Error::ShortPayload {
                expected: len,
                actual: out.len(),
            });
        }
        out[0] = self.data.len() as u8;
        out[1..1 + self.data.len()].copy_from_slice(self.data);
        for byte in out[1 + self.data.len()..len].iter_mut() {
            *byte = 0xFF;
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm14_matches_the_reference_bit_packing() {
        let request = Dm14 {
            requested_bytes: 16,
            command: MemoryCommand::Read,
            pointer_type: PointerType::ExtensionIsCommand,
            pointer: 0x001000,
            pointer_extension: pointer_extension::EEPROM,
            key: 0xFFFF,
        };
        // byte 1 = count high bits | pointer type << 4 | command << 1 | reserved
        let expected_byte1 = ((16u16 >> 3) as u8 & 0xE0) | (1 << 4) | (1 << 1) | 1;
        assert_eq!(
            request.encode(),
            [16, expected_byte1, 0x00, 0x10, 0x00, 0x01, 0xFF, 0xFF]
        );
        assert_eq!(Dm14::decode(&request.encode()), request);
    }

    /// The 11-bit byte count is split across two bytes; the top three bits ride
    /// in the high bits of byte 1.
    #[test]
    fn dm14_round_trips_the_full_11_bit_count() {
        for count in [0u16, 1, 255, 256, 1000, MAX_BYTE_COUNT] {
            let request = Dm14::new(count, MemoryCommand::Write, 0).unwrap();
            let decoded = Dm14::decode(&request.encode());
            assert_eq!(decoded.requested_bytes, count, "count {count}");
        }
    }

    #[test]
    fn dm14_round_trips_the_full_24_bit_pointer() {
        for pointer in [0u32, 1, 0xFF, 0x1234, 0xFF_FFFF] {
            let request = Dm14::new(8, MemoryCommand::Read, pointer).unwrap();
            assert_eq!(
                Dm14::decode(&request.encode()).pointer,
                pointer,
                "pointer {pointer:#x}"
            );
        }
    }

    #[test]
    fn dm14_rejects_out_of_range_fields() {
        assert_eq!(
            Dm14::new(MAX_BYTE_COUNT + 1, MemoryCommand::Read, 0),
            Err(Error::ValueOutOfRange {
                field: "requested_bytes",
                value: 2048
            })
        );
        assert_eq!(
            Dm14::new(8, MemoryCommand::Read, MAX_POINTER + 1),
            Err(Error::ValueOutOfRange {
                field: "pointer",
                value: 0x0100_0000
            })
        );
    }

    #[test]
    fn every_memory_command_round_trips() {
        for command in [
            MemoryCommand::Erase,
            MemoryCommand::Read,
            MemoryCommand::Write,
            MemoryCommand::StatusRequest,
            MemoryCommand::OperationCompleted,
            MemoryCommand::OperationFailed,
            MemoryCommand::BootLoad,
            MemoryCommand::EdcpGeneration,
        ] {
            let request = Dm14::new(8, command, 0x100).unwrap();
            assert_eq!(Dm14::decode(&request.encode()).command, command);
            assert_eq!(MemoryCommand::from_u8(command.as_u8()), command);
        }
    }

    #[test]
    fn dm15_matches_the_reference_bit_packing() {
        let response = Dm15 {
            allowed_bytes: 16,
            status: MemoryStatus::Proceed,
            edc_parameter: 0x00_1112,
            edcp_extension: 0x00,
            seed: 0xFFFF,
        };
        let expected_byte1 =
            ((16u16 >> 3) as u8 & 0xE0) | (1 << 4) | (MemoryStatus::Proceed.as_u8() << 1) | 1;
        assert_eq!(
            response.encode(),
            [16, expected_byte1, 0x12, 0x11, 0x00, 0x00, 0xFF, 0xFF]
        );
        assert_eq!(Dm15::decode(&response.encode()), response);
    }

    #[test]
    fn dm15_statuses_round_trip() {
        for status in [
            MemoryStatus::Proceed,
            MemoryStatus::Busy,
            MemoryStatus::OperationCompleted,
            MemoryStatus::OperationFailed,
            MemoryStatus::Other(6),
        ] {
            let response = Dm15::new(32, status).unwrap();
            assert_eq!(Dm15::decode(&response.encode()).status, status);
        }
    }

    #[test]
    fn dm15_rejects_an_out_of_range_count() {
        assert_eq!(
            Dm15::new(MAX_BYTE_COUNT + 1, MemoryStatus::Proceed),
            Err(Error::ValueOutOfRange {
                field: "allowed_bytes",
                value: 2048
            })
        );
    }

    /// DM14 and DM15 share a byte-1 layout, so a count encoded by one must
    /// decode identically from the other.
    #[test]
    fn dm14_and_dm15_agree_on_the_shared_count_field() {
        for count in [0u16, 7, 8, 255, 2047] {
            let request = Dm14::new(count, MemoryCommand::Read, 0).unwrap().encode();
            let response = Dm15::new(count, MemoryStatus::Proceed).unwrap().encode();
            assert_eq!(request[0], response[0], "count {count} low byte");
            assert_eq!(
                request[1] & 0xE0,
                response[1] & 0xE0,
                "count {count} high bits"
            );
        }
    }

    #[test]
    fn dm16_round_trips_and_pads_a_short_transfer() {
        let payload = [0xDE, 0xAD, 0xBE];
        let dm16 = Dm16::new(&payload).unwrap();
        let mut buf = [0u8; 8];
        let len = dm16.encode_into(&mut buf).unwrap();
        assert_eq!(len, 8, "short transfers fill a CAN frame");
        assert_eq!(buf, [3, 0xDE, 0xAD, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF]);

        // The count byte is authoritative: the 0xFF padding is not data.
        let parsed = Dm16::parse(&buf).unwrap();
        assert_eq!(parsed.data(), &payload);
    }

    #[test]
    fn dm16_handles_a_transfer_too_large_for_one_frame() {
        let payload: std::vec::Vec<u8> = (0..100).collect();
        let dm16 = Dm16::new(&payload).unwrap();
        assert_eq!(dm16.encoded_len(), 101);

        let mut buf = [0u8; 128];
        let len = dm16.encode_into(&mut buf).unwrap();
        assert_eq!(len, 101);
        assert_eq!(Dm16::parse(&buf[..len]).unwrap().data(), payload.as_slice());
    }

    #[test]
    fn dm16_rejects_bad_input() {
        // Too much data for the one-byte count field.
        assert!(Dm16::new(&[0u8; 256]).is_err());
        assert!(Dm16::new(&[0u8; 255]).is_ok());

        // An empty payload has no count byte.
        assert_eq!(
            Dm16::parse(&[]),
            Err(Error::ShortPayload {
                expected: 1,
                actual: 0
            })
        );
        // A payload claiming more bytes than it carries is truncated, not silently short.
        assert_eq!(
            Dm16::parse(&[10, 1, 2, 3]),
            Err(Error::ShortPayload {
                expected: 11,
                actual: 4
            })
        );
    }

    #[test]
    fn dm16_encode_rejects_an_undersized_buffer() {
        let dm16 = Dm16::new(&[0u8; 20]).unwrap();
        let mut small = [0u8; 8];
        assert_eq!(
            dm16.encode_into(&mut small),
            Err(Error::ShortPayload {
                expected: 21,
                actual: 8
            })
        );
    }

    /// A realistic exchange: a tool asks to read 16 bytes, the ECU says
    /// proceed, and the data comes back as a DM16 over the transport protocol.
    #[test]
    fn a_read_exchange_flows_end_to_end() {
        use crate::pgn;
        use crate::tp::{Reassembler, Rx, Transmitter};
        use crate::types::Address;

        let tool = Address::new(0x00);
        let ecu = Address::new(0x80);

        // Tool -> ECU: read 16 bytes of EEPROM at 0x1000.
        let request = Dm14::new(16, MemoryCommand::Read, 0x1000)
            .unwrap()
            .with_pointer_extension(pointer_extension::EEPROM);
        let decoded = Dm14::decode(&request.encode());
        assert_eq!(decoded.command, MemoryCommand::Read);
        assert_eq!(decoded.requested_bytes, 16);

        // ECU -> tool: proceed.
        let response = Dm15::new(16, MemoryStatus::Proceed).unwrap();
        assert_eq!(
            Dm15::decode(&response.encode()).status,
            MemoryStatus::Proceed
        );

        // ECU -> tool: 16 bytes of data. 17 encoded bytes needs the transport protocol.
        let memory: [u8; 16] = core::array::from_fn(|i| (i * 3) as u8);
        let dm16 = Dm16::new(&memory).unwrap();
        let mut payload = [0u8; 32];
        let len = dm16.encode_into(&mut payload).unwrap();
        assert!(len > 8, "this transfer must not fit a single frame");

        let mut tx = Transmitter::broadcast(pgn::DM16, &payload[..len]).unwrap();
        let mut rx = Reassembler::<256>::new();
        rx.on_tp_cm(ecu, &tx.start());

        let mut received = None;
        while let Some(packet) = tx.next_packet() {
            if let Rx::Message { data, .. } = rx.on_tp_dt(ecu, &packet) {
                received = Some(data.to_vec());
            }
        }
        let received = received.expect("the DM16 should reassemble");
        assert_eq!(Dm16::parse(&received).unwrap().data(), &memory);
        let _ = tool;
    }
}
