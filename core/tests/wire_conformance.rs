// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte-for-byte conformance against the Open-SAE-J1939 C reference.
//!
//! The module tests check that each codec round-trips, which catches a decoder
//! that disagrees with its own encoder but not one where *both* halves put a
//! field in the wrong place. Only a second implementation can catch that.
//!
//! So every check here builds the expected bytes with the arithmetic the
//! MIT-licensed [Open-SAE-J1939] C reference writes out longhand — transcribed,
//! not copied — and compares. The expressions are deliberately left in their
//! shifted-and-masked form rather than folded into hex literals: a literal says
//! *what* the byte is, and the expression says *why*, which is what a reader
//! needs in order to check it against the standard.
//!
//! Where the reference and J1939 disagree, the standard wins and the difference
//! is called out in a comment.
//!
//! [Open-SAE-J1939]: https://github.com/DanielMartensson/Open-SAE-J1939

use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
use sae_j1939_rs::iso11783::{
    AuxiliaryValveCommand, AuxiliaryValveEstimatedFlow, AuxiliaryValveMeasuredPosition,
    FailSafeMode, GeneralPurposeValveCommand, GeneralPurposeValveEstimatedFlow, ValveNumber,
    ValveState, GENERAL_PURPOSE_VALVE_COMMAND, GENERAL_PURPOSE_VALVE_ESTIMATED_FLOW,
};
use sae_j1939_rs::memory_access::{
    Dm14, Dm15, MemoryCommand, MemoryStatus, PointerType, MAX_BYTE_COUNT,
};
use sae_j1939_rs::request::{AckControl, Acknowledgement, Request};
use sae_j1939_rs::tp::{AbortReason, TpCm, TpDt};
use sae_j1939_rs::{pgn, Address, Id, Name, Pgn, Priority};

/// The three PGN bytes every reference message ends with:
/// `data[5] = PGN; data[6] = PGN >> 8; data[7] = PGN >> 16;`
fn reference_pgn_bytes(group: Pgn) -> [u8; 3] {
    let raw = group.as_u32();
    [raw as u8, (raw >> 8) as u8, (raw >> 16) as u8]
}

// ---------------------------------------------------------------------------
// J1939-21 — transport protocol
// ---------------------------------------------------------------------------

/// Every TP.CM variant, assembled exactly as
/// `SAE_J1939_Send_Transport_Protocol_Connection_Management` assembles it.
///
/// The control byte comes from the reference's `ENUM_CONTROL_BYTES_CODES`, and
/// the four bytes after it differ per variant — which is the whole reason the
/// control byte has to be read first.
#[test]
fn tp_cm_matches_the_reference_byte_for_byte() {
    const RTS: u8 = 0x10;
    const CTS: u8 = 0x11;
    const EOM_ACK: u8 = 0x13;
    const BAM: u8 = 0x20;
    const ABORT: u8 = 0xFF;

    let group = pgn::DM1;
    let [p0, p1, p2] = reference_pgn_bytes(group);

    // The reference sizes a transfer as `total_message_size_being_transmitted`
    // and `number_of_packages_being_transmitted`; 100 bytes is 15 packets.
    let size: u16 = 100;
    let packets: u8 = 15;

    // RTS: data[4] is "max number of packages to be transmitted at once", which
    // the reference always sets to 1. Ours carries whatever the sender chose, so
    // ask for the reference's value to compare the field position.
    assert_eq!(
        TpCm::Rts {
            size,
            packets,
            max_packets_per_cts: 1,
            pgn: group,
        }
        .encode(),
        [
            RTS,
            size as u8,
            (size >> 8) as u8,
            packets,
            0x01,
            p0,
            p1,
            p2
        ],
        "RTS layout"
    );

    // CTS: data[3] and data[4] are reserved and set, not zero.
    assert_eq!(
        TpCm::Cts {
            packets: 2,
            next_packet: 7,
            pgn: group,
        }
        .encode(),
        [CTS, 2, 7, 0xFF, 0xFF, p0, p1, p2],
        "CTS layout"
    );

    // End of message acknowledgement: byte count and packet count received.
    assert_eq!(
        TpCm::EndOfMsgAck {
            size,
            packets,
            pgn: group,
        }
        .encode(),
        [
            EOM_ACK,
            size as u8,
            (size >> 8) as u8,
            packets,
            0xFF,
            p0,
            p1,
            p2
        ],
        "end-of-message acknowledgement layout"
    );

    // BAM: same shape as RTS, but byte 4 is reserved — there is no CTS to cap.
    assert_eq!(
        TpCm::bam(size, group).unwrap().encode(),
        [
            BAM,
            size as u8,
            (size >> 8) as u8,
            packets,
            0xFF,
            p0,
            p1,
            p2
        ],
        "BAM layout"
    );

    // Abort: the reference never sends one, so this follows J1939-21 — the
    // connection abort reason in byte 1, the rest reserved.
    assert_eq!(
        TpCm::Abort {
            reason: AbortReason::Timeout,
            pgn: group,
        }
        .encode(),
        [ABORT, 3, 0xFF, 0xFF, 0xFF, p0, p1, p2],
        "connection abort layout"
    );
}

/// The reference reads a TP.CM by switching on `data[0]` and recovering the size
/// as `(data[2] << 8) | data[1]` and the PGN as
/// `(data[7] << 16) | (data[6] << 8) | data[5]`. Decoding must agree at every
/// size the protocol allows.
#[test]
fn tp_cm_decodes_the_way_the_reference_reads_it() {
    for size in [9u16, 10, 255, 256, 257, 1784, 1785] {
        for group in [pgn::DM1, pgn::COMMANDED_ADDRESS, pgn::ECU_IDENTIFICATION] {
            let bytes = TpCm::bam(size, group).unwrap().encode();

            let reference_size = ((bytes[2] as u16) << 8) | bytes[1] as u16;
            let reference_pgn =
                ((bytes[7] as u32) << 16) | ((bytes[6] as u32) << 8) | bytes[5] as u32;

            assert_eq!(reference_size, size, "size of a {size}-byte BAM");
            assert_eq!(
                reference_pgn,
                group.as_u32(),
                "PGN of a {size}-byte BAM of {group}"
            );

            // ...and the packet count the reference would compute from it.
            assert_eq!(
                bytes[3] as usize,
                (size as usize).div_ceil(7),
                "packet count of a {size}-byte BAM"
            );
        }
    }
}

/// A TP.DT packet is a sequence number followed by seven payload bytes, and the
/// reference indexes the reassembly buffer as `(data[0] - 1) * 7 + i - 1`.
/// Unused trailing bytes are `0xFF`, not zero.
#[test]
fn tp_dt_matches_the_reference_packet_layout() {
    let payload: [u8; 100] = core::array::from_fn(|i| (i * 3) as u8);

    for sequence in 1..=15u8 {
        let offset = (sequence as usize - 1) * 7;
        let end = (offset + 7).min(payload.len());
        let packet = TpDt::new(sequence, &payload[offset..end]);
        let bytes = packet.encode();

        assert_eq!(bytes[0], sequence, "packet {sequence} sequence number");
        for (i, byte) in bytes.iter().enumerate().skip(1) {
            let source = offset + i - 1;
            let expected = if source < payload.len() {
                payload[source]
            } else {
                0xFF // The reference fills the tail of the last packet with 0xFF.
            };
            assert_eq!(*byte, expected, "packet {sequence} byte {i}");
        }
    }
}

/// Transport-protocol identifiers, built as `(0x1CEC << 16) | (DA << 8) | SA`
/// and `(0x1CEB << 16) | (DA << 8) | SA`. Priority 7 is not decorative: bulk
/// transfers must lose arbitration to control traffic.
#[test]
fn transport_protocol_identifiers_match_the_reference() {
    let source = Address::new(0x80);
    let destination = Address::new(0x90);

    let cm = Id::from_parts(Priority::LOWEST, pgn::TP_CM, destination, source).unwrap();
    assert_eq!(cm.as_u32(), (0x1CEC << 16) | (0x90 << 8) | 0x80);

    let dt = Id::from_parts(Priority::LOWEST, pgn::TP_DT, destination, source).unwrap();
    assert_eq!(dt.as_u32(), (0x1CEB << 16) | (0x90 << 8) | 0x80);

    // A BAM goes to the global address; the reference passes DA = 0xFF.
    let bam = Id::broadcast(Priority::LOWEST, pgn::TP_CM, source);
    assert_eq!(bam.as_u32(), (0x1CEC << 16) | (0xFF << 8) | 0x80);
}

// ---------------------------------------------------------------------------
// J1939-21 — request and acknowledgement
// ---------------------------------------------------------------------------

/// `SAE_J1939_Send_Request` sends the PGN as three little-endian bytes on
/// identifier `(0x18EA << 16) | (DA << 8) | SA`.
#[test]
fn request_matches_the_reference_layout() {
    for group in [
        pgn::ADDRESS_CLAIMED,
        pgn::DM1,
        pgn::DM2,
        pgn::DM3,
        pgn::SOFTWARE_IDENTIFICATION,
        pgn::ECU_IDENTIFICATION,
        pgn::COMPONENT_IDENTIFICATION,
        pgn::PROPRIETARY_A,
    ] {
        let raw = group.as_u32();
        assert_eq!(
            Request::new(group).encode(),
            [raw as u8, (raw >> 8) as u8, (raw >> 16) as u8],
            "request payload for {group}"
        );
    }

    let id = Id::from_parts(
        Priority::DEFAULT,
        pgn::REQUEST,
        Address::new(0x90),
        Address::new(0x80),
    )
    .unwrap();
    assert_eq!(id.as_u32(), (0x18EA << 16) | (0x90 << 8) | 0x80);
}

/// `SAE_J1939_Send_Acknowledgement` puts the control byte first, the group
/// function value second, two reserved bytes, the responder's own address, and
/// then the PGN. The identifier is `(0x18E8 << 16) | (DA << 8) | SA`.
#[test]
fn acknowledgement_matches_the_reference_layout() {
    let responder = Address::new(0x80);
    let group = pgn::COMPONENT_IDENTIFICATION;
    let [p0, p1, p2] = reference_pgn_bytes(group);

    // The reference's four control bytes, in its own order.
    for (control, raw) in [
        (AckControl::Acknowledged, 0x00u8),
        (AckControl::NotSupported, 0x01),
        (AckControl::AccessDenied, 0x02),
        (AckControl::Busy, 0x03),
    ] {
        let ack = Acknowledgement {
            control,
            group_function: 0xFF,
            address: responder,
            pgn: group,
        };
        assert_eq!(
            ack.encode(),
            [raw, 0xFF, 0xFF, 0xFF, responder.as_u8(), p0, p1, p2],
            "acknowledgement with control byte {raw:#04x}"
        );
    }

    let id = Id::from_parts(
        Priority::DEFAULT,
        pgn::ACKNOWLEDGEMENT,
        Address::new(0x90),
        responder,
    )
    .unwrap();
    assert_eq!(id.as_u32(), (0x18E8 << 16) | (0x90 << 8) | 0x80);
}

// ---------------------------------------------------------------------------
// J1939-81 — the NAME
// ---------------------------------------------------------------------------

/// The NAME, packed as `SAE_J1939_Response_Request_Address_Claimed` packs it and
/// unpacked as `SAE_J1939_Read_Response_Request_Address_Claimed` unpacks it.
///
/// Both directions are checked, at values chosen so that every field's top bit
/// is set in at least one vector — a field that is one bit too wide only shows
/// up when the neighbour above it is non-zero.
#[test]
fn name_bit_packing_matches_the_reference_in_both_directions() {
    struct Vector {
        identity: u32,
        manufacturer: u16,
        function_instance: u8,
        ecu_instance: u8,
        function: u8,
        vehicle_system: u8,
        arbitrary: u8,
        industry_group: u8,
        vehicle_system_instance: u8,
    }

    let vectors = [
        // The reference's own Address Claimed example.
        Vector {
            identity: 100,
            manufacturer: 300,
            function_instance: 10,
            ecu_instance: 2,
            function: 0x87,
            vehicle_system: 100,
            arbitrary: 0,
            industry_group: 3,
            vehicle_system_instance: 10,
        },
        // Every field at its maximum: the packing's worst case.
        Vector {
            identity: 0x1F_FFFF,
            manufacturer: 0x7FF,
            function_instance: 0x1F,
            ecu_instance: 0x7,
            function: 0xFF,
            vehicle_system: 0x7F,
            arbitrary: 1,
            industry_group: 0x7,
            vehicle_system_instance: 0xF,
        },
        // Alternating bits, so a one-place shift cannot pass by luck.
        Vector {
            identity: 0x15_5555,
            manufacturer: 0x555,
            function_instance: 0x15,
            ecu_instance: 0x5,
            function: 0x55,
            vehicle_system: 0x55,
            arbitrary: 1,
            industry_group: 0x5,
            vehicle_system_instance: 0x5,
        },
        // ...and its complement.
        Vector {
            identity: 0x0A_AAAA,
            manufacturer: 0x2AA,
            function_instance: 0x0A,
            ecu_instance: 0x2,
            function: 0xAA,
            vehicle_system: 0x2A,
            arbitrary: 0,
            industry_group: 0x2,
            vehicle_system_instance: 0xA,
        },
    ];

    for (index, v) in vectors.iter().enumerate() {
        let name = Name::new()
            .with_identity_number(v.identity)
            .with_manufacturer_code(v.manufacturer)
            .with_function_instance(v.function_instance)
            .with_ecu_instance(v.ecu_instance)
            .with_function(v.function)
            .with_vehicle_system(v.vehicle_system)
            .with_arbitrary_address_capable(v.arbitrary == 1)
            .with_industry_group(v.industry_group)
            .with_vehicle_system_instance(v.vehicle_system_instance);

        // Encode: the eight assignments the reference makes, verbatim.
        let expected = [
            v.identity as u8,
            (v.identity >> 8) as u8,
            ((v.identity >> 16) as u8) | ((v.manufacturer << 5) as u8),
            (v.manufacturer >> 3) as u8,
            (v.function_instance << 3) | v.ecu_instance,
            v.function,
            v.vehicle_system << 1,
            (v.arbitrary << 7) | (v.industry_group << 4) | v.vehicle_system_instance,
        ];
        let bytes = name.to_bytes();
        assert_eq!(bytes, expected, "NAME vector {index} encodes wrongly");

        // Decode: the nine extractions the reference makes, verbatim.
        assert_eq!(
            (((bytes[2] & 0b0001_1111) as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[0] as u32,
            v.identity,
            "identity number of vector {index}"
        );
        assert_eq!(
            ((bytes[3] as u16) << 3) | (bytes[2] >> 5) as u16,
            v.manufacturer,
            "manufacturer code of vector {index}"
        );
        assert_eq!(bytes[4] >> 3, v.function_instance, "function instance");
        assert_eq!(bytes[4] & 0b0000_0111, v.ecu_instance, "ECU instance");
        assert_eq!(bytes[5], v.function, "function");
        assert_eq!(bytes[6] >> 1, v.vehicle_system, "vehicle system");
        assert_eq!(bytes[7] >> 7, v.arbitrary, "arbitrary address capable");
        assert_eq!(
            (bytes[7] >> 4) & 0b0111,
            v.industry_group,
            "industry group of vector {index}"
        );
        assert_eq!(
            bytes[7] & 0b0000_1111,
            v.vehicle_system_instance,
            "vehicle system instance of vector {index}"
        );

        // Bit 48 — the low bit of byte 6 — is reserved by J1939-81. The
        // reference leaves it clear by writing `vehicle_system << 1`, and so
        // must we, at every vehicle system value.
        assert_eq!(bytes[6] & 1, 0, "reserved bit set in vector {index}");
    }
}

/// Address Claimed goes out as `(0x18EEFF << 8) | SA`, and an ECU that has given
/// up sends the same message from the null address `0xFE`.
#[test]
fn address_claim_identifiers_match_the_reference() {
    for source in [0x00u8, 0x03, 0x80, 0xFD] {
        let id = Id::broadcast(
            Priority::DEFAULT,
            pgn::ADDRESS_CLAIMED,
            Address::new(source),
        );
        assert_eq!(id.as_u32(), (0x18EEFF << 8) | source as u32);
    }

    // Cannot Claim Address: the reference's `SAE_J1939_Send_Address_Not_Claimed`
    // uses the null address 0xFE as the source.
    let cannot_claim = Id::broadcast(Priority::DEFAULT, pgn::ADDRESS_CLAIMED, Address::NULL);
    assert_eq!(cannot_claim.as_u32(), 0x18EE_FFFE);
}

// ---------------------------------------------------------------------------
// J1939-73 — diagnostics
// ---------------------------------------------------------------------------

/// A single-frame DM1, byte for byte against `SAE_J1939_Response_Request_DM1`.
///
/// The 19-bit SPN is the awkward part: its top three bits ride in the *high*
/// bits of the third DTC byte, above the FMI, which the reference writes as
/// `((SPN >> 11) & 0b11100000) | FMI`.
#[test]
fn dm1_matches_the_reference_layout() {
    let lamps = Lamps::new()
        .with_status(Lamp::MalfunctionIndicator, LampStatus::On)
        .with_status(Lamp::RedStop, LampStatus::NotAvailable)
        .with_status(Lamp::AmberWarning, LampStatus::On)
        .with_status(Lamp::Protect, LampStatus::Reserved)
        .with_flash_status(Lamp::AmberWarning, LampStatus::On);

    // The four two-bit lamp fields, in the reference's order. Only the amber
    // warning lamp flashes, so its neighbours in the flash byte are zero — which
    // is exactly the case where a shifted field would go unnoticed.
    let (mil, red, amber, protect) = (1u8, 3u8, 1u8, 2u8);
    let (flash_mil, flash_red, flash_amber, flash_protect) = (0u8, 0u8, 1u8, 0u8);
    let expected_status = (mil << 6) | (red << 4) | (amber << 2) | protect;
    let expected_flash = (flash_mil << 6) | (flash_red << 4) | (flash_amber << 2) | flash_protect;

    for (spn, fmi, count, conversion) in [
        (299u32, 4u8, 3u8, 1u8),
        (0, 0, 0, 1),
        (0x7_FFFF, 0x1F, 0x7F, 1),
        (0x7_0000, 0, 0, 0),
        (1569, 31, 126, 1),
    ] {
        let dtc = Dtc {
            spn,
            fmi,
            occurrence_count: count,
            conversion_method: conversion == 1,
        };
        let mut buf = [0u8; 8];
        let len = diagnostics::encode(lamps, &[dtc], &mut buf).unwrap();
        assert_eq!(len, 8, "one DTC must fill exactly one CAN frame");

        assert_eq!(
            buf,
            [
                expected_status,
                expected_flash,
                spn as u8,
                (spn >> 8) as u8,
                (((spn >> 11) as u8) & 0b1110_0000) | fmi,
                (conversion << 7) | count,
                0xFF, // Reserved.
                0xFF,
            ],
            "DM1 carrying SPN {spn} FMI {fmi} count {count}"
        );
    }

    let id = Id::broadcast(Priority::DEFAULT, pgn::DM1, Address::new(0x80));
    assert_eq!(id.as_u32(), (0x18FECA << 8) | 0x80);
    let dm2 = Id::broadcast(Priority::DEFAULT, pgn::DM2, Address::new(0x80));
    assert_eq!(dm2.as_u32(), (0x18FECB << 8) | 0x80);
}

/// A multi-DTC DM1, which the reference lays out as two lamp bytes followed by
/// codes at `i * 4 + 2`. This is the form that goes over the transport protocol,
/// and the reference recovers the DTC count as `(total_message_size - 2) / 4`.
#[test]
fn a_multi_dtc_dm1_matches_the_reference_layout() {
    let lamps = Lamps::new().with_status(Lamp::RedStop, LampStatus::On);
    let dtcs = [
        Dtc::new(299, 4, 3).unwrap(),
        Dtc::new(100, 1, 7).unwrap(),
        Dtc::new(0x7_FFFF, 31, 127).unwrap(),
        Dtc::new(1569, 31, 126).unwrap(),
    ];

    let mut buf = [0u8; 64];
    let len = diagnostics::encode(lamps, &dtcs, &mut buf).unwrap();
    assert_eq!(
        len,
        dtcs.len() * 4 + 2,
        "four bytes per code, plus the lamps"
    );
    assert_eq!(
        (len - 2) / 4,
        dtcs.len(),
        "the reference recovers the count from the message size"
    );

    // Only the red stop lamp is lit, in the second of the four two-bit fields.
    let (mil, red, amber, protect) = (0u8, 1u8, 0u8, 0u8);
    assert_eq!(
        buf[0],
        (mil << 6) | (red << 4) | (amber << 2) | protect,
        "lamp status byte"
    );
    assert_eq!(buf[1], 0, "lamp flash byte");

    for (i, dtc) in dtcs.iter().enumerate() {
        assert_eq!(buf[i * 4 + 2], dtc.spn as u8, "code {i} SPN low");
        assert_eq!(buf[i * 4 + 3], (dtc.spn >> 8) as u8, "code {i} SPN mid");
        assert_eq!(
            buf[i * 4 + 4],
            (((dtc.spn >> 11) as u8) & 0b1110_0000) | dtc.fmi,
            "code {i} SPN high and FMI"
        );
        assert_eq!(
            buf[i * 4 + 5],
            ((dtc.conversion_method as u8) << 7) | dtc.occurrence_count,
            "code {i} conversion method and occurrence count"
        );
    }

    // ...and the parser recovers exactly what went in.
    let message = diagnostics::Message::parse(&buf[..len]).unwrap();
    assert_eq!(message.dtc_count(), dtcs.len());
    assert_eq!(message.dtcs().collect::<Vec<_>>(), dtcs);
}

// ---------------------------------------------------------------------------
// J1939-73 — memory access
// ---------------------------------------------------------------------------

/// DM14 and DM15 share a byte-1 layout that packs four things into one byte, and
/// the reference writes both halves of it explicitly:
///
/// ```text
/// send: ((count >> 3) & 0xE0) | (pointer_type << 4) | (command << 1) | 0b1
/// read: count = ((data[1] & 0b11100000) << 3) | data[0]
///       type  = (data[1] >> 4) & 0b0001
///       cmd   = (data[1] >> 1) & 0b0000111
/// ```
///
/// Swept across the whole 11-bit count and all eight commands, because the count
/// and the command are adjacent and a one-bit slip between them is invisible at
/// small counts.
#[test]
fn dm14_byte_packing_matches_the_reference_across_every_count_and_command() {
    let commands = [
        (MemoryCommand::Erase, 0u8),
        (MemoryCommand::Read, 1),
        (MemoryCommand::Write, 2),
        (MemoryCommand::StatusRequest, 3),
        (MemoryCommand::OperationCompleted, 4),
        (MemoryCommand::OperationFailed, 5),
        (MemoryCommand::BootLoad, 6),
        (MemoryCommand::EdcpGeneration, 7),
    ];

    for count in 0..=MAX_BYTE_COUNT {
        for (command, raw_command) in commands {
            for (pointer_type, raw_type) in [
                (PointerType::JoinWithExtension, 0u8),
                (PointerType::ExtensionIsCommand, 1),
            ] {
                let request = Dm14 {
                    requested_bytes: count,
                    command,
                    pointer_type,
                    pointer: 0x12_3456,
                    pointer_extension: 0x01,
                    key: 0xBEEF,
                };
                let bytes = request.encode();

                assert_eq!(bytes[0], count as u8, "count {count} low byte");
                assert_eq!(
                    bytes[1],
                    (((count >> 3) as u8) & 0xE0) | (raw_type << 4) | (raw_command << 1) | 0b1,
                    "count {count}, command {raw_command}, pointer type {raw_type}"
                );

                // The reference's read path must recover all three.
                assert_eq!(
                    (((bytes[1] & 0b1110_0000) as u16) << 3) | bytes[0] as u16,
                    count,
                    "count {count} does not survive the reference read"
                );
                assert_eq!((bytes[1] >> 4) & 0b0001, raw_type, "pointer type");
                assert_eq!((bytes[1] >> 1) & 0b0000_0111, raw_command, "command");
            }
        }
    }
}

/// The rest of DM14: a 24-bit pointer little-endian, the extension byte, then a
/// 16-bit key little-endian. Identifier `(0x18D9 << 16) | (DA << 8) | SA`.
#[test]
fn dm14_pointer_and_key_match_the_reference() {
    for pointer in [0u32, 1, 0xFF, 0x100, 0x1234, 0xFF_0000, 0xFF_FFFF] {
        for key in [0u16, 1, 0x00FF, 0xFF00, 0xFFFF] {
            let request = Dm14::new(16, MemoryCommand::Read, pointer)
                .unwrap()
                .with_pointer_extension(1)
                .with_key(key);
            let bytes = request.encode();

            assert_eq!(bytes[2], pointer as u8, "pointer {pointer:#x} byte 0");
            assert_eq!(
                bytes[3],
                (pointer >> 8) as u8,
                "pointer {pointer:#x} byte 1"
            );
            assert_eq!(
                bytes[4],
                (pointer >> 16) as u8,
                "pointer {pointer:#x} byte 2"
            );
            assert_eq!(bytes[5], 1, "pointer extension");
            assert_eq!(bytes[6], key as u8, "key {key:#x} low byte");
            assert_eq!(bytes[7], (key >> 8) as u8, "key {key:#x} high byte");

            // The reference reads them back as
            // `(data[4] << 16) | (data[3] << 8) | data[2]` and
            // `(data[7] << 8) | data[6]`.
            assert_eq!(
                ((bytes[4] as u32) << 16) | ((bytes[3] as u32) << 8) | bytes[2] as u32,
                pointer
            );
            assert_eq!(((bytes[7] as u16) << 8) | bytes[6] as u16, key);
        }
    }

    let id = Id::from_parts(
        Priority::DEFAULT,
        pgn::DM14,
        Address::new(0x90),
        Address::new(0x80),
    )
    .unwrap();
    assert_eq!(id.as_u32(), (0x18D9 << 16) | (0x90 << 8) | 0x80);
}

/// DM15 mirrors DM14, with a status where the command goes and a seed where the
/// key goes. The reference hard-codes bit 4 — DM14's pointer-type bit — to 1,
/// because DM15 has no pointer to describe.
#[test]
fn dm15_byte_packing_matches_the_reference() {
    let statuses = [
        (MemoryStatus::Proceed, 0u8),
        (MemoryStatus::Busy, 1),
        (MemoryStatus::Other(2), 2),
        (MemoryStatus::Other(3), 3),
        (MemoryStatus::OperationCompleted, 4),
        (MemoryStatus::OperationFailed, 5),
        (MemoryStatus::Other(6), 6),
        (MemoryStatus::Other(7), 7),
    ];

    for count in 0..=MAX_BYTE_COUNT {
        for (status, raw_status) in statuses {
            let response = Dm15 {
                allowed_bytes: count,
                status,
                edc_parameter: 0x00_1112,
                edcp_extension: 0x00,
                seed: 0xFFFF,
            };
            let bytes = response.encode();

            assert_eq!(bytes[0], count as u8);
            assert_eq!(
                bytes[1],
                (((count >> 3) as u8) & 0xE0) | (0b1 << 4) | (raw_status << 1) | 0b1,
                "count {count}, status {raw_status}"
            );
            assert_eq!(
                (((bytes[1] & 0b1110_0000) as u16) << 3) | bytes[0] as u16,
                count
            );
            assert_eq!((bytes[1] >> 1) & 0b0000_0111, raw_status);
        }
    }

    // The EDC parameter and seed occupy DM14's pointer and key positions.
    let response = Dm15 {
        allowed_bytes: 16,
        status: MemoryStatus::Proceed,
        edc_parameter: 0x00_1112,
        edcp_extension: 0x42,
        seed: 0xBEEF,
    };
    let proceed = MemoryStatus::Proceed.as_u8();
    assert_eq!(
        response.encode(),
        [
            16,
            ((16u16 >> 3) as u8 & 0xE0) | (1 << 4) | (proceed << 1) | 1,
            0x12,
            0x11,
            0x00,
            0x42,
            0xEF,
            0xBE
        ]
    );

    let id = Id::from_parts(
        Priority::DEFAULT,
        pgn::DM15,
        Address::new(0x90),
        Address::new(0x80),
    )
    .unwrap();
    assert_eq!(id.as_u32(), (0x18D8 << 16) | (0x90 << 8) | 0x80);
}

// ---------------------------------------------------------------------------
// ISO 11783 — valves
// ---------------------------------------------------------------------------

/// The byte all four valve command and estimated-flow messages share:
/// `(fail_safe_mode << 6) | (0b11 << 4) | valve_state`. The two reserved bits in
/// the middle are *set*, not clear, so a decoder that masks them off wrongly
/// reads a fail-safe mode of 3.
fn reference_mode_and_state(mode: u8, state: u8) -> u8 {
    (mode << 6) | (0b11 << 4) | state
}

/// Auxiliary valve command, against `ISO_11783_Send_Auxiliary_Valve_Command`,
/// swept over every valve state and fail-safe mode.
#[test]
fn auxiliary_valve_command_matches_the_reference() {
    for state in 0..16u8 {
        for mode in 0..4u8 {
            for flow in [0u8, 40, 100, 200, 250, 255] {
                let command = AuxiliaryValveCommand {
                    standard_flow: flow,
                    valve_state: ValveState::from_u8(state),
                    fail_safe_mode: FailSafeMode::from_u8(mode),
                };
                assert_eq!(
                    command.encode(),
                    [
                        flow,
                        0xFF, // Reserved.
                        reference_mode_and_state(mode, state),
                        0xFF,
                        0xFF,
                        0xFF,
                        0xFF,
                        0xFF,
                    ],
                    "valve command: state {state}, mode {mode}, flow {flow}"
                );

                // The reference reads back `data[2] >> 6` and `data[2] & 0x0F`.
                let bytes = command.encode();
                assert_eq!(bytes[2] >> 6, mode, "fail-safe mode");
                assert_eq!(bytes[2] & 0b0000_1111, state, "valve state");
            }
        }
    }

    // Identifier: (0x0CFE << 16) | ((0x30 + valve) << 8) | SA — priority 3.
    for number in 0..=15u8 {
        let valve = ValveNumber::new(number).unwrap();
        let id = ValveNumber::broadcast_id(valve.command_pgn(), Address::new(0x80));
        assert_eq!(
            id.as_u32(),
            (0x0CFE << 16) | ((0x30 + number as u32) << 8) | 0x80,
            "auxiliary valve {number} command identifier"
        );
    }
}

/// Auxiliary valve estimated flow: two flow bytes, the shared mode/state byte,
/// then the limit in the top three bits of byte 3.
#[test]
fn auxiliary_valve_estimated_flow_matches_the_reference() {
    for state in 0..16u8 {
        for mode in 0..4u8 {
            for limit in 0..8u8 {
                let flow = AuxiliaryValveEstimatedFlow {
                    extend_flow: 75,
                    retract_flow: 30,
                    valve_state: ValveState::from_u8(state),
                    fail_safe_mode: FailSafeMode::from_u8(mode),
                    limit,
                };
                assert_eq!(
                    flow.encode(),
                    [
                        75,
                        30,
                        reference_mode_and_state(mode, state),
                        limit << 5,
                        0xFF,
                        0xFF,
                        0xFF,
                        0xFF,
                    ],
                    "estimated flow: state {state}, mode {mode}, limit {limit}"
                );
                // `data[3] >> 5` is how the reference reads the limit back.
                assert_eq!(flow.encode()[3] >> 5, limit);
                assert_eq!(AuxiliaryValveEstimatedFlow::decode(&flow.encode()), flow);
            }
        }
    }

    for number in 0..=15u8 {
        let valve = ValveNumber::new(number).unwrap();
        let id = ValveNumber::broadcast_id(valve.estimated_flow_pgn(), Address::new(0x80));
        assert_eq!(
            id.as_u32(),
            (0x0CFE << 16) | ((0x10 + number as u32) << 8) | 0x80,
            "auxiliary valve {number} estimated flow identifier"
        );
    }
}

/// Auxiliary valve measured position: two little-endian scales either side of a
/// state byte whose top nibble is reserved and set.
#[test]
fn auxiliary_valve_measured_position_matches_the_reference() {
    for state in 0..16u8 {
        for (percent, micrometres) in [
            (0u16, 0u16),
            (6400, 51_234),
            (0x00FF, 0xFF00),
            (u16::MAX, u16::MAX),
        ] {
            let position = AuxiliaryValveMeasuredPosition {
                position_percent: percent,
                position_micrometres: micrometres,
                valve_state: ValveState::from_u8(state),
            };
            assert_eq!(
                position.encode(),
                [
                    percent as u8,
                    (percent >> 8) as u8,
                    0b1111_0000 | state,
                    micrometres as u8,
                    (micrometres >> 8) as u8,
                    0xFF,
                    0xFF,
                    0xFF,
                ],
                "measured position: state {state}, {percent}%, {micrometres} um"
            );
            assert_eq!(
                AuxiliaryValveMeasuredPosition::decode(&position.encode()),
                position
            );
        }
    }

    // The measured position block is at 0x0CFF20.., inside Proprietary B.
    for number in 0..=15u8 {
        let valve = ValveNumber::new(number).unwrap();
        let id = ValveNumber::broadcast_id(valve.measured_position_pgn(), Address::new(0x80));
        assert_eq!(
            id.as_u32(),
            (0x0CFF << 16) | ((0x20 + number as u32) << 8) | 0x80,
            "auxiliary valve {number} measured position identifier"
        );
    }
}

/// The general purpose valve command adds a 16-bit extended flow in bytes 3 and
/// 4, where the auxiliary command has reserved filler.
#[test]
fn general_purpose_valve_command_matches_the_reference() {
    for state in 0..16u8 {
        for mode in 0..4u8 {
            for extended in [0u16, 1, 0x00FF, 0xBEEF, u16::MAX] {
                let command = GeneralPurposeValveCommand {
                    standard_flow: 55,
                    extended_flow: extended,
                    valve_state: ValveState::from_u8(state),
                    fail_safe_mode: FailSafeMode::from_u8(mode),
                };
                assert_eq!(
                    command.encode(),
                    [
                        55,
                        0xFF,
                        reference_mode_and_state(mode, state),
                        extended as u8,
                        (extended >> 8) as u8,
                        0xFF,
                        0xFF,
                        0xFF,
                    ],
                    "general purpose command: state {state}, mode {mode}, flow {extended:#x}"
                );
            }
        }
    }

    // (0x0CC4 << 16) | (DA << 8) | SA — this one is PDU1, so it is addressed.
    let id = Id::from_parts(
        Priority::CONTROL,
        GENERAL_PURPOSE_VALVE_COMMAND,
        Address::new(0x90),
        Address::new(0x80),
    )
    .unwrap();
    assert_eq!(id.as_u32(), (0x0CC4 << 16) | (0x90 << 8) | 0x80);
}

/// The general purpose valve's estimated flow is the only valve message that
/// fills all eight bytes: two extended figures follow the limit byte.
#[test]
fn general_purpose_valve_estimated_flow_matches_the_reference() {
    for state in 0..16u8 {
        for mode in 0..4u8 {
            for limit in 0..8u8 {
                let flow = GeneralPurposeValveEstimatedFlow {
                    extend_flow: 80,
                    retract_flow: 20,
                    extend_flow_extended: 0x1234,
                    retract_flow_extended: 0x5678,
                    valve_state: ValveState::from_u8(state),
                    fail_safe_mode: FailSafeMode::from_u8(mode),
                    limit,
                };
                assert_eq!(
                    flow.encode(),
                    [
                        80,
                        20,
                        reference_mode_and_state(mode, state),
                        limit << 5,
                        0x34,
                        0x12,
                        0x78,
                        0x56,
                    ],
                    "general purpose flow: state {state}, mode {mode}, limit {limit}"
                );
                assert_eq!(
                    GeneralPurposeValveEstimatedFlow::decode(&flow.encode()),
                    flow
                );
            }
        }
    }

    let id = Id::from_parts(
        Priority::CONTROL,
        GENERAL_PURPOSE_VALVE_ESTIMATED_FLOW,
        Address::new(0x90),
        Address::new(0x80),
    )
    .unwrap();
    assert_eq!(id.as_u32(), (0x0CC6 << 16) | (0x90 << 8) | 0x80);
}

/// The three auxiliary valve blocks are sixteen PGNs each and must not overlap
/// or be confused with each other — the reference switches on ranges, so an
/// off-by-one at a block edge routes a command into a flow report.
#[test]
fn the_valve_pgn_blocks_are_exactly_sixteen_wide() {
    for (base, from_block) in [
        (
            0x00FE30u32,
            ValveNumber::from_command_pgn as fn(Pgn) -> Option<ValveNumber>,
        ),
        (0x00FE10, ValveNumber::from_estimated_flow_pgn),
        (0x00FF20, ValveNumber::from_measured_position_pgn),
    ] {
        assert_eq!(
            from_block(Pgn::new(base - 1).unwrap()),
            None,
            "the PGN below block {base:#08x} is not a valve"
        );
        for number in 0..16u32 {
            assert_eq!(
                from_block(Pgn::new(base + number).unwrap()).map(ValveNumber::get),
                Some(number as u8),
                "{:#08x} should be valve {number}",
                base + number
            );
        }
        assert_eq!(
            from_block(Pgn::new(base + 16).unwrap()),
            None,
            "the PGN above block {base:#08x} is not a valve"
        );
    }
}
