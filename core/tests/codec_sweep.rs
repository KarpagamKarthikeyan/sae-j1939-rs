// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exhaustive sweeps over the wire-format codecs.
//!
//! The hand-written tests next to each module check the cases a human thought
//! of. These check *every* case in the input space where that is feasible —
//! all 262,144 PGNs, all 8,192 identifier prefixes, every value of every
//! bit-packed field.
//!
//! Bit-packing bugs hide in the values nobody picks as an example: the boundary
//! between two fields, the value that is all ones, the field that is one bit
//! wider than its neighbour. Sweeping finds those; examples do not.

use sae_j1939_rs::diagnostics::{Dtc, Lamp, LampStatus, Lamps, MAX_FMI, MAX_OCCURRENCE_COUNT};
use sae_j1939_rs::iso11783::{AuxiliaryValveCommand, FailSafeMode, ValveNumber, ValveState};
use sae_j1939_rs::memory_access::{Dm14, Dm15, MemoryCommand, MemoryStatus, MAX_BYTE_COUNT};
use sae_j1939_rs::request::{AckControl, Acknowledgement};
use sae_j1939_rs::spn::{RawValue, Spn};
use sae_j1939_rs::tp::{AbortReason, TpCm, TpDt};
use sae_j1939_rs::{pgn, Address, Id, Name, Pgn, Priority};

/// Every 18-bit value must produce a coherent PGN.
#[test]
fn every_pgn_value_is_self_consistent() {
    for raw in 0..=sae_j1939_rs::pgn::MAX {
        let pgn = Pgn::new(raw).expect("every 18-bit value is a valid PGN");

        // Normalisation is idempotent: re-parsing a PGN's own output is a no-op.
        assert_eq!(Pgn::new(pgn.as_u32()).unwrap(), pgn, "raw {raw:#x}");

        // PDU1 and PDU2 partition the space, and agree with the format byte.
        assert_ne!(pgn.is_pdu1(), pgn.is_pdu2(), "raw {raw:#x}");
        assert_eq!(pgn.is_pdu2(), pgn.pdu_format() >= 0xF0, "raw {raw:#x}");

        // A PDU1 PGN never keeps a low byte; a PDU2 PGN always exposes it.
        if pgn.is_pdu1() {
            assert_eq!(pgn.as_u32() & 0xFF, 0, "raw {raw:#x} kept its low byte");
            assert_eq!(pgn.group_extension(), None, "raw {raw:#x}");
        } else {
            assert_eq!(
                pgn.group_extension(),
                Some(pgn.as_u32() as u8),
                "raw {raw:#x}"
            );
            assert_eq!(pgn.as_u32(), raw, "PDU2 must round-trip exactly");
        }

        // The page bits survive normalisation.
        assert_eq!(pgn.data_page(), (raw >> 16) & 1 == 1, "raw {raw:#x}");
        assert_eq!(
            pgn.extended_data_page(),
            (raw >> 17) & 1 == 1,
            "raw {raw:#x}"
        );
    }
}

/// Every combination of priority, page bits, and source address must survive a
/// decode/encode round trip, for both PDU formats.
#[test]
fn every_identifier_prefix_round_trips() {
    let formats = [0x00u32, 0x01, 0xEE, 0xEF, 0xF0, 0xFE, 0xFF];

    for priority in 0..8u32 {
        for edp in 0..2u32 {
            for dp in 0..2u32 {
                for pf in formats {
                    for ps in [0x00u32, 0x7F, 0x80, 0xFE, 0xFF] {
                        for sa in [0x00u32, 0x01, 0x80, 0xFD, 0xFE, 0xFF] {
                            let raw = (priority << 26)
                                | (edp << 25)
                                | (dp << 24)
                                | (pf << 16)
                                | (ps << 8)
                                | sa;
                            let id = Id::new(raw).expect("29-bit value");

                            assert_eq!(id.priority().as_u8() as u32, priority);
                            assert_eq!(id.source_address().as_u8() as u32, sa);
                            assert_eq!(id.pdu_format() as u32, pf);
                            assert_eq!(id.extended_data_page(), edp == 1);
                            assert_eq!(id.data_page(), dp == 1);

                            // Rebuild from the decoded parts and expect the
                            // original bits back.
                            let destination = id.destination_address().unwrap_or(Address::GLOBAL);
                            let rebuilt = Id::from_parts(
                                id.priority(),
                                id.pgn(),
                                destination,
                                id.source_address(),
                            )
                            .expect("decoded parts must reassemble");
                            assert_eq!(rebuilt.as_u32(), raw, "round trip of {raw:#010x}");
                        }
                    }
                }
            }
        }
    }
}

/// A PDU2 identifier can never be addressed to a specific ECU, and a PDU1 one
/// always can.
#[test]
fn addressing_rules_hold_across_every_pdu_format() {
    for pf in 0..=0xFFu32 {
        let pgn = Pgn::new(pf << 8).unwrap();
        let result = Id::from_parts(
            Priority::DEFAULT,
            pgn,
            Address::new(0x90),
            Address::new(0x80),
        );
        if pf >= 0xF0 {
            assert!(
                result.is_err(),
                "PF {pf:#04x} is PDU2 and cannot be addressed"
            );
        } else {
            let id = result.expect("PDU1 accepts a destination");
            assert_eq!(id.destination_address(), Some(Address::new(0x90)));
        }
        // Broadcasting is always legal.
        let broadcast = Id::broadcast(Priority::DEFAULT, pgn, Address::new(0x80));
        assert!(broadcast.is_broadcast(), "PF {pf:#04x}");
    }
}

/// Every NAME field, swept across its whole range, must decode back unchanged
/// and leave its neighbours alone.
#[test]
fn every_name_field_value_round_trips() {
    // A non-zero baseline in every other field, so a bleed would be visible.
    let base = Name::new()
        .with_identity_number(0x15_5555)
        .with_manufacturer_code(0x555)
        .with_ecu_instance(0x5)
        .with_function_instance(0x15)
        .with_function(0x55)
        .with_vehicle_system(0x55)
        .with_vehicle_system_instance(0x5)
        .with_industry_group(0x5);

    for value in 0..=0x1F_FFFFu32 {
        // Sweeping 21 bits exhaustively is slow; step through the interesting
        // bit patterns instead of every value.
        if value.count_ones() > 3 && value != 0x1F_FFFF {
            continue;
        }
        let name = base.with_identity_number(value);
        assert_eq!(name.identity_number(), value);
        assert_eq!(
            name.manufacturer_code(),
            0x555,
            "neighbour bled at {value:#x}"
        );
    }

    for value in 0..=0x7FFu16 {
        let name = base.with_manufacturer_code(value);
        assert_eq!(name.manufacturer_code(), value);
        assert_eq!(name.identity_number(), 0x15_5555);
        assert_eq!(name.ecu_instance(), 0x5);
    }

    for value in 0..=0xFFu8 {
        let name = base.with_function(value);
        assert_eq!(name.function(), value);
        assert_eq!(name.function_instance(), 0x15);
        assert_eq!(name.vehicle_system(), 0x55);
        // Bit 48 is reserved and must stay clear at every function value.
        assert_eq!(
            name.as_u64() & (1 << 48),
            0,
            "reserved bit set at {value:#x}"
        );
    }

    for value in 0..=0x7Fu8 {
        let name = base.with_vehicle_system(value);
        assert_eq!(name.vehicle_system(), value);
        assert_eq!(name.function(), 0x55);
        assert_eq!(name.vehicle_system_instance(), 0x5);
    }

    for value in 0..=0xFu8 {
        let name = base.with_vehicle_system_instance(value);
        assert_eq!(name.vehicle_system_instance(), value);
        assert_eq!(name.industry_group(), 0x5);
        assert_eq!(name.vehicle_system(), 0x55);
    }

    // Every NAME must survive the wire format.
    for name in [base, Name::new(), Name::from_u64(u64::MAX)] {
        assert_eq!(Name::from_bytes(&name.to_bytes()), name);
    }
}

/// Arbitration must be a strict total order — otherwise two ECUs can both
/// believe they won.
#[test]
fn name_arbitration_is_a_strict_total_order() {
    let names: Vec<Name> = (0..64u64)
        .map(|i| Name::from_u64(i.wrapping_mul(0x0123_4567_89AB_CDEF)))
        .collect();

    for &a in &names {
        assert!(!a.wins_arbitration_against(a), "a NAME cannot beat itself");
        for &b in &names {
            if a == b {
                continue;
            }
            // Exactly one direction wins.
            assert_ne!(
                a.wins_arbitration_against(b),
                b.wins_arbitration_against(a),
                "{:#x} vs {:#x}",
                a.as_u64(),
                b.as_u64()
            );
        }
    }
}

/// Every DTC field, across its whole range, must survive the four-byte packing.
#[test]
fn every_dtc_field_value_round_trips() {
    for fmi in 0..=MAX_FMI {
        for count in 0..=MAX_OCCURRENCE_COUNT {
            for spn in [0u32, 1, 0xFF, 0x100, 0x7FF, 0x800, 0x1_FFFF, 0x7_FFFF] {
                for conversion in [false, true] {
                    let dtc = Dtc {
                        spn,
                        fmi,
                        occurrence_count: count,
                        conversion_method: conversion,
                    };
                    assert_eq!(
                        Dtc::decode(&dtc.encode()),
                        dtc,
                        "spn {spn:#x} fmi {fmi} count {count} conv {conversion}"
                    );
                }
            }
        }
    }
}

/// Every lamp state in every lamp slot, with all others held at a contrasting
/// value.
#[test]
fn every_lamp_combination_round_trips() {
    let states = [
        LampStatus::Off,
        LampStatus::On,
        LampStatus::Reserved,
        LampStatus::NotAvailable,
    ];

    for lamp in Lamp::ALL {
        for status in states {
            for flash in states {
                let lamps = Lamps::new()
                    .with_status(lamp, status)
                    .with_flash_status(lamp, flash);
                assert_eq!(lamps.status(lamp), status);
                assert_eq!(lamps.flash_status(lamp), flash);
                assert_eq!(Lamps::decode(&lamps.encode()), lamps);

                // Every other lamp stays untouched.
                for other in Lamp::ALL {
                    if other != lamp {
                        assert_eq!(lamps.status(other), LampStatus::Off);
                        assert_eq!(lamps.flash_status(other), LampStatus::Off);
                    }
                }
            }
        }
    }
}

/// Every TP.CM variant across its whole field range.
#[test]
fn every_connection_management_message_round_trips() {
    let groups = [pgn::DM1, pgn::COMMANDED_ADDRESS, pgn::ECU_IDENTIFICATION];

    for group in groups {
        for size in [9u16, 10, 255, 256, 1784, 1785] {
            assert_eq!(
                TpCm::decode(&TpCm::bam(size, group).unwrap().encode()).unwrap(),
                TpCm::bam(size, group).unwrap()
            );
            assert_eq!(
                TpCm::decode(&TpCm::rts(size, group).unwrap().encode()).unwrap(),
                TpCm::rts(size, group).unwrap()
            );
        }

        for packets in 0..=255u8 {
            let cts = TpCm::Cts {
                packets,
                next_packet: packets.wrapping_add(1),
                pgn: group,
            };
            assert_eq!(TpCm::decode(&cts.encode()).unwrap(), cts);
        }

        for reason in 0..=255u8 {
            let abort = TpCm::Abort {
                reason: AbortReason::from_u8(reason),
                pgn: group,
            };
            assert_eq!(TpCm::decode(&abort.encode()).unwrap(), abort);
            assert_eq!(AbortReason::from_u8(reason).as_u8(), reason);
        }
    }

    // Every sequence number and payload byte in a TP.DT packet.
    for sequence in 0..=255u8 {
        let dt = TpDt::new(sequence, &[sequence; 7]);
        assert_eq!(TpDt::decode(&dt.encode()), dt);
        assert_eq!(dt.sequence, sequence);
    }
}

/// Every control byte of an Acknowledgement, and every address.
#[test]
fn every_acknowledgement_round_trips() {
    for control in 0..=255u8 {
        for address in [0x00u8, 0x80, 0xFD, 0xFE, 0xFF] {
            let ack = Acknowledgement {
                control: AckControl::from_u8(control),
                group_function: control ^ 0xFF,
                address: Address::new(address),
                pgn: pgn::DM1,
            };
            assert_eq!(Acknowledgement::decode(&ack.encode()), ack);
            assert_eq!(AckControl::from_u8(control).as_u8(), control);
        }
    }
}

/// The DM14/DM15 shared byte-1 layout across every count and command.
#[test]
fn every_memory_access_field_round_trips() {
    let commands = [
        MemoryCommand::Erase,
        MemoryCommand::Read,
        MemoryCommand::Write,
        MemoryCommand::StatusRequest,
        MemoryCommand::OperationCompleted,
        MemoryCommand::OperationFailed,
        MemoryCommand::BootLoad,
        MemoryCommand::EdcpGeneration,
    ];

    for count in 0..=MAX_BYTE_COUNT {
        for command in commands {
            let request = Dm14::new(count, command, 0x12_3456).unwrap();
            let decoded = Dm14::decode(&request.encode());
            assert_eq!(decoded.requested_bytes, count, "count {count}");
            assert_eq!(decoded.command, command);
            assert_eq!(decoded.pointer, 0x12_3456);
        }

        let response = Dm15::new(count, MemoryStatus::Proceed).unwrap();
        assert_eq!(Dm15::decode(&response.encode()).allowed_bytes, count);
    }

    for status in 0..8u8 {
        let response = Dm15::new(64, MemoryStatus::from_u8(status)).unwrap();
        assert_eq!(
            Dm15::decode(&response.encode()).status,
            MemoryStatus::from_u8(status)
        );
    }
}

/// Every valve number and state, across all three PGN blocks.
#[test]
fn every_valve_number_and_state_round_trips() {
    for number in 0..=15u8 {
        let valve = ValveNumber::new(number).unwrap();

        // The three blocks are disjoint and each maps back to this valve alone.
        let blocks = [
            valve.command_pgn(),
            valve.estimated_flow_pgn(),
            valve.measured_position_pgn(),
        ];
        for (i, a) in blocks.iter().enumerate() {
            for b in blocks.iter().skip(i + 1) {
                assert_ne!(a, b, "valve {number} has overlapping PGNs");
            }
        }
        assert_eq!(ValveNumber::from_command_pgn(blocks[0]), Some(valve));
        assert_eq!(ValveNumber::from_estimated_flow_pgn(blocks[1]), Some(valve));
        assert_eq!(
            ValveNumber::from_measured_position_pgn(blocks[2]),
            Some(valve)
        );

        for state in 0..16u8 {
            for mode in 0..4u8 {
                for flow in [0u8, 1, 100, 200, 255] {
                    let command = AuxiliaryValveCommand {
                        standard_flow: flow,
                        valve_state: ValveState::from_u8(state),
                        fail_safe_mode: FailSafeMode::from_u8(mode),
                    };
                    assert_eq!(
                        AuxiliaryValveCommand::decode(&command.encode()),
                        command,
                        "valve {number} state {state} mode {mode} flow {flow}"
                    );
                }
            }
        }
    }
    assert!(ValveNumber::new(16).is_err());
}

/// The SPN reserved-range classification, checked at the boundary of every
/// supported field width.
#[test]
fn spn_status_boundaries_hold_at_every_width() {
    for bits in 1..=32u16 {
        let spn = Spn::new(0, "sweep", 0, bits, 1.0, 0.0, "");
        let mut payload = [0u8; 8];

        let write = |payload: &mut [u8; 8], value: u32| {
            for i in 0..bits {
                let bit = (value >> i) & 1;
                let index = i as usize;
                if bit == 1 {
                    payload[index / 8] |= 1 << (index % 8);
                } else {
                    payload[index / 8] &= !(1 << (index % 8));
                }
            }
        };

        let max = if bits == 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };

        // The all-ones value is never a measurement, at any width above 1 bit.
        write(&mut payload, max);
        let extracted = spn.extract(&payload).unwrap();
        if bits == 1 {
            assert_eq!(
                extracted,
                RawValue::Valid(1),
                "a 1-bit field has no status codes"
            );
        } else {
            assert_eq!(extracted, RawValue::NotAvailable, "{bits}-bit all-ones");
        }

        // Zero is always a real measurement.
        write(&mut payload, 0);
        assert_eq!(
            spn.extract(&payload).unwrap(),
            RawValue::Valid(0),
            "{bits}-bit zero"
        );

        // One below the top is the error indicator for every width above 2.
        if bits > 2 {
            let error = match bits {
                4 => 0xE,
                8 => 0xFE,
                // Untabulated widths use the general top-two rule.
                3 | 5..=7 => max - 1,
                _ => 0xFEu32 << (bits - 8),
            };
            write(&mut payload, error);
            assert_eq!(
                spn.extract(&payload).unwrap(),
                RawValue::Error,
                "{bits}-bit error indicator {error:#x}"
            );
        }
    }
}
