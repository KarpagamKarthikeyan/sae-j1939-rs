// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An ECU publishing on a schedule, the way a microcontroller does it.
//!
//! The path a real engine controller spends its life on, with no host crate
//! involved: a [`Schedule`] says what is due, the application builds the
//! payload, and a frame goes out that a receiver can decode into engineering
//! units. Driving it end to end is what catches a schedule that fires at the
//! wrong rate, or a payload that does not survive the trip.

use sae_j1939_rs::schedule::{Schedule, DEFAULT_SUSPEND_MS};
use sae_j1939_rs::spn::{catalogue, SpnValue};
use sae_j1939_rs::{pgn, Address, Frame, Id, Pgn, Priority};

const SOURCE: Address = Address::new(0x00);

/// SPN 190 at byte 4, 0.125 rpm per count — the definition
/// `catalogue::ENGINE_SPEED` decodes with.
fn engine_speed(rpm: f32) -> [u8; 8] {
    let raw = (rpm / 0.125) as u16;
    let mut payload = [0xFFu8; 8];
    payload[3] = raw as u8;
    payload[4] = (raw >> 8) as u8;
    payload
}

/// SPN 110 at byte 1, offset -40 °C.
fn coolant_temperature(celsius: i16) -> [u8; 8] {
    let mut payload = [0xFFu8; 8];
    payload[0] = (celsius + 40).clamp(0, 250) as u8;
    payload
}

/// One pass of a control loop: advance the clock, send whatever came due.
///
/// `rpm` is recomputed every pass, as a real controller would — the whole
/// reason the schedule stores no payload.
fn run(schedule: &mut Schedule<4>, tick_ms: u16, passes: usize, rpm: &mut f32) -> Vec<Frame> {
    let mut sent = Vec::new();
    for _ in 0..passes {
        *rpm = if *rpm >= 1800.0 { 1200.0 } else { *rpm + 5.0 };
        schedule.tick(tick_ms);
        while let Some(due) = schedule.next_due() {
            let payload = if due.pgn == pgn::EEC1 {
                engine_speed(*rpm)
            } else {
                coolant_temperature(80)
            };
            // Engine data arbitrates above diagnostics.
            let id = Id::broadcast(Priority::new(3).unwrap(), due.pgn, SOURCE);
            sent.push(Frame::from_payload(id, payload));
        }
    }
    sent
}

fn count_of(frames: &[Frame], group: Pgn) -> usize {
    frames.iter().filter(|f| f.pgn() == group).count()
}

#[test]
fn each_group_goes_out_at_its_own_rate() {
    let mut schedule = Schedule::<4>::new();
    schedule.broadcast_every(pgn::EEC1, 50).unwrap();
    schedule
        .broadcast_every(pgn::ENGINE_TEMPERATURE_1, 1000)
        .unwrap();

    // Ten seconds at 10 ms a pass.
    let mut rpm = 1500.0;
    let sent = run(&mut schedule, 10, 1000, &mut rpm);

    assert_eq!(count_of(&sent, pgn::EEC1), 200, "50 ms over ten seconds");
    assert_eq!(
        count_of(&sent, pgn::ENGINE_TEMPERATURE_1),
        10,
        "1 s over ten seconds"
    );
}

#[test]
fn what_goes_out_decodes_back_to_what_went_in() {
    let mut schedule = Schedule::<4>::new();
    schedule.broadcast_every(pgn::EEC1, 20).unwrap();

    let mut rpm = 1500.0;
    let sent = run(&mut schedule, 20, 50, &mut rpm);
    assert_eq!(sent.len(), 50);

    for frame in &sent {
        // The identifier a receiver sees: priority 3, EEC1, from 0x00.
        assert_eq!(frame.id().as_u32(), 0x0CF00400);
        assert_eq!(frame.pgn(), pgn::EEC1);
        assert!(frame.id().is_broadcast());

        // And the payload reads back as a plausible engine speed rather than
        // as "not available", which is what a mis-packed field looks like.
        match catalogue::ENGINE_SPEED.decode(frame.data()).unwrap() {
            SpnValue::Valid(rpm) => {
                assert!(
                    (1200.0..=1800.0).contains(&rpm),
                    "{rpm} rpm is off the dial"
                )
            }
            other => panic!("engine speed decoded as {other:?}"),
        }
    }

    // Successive frames must differ: a schedule that cached the payload would
    // publish the same stale value forever.
    let first = catalogue::ENGINE_SPEED.decode(sent[0].data()).unwrap();
    let last = catalogue::ENGINE_SPEED.decode(sent[49].data()).unwrap();
    assert_ne!(first, last, "the published value never changed");
}

#[test]
fn everything_the_catalogue_knows_survives_the_trip() {
    // Both groups, both definitions, exact values.
    let mut schedule = Schedule::<4>::new();
    schedule.broadcast_every(pgn::EEC1, 10).unwrap();
    schedule
        .broadcast_every(pgn::ENGINE_TEMPERATURE_1, 10)
        .unwrap();

    schedule.tick(10);
    let mut seen = 0;
    while let Some(due) = schedule.next_due() {
        seen += 1;
        for spn in catalogue::for_pgn(due.pgn) {
            let payload = if due.pgn == pgn::EEC1 {
                engine_speed(1500.0)
            } else {
                coolant_temperature(80)
            };
            let decoded = spn.decode(&payload).unwrap();
            match spn.number {
                190 => assert_eq!(decoded, SpnValue::Valid(1500.0)),
                110 => assert_eq!(decoded, SpnValue::Valid(80.0)),
                // The fields this ECU does not populate must read as "not
                // available", not as zero — a receiver treating an unset byte
                // as a real reading is the bug this guards against.
                _ => assert_eq!(decoded, SpnValue::NotAvailable, "SPN {}", spn.number),
            }
        }
    }
    assert_eq!(seen, 2, "both groups came due");
}

#[test]
fn a_stalled_loop_does_not_flood_the_bus_on_recovery() {
    let mut schedule = Schedule::<4>::new();
    schedule.broadcast_every(pgn::EEC1, 20).unwrap();

    // One pass, and a whole second went by — fifty periods.
    let mut rpm = 1500.0;
    let sent = run(&mut schedule, 1000, 1, &mut rpm);
    assert_eq!(sent.len(), 1, "one frame on recovery, not fifty stale ones");
}

#[test]
fn a_quietened_ecu_comes_back_on_its_own() {
    // The safety property, end to end: a tool sends DM13 and unplugs.
    let mut schedule = Schedule::<4>::new();
    schedule.broadcast_every(pgn::EEC1, 20).unwrap();
    let mut rpm = 1500.0;

    schedule.suspend(DEFAULT_SUSPEND_MS);

    // Two seconds, comfortably inside the five-second timeout.
    let during = run(&mut schedule, 20, 100, &mut rpm);
    assert!(during.is_empty(), "the bus must actually go quiet");
    assert!(schedule.is_suspended());

    // Four more, taking the total past the timeout. Nobody renewed it.
    let recovery = run(&mut schedule, 20, 200, &mut rpm);
    assert!(
        !recovery.is_empty(),
        "an ECU that can be silenced permanently is worse than any decode bug"
    );
    assert!(!schedule.is_suspended());

    // ...and it comes back at the rate it was set to, not faster.
    let steady = run(&mut schedule, 20, 100, &mut rpm);
    assert_eq!(steady.len(), 100, "one per 20 ms tick");
}
