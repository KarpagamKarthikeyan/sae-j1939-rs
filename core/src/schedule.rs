// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Periodic transmission: the thing a J1939 ECU spends most of its life doing.
//!
//! An engine controller does not sit waiting to be asked. It broadcasts engine
//! speed every 20 ms, temperatures every second, fuel economy every 100 ms —
//! whether anyone is listening or not. A stack that can only send on demand
//! covers the rare case and leaves the common one to the application.
//!
//! [`Schedule`] is the timer multiplexer for that. It holds *when* to send, not
//! *what*: the payload of a periodic message changes every cycle, so keeping a
//! copy would be a copy that is always stale. Ask it what is due, then build
//! and send it.
//!
//! ```
//! use sae_j1939_rs::schedule::Schedule;
//! use sae_j1939_rs::pgn;
//!
//! let mut schedule = Schedule::<4>::new();
//! schedule.broadcast_every(pgn::ENGINE_TEMPERATURE_1, 1000).unwrap();
//!
//! // Nothing is due until a second has passed.
//! assert_eq!(schedule.tick(999), 0);
//! assert_eq!(schedule.tick(1), 1);
//!
//! let due = schedule.next_due().unwrap();
//! assert_eq!(due.pgn, pgn::ENGINE_TEMPERATURE_1);
//! assert!(schedule.next_due().is_none());
//! ```
//!
//! Like everything else in this crate it owns no bus and no clock: it is driven
//! by [`Schedule::tick`], so the same code runs against a `SysTick` counter, a
//! host clock, and a test that advances time by hand.
//!
//! # Being told to be quiet
//!
//! A service tool working on a busy bus can send DM13 to stop normal broadcasts
//! and free up bandwidth — see [`crate::diagnostics::Dm13`].
//! [`Schedule::suspend`] is the receiving end of that.
//!
//! Suspension always expires. A tool that sends "stop" and is then unplugged
//! must not silence an ECU until the next power cycle, so the tool is expected
//! to keep saying so; when it stops saying so, broadcasts resume on their own.

use crate::pgn::Pgn;
use crate::types::{Address, Error, Result};

/// How long a [`Schedule::suspend`] lasts if nothing renews it.
///
/// DM13 works by repetition: a tool that wants a quiet bus keeps saying so.
/// The value matters less than the fact that there *is* one — an ECU that
/// stayed silent forever because a tool was unplugged mid-session would be a
/// far worse failure than one that resumes a few seconds early.
pub const DEFAULT_SUSPEND_MS: u16 = 5_000;

/// A message that is due to be transmitted now.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Due {
    /// The parameter group to send.
    pub pgn: Pgn,
    /// Where it goes. [`Address::GLOBAL`] for an ordinary broadcast.
    pub destination: Address,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    pgn: Pgn,
    destination: Address,
    period_ms: u16,
    /// Time accumulated toward the next transmission.
    elapsed_ms: u16,
    /// This entry is due and has not been drained yet.
    due: bool,
}

const UNUSED: Entry = Entry {
    pgn: Pgn::new_masked(0),
    destination: Address::GLOBAL,
    period_ms: 1,
    elapsed_ms: 0,
    due: false,
};

/// What to transmit, and how often.
///
/// Holds up to `N` periodic messages. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Schedule<const N: usize> {
    entries: [Entry; N],
    len: usize,
    /// Milliseconds left before broadcasts resume, or zero when running.
    suspended_ms: u16,
}

impl<const N: usize> Default for Schedule<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Schedule<N> {
    /// An empty schedule: nothing is transmitted periodically.
    pub const fn new() -> Self {
        Schedule {
            entries: [UNUSED; N],
            len: 0,
            suspended_ms: 0,
        }
    }

    /// How many periodic messages this schedule can hold.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many are registered.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing is registered.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Broadcast `pgn` every `period_ms` milliseconds.
    ///
    /// Re-registering a parameter group already scheduled to the same
    /// destination changes its period and keeps its phase, so adjusting a rate
    /// does not restart the interval.
    ///
    /// # Errors
    ///
    /// [`Error::ValueOutOfRange`] for a period of zero — "every zero
    /// milliseconds" has no meaning, and treating it as "as fast as possible"
    /// would turn a typo into a bus flood — or when the schedule is full.
    pub fn broadcast_every(&mut self, pgn: Pgn, period_ms: u16) -> Result<()> {
        self.send_every(pgn, Address::GLOBAL, period_ms)
    }

    /// Send `pgn` to one ECU every `period_ms` milliseconds.
    ///
    /// See [`Schedule::broadcast_every`]. A destination-specific periodic
    /// message is unusual on J1939 but not forbidden, and the schedule does not
    /// need to know the difference.
    pub fn send_every(&mut self, pgn: Pgn, destination: Address, period_ms: u16) -> Result<()> {
        if period_ms == 0 {
            return Err(Error::ValueOutOfRange {
                field: "transmission period",
                value: 0,
            });
        }

        if let Some(index) = self.position(pgn, destination) {
            self.entries[index].period_ms = period_ms;
            // A rate change should not restart the interval, but it must not
            // leave the entry more than a whole period overdue either.
            self.entries[index].elapsed_ms = self.entries[index].elapsed_ms.min(period_ms - 1);
            return Ok(());
        }

        if self.len == N {
            return Err(Error::ValueOutOfRange {
                field: "schedule capacity",
                value: N as u32,
            });
        }

        self.entries[self.len] = Entry {
            pgn,
            destination,
            period_ms,
            elapsed_ms: 0,
            due: false,
        };
        self.len += 1;
        Ok(())
    }

    /// Stop transmitting `pgn` to `destination`, returning whether it was
    /// scheduled.
    pub fn remove(&mut self, pgn: Pgn, destination: Address) -> bool {
        let Some(index) = self.position(pgn, destination) else {
            return false;
        };
        // Shift rather than swap: the registration order is the order messages
        // go out in, and a reordered bus is a needlessly different bus.
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        true
    }

    /// Stop transmitting everything.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Whether `pgn` is scheduled to `destination`.
    pub fn contains(&self, pgn: Pgn, destination: Address) -> bool {
        self.position(pgn, destination).is_some()
    }

    /// The period `pgn` is scheduled at, if it is.
    pub fn period(&self, pgn: Pgn, destination: Address) -> Option<u16> {
        self.position(pgn, destination)
            .map(|index| self.entries[index].period_ms)
    }

    /// Every registered message, in the order it was added.
    pub fn entries(&self) -> impl Iterator<Item = (Due, u16)> + '_ {
        self.entries[..self.len].iter().map(|entry| {
            (
                Due {
                    pgn: entry.pgn,
                    destination: entry.destination,
                },
                entry.period_ms,
            )
        })
    }

    /// Advance every timer by `elapsed_ms`, returning how many messages are
    /// now waiting to be sent.
    ///
    /// The count includes anything left over from a previous tick that was
    /// never drained, so a slow loop delays a message rather than losing it.
    ///
    /// A message becomes due **once** however many periods have gone by. If the
    /// loop stalls for a second, a 20 ms broadcast sends one frame, not fifty:
    /// a burst of stale copies is worse for the bus and for the receiver than a
    /// missed sample. The phase is preserved across the stall, so the average
    /// rate stays right rather than drifting by the length of every hiccup.
    pub fn tick(&mut self, elapsed_ms: u16) -> usize {
        if self.suspended_ms > 0 {
            // Only the suspension timer runs while broadcasts are stopped;
            // letting the entries accumulate would mean everything fired at
            // once on resume, which is the opposite of quietening the bus.
            self.suspended_ms = self.suspended_ms.saturating_sub(elapsed_ms);
            return 0;
        }

        for entry in self.entries[..self.len].iter_mut() {
            entry.elapsed_ms = entry.elapsed_ms.saturating_add(elapsed_ms);
            if entry.elapsed_ms >= entry.period_ms {
                entry.elapsed_ms %= entry.period_ms;
                entry.due = true;
            }
        }
        self.pending()
    }

    /// How many messages are waiting to be sent.
    pub fn pending(&self) -> usize {
        self.entries[..self.len].iter().filter(|e| e.due).count()
    }

    /// Take the next message that is due, or `None` when none are.
    ///
    /// Drain this to empty after every [`Schedule::tick`]:
    ///
    /// ```
    /// # use sae_j1939_rs::schedule::Schedule;
    /// # use sae_j1939_rs::pgn;
    /// # let mut schedule = Schedule::<4>::new();
    /// # schedule.broadcast_every(pgn::DM1, 10).unwrap();
    /// # let elapsed_ms = 10;
    /// # fn build_and_send(_: sae_j1939_rs::schedule::Due) {}
    /// schedule.tick(elapsed_ms);
    /// while let Some(due) = schedule.next_due() {
    ///     build_and_send(due);
    /// }
    /// ```
    pub fn next_due(&mut self) -> Option<Due> {
        let entry = self.entries[..self.len].iter_mut().find(|e| e.due)?;
        entry.due = false;
        Some(Due {
            pgn: entry.pgn,
            destination: entry.destination,
        })
    }

    /// Stop transmitting for `timeout_ms`, then resume on our own.
    ///
    /// The receiving end of a DM13 stop-broadcast command. Anything already due
    /// is dropped rather than held: being told to stop and then sending a queued
    /// message anyway is not stopping.
    ///
    /// Renew it by calling this again — a tool that wants a longer quiet period
    /// keeps asking. Pass [`DEFAULT_SUSPEND_MS`] if you have no reason to pick
    /// something else. A `timeout_ms` of zero resumes immediately.
    pub fn suspend(&mut self, timeout_ms: u16) {
        self.suspended_ms = timeout_ms;
        for entry in self.entries[..self.len].iter_mut() {
            entry.due = false;
        }
    }

    /// Resume transmitting now, whatever the suspension had left to run.
    ///
    /// The receiving end of a DM13 start-broadcast command.
    pub fn resume(&mut self) {
        self.suspended_ms = 0;
    }

    /// Whether broadcasts are currently stopped.
    pub fn is_suspended(&self) -> bool {
        self.suspended_ms > 0
    }

    /// Milliseconds until broadcasts resume on their own, or `None` if they are
    /// not suspended.
    pub fn resumes_in_ms(&self) -> Option<u16> {
        (self.suspended_ms > 0).then_some(self.suspended_ms)
    }

    fn position(&self, pgn: Pgn, destination: Address) -> Option<usize> {
        self.entries[..self.len]
            .iter()
            .position(|entry| entry.pgn == pgn && entry.destination == destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgn;
    use std::vec::Vec;

    #[test]
    fn an_empty_schedule_never_has_anything_to_send() {
        let mut schedule = Schedule::<4>::new();
        assert!(schedule.is_empty());
        assert_eq!(schedule.capacity(), 4);
        for _ in 0..100 {
            assert_eq!(schedule.tick(1000), 0);
            assert!(schedule.next_due().is_none());
        }
    }

    #[test]
    fn a_message_comes_due_once_per_period() {
        let mut schedule = Schedule::<4>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();

        for cycle in 0..20 {
            // Ninety-nine milliseconds in ten-millisecond steps: nothing yet.
            for _ in 0..9 {
                assert_eq!(schedule.tick(10), 0, "cycle {cycle}");
            }
            assert_eq!(schedule.tick(10), 1, "cycle {cycle}");
            assert_eq!(schedule.next_due().unwrap().pgn, pgn::DM1);
            assert!(schedule.next_due().is_none());
        }
    }

    #[test]
    fn several_messages_keep_their_own_rates() {
        let mut schedule = Schedule::<4>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        schedule.broadcast_every(pgn::DM2, 250).unwrap();
        schedule.broadcast_every(pgn::DM5, 1000).unwrap();

        let mut counts = [0usize; 3];
        // Ten seconds in one-millisecond steps.
        for _ in 0..10_000 {
            schedule.tick(1);
            while let Some(due) = schedule.next_due() {
                match due.pgn {
                    p if p == pgn::DM1 => counts[0] += 1,
                    p if p == pgn::DM2 => counts[1] += 1,
                    p if p == pgn::DM5 => counts[2] += 1,
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(counts, [100, 40, 10]);
    }

    #[test]
    fn a_stalled_loop_sends_one_message_rather_than_a_burst() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 20).unwrap();

        // A whole second passes in one tick — fifty periods.
        assert_eq!(schedule.tick(1000), 1, "one message, not fifty");
        assert_eq!(schedule.next_due().unwrap().pgn, pgn::DM1);
        assert!(schedule.next_due().is_none());
    }

    #[test]
    fn the_average_rate_survives_an_irregular_loop() {
        // Phase is preserved across a stall rather than reset, so a loop that
        // hiccups does not slowly drift behind.
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();

        let mut sent = 0;
        let mut clock = 0u32;
        // Alternating 7 ms and 13 ms steps: never a multiple of the period.
        for step in 0..1000u32 {
            let dt = if step % 2 == 0 { 7 } else { 13 };
            clock += dt;
            schedule.tick(dt as u16);
            while schedule.next_due().is_some() {
                sent += 1;
            }
        }
        // Ten seconds at 100 ms is a hundred messages, give or take the final
        // partial period.
        assert_eq!(clock, 10_000);
        assert_eq!(sent, 100);
    }

    #[test]
    fn an_undrained_message_is_delayed_rather_than_lost() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();

        assert_eq!(schedule.tick(100), 1);
        // Do not drain it. The next tick must still report it as waiting.
        assert_eq!(schedule.tick(10), 1);
        assert_eq!(schedule.pending(), 1);
        assert!(schedule.next_due().is_some());
        assert_eq!(schedule.pending(), 0);
    }

    #[test]
    fn a_period_of_zero_is_refused() {
        let mut schedule = Schedule::<2>::new();
        assert_eq!(
            schedule.broadcast_every(pgn::DM1, 0),
            Err(Error::ValueOutOfRange {
                field: "transmission period",
                value: 0
            })
        );
        assert!(schedule.is_empty(), "nothing was registered");
    }

    #[test]
    fn a_full_schedule_is_refused_rather_than_silently_dropping_one() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        schedule.broadcast_every(pgn::DM2, 100).unwrap();
        assert_eq!(
            schedule.broadcast_every(pgn::DM5, 100),
            Err(Error::ValueOutOfRange {
                field: "schedule capacity",
                value: 2
            })
        );
        assert_eq!(schedule.len(), 2);
    }

    #[test]
    fn re_registering_changes_the_rate_without_restarting_the_interval() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 1000).unwrap();
        schedule.tick(900);

        // Speed it up. The 900 ms already accumulated should not be thrown
        // away, so at the new rate it is already overdue.
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        assert_eq!(schedule.len(), 1, "re-registering is not a second entry");
        assert_eq!(schedule.period(pgn::DM1, Address::GLOBAL), Some(100));
        assert_eq!(schedule.tick(1), 1);
    }

    #[test]
    fn the_same_group_to_two_destinations_is_two_entries() {
        let mut schedule = Schedule::<4>::new();
        let a = Address::new(0x21);
        let b = Address::new(0x22);
        schedule.send_every(pgn::DM1, a, 100).unwrap();
        schedule.send_every(pgn::DM1, b, 100).unwrap();
        assert_eq!(schedule.len(), 2);

        assert_eq!(schedule.tick(100), 2);
        let first = schedule.next_due().unwrap();
        let second = schedule.next_due().unwrap();
        assert_eq!(first.destination, a);
        assert_eq!(second.destination, b);
    }

    #[test]
    fn removing_a_message_stops_it_and_leaves_the_others_in_order() {
        let mut schedule = Schedule::<4>::new();
        for group in [pgn::DM1, pgn::DM2, pgn::DM5] {
            schedule.broadcast_every(group, 100).unwrap();
        }

        assert!(schedule.remove(pgn::DM2, Address::GLOBAL));
        assert!(!schedule.remove(pgn::DM2, Address::GLOBAL), "already gone");
        assert!(!schedule.contains(pgn::DM2, Address::GLOBAL));

        schedule.tick(100);
        let sent: Vec<Pgn> = core::iter::from_fn(|| schedule.next_due())
            .map(|due| due.pgn)
            .collect();
        assert_eq!(sent, [pgn::DM1, pgn::DM5]);
    }

    #[test]
    fn suspending_stops_everything_and_drops_what_was_waiting() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        assert_eq!(schedule.tick(100), 1);

        schedule.suspend(DEFAULT_SUSPEND_MS);
        assert!(schedule.is_suspended());
        assert_eq!(
            schedule.pending(),
            0,
            "being told to stop and sending anyway is not stopping"
        );

        for _ in 0..40 {
            assert_eq!(schedule.tick(100), 0, "nothing goes out while suspended");
        }
    }

    #[test]
    fn a_suspension_expires_on_its_own() {
        // The safety property: a tool that says "stop" and is then unplugged
        // must not silence this ECU until the next power cycle.
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        schedule.suspend(1000);

        for _ in 0..9 {
            assert_eq!(schedule.tick(100), 0);
            assert!(schedule.is_suspended());
        }
        assert_eq!(schedule.tick(100), 0, "the last tick of the suspension");
        assert!(!schedule.is_suspended(), "it must expire on its own");

        // And transmission picks up again.
        assert_eq!(schedule.tick(100), 1);
    }

    #[test]
    fn a_suspension_can_be_renewed_and_cancelled() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();

        schedule.suspend(1000);
        schedule.tick(900);
        assert_eq!(schedule.resumes_in_ms(), Some(100));

        // The tool says so again, so the clock restarts.
        schedule.suspend(1000);
        assert_eq!(schedule.resumes_in_ms(), Some(1000));

        // ...and an explicit start command ends it at once.
        schedule.resume();
        assert!(!schedule.is_suspended());
        assert_eq!(schedule.resumes_in_ms(), None);
        assert_eq!(schedule.tick(100), 1);
    }

    #[test]
    fn resuming_does_not_release_a_backlog() {
        // Entries do not accumulate while stopped, so ten seconds of suspension
        // is not ten seconds of messages arriving at once.
        let mut schedule = Schedule::<4>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        schedule.broadcast_every(pgn::DM2, 100).unwrap();

        schedule.suspend(10_000);
        for _ in 0..100 {
            schedule.tick(100);
        }
        schedule.resume();

        assert_eq!(schedule.pending(), 0);
        assert_eq!(schedule.tick(99), 0, "the interval restarts, not the flood");
        assert_eq!(schedule.tick(1), 2);
    }

    #[test]
    fn suspending_with_no_timeout_is_not_a_suspension() {
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        schedule.suspend(0);
        assert!(!schedule.is_suspended());
        assert_eq!(schedule.tick(100), 1);
    }

    #[test]
    fn the_registration_list_reads_back() {
        let mut schedule = Schedule::<4>::new();
        schedule.broadcast_every(pgn::DM1, 100).unwrap();
        schedule
            .send_every(pgn::DM2, Address::new(0x21), 250)
            .unwrap();

        let listed: Vec<(Pgn, Address, u16)> = schedule
            .entries()
            .map(|(due, period)| (due.pgn, due.destination, period))
            .collect();
        assert_eq!(
            listed,
            [
                (pgn::DM1, Address::GLOBAL, 100),
                (pgn::DM2, Address::new(0x21), 250)
            ]
        );
    }

    #[test]
    fn every_capacity_fills_and_drains() {
        fn exercise<const N: usize>() {
            let mut schedule = Schedule::<N>::new();
            for index in 0..N {
                let group = Pgn::new_masked(0x00F000 + index as u32);
                schedule.broadcast_every(group, 100).unwrap();
            }
            assert_eq!(schedule.len(), N);
            assert!(schedule.broadcast_every(pgn::DM13, 100).is_err());

            assert_eq!(schedule.tick(100), N);
            let mut drained = 0;
            while schedule.next_due().is_some() {
                drained += 1;
            }
            assert_eq!(drained, N);

            schedule.clear();
            assert!(schedule.is_empty());
            assert_eq!(schedule.tick(1000), 0);
        }
        exercise::<1>();
        exercise::<2>();
        exercise::<8>();
        exercise::<16>();
    }

    #[test]
    fn a_very_long_period_still_fires() {
        // u16 milliseconds tops out at about 65 seconds; the accumulator
        // saturates rather than wrapping, so a slow message is late at worst.
        let mut schedule = Schedule::<2>::new();
        schedule.broadcast_every(pgn::DM1, u16::MAX).unwrap();
        for _ in 0..64 {
            assert_eq!(schedule.tick(1000), 0);
        }
        assert_eq!(schedule.tick(2000), 1);
    }
}
