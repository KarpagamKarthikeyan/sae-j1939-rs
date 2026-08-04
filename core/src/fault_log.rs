// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The fault state an ECU reports about itself (J1939-73).
//!
//! [`crate::diagnostics`] is a codec: it turns trouble codes into bytes and
//! back. That is the whole job for a *tool* reading someone else's faults, but
//! an ECU reporting its own has to remember things — which faults are active,
//! which have been active, how many times each has occurred, which lamps they
//! light, and when the next DM1 is due.
//!
//! [`FaultLog`] is that memory. It owns no bus and no clock, so it runs
//! unchanged on a microcontroller and under a test: raise and clear faults as
//! the application detects them, call [`FaultLog::tick`] with however long has
//! passed, and transmit a DM1 whenever it says one is due.
//!
//! ```
//! use sae_j1939_rs::diagnostics::Lamp;
//! use sae_j1939_rs::fault_log::FaultLog;
//!
//! let mut faults = FaultLog::<8>::new();
//!
//! // The oil pressure sensor reads low (SPN 100, FMI 1).
//! faults.set(100, 1, Lamp::RedStop).unwrap();
//!
//! // One second later a DM1 is due, carrying that one code.
//! assert!(faults.tick(1000));
//! let mut payload = [0u8; 8];
//! let len = faults.dm1(&mut payload).unwrap();
//! assert_eq!(len, 8); // one code still fits a single CAN frame
//!
//! // The pressure recovers. The code stops being active and becomes history,
//! // and one final DM1 goes out to say the lamp is off.
//! assert!(faults.clear(100, 1));
//! assert!(faults.active().is_empty());
//! assert_eq!(faults.previously_active().len(), 1);
//! assert!(faults.tick(1000));
//!
//! // With nothing active and the all-clear already sent, DM1 stops.
//! assert!(!faults.tick(1000));
//! ```
//!
//! # Sizing
//!
//! `N` bounds both lists, so a `FaultLog<8>` is a little over 150 bytes and
//! allocates nothing. Pick it for the number of faults the ECU can *detect*,
//! not the number you expect: a wiring harness failure sets many at once.
//!
//! # What this does not do
//!
//! It does not transmit. A DM1 with two or more codes is longer than eight
//! bytes and has to go out over the transport protocol — see
//! [`crate::node::Outgoing`], or use `sae-j1939-host`'s `Ecu`, which wires
//! all of this to a real bus for you.

use crate::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps, MAX_OCCURRENCE_COUNT};
use crate::types::{Error, Result};

/// How often DM1 is broadcast while any fault is active, and the shortest gap
/// J1939-73 allows between two DM1s.
///
/// The same number serves both roles: a change to the fault state is reported
/// as soon as it happens, but never more than once per second, so "on change"
/// and "every second" collapse into one timer.
pub const DM1_INTERVAL_MS: u16 = 1000;

/// The slot filler. Never read — `active_len` and `previous_len` bound every
/// access — but an array has to start somewhere.
const UNUSED: Dtc = Dtc {
    spn: 0,
    fmi: 0,
    occurrence_count: 0,
    conversion_method: true,
};

/// Which faults an ECU has, and which it has had.
///
/// Holds up to `N` active codes (reported as DM1) and up to `N` previously
/// active ones (reported as DM2). See the [module documentation](self) for the
/// lifecycle.
#[derive(Debug, Clone)]
pub struct FaultLog<const N: usize> {
    active: [Dtc; N],
    /// The lamp each active code lights, parallel to `active`.
    lamps: [Lamp; N],
    active_len: usize,
    previous: [Dtc; N],
    previous_len: usize,
    since_dm1_ms: u32,
    /// A DM1 saying "nothing is wrong any more" is still owed. Without it a
    /// tool that saw the fault would keep showing it: the periodic DM1 stops
    /// when the last code clears, so silence has to be preceded by an
    /// explicit all-clear.
    owes_all_clear: bool,
}

impl<const N: usize> Default for FaultLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FaultLog<N> {
    /// An ECU with nothing wrong with it.
    pub const fn new() -> Self {
        FaultLog {
            active: [UNUSED; N],
            lamps: [Lamp::AmberWarning; N],
            active_len: 0,
            previous: [UNUSED; N],
            previous_len: 0,
            // Pre-charged, so a fault raised on a fresh log is reported at the
            // first tick rather than a second into the ECU's life.
            since_dm1_ms: DM1_INTERVAL_MS as u32,
            owes_all_clear: false,
        }
    }

    /// How many active codes this log can hold, and separately how many
    /// previously active ones.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The active trouble codes, in the order they were raised — which is to
    /// say oldest first, so the root cause of a cascade leads.
    pub fn active(&self) -> &[Dtc] {
        &self.active[..self.active_len]
    }

    /// The previously active trouble codes: faults that occurred and then
    /// stopped. Most recent last.
    pub fn previously_active(&self) -> &[Dtc] {
        &self.previous[..self.previous_len]
    }

    /// Whether a particular fault is active right now.
    pub fn is_active(&self, spn: u32, fmi: u8) -> bool {
        find(self.active(), spn, fmi).is_some()
    }

    /// Whether anything at all is wrong.
    pub fn is_healthy(&self) -> bool {
        self.active_len == 0
    }

    /// Raise a fault, or refresh one already raised.
    ///
    /// The occurrence count moves only on an inactive-to-active transition, as
    /// J1939-73 defines it: calling this every time the condition is re-checked
    /// does not inflate the count. A fault returning after it had cleared
    /// resumes from the count it left off at, saturating at
    /// [`MAX_OCCURRENCE_COUNT`].
    ///
    /// `lamp` is the lamp this fault lights; [`FaultLog::lamps`] turns the set
    /// of active faults into the two lamp bytes of a DM1.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDtc`] if `spn` exceeds 19 bits or `fmi` exceeds 5.
    ///
    /// [`Error::ValueOutOfRange`] if the log is full. The new fault is refused
    /// rather than displacing an existing one: when a harness fails, the first
    /// fault raised is usually the cause and the rest are consequences, so the
    /// oldest entries are the ones worth keeping.
    ///
    /// ```
    /// use sae_j1939_rs::diagnostics::Lamp;
    /// use sae_j1939_rs::fault_log::FaultLog;
    ///
    /// let mut faults = FaultLog::<4>::new();
    /// faults.set(100, 1, Lamp::AmberWarning).unwrap();
    /// faults.set(100, 1, Lamp::AmberWarning).unwrap(); // still the same occurrence
    /// assert_eq!(faults.active()[0].occurrence_count, 1);
    ///
    /// faults.clear(100, 1);
    /// faults.set(100, 1, Lamp::AmberWarning).unwrap(); // it came back
    /// assert_eq!(faults.active()[0].occurrence_count, 2);
    /// ```
    pub fn set(&mut self, spn: u32, fmi: u8, lamp: Lamp) -> Result<()> {
        // Validate before touching anything, so a rejected code cannot leave
        // the log half-updated.
        let mut dtc = Dtc::new(spn, fmi, 1)?;

        // Already active: the condition never went away, so this is the same
        // occurrence. Only the lamp may have been reassessed.
        if let Some(index) = find(self.active(), spn, fmi) {
            self.lamps[index] = lamp;
            return Ok(());
        }

        if self.active_len == N {
            return Err(Error::ValueOutOfRange {
                field: "active fault log capacity",
                value: N as u32,
            });
        }

        // Coming back after having cleared: a new occurrence of a known fault.
        if let Some(index) = find(self.previously_active(), spn, fmi) {
            let seen = self.previous[index].occurrence_count;
            dtc.occurrence_count = seen.saturating_add(1).min(MAX_OCCURRENCE_COUNT);
            self.remove_previous(index);
        }

        self.active[self.active_len] = dtc;
        self.lamps[self.active_len] = lamp;
        self.active_len += 1;
        self.owes_all_clear = false;
        Ok(())
    }

    /// Retire a fault whose condition has gone away, moving it to the
    /// previously active list.
    ///
    /// Returns whether it was active. Clearing the last active fault leaves one
    /// final DM1 owed, so that a tool watching the bus sees the lamps go out
    /// rather than merely losing the signal.
    pub fn clear(&mut self, spn: u32, fmi: u8) -> bool {
        let Some(index) = find(self.active(), spn, fmi) else {
            return false;
        };
        let dtc = self.active[index];
        self.remove_active(index);
        self.record_previous(dtc);
        if self.active_len == 0 {
            self.owes_all_clear = true;
        }
        true
    }

    /// Discard the active codes without recording them as history — the
    /// response to a DM11 request.
    ///
    /// The codes are erased, not retired. A fault becomes *previously* active
    /// when its condition stops, and a tool asking for a reset is not evidence
    /// that anything stopped; if the condition persists the ECU will simply
    /// raise it again, from a fresh occurrence count. See
    /// [`crate::diagnostics::dm11`].
    pub fn clear_active(&mut self) {
        if self.active_len > 0 {
            self.owes_all_clear = true;
        }
        self.active_len = 0;
    }

    /// Discard the fault history — the response to a DM3 request.
    ///
    /// See [`crate::diagnostics::dm3`]. Active faults are untouched: DM3 clears
    /// what has happened, not what is happening.
    pub fn clear_previously_active(&mut self) {
        self.previous_len = 0;
    }

    /// The lamp bytes for the current set of active faults: every lamp named by
    /// an active code is on, the rest off.
    ///
    /// Flash status is left off, which reports a steady lamp. Flashing encodes
    /// manufacturer-specific meaning that only the application knows, so build
    /// on this with [`Lamps::with_flash_status`] if the ECU has such a meaning.
    pub fn lamps(&self) -> Lamps {
        let mut lamps = Lamps::new();
        for lamp in &self.lamps[..self.active_len] {
            lamps = lamps.with_status(*lamp, LampStatus::On);
        }
        lamps
    }

    /// Encode the DM1 payload — lamps plus every active code — returning its
    /// length.
    ///
    /// With no active faults this is the all-clear message: lamps off and the
    /// zero placeholder code, eight bytes. With one fault it is still eight
    /// bytes. With two or more it exceeds a CAN frame and must go out over the
    /// transport protocol; [`FaultLog::dm1_len`] says how large a buffer to
    /// bring.
    ///
    /// # Errors
    ///
    /// [`Error::ShortPayload`] if `out` is smaller than [`FaultLog::dm1_len`].
    pub fn dm1(&self, out: &mut [u8]) -> Result<usize> {
        if self.active_len == 0 {
            // Not an empty code list: J1939-73 reports "no active faults" as a
            // single all-zero code, which is what a tool looks for.
            return diagnostics::encode(self.lamps(), &[Dtc::default()], out);
        }
        diagnostics::encode(self.lamps(), self.active(), out)
    }

    /// Encode the DM2 payload — the fault history — returning its length.
    ///
    /// The lamps are reported off: DM2 describes faults that are no longer
    /// happening, so nothing about it should light a lamp.
    ///
    /// # Errors
    ///
    /// [`Error::ShortPayload`] if `out` is smaller than [`FaultLog::dm2_len`].
    pub fn dm2(&self, out: &mut [u8]) -> Result<usize> {
        if self.previous_len == 0 {
            return diagnostics::encode(Lamps::new(), &[Dtc::default()], out);
        }
        diagnostics::encode(Lamps::new(), self.previously_active(), out)
    }

    /// How many bytes [`FaultLog::dm1`] will write.
    pub const fn dm1_len(&self) -> usize {
        payload_len(self.active_len)
    }

    /// How many bytes [`FaultLog::dm2`] will write.
    pub const fn dm2_len(&self) -> usize {
        payload_len(self.previous_len)
    }

    /// Advance the DM1 timer by `elapsed_ms`, returning whether a DM1 should be
    /// transmitted now.
    ///
    /// Says yes at most once per [`DM1_INTERVAL_MS`]: once per second while any
    /// fault is active, once more after the last one clears, then nothing until
    /// something goes wrong again.
    ///
    /// ```
    /// use sae_j1939_rs::diagnostics::Lamp;
    /// use sae_j1939_rs::fault_log::FaultLog;
    ///
    /// let mut faults = FaultLog::<4>::new();
    ///
    /// // A healthy ECU says nothing.
    /// assert!(!faults.tick(5000));
    ///
    /// // A fault raised long after the last DM1 is reported at once...
    /// faults.set(110, 0, Lamp::AmberWarning).unwrap();
    /// assert!(faults.tick(1));
    /// // ...and not again until a second has passed.
    /// assert!(!faults.tick(999));
    /// assert!(faults.tick(1));
    /// ```
    #[must_use = "the DM1 has to be transmitted, or the timer just moved for nothing"]
    pub fn tick(&mut self, elapsed_ms: u16) -> bool {
        // Saturating rather than wrapping: an ECU can be healthy for weeks, and
        // wrapping would silently withhold the first report of a real fault.
        self.since_dm1_ms = self.since_dm1_ms.saturating_add(elapsed_ms as u32);

        if self.since_dm1_ms < DM1_INTERVAL_MS as u32 {
            return false;
        }
        if self.active_len == 0 && !self.owes_all_clear {
            return false;
        }
        self.since_dm1_ms = 0;
        self.owes_all_clear = false;
        true
    }

    fn remove_active(&mut self, index: usize) {
        // Shift rather than swap with the last: the order carries meaning, and
        // a reordered DM1 looks to a tool like the fault set changed.
        self.active.copy_within(index + 1..self.active_len, index);
        self.lamps.copy_within(index + 1..self.active_len, index);
        self.active_len -= 1;
    }

    fn remove_previous(&mut self, index: usize) {
        self.previous
            .copy_within(index + 1..self.previous_len, index);
        self.previous_len -= 1;
    }

    fn record_previous(&mut self, dtc: Dtc) {
        // A fault that occurs, clears, and occurs again should appear once,
        // with the higher count — not twice.
        if let Some(index) = find(self.previously_active(), dtc.spn, dtc.fmi) {
            self.previous[index] = dtc;
            return;
        }
        if self.previous_len == N {
            // History, unlike the active list, is worth losing from the far
            // end: a technician is diagnosing the recent past, so drop the
            // oldest entry rather than refusing to record the newest.
            self.remove_previous(0);
        }
        self.previous[self.previous_len] = dtc;
        self.previous_len += 1;
    }
}

/// Where a fault sits in a list, matched on SPN and FMI — the pair that
/// identifies a fault. Occurrence count is state, not identity.
fn find(dtcs: &[Dtc], spn: u32, fmi: u8) -> Option<usize> {
    dtcs.iter().position(|dtc| dtc.spn == spn && dtc.fmi == fmi)
}

/// Lamps plus one code per fault, and never less than a full CAN frame — an
/// empty list is still reported as the single zero placeholder.
const fn payload_len(count: usize) -> usize {
    let body = 2 + if count == 0 { 1 } else { count } * 4;
    if body < 8 {
        8
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::Message;

    fn parse(payload: &[u8]) -> (Lamps, std::vec::Vec<Dtc>) {
        let dm = Message::parse(payload).unwrap();
        (dm.lamps(), dm.dtcs().collect())
    }

    #[test]
    fn a_new_log_is_healthy_and_silent() {
        let mut faults = FaultLog::<4>::new();
        assert!(faults.is_healthy());
        assert!(faults.active().is_empty());
        assert!(faults.previously_active().is_empty());
        // Nothing wrong, so nothing to say — however long we wait.
        assert!(!faults.tick(1000));
        assert!(!faults.tick(60_000));
    }

    #[test]
    fn a_fault_lights_its_lamp_and_only_its_lamp() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();

        let lamps = faults.lamps();
        assert_eq!(lamps.status(Lamp::RedStop), LampStatus::On);
        assert_eq!(lamps.status(Lamp::AmberWarning), LampStatus::Off);
        assert_eq!(lamps.status(Lamp::MalfunctionIndicator), LampStatus::Off);
        assert_eq!(lamps.status(Lamp::Protect), LampStatus::Off);
    }

    #[test]
    fn lamps_are_the_union_of_every_active_fault() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();
        faults.set(190, 16, Lamp::AmberWarning).unwrap();

        let lamps = faults.lamps();
        assert_eq!(lamps.status(Lamp::RedStop), LampStatus::On);
        assert_eq!(lamps.status(Lamp::AmberWarning), LampStatus::On);
        assert_eq!(lamps.status(Lamp::Protect), LampStatus::Off);

        // Clearing the red-stop fault puts that lamp out but leaves the amber
        // one on: two faults still name it.
        assert!(faults.clear(100, 1));
        assert_eq!(faults.lamps().status(Lamp::RedStop), LampStatus::Off);
        assert_eq!(faults.lamps().status(Lamp::AmberWarning), LampStatus::On);
    }

    #[test]
    fn re_asserting_a_live_fault_is_not_a_new_occurrence() {
        let mut faults = FaultLog::<4>::new();
        for _ in 0..50 {
            faults.set(100, 1, Lamp::AmberWarning).unwrap();
        }
        assert_eq!(faults.active().len(), 1);
        assert_eq!(faults.active()[0].occurrence_count, 1);
    }

    #[test]
    fn a_fault_that_returns_counts_again() {
        let mut faults = FaultLog::<4>::new();
        for expected in 1..=5 {
            faults.set(100, 1, Lamp::AmberWarning).unwrap();
            assert_eq!(faults.active()[0].occurrence_count, expected);
            assert!(faults.clear(100, 1));
            // Retiring it does not lose the count.
            assert_eq!(faults.previously_active()[0].occurrence_count, expected);
        }
        // And it is one entry in the history, not five.
        assert_eq!(faults.previously_active().len(), 1);
    }

    #[test]
    fn the_occurrence_count_saturates_rather_than_wrapping() {
        let mut faults = FaultLog::<2>::new();
        for _ in 0..MAX_OCCURRENCE_COUNT as u32 + 10 {
            faults.set(100, 1, Lamp::AmberWarning).unwrap();
            faults.clear(100, 1);
        }
        faults.set(100, 1, Lamp::AmberWarning).unwrap();
        assert_eq!(faults.active()[0].occurrence_count, MAX_OCCURRENCE_COUNT);
    }

    #[test]
    fn clearing_a_fault_that_is_not_set_changes_nothing() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::AmberWarning).unwrap();
        assert!(!faults.clear(999, 3));
        assert_eq!(faults.active().len(), 1);
        assert!(faults.previously_active().is_empty());
    }

    #[test]
    fn a_full_log_refuses_the_newest_fault_and_keeps_the_oldest() {
        let mut faults = FaultLog::<3>::new();
        faults.set(100, 1, Lamp::AmberWarning).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();
        faults.set(190, 16, Lamp::AmberWarning).unwrap();

        assert_eq!(
            faults.set(157, 3, Lamp::AmberWarning),
            Err(Error::ValueOutOfRange {
                field: "active fault log capacity",
                value: 3,
            })
        );
        // The first fault raised — usually the cause — is still there.
        assert_eq!(faults.active()[0].spn, 100);
        assert_eq!(faults.active().len(), 3);
    }

    #[test]
    fn history_drops_its_oldest_entry_when_full() {
        let mut faults = FaultLog::<2>::new();
        for spn in [100u32, 110, 190] {
            faults.set(spn, 1, Lamp::AmberWarning).unwrap();
            faults.clear(spn, 1);
        }
        // Two slots, three faults: the oldest went, the two most recent stayed.
        let history: std::vec::Vec<u32> =
            faults.previously_active().iter().map(|d| d.spn).collect();
        assert_eq!(history, [110, 190]);
    }

    #[test]
    fn a_full_active_list_still_accepts_a_fault_returning_from_history() {
        // The returning fault takes a slot the log has, so capacity is checked
        // before the history lookup, not after.
        let mut faults = FaultLog::<2>::new();
        faults.set(100, 1, Lamp::AmberWarning).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();
        faults.clear(100, 1);

        faults.set(100, 1, Lamp::AmberWarning).unwrap();
        assert_eq!(faults.active().len(), 2);
        assert_eq!(faults.active()[1].occurrence_count, 2);
        assert!(faults.previously_active().is_empty());
    }

    #[test]
    fn rejects_a_trouble_code_that_does_not_fit_the_wire_format() {
        let mut faults = FaultLog::<4>::new();
        assert_eq!(
            faults.set(1 << 20, 1, Lamp::AmberWarning),
            Err(Error::InvalidDtc)
        );
        assert_eq!(
            faults.set(100, 32, Lamp::AmberWarning),
            Err(Error::InvalidDtc)
        );
        // Rejected, and nothing was recorded.
        assert!(faults.active().is_empty());
    }

    #[test]
    fn faults_keep_the_order_they_were_raised_in() {
        let mut faults = FaultLog::<8>::new();
        for spn in [100u32, 110, 190, 157] {
            faults.set(spn, 1, Lamp::AmberWarning).unwrap();
        }
        // Remove from the middle: the rest must not be reordered, or a tool
        // reading successive DM1s would see the fault set apparently change.
        assert!(faults.clear(190, 1));
        let order: std::vec::Vec<u32> = faults.active().iter().map(|d| d.spn).collect();
        assert_eq!(order, [100, 110, 157]);
    }

    #[test]
    fn a_dm1_with_no_faults_reads_back_as_fault_free() {
        let faults = FaultLog::<4>::new();
        let mut payload = [0u8; 8];
        let len = faults.dm1(&mut payload).unwrap();
        assert_eq!(len, faults.dm1_len());
        assert_eq!(len, 8);

        let dm = Message::parse(&payload[..len]).unwrap();
        assert!(dm.is_fault_free(), "an ECU with no faults must say so");
        assert!(!dm.lamps().any_on());
    }

    #[test]
    fn a_dm1_round_trips_through_the_wire_format() {
        let mut faults = FaultLog::<8>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();
        faults.set(190, 16, Lamp::Protect).unwrap();

        let mut payload = [0u8; 32];
        let len = faults.dm1(&mut payload).unwrap();
        assert_eq!(len, faults.dm1_len());
        assert_eq!(len, 2 + 3 * 4);

        let (lamps, dtcs) = parse(&payload[..len]);
        assert_eq!(lamps, faults.lamps());
        assert_eq!(dtcs, faults.active());
    }

    #[test]
    fn dm2_reports_history_with_the_lamps_off() {
        let mut faults = FaultLog::<8>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.clear(100, 1);
        // Still-active faults must not leak into DM2, nor light its lamps.
        faults.set(110, 0, Lamp::AmberWarning).unwrap();

        let mut payload = [0u8; 32];
        let len = faults.dm2(&mut payload).unwrap();
        let (lamps, dtcs) = parse(&payload[..len]);

        assert!(!lamps.any_on(), "history lights no lamps");
        assert_eq!(dtcs.len(), 1);
        assert_eq!(dtcs[0].spn, 100);
    }

    #[test]
    fn an_empty_dm2_reads_back_as_fault_free() {
        let faults = FaultLog::<4>::new();
        let mut payload = [0u8; 8];
        let len = faults.dm2(&mut payload).unwrap();
        assert_eq!(len, faults.dm2_len());
        assert!(Message::parse(&payload[..len]).unwrap().is_fault_free());
    }

    #[test]
    fn encoding_reports_a_buffer_that_is_too_small() {
        let mut faults = FaultLog::<8>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();

        let mut payload = [0u8; 8];
        assert_eq!(
            faults.dm1(&mut payload),
            Err(Error::ShortPayload {
                expected: 10,
                actual: 8
            })
        );
        assert_eq!(faults.dm1_len(), 10);
    }

    #[test]
    fn dm1_is_broadcast_once_a_second_while_a_fault_is_active() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();

        // The first report is immediate: nothing has been said for a while.
        assert!(faults.tick(10));
        // Then strictly once per second, however finely the loop ticks.
        for second in 0..5 {
            for _ in 0..100 {
                assert!(!faults.tick(9), "too early, in second {second}");
            }
            assert!(faults.tick(100), "a second passed in second {second}");
        }
    }

    #[test]
    fn the_last_fault_clearing_leaves_one_all_clear_owed() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        assert!(faults.tick(1000));

        faults.clear(100, 1);
        assert!(faults.tick(1000), "the lamps going out must be announced");

        let mut payload = [0u8; 8];
        let len = faults.dm1(&mut payload).unwrap();
        let dm = Message::parse(&payload[..len]).unwrap();
        assert!(dm.is_fault_free());
        assert!(!dm.lamps().any_on());

        // And then silence.
        for _ in 0..10 {
            assert!(!faults.tick(1000));
        }
    }

    #[test]
    fn clearing_one_of_several_faults_does_not_announce_an_all_clear() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();
        assert!(faults.tick(1000));

        faults.clear(100, 1);
        // Still due — but because a fault is active, not because of an
        // all-clear. Draining the periodic report leaves nothing extra behind.
        assert!(faults.tick(1000));
        faults.clear(110, 0);
        assert!(faults.tick(1000), "now the last one has gone");
        assert!(!faults.tick(1000));
    }

    #[test]
    fn dm11_erases_active_codes_without_inventing_history() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.set(110, 0, Lamp::AmberWarning).unwrap();

        faults.clear_active();
        assert!(faults.is_healthy());
        // A reset command is not evidence the condition stopped, so nothing is
        // recorded as previously active.
        assert!(faults.previously_active().is_empty());
        // The lamps going out is still worth announcing.
        assert!(faults.tick(1000));

        // If the condition persists the ECU raises it again, from a fresh count.
        faults.set(100, 1, Lamp::RedStop).unwrap();
        assert_eq!(faults.active()[0].occurrence_count, 1);
    }

    #[test]
    fn dm11_on_a_healthy_ecu_says_nothing() {
        let mut faults = FaultLog::<4>::new();
        faults.clear_active();
        assert!(!faults.tick(1000), "there was no lamp to put out");
    }

    #[test]
    fn dm3_clears_history_and_leaves_live_faults_alone() {
        let mut faults = FaultLog::<4>::new();
        faults.set(100, 1, Lamp::RedStop).unwrap();
        faults.clear(100, 1);
        faults.set(110, 0, Lamp::AmberWarning).unwrap();

        faults.clear_previously_active();
        assert!(faults.previously_active().is_empty());
        assert_eq!(faults.active().len(), 1);
        assert_eq!(faults.active()[0].spn, 110);
    }

    #[test]
    fn the_log_survives_a_long_healthy_run() {
        // u32 milliseconds is 49 days; saturation must not turn into a wrap
        // that withholds the first report of a real fault.
        let mut faults = FaultLog::<4>::new();
        for _ in 0..2000 {
            assert!(!faults.tick(u16::MAX));
        }
        faults.set(100, 1, Lamp::RedStop).unwrap();
        assert!(
            faults.tick(1),
            "a fault after a long quiet spell reports at once"
        );
    }

    #[test]
    fn capacity_is_reported_and_respected() {
        let faults = FaultLog::<7>::new();
        assert_eq!(faults.capacity(), 7);
    }

    #[test]
    fn every_capacity_fills_and_empties_cleanly() {
        fn exercise<const N: usize>() {
            let mut faults = FaultLog::<N>::new();
            for i in 0..N as u32 {
                faults.set(i + 1, 1, Lamp::AmberWarning).unwrap();
            }
            assert_eq!(faults.active().len(), N);
            assert!(faults.set(9999, 1, Lamp::AmberWarning).is_err());

            for i in 0..N as u32 {
                assert!(faults.clear(i + 1, 1));
            }
            assert!(faults.is_healthy());
            assert_eq!(faults.previously_active().len(), N);

            // And the whole set can be re-raised from history.
            for i in 0..N as u32 {
                faults.set(i + 1, 1, Lamp::AmberWarning).unwrap();
                assert_eq!(faults.active().last().unwrap().occurrence_count, 2);
            }
        }
        exercise::<1>();
        exercise::<2>();
        exercise::<3>();
        exercise::<8>();
        exercise::<32>();
    }
}
