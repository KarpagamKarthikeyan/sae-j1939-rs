// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading `candump` captures, and replaying them through the stack.
//!
//! Three modules in this crate — [`etp`](sae_j1939_rs::etp),
//! [`working_set`](sae_j1939_rs::iso11783::working_set), and
//! [`task_controller`](sae_j1939_rs::iso11783::task_controller) — are built from
//! the specification alone, with no reference implementation to check them
//! against. Tests prove they are self-consistent; only real traffic proves they
//! are *right*.
//!
//! This module closes that gap without needing a live bus. Capture once:
//!
//! ```text
//! candump -l can0            # writes candump-2026-08-02_120000.log
//! ```
//!
//! then replay the file offline, as many times as you like, through the same
//! code that would have run on the vehicle:
//!
//! ```
//! use sae_j1939_host::log::Replay;
//! use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name};
//!
//! let capture = "\
//! (1754140800.100000) can0 18FECA80#04002B0104830000
//! (1754140800.200000) can0 0CF00400#FF8796E02EFFFFFF
//! ";
//!
//! let name = Name::new().with_manufacturer_code(300).with_identity_number(1);
//! let mut replay = Replay::new(name, Address::new(0xF9));
//! let messages = replay.run(capture)?;
//!
//! // Both frames are single-frame broadcasts, so both arrive whole.
//! assert_eq!(messages.len(), 2);
//! assert_eq!(messages[0].pgn, pgn::DM1);
//! # Ok::<(), sae_j1939_host::log::LogError>(())
//! ```
//!
//! # Why the timestamps matter
//!
//! A replay drives [`Node::tick`](sae_j1939_rs::node::Node::tick) from the
//! *capture's own* timestamps, not from wall-clock time. A transfer that stalled
//! on the real bus therefore stalls here at the same point, and a session that
//! timed out times out. That is only possible because the state machines own no
//! clock — the whole sans-I/O design paying off somewhere concrete.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use sae_j1939_rs::etp::{self, EtpCm, EtpDt};
use sae_j1939_rs::node::{Event, Node};
use sae_j1939_rs::{Address, Frame, Id, Name};

use crate::bus::Message;

/// Something that went wrong reading a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// A line was not in `candump` format.
    Malformed {
        /// The 1-based line number.
        line: usize,
        /// What was expected.
        expected: &'static str,
    },
    /// An identifier that is not a valid 29-bit J1939 identifier.
    NotJ1939 {
        /// The 1-based line number.
        line: usize,
        /// The identifier as written.
        id: String,
    },
    /// A payload with an odd number of hex digits, or more than eight bytes.
    BadPayload {
        /// The 1-based line number.
        line: usize,
    },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::Malformed { line, expected } => write!(f, "line {line}: expected {expected}"),
            LogError::NotJ1939 { line, id } => {
                write!(f, "line {line}: {id} is not a 29-bit J1939 identifier")
            }
            LogError::BadPayload { line } => write!(f, "line {line}: malformed payload"),
        }
    }
}

impl std::error::Error for LogError {}

/// One frame from a capture, with the time it was seen.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Entry {
    /// Seconds since the epoch, as `candump` recorded it.
    pub timestamp: f64,
    /// The frame.
    pub frame: Frame,
}

/// Parse one `candump -l` line.
///
/// The format is `(timestamp) interface ID#DATA`. Returns `Ok(None)` for a line
/// this crate cannot use — a blank line, an 11-bit standard identifier, a remote
/// frame, or a CAN FD frame — rather than failing, so a mixed capture from a
/// shared bus replays without being edited first.
///
/// ```
/// use sae_j1939_host::log::parse_line;
///
/// let entry = parse_line("(1754140800.123456) can0 18FECA80#0400000000000000", 1)
///     .unwrap()
///     .expect("a J1939 frame");
/// assert_eq!(entry.frame.id().as_u32(), 0x18FECA80);
/// assert_eq!(entry.frame.data().len(), 8);
///
/// // A CANopen frame sharing the bus is skipped, not an error.
/// assert!(parse_line("(1754140800.2) can0 581#4300100000000000", 2).unwrap().is_none());
/// ```
pub fn parse_line(line: &str, number: usize) -> Result<Option<Entry>, LogError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    let malformed = |expected| LogError::Malformed {
        line: number,
        expected,
    };

    let rest = line
        .strip_prefix('(')
        .ok_or_else(|| malformed("a '(' starting the timestamp"))?;
    let (timestamp_text, rest) = rest
        .split_once(')')
        .ok_or_else(|| malformed("a ')' after the timestamp"))?;
    let timestamp: f64 = timestamp_text
        .trim()
        .parse()
        .map_err(|_| malformed("a numeric timestamp"))?;

    let mut parts = rest.split_whitespace();
    let _interface = parts.next().ok_or_else(|| malformed("an interface name"))?;
    let frame_text = parts.next().ok_or_else(|| malformed("an ID#DATA frame"))?;

    // CAN FD uses `##`, which this stack does not carry.
    if frame_text.contains("##") {
        return Ok(None);
    }
    let (id_text, payload_text) = frame_text
        .split_once('#')
        .ok_or_else(|| malformed("a '#' between identifier and payload"))?;

    // A remote frame has no payload to decode.
    if payload_text.starts_with('R') || payload_text.starts_with('r') {
        return Ok(None);
    }
    // An 11-bit identifier is not J1939 — it may be CANopen on a shared bus.
    if id_text.len() <= 3 {
        return Ok(None);
    }

    let raw = u32::from_str_radix(id_text, 16).map_err(|_| LogError::NotJ1939 {
        line: number,
        id: id_text.to_string(),
    })?;
    let id = Id::new(raw).map_err(|_| LogError::NotJ1939 {
        line: number,
        id: id_text.to_string(),
    })?;

    if payload_text.len() % 2 != 0 || payload_text.len() > 16 {
        return Err(LogError::BadPayload { line: number });
    }
    let mut data = [0u8; 8];
    let len = payload_text.len() / 2;
    for i in 0..len {
        data[i] = u8::from_str_radix(&payload_text[i * 2..i * 2 + 2], 16)
            .map_err(|_| LogError::BadPayload { line: number })?;
    }

    let frame = Frame::new(id, &data[..len]).map_err(|_| LogError::BadPayload { line: number })?;
    Ok(Some(Entry { timestamp, frame }))
}

/// Parse a whole capture.
pub fn parse(text: &str) -> Result<Vec<Entry>, LogError> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if let Some(entry) = parse_line(line, index + 1)? {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Read and parse a capture file.
pub fn from_file(path: impl AsRef<Path>) -> io::Result<Vec<Entry>> {
    let text = fs::read_to_string(path)?;
    parse(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Drives a capture through a [`Node`], reassembling as the bus did.
///
/// Deliberately not generic. Everywhere else in this crate buffer sizes are a
/// const parameter, because an MCU has to bound its memory. A capture analyser
/// runs on a workstation, so the knob would be a papercut with no payoff — and
/// const-generic defaults do not apply to associated function calls anyway, so
/// `Replay::new` would need a turbofish every time.
#[derive(Debug)]
pub struct Replay {
    node: Node<1785, 8>,
    /// Extended transport protocol. A capture may well contain one — and since
    /// `etp` is among the modules with no reference implementation to check it
    /// against, a replay that could not reassemble it would be useless for
    /// exactly the traffic it most needs to prove.
    etp: etp::Reassembler<{ 64 * 1024 }, 2>,
    /// The timestamp of the previous frame, so elapsed time comes from the
    /// capture rather than from now.
    previous: Option<f64>,
    /// Frames the node asked to transmit. A replay puts nothing on a bus, so
    /// they are recorded instead — which is what makes the responses inspectable.
    transmitted: Vec<Frame>,
    /// Every ECU seen claiming an address, and the NAME it claimed with.
    ///
    /// `Node` consumes address claims as network management, so they never
    /// surface as messages. For a replay that is exactly backwards: "who is on
    /// this bus" is the first thing anyone asks of a capture.
    claims: BTreeMap<u8, Name>,
}

impl Replay {
    /// A replay as an ECU with this NAME and address.
    ///
    /// The address matters: a capture contains traffic addressed to other ECUs,
    /// and the node applies the same receive filter it would on a real bus. Use
    /// the address of the ECU whose view you want to reconstruct.
    pub fn new(name: Name, address: Address) -> Self {
        let mut node = Node::new(name, address);
        // Claim immediately: a replay reconstructs what an already-running ECU
        // would have seen, not a cold start.
        node.start();
        node.tick(sae_j1939_rs::node::ADDRESS_CLAIM_WINDOW_MS, |_| {});
        Replay {
            node,
            etp: etp::Reassembler::new(),
            previous: None,
            transmitted: Vec::new(),
            claims: BTreeMap::new(),
        }
    }

    /// Feed one entry, returning any message it completed.
    pub fn feed(&mut self, entry: &Entry) -> Option<Message> {
        // Elapsed time comes from the capture, so a transfer that stalled on the
        // real bus stalls here at the same point.
        if let Some(previous) = self.previous {
            let elapsed = ((entry.timestamp - previous) * 1000.0).max(0.0);
            let elapsed_ms = elapsed.min(u16::MAX as f64) as u16;
            let mut timeouts = Vec::new();
            self.node.tick(elapsed_ms, |frame| timeouts.push(frame));
            self.transmitted.extend(timeouts);
        }
        self.previous = Some(entry.timestamp);

        // Record the claim before the node consumes it.
        if entry.frame.pgn() == sae_j1939_rs::pgn::ADDRESS_CLAIMED {
            let source = entry.frame.source_address();
            if source.is_specific() {
                self.claims
                    .insert(source.as_u8(), Name::from_bytes(entry.frame.payload()));
            }
        }

        // The extended transport protocol first: `Node` does not model it.
        let group = entry.frame.pgn();
        if group == sae_j1939_rs::pgn::ETP_CM || group == sae_j1939_rs::pgn::ETP_DT {
            return self.feed_etp(&entry.frame);
        }

        let mut reply = None;
        let mut message = None;
        match self.node.on_frame(&entry.frame) {
            Event::Idle => {}
            Event::Transmit(frame) => reply = Some(frame),
            Event::Message {
                pgn,
                source,
                data,
                reply: ack,
            } => {
                reply = ack;
                message = Some(Message {
                    pgn,
                    source,
                    data: data.to_vec(),
                });
            }
        }
        self.transmitted.extend(reply);
        message
    }

    /// Reassemble an extended-transport-protocol frame.
    fn feed_etp(&mut self, frame: &Frame) -> Option<Message> {
        let source = frame.source_address();
        let outcome = if frame.pgn() == sae_j1939_rs::pgn::ETP_CM {
            match EtpCm::decode(frame.payload()) {
                Ok(cm) => self.etp.on_etp_cm(source, &cm),
                Err(_) => return None,
            }
        } else {
            self.etp.on_etp_dt(source, &EtpDt::decode(frame.payload()))
        };

        match outcome {
            etp::Rx::Idle | etp::Rx::Send(_) => None,
            etp::Rx::Message {
                pgn, source, data, ..
            } => Some(Message {
                pgn,
                source,
                data: data.to_vec(),
            }),
        }
    }

    /// Replay a whole capture, returning every message it completed.
    pub fn run(&mut self, text: &str) -> Result<Vec<Message>, LogError> {
        let entries = parse(text)?;
        Ok(entries
            .iter()
            .filter_map(|entry| self.feed(entry))
            .collect())
    }

    /// Replay a capture file.
    pub fn run_file(&mut self, path: impl AsRef<Path>) -> io::Result<Vec<Message>> {
        let entries = from_file(path)?;
        Ok(entries
            .iter()
            .filter_map(|entry| self.feed(entry))
            .collect())
    }

    /// The frames the node would have transmitted.
    ///
    /// A replay sends nothing, so these are recorded instead — which is how you
    /// check that the stack answered a capture the way the real ECU did. Compare
    /// them against the outgoing frames in the same capture.
    pub fn transmitted(&self) -> &[Frame] {
        &self.transmitted
    }

    /// Every ECU observed claiming an address, with the NAME it used.
    ///
    /// This is the bus inventory a capture is usually opened to get. Address
    /// claims are network management, so [`Replay::run`] never returns them as
    /// messages — they are collected here instead.
    pub fn claimed_addresses(&self) -> impl Iterator<Item = (Address, Name)> + '_ {
        self.claims
            .iter()
            .map(|(&address, &name)| (Address::new(address), name))
    }

    /// The node being driven, for its address and claim state.
    pub fn node(&self) -> &Node<1785, 8> {
        &self.node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sae_j1939_rs::diagnostics::{self, Dtc, Lamp, LampStatus, Lamps};
    use sae_j1939_rs::node::Outgoing;
    use sae_j1939_rs::pgn;

    fn name() -> Name {
        Name::new()
            .with_manufacturer_code(300)
            .with_identity_number(1)
    }

    #[test]
    fn parses_the_candump_line_format() {
        let entry = parse_line("(1754140800.123456) can0 18FECA80#04002B0104830000", 1)
            .unwrap()
            .unwrap();
        assert_eq!(entry.timestamp, 1754140800.123456);
        assert_eq!(entry.frame.id().as_u32(), 0x18FECA80);
        assert_eq!(entry.frame.pgn(), pgn::DM1);
        assert_eq!(
            entry.frame.data(),
            &[0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0x00, 0x00]
        );
    }

    #[test]
    fn a_short_payload_keeps_its_length() {
        // A Request is three bytes, and a capture records exactly three.
        let entry = parse_line("(1.0) can0 18EA80F9#CAFE00", 1)
            .unwrap()
            .unwrap();
        assert_eq!(entry.frame.data(), &[0xCA, 0xFE, 0x00]);
        assert_eq!(entry.frame.dlc(), 3);
    }

    /// A capture from a shared bus contains traffic this stack cannot use.
    /// Skipping it beats making the user edit the file first.
    #[test]
    fn unusable_lines_are_skipped_rather_than_failing() {
        for line in [
            "",
            "   ",
            "# a comment",
            "(1.0) can0 581#4300100000000000", // 11-bit: CANopen, not J1939
            "(1.0) can0 123#R",                // remote frame
            "(1.0) can0 18FECA80##1AABBCC",    // CAN FD
        ] {
            assert_eq!(parse_line(line, 1).unwrap(), None, "line {line:?}");
        }
    }

    #[test]
    fn malformed_lines_name_the_line_number() {
        assert!(matches!(
            parse_line("not a candump line", 7),
            Err(LogError::Malformed { line: 7, .. })
        ));
        assert!(matches!(
            parse_line("(1.0) can0 1FFFFFFFF#00", 3),
            Err(LogError::NotJ1939 { line: 3, .. })
        ));
        assert!(matches!(
            parse_line("(1.0) can0 18FECA80#ABC", 4),
            Err(LogError::BadPayload { line: 4 })
        ));
    }

    #[test]
    fn a_capture_of_single_frames_replays_whole() {
        let capture = "\
(1754140800.100000) can0 18FECA80#04002B0104830000
(1754140800.200000) can0 0CF00400#FF8796E02EFFFFFF
(1754140800.300000) can0 581#4300100000000000
";
        let mut replay = Replay::new(name(), Address::new(0xF9));
        let messages = replay.run(capture).unwrap();

        // The CANopen frame is skipped; the two J1939 frames arrive.
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].pgn, pgn::DM1);
        assert_eq!(messages[1].pgn.as_u32(), 0x00F004);
    }

    /// The point of the module: a multi-packet transfer captured off a real bus
    /// reassembles exactly as it did there.
    #[test]
    fn a_captured_multi_packet_transfer_reassembles() {
        // Build a capture the way a real ECU would have produced one.
        let faults = [
            Dtc::new(100, 1, 2).unwrap(),
            Dtc::new(110, 0, 5).unwrap(),
            Dtc::new(1569, 31, 126).unwrap(),
        ];
        let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
        let mut payload = [0u8; 64];
        let len = diagnostics::encode(lamps, &faults, &mut payload).unwrap();

        let mut tx = Outgoing::new(
            pgn::DM1,
            Address::new(0x00),
            Address::GLOBAL,
            &payload[..len],
        )
        .unwrap();
        let mut capture = String::new();
        let mut timestamp = 1754140800.0;
        while let Some(frame) = tx.next_frame() {
            // BAM packets are paced 50 ms apart, as on a real bus.
            capture.push_str(&format!("({timestamp:.6}) can0 {frame}\n"));
            timestamp += 0.05;
        }

        let mut replay = Replay::new(name(), Address::new(0xF9));
        let messages = replay.run(&capture).unwrap();

        assert_eq!(messages.len(), 1, "the packets form one message");
        let dm = diagnostics::Message::parse(&messages[0].data).unwrap();
        assert_eq!(dm.dtcs().collect::<Vec<_>>(), faults);
    }

    /// A stalled transfer must stall in replay too — which only works because
    /// elapsed time comes from the capture, not from wall-clock.
    #[test]
    fn a_transfer_that_stalled_on_the_bus_stalls_in_replay() {
        // An announcement, one packet, then a two-second gap: past T1.
        let announce = format!(
            "(1000.000000) can0 1CECFF00#{}",
            hex(&sae_j1939_rs::tp::TpCm::bam(14, pgn::DM1).unwrap().encode())
        );
        let packet = format!(
            "(1000.050000) can0 1CEBFF00#{}",
            hex(&sae_j1939_rs::tp::TpDt::new(1, &[1; 7]).encode())
        );
        // The second packet arrives far too late.
        let late = format!(
            "(1002.000000) can0 1CEBFF00#{}",
            hex(&sae_j1939_rs::tp::TpDt::new(2, &[2; 7]).encode())
        );

        let capture = format!("{announce}\n{packet}\n{late}\n");
        let mut replay = Replay::new(name(), Address::new(0xF9));
        let messages = replay.run(&capture).unwrap();

        assert!(
            messages.is_empty(),
            "the session timed out on the bus, so it must time out here"
        );
    }

    /// The same capture without the gap completes, proving the previous test
    /// failed for the timing and not for some other reason.
    #[test]
    fn the_same_transfer_without_the_gap_completes() {
        let announce = format!(
            "(1000.000000) can0 1CECFF00#{}",
            hex(&sae_j1939_rs::tp::TpCm::bam(14, pgn::DM1).unwrap().encode())
        );
        let packet = format!(
            "(1000.050000) can0 1CEBFF00#{}",
            hex(&sae_j1939_rs::tp::TpDt::new(1, &[1; 7]).encode())
        );
        let second = format!(
            "(1000.100000) can0 1CEBFF00#{}",
            hex(&sae_j1939_rs::tp::TpDt::new(2, &[2; 7]).encode())
        );

        let capture = format!("{announce}\n{packet}\n{second}\n");
        let mut replay = Replay::new(name(), Address::new(0xF9));
        let messages = replay.run(&capture).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.len(), 14);
    }

    /// Traffic addressed to a different ECU is filtered exactly as it would be
    /// on the bus, so a replay reconstructs one ECU's view rather than the whole
    /// bus's.
    #[test]
    fn the_replay_sees_only_what_its_address_would_have_seen() {
        let capture = "\
(1.0) can0 18EA80F9#CAFE00
(1.1) can0 18EAF980#CAFE00
";
        // As 0xF9: the second frame is addressed to us, the first to 0x80.
        let mut ours = Replay::new(name(), Address::new(0xF9));
        assert_eq!(ours.run(capture).unwrap().len(), 1);

        // As 0x80: the other way round.
        let mut theirs = Replay::new(name(), Address::new(0x80));
        assert_eq!(theirs.run(capture).unwrap().len(), 1);
    }

    /// "Who is on this bus" is the first question a capture is opened to answer,
    /// and address claims are consumed by the node rather than delivered.
    #[test]
    fn every_address_claim_is_recorded_as_a_bus_inventory() {
        let engine = Name::new()
            .with_manufacturer_code(300)
            .with_identity_number(100);
        let gearbox = Name::new()
            .with_manufacturer_code(400)
            .with_identity_number(200);

        let capture = format!(
            "(1.0) can0 18EEFF00#{}\n(1.1) can0 18EEFF03#{}\n",
            hex(&engine.to_bytes()),
            hex(&gearbox.to_bytes())
        );

        let mut replay = Replay::new(name(), Address::new(0xF9));
        let messages = replay.run(&capture).unwrap();
        assert!(
            messages.is_empty(),
            "claims are network management, not application messages"
        );

        let inventory: Vec<_> = replay.claimed_addresses().collect();
        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory[0], (Address::new(0x00), engine));
        assert_eq!(inventory[1], (Address::new(0x03), gearbox));
    }

    #[test]
    fn a_cannot_claim_announcement_is_not_an_inventory_entry() {
        // 0xFE is the null address: this ECU is telling the bus it has given up.
        let capture = "(1.0) can0 18EEFFFE#0000000000000000\n";
        let mut replay = Replay::new(name(), Address::new(0xF9));
        replay.run(capture).unwrap();
        assert_eq!(
            replay.claimed_addresses().count(),
            0,
            "an ECU that cannot claim holds no address"
        );
    }

    /// The reason `Replay` carries its own extended-protocol reassembler: `etp`
    /// is one of the modules with no reference implementation to check it
    /// against, so a replay that could not reassemble it would be useless for
    /// exactly the traffic it most needs to prove.
    #[test]
    fn a_captured_extended_transfer_reassembles() {
        use sae_j1939_rs::etp::{Reassembler, Rx, Transmitter, Tx};

        // 4 KiB: past the ordinary protocol's ceiling, so it can only be ETP.
        let payload: Vec<u8> = (0..4000).map(|i| (i * 13 % 251) as u8).collect();
        let sender = Address::new(0x00);

        // Build the capture by driving a real transmitter against a real
        // receiver, so the CTS timing matches what a bus would produce.
        let mut tx = Transmitter::new(pgn::PROPRIETARY_A, &payload).unwrap();
        let mut peer = Reassembler::<8192>::new();
        let mut capture = String::new();
        let mut timestamp = 2000.0;
        let push = |capture: &mut String, timestamp: &mut f64, id: u32, bytes: [u8; 8]| {
            *capture += &format!("({timestamp:.6}) can0 {id:08X}#{}\n", hex(&bytes));
            *timestamp += 0.001;
        };

        let etp_cm = 0x1CC8FF00u32; // ETP.CM, broadcast, from 0x00
        let etp_dt = 0x1CC7FF00u32; // ETP.DT

        let mut response = match peer.on_etp_cm(sender, &tx.start()) {
            Rx::Send(cm) => {
                push(&mut capture, &mut timestamp, etp_cm, tx.start().encode());
                Some(cm)
            }
            other => panic!("expected a CTS, got {other:?}"),
        };
        'transfer: while let Some(cm) = response.take() {
            assert_eq!(tx.on_etp_cm(&cm), Tx::SendData);
            let dpo = tx.offset().expect("each block needs an offset");
            peer.on_etp_cm(sender, &dpo);
            push(&mut capture, &mut timestamp, etp_cm, dpo.encode());

            while let Some(packet) = tx.next_packet() {
                push(&mut capture, &mut timestamp, etp_dt, packet.encode());
                match peer.on_etp_dt(sender, &packet) {
                    Rx::Idle => {}
                    Rx::Send(next) => response = Some(next),
                    Rx::Message { .. } => break 'transfer,
                }
            }
        }

        // Now replay that capture through the tool, which must reach the same
        // answer without any of the above machinery.
        let mut replay = Replay::new(name(), Address::new(0xF9));
        let messages = replay.run(&capture).unwrap();

        assert_eq!(messages.len(), 1, "the blocks form one message");
        assert_eq!(messages[0].pgn, pgn::PROPRIETARY_A);
        assert_eq!(
            messages[0].data, payload,
            "a 4 KiB extended transfer must survive the capture round trip"
        );
    }

    #[test]
    fn responses_the_node_would_have_sent_are_recorded() {
        // A global request for Address Claimed: every ECU must answer.
        let capture = "(1.0) can0 18EAFFF9#00EE00\n";
        let mut replay = Replay::new(name(), Address::new(0x80));
        replay.run(capture).unwrap();

        let claims: Vec<_> = replay
            .transmitted()
            .iter()
            .filter(|f| f.id().pgn() == pgn::ADDRESS_CLAIMED)
            .collect();
        assert!(
            !claims.is_empty(),
            "the node must have answered the request; transmitted: {:?}",
            replay.transmitted()
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }
}
