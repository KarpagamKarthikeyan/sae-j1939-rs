// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! J1939-73 diagnostics: trouble codes, lamps, and readiness.
//!
//! **DM1** (PGN `0x00FECA`) reports the faults an ECU currently has active;
//! **DM2** (PGN `0x00FECB`) reports faults that were active previously. Both
//! share a layout: two bytes of lamp status followed by a list of Diagnostic
//! Trouble Codes, four bytes each.
//!
//! So do four more, which differ only in *which* faults they list — pending,
//! emissions-related, and so on. [`Message`] parses all six; [`is_dtc_list`]
//! says which parameter groups they are.
//!
//! ```text
//! byte 0   lamp status        MIL | red stop | amber warning | protect  (2 bits each)
//! byte 1   lamp flash status  same four lamps, same packing
//! byte 2+  DTCs, four bytes each
//! ```
//!
//! One DTC fits in a single CAN frame; the reserved bytes 6 and 7 are `0xFF`.
//! **Two or more DTCs do not fit**, so the message is sent over the transport
//! protocol ([`crate::tp`]) instead — the usual reason an embedded stack needs
//! BAM at all.
//!
//! Parsing borrows the payload rather than copying it, so the same code handles
//! a single frame and a 1785-byte reassembled buffer.
//!
//! ```
//! use sae_j1939_rs::diagnostics::{Dtc, Lamp, LampStatus, Message};
//!
//! // A single-frame DM1: amber warning lamp on, one fault.
//! let frame = [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF];
//! let dm = Message::parse(&frame).unwrap();
//!
//! assert_eq!(dm.lamps().status(Lamp::AmberWarning), LampStatus::On);
//! assert_eq!(dm.dtc_count(), 1);
//!
//! let dtc = dm.dtcs().next().unwrap();
//! assert_eq!(dtc.spn, 299);          // suspect parameter number
//! assert_eq!(dtc.fmi, 4);            // failure mode: voltage below normal
//! assert_eq!(dtc.occurrence_count, 3);
//! ```

use crate::pgn;
use crate::pgn::Pgn;
use crate::request::{AckControl, Acknowledgement, Request};
use crate::types::{Address, Error, Result};

/// The parameter groups that carry lamp status followed by a trouble-code list.
///
/// They differ only in which faults they report, not in how they report them,
/// so one codec reads all six.
///
/// | PGN | What it lists |
/// |-----|---------------|
/// | DM1 | active faults |
/// | DM2 | previously active faults |
/// | DM6 | pending faults — seen once, not yet confirmed |
/// | DM12 | emissions-related active faults |
/// | DM23 | previously active emissions-related faults |
/// | DM27 | all pending faults |
pub const DTC_LIST_GROUPS: [Pgn; 6] = [
    pgn::DM1,
    pgn::DM2,
    pgn::DM6,
    pgn::DM12,
    pgn::DM23,
    pgn::DM27,
];

/// Whether a parameter group carries a lamp-status-and-trouble-code list, and
/// so can be read with [`Message::parse`].
///
/// ```
/// use sae_j1939_rs::diagnostics::is_dtc_list;
/// use sae_j1939_rs::pgn;
///
/// assert!(is_dtc_list(pgn::DM1));
/// assert!(is_dtc_list(pgn::DM12));   // emissions-related, same layout
/// assert!(!is_dtc_list(pgn::DM5));   // readiness counts, a different shape
/// assert!(!is_dtc_list(pgn::DM3));   // a command, with no payload of its own
/// ```
pub fn is_dtc_list(pgn: Pgn) -> bool {
    DTC_LIST_GROUPS.contains(&pgn)
}

/// Bytes each Diagnostic Trouble Code occupies.
pub const DTC_LEN: usize = 4;

/// Bytes of lamp status preceding the trouble codes.
pub const LAMP_LEN: usize = 2;

/// The largest Suspect Parameter Number: SPNs are 19 bits.
pub const MAX_SPN: u32 = 0x0007_FFFF;

/// The largest Failure Mode Identifier: FMIs are 5 bits.
pub const MAX_FMI: u8 = 0x1F;

/// The largest occurrence count that fits the 7-bit field. J1939-73 stops
/// counting here rather than wrapping.
pub const MAX_OCCURRENCE_COUNT: u8 = 0x7F;

/// The four lamps a diagnostic message reports on.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lamp {
    /// Malfunction Indicator Lamp — an emissions-related fault.
    MalfunctionIndicator,
    /// Red Stop Lamp — stop the vehicle safely and immediately.
    RedStop,
    /// Amber Warning Lamp — a fault that does not require stopping.
    AmberWarning,
    /// Protect Lamp — a system is operating outside its normal range.
    Protect,
}

impl Lamp {
    /// Every lamp, in the order they are packed into the status byte.
    pub const ALL: [Lamp; 4] = [
        Lamp::MalfunctionIndicator,
        Lamp::RedStop,
        Lamp::AmberWarning,
        Lamp::Protect,
    ];

    /// How far to shift this lamp's two-bit field within its status byte.
    const fn shift(self) -> u8 {
        match self {
            Lamp::MalfunctionIndicator => 6,
            Lamp::RedStop => 4,
            Lamp::AmberWarning => 2,
            Lamp::Protect => 0,
        }
    }
}

/// The state of one lamp: a two-bit field.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LampStatus {
    /// The lamp is off.
    #[default]
    Off,
    /// The lamp is on.
    On,
    /// Reserved by J1939-73.
    Reserved,
    /// This ECU does not support the lamp.
    NotAvailable,
}

impl LampStatus {
    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => LampStatus::Off,
            1 => LampStatus::On,
            2 => LampStatus::Reserved,
            _ => LampStatus::NotAvailable,
        }
    }

    const fn to_bits(self) -> u8 {
        match self {
            LampStatus::Off => 0,
            LampStatus::On => 1,
            LampStatus::Reserved => 2,
            LampStatus::NotAvailable => 3,
        }
    }
}

/// The lamp status and lamp flash status bytes of a diagnostic message.
///
/// Each of the four lamps has a *status* (on/off) and a *flash status*
/// describing how it should blink.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lamps {
    status: u8,
    flash: u8,
}

impl Lamps {
    /// All lamps off.
    pub const fn new() -> Self {
        Lamps {
            status: 0,
            flash: 0,
        }
    }

    /// The status of one lamp.
    pub const fn status(&self, lamp: Lamp) -> LampStatus {
        LampStatus::from_bits(self.status >> lamp.shift())
    }

    /// The flash status of one lamp.
    pub const fn flash_status(&self, lamp: Lamp) -> LampStatus {
        LampStatus::from_bits(self.flash >> lamp.shift())
    }

    /// Set one lamp's status.
    #[must_use]
    pub const fn with_status(self, lamp: Lamp, status: LampStatus) -> Self {
        Lamps {
            status: set_field(self.status, lamp.shift(), status.to_bits()),
            flash: self.flash,
        }
    }

    /// Set one lamp's flash status.
    #[must_use]
    pub const fn with_flash_status(self, lamp: Lamp, status: LampStatus) -> Self {
        Lamps {
            status: self.status,
            flash: set_field(self.flash, lamp.shift(), status.to_bits()),
        }
    }

    /// Whether any lamp is on — a quick "is this ECU unhappy?" check.
    pub fn any_on(&self) -> bool {
        Lamp::ALL
            .iter()
            .any(|&lamp| self.status(lamp) == LampStatus::On)
    }

    /// Encode to the two lamp bytes.
    pub const fn encode(&self) -> [u8; LAMP_LEN] {
        [self.status, self.flash]
    }

    /// Decode from the two lamp bytes.
    pub const fn decode(data: &[u8; LAMP_LEN]) -> Self {
        Lamps {
            status: data[0],
            flash: data[1],
        }
    }
}

const fn set_field(byte: u8, shift: u8, bits: u8) -> u8 {
    (byte & !(0b11 << shift)) | ((bits & 0b11) << shift)
}

/// A Diagnostic Trouble Code: what failed, how, and how often.
///
/// ```text
/// byte 0   SPN bits 7..0
/// byte 1   SPN bits 15..8
/// byte 2   SPN bits 18..16 (top 3 bits) | FMI (low 5 bits)
/// byte 3   SPN conversion method (top bit) | occurrence count (low 7 bits)
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Dtc {
    /// Suspect Parameter Number: which parameter is at fault (19 bits).
    pub spn: u32,
    /// Failure Mode Identifier: how it failed (5 bits).
    pub fmi: u8,
    /// How many times this fault has gone from inactive to active, saturating
    /// at [`MAX_OCCURRENCE_COUNT`] (7 bits).
    pub occurrence_count: u8,
    /// The SPN conversion method. `false` selects one of the three legacy
    /// alignments, `true` the current one.
    pub conversion_method: bool,
}

/// Prints the way a service tool reads a fault: `SPN 100 FMI 1 (x2)`.
impl core::fmt::Display for Dtc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_no_fault() {
            return f.write_str("no active fault");
        }
        write!(
            f,
            "SPN {} FMI {} (x{})",
            self.spn, self.fmi, self.occurrence_count
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Dtc {
    fn format(&self, f: defmt::Formatter) {
        if self.is_no_fault() {
            defmt::write!(f, "no active fault")
        } else {
            defmt::write!(
                f,
                "SPN {=u32} FMI {=u8} (x{=u8})",
                self.spn,
                self.fmi,
                self.occurrence_count
            )
        }
    }
}

impl core::fmt::Debug for Dtc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Dtc({self}")?;
        if !self.conversion_method {
            f.write_str(", legacy conversion")?;
        }
        f.write_str(")")
    }
}

impl Dtc {
    /// Build a trouble code.
    ///
    /// Returns [`Error::InvalidDtc`] if `spn` exceeds 19 bits, `fmi` exceeds 5
    /// bits, or `occurrence_count` exceeds 7 bits.
    pub const fn new(spn: u32, fmi: u8, occurrence_count: u8) -> Result<Self> {
        if spn > MAX_SPN || fmi > MAX_FMI || occurrence_count > MAX_OCCURRENCE_COUNT {
            return Err(Error::InvalidDtc);
        }
        Ok(Dtc {
            spn,
            fmi,
            occurrence_count,
            conversion_method: true,
        })
    }

    /// Whether this is a placeholder rather than a real fault.
    ///
    /// Two encodings mean "nothing to report", and both turn up on real buses:
    ///
    /// - **All zero** — SPN 0, FMI 0. What J1939-73 specifies, and what
    ///   [`crate::fault_log::FaultLog`] transmits.
    /// - **All ones** — SPN `0x7FFFF`, FMI 31. Not a code at all, but what you
    ///   get by reading the `0xFF` bytes an ECU pads a fault-free DM1 with.
    ///   Neither value is assignable, so this cannot collide with a real fault.
    ///
    /// ```
    /// use sae_j1939_rs::diagnostics::Dtc;
    ///
    /// assert!(Dtc::decode(&[0x00, 0x00, 0x00, 0x00]).is_no_fault());
    /// assert!(Dtc::decode(&[0xFF, 0xFF, 0xFF, 0xFF]).is_no_fault());
    /// assert!(!Dtc::new(100, 1, 1).unwrap().is_no_fault());
    /// ```
    pub const fn is_no_fault(&self) -> bool {
        (self.spn == 0 && self.fmi == 0) || (self.spn == MAX_SPN && self.fmi == MAX_FMI)
    }

    /// Encode to four bytes.
    pub const fn encode(&self) -> [u8; DTC_LEN] {
        [
            self.spn as u8,
            (self.spn >> 8) as u8,
            (((self.spn >> 11) as u8) & 0xE0) | (self.fmi & MAX_FMI),
            ((self.conversion_method as u8) << 7) | (self.occurrence_count & MAX_OCCURRENCE_COUNT),
        ]
    }

    /// Decode from four bytes.
    pub const fn decode(data: &[u8; DTC_LEN]) -> Self {
        Dtc {
            // The top three SPN bits live in the high bits of byte 2.
            spn: (((data[2] & 0xE0) as u32) << 11) | ((data[1] as u32) << 8) | data[0] as u32,
            fmi: data[2] & MAX_FMI,
            occurrence_count: data[3] & MAX_OCCURRENCE_COUNT,
            conversion_method: data[3] >> 7 == 1,
        }
    }
}

/// A parsed DM1 or DM2 message, borrowing its payload.
///
/// The same type covers a single CAN frame and a transport-protocol
/// reassembly, because the layout is identical — only the number of trouble
/// codes differs.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    lamps: Lamps,
    dtc_bytes: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse a DM1/DM2 payload.
    ///
    /// Returns [`Error::ShortPayload`] if fewer than the two lamp bytes are
    /// present. Trailing bytes that do not form a whole trouble code — the two
    /// `0xFF` reserved bytes of a single-frame message — are ignored.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < LAMP_LEN {
            return Err(Error::ShortPayload {
                expected: LAMP_LEN,
                actual: data.len(),
            });
        }
        Ok(Message {
            lamps: Lamps::decode(&[data[0], data[1]]),
            dtc_bytes: &data[LAMP_LEN..],
        })
    }

    /// The lamp and flash status.
    pub const fn lamps(&self) -> Lamps {
        self.lamps
    }

    /// How many complete trouble codes the payload carries.
    pub const fn dtc_count(&self) -> usize {
        self.dtc_bytes.len() / DTC_LEN
    }

    /// The trouble codes, decoded lazily.
    pub fn dtcs(&self) -> impl Iterator<Item = Dtc> + '_ {
        self.dtc_bytes.chunks_exact(DTC_LEN).map(|chunk| {
            let mut bytes = [0u8; DTC_LEN];
            bytes.copy_from_slice(chunk);
            Dtc::decode(&bytes)
        })
    }

    /// Whether this message reports no active faults: no trouble codes, or the
    /// single all-zero placeholder.
    pub fn is_fault_free(&self) -> bool {
        let mut dtcs = self.dtcs();
        match dtcs.next() {
            None => true,
            Some(first) => first.is_no_fault() && dtcs.next().is_none(),
        }
    }
}

/// Encode a DM1/DM2 message into `out`, returning how many bytes were written.
///
/// With zero or one trouble code the result is padded to a full eight-byte CAN
/// frame with `0xFF`, as J1939-73 requires. With two or more it is
/// `2 + 4 × dtcs.len()` bytes, which exceeds a single frame and must be sent
/// over the transport protocol — see [`crate::tp::Transmitter`].
///
/// Returns [`Error::ShortPayload`] if `out` is too small.
///
/// ```
/// use sae_j1939_rs::diagnostics::{encode, Dtc, Lamp, LampStatus, Lamps};
/// use sae_j1939_rs::tp::Transmitter;
/// use sae_j1939_rs::pgn;
///
/// let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
/// let dtcs = [
///     Dtc::new(299, 4, 3).unwrap(),
///     Dtc::new(100, 1, 7).unwrap(),
/// ];
///
/// let mut buf = [0u8; 32];
/// let len = encode(lamps, &dtcs, &mut buf).unwrap();
/// assert_eq!(len, 10); // two lamp bytes + two 4-byte codes
///
/// // Ten bytes will not fit one frame, so it goes out over the transport protocol.
/// let mut tx = Transmitter::broadcast(pgn::DM1, &buf[..len]).unwrap();
/// assert_eq!(tx.packets(), 2);
/// ```
pub fn encode(lamps: Lamps, dtcs: &[Dtc], out: &mut [u8]) -> Result<usize> {
    let body = LAMP_LEN + dtcs.len() * DTC_LEN;
    // Zero or one code fits a single frame, so pad it out to a full eight bytes;
    // two or more already exceed a frame and are sent verbatim over TP.
    let len = if dtcs.len() <= 1 { body.max(8) } else { body };
    if out.len() < len {
        return Err(Error::ShortPayload {
            expected: len,
            actual: out.len(),
        });
    }
    out[..LAMP_LEN].copy_from_slice(&lamps.encode());
    for (i, dtc) in dtcs.iter().enumerate() {
        let start = LAMP_LEN + i * DTC_LEN;
        out[start..start + DTC_LEN].copy_from_slice(&dtc.encode());
    }
    // Reserved trailing bytes.
    for byte in out[body..len].iter_mut() {
        *byte = 0xFF;
    }
    Ok(len)
}

/// DM3 — clear previously active diagnostic trouble codes (PGN `0x00FECC`).
///
/// DM3 carries no payload of its own: it is issued as a [`Request`] for the DM3
/// parameter group, and the target answers with an [`Acknowledgement`]. These
/// helpers spell that exchange out so it does not have to be rediscovered.
///
/// ```
/// use sae_j1939_rs::diagnostics::dm3;
/// use sae_j1939_rs::request::AckControl;
/// use sae_j1939_rs::{pgn, Address};
///
/// // A tool asks an ECU to clear its stored faults.
/// let request = dm3::clear_request();
/// assert_eq!(request.pgn, pgn::DM3);
///
/// // The ECU confirms it did.
/// let ack = dm3::acknowledge(Address::new(0x80));
/// assert_eq!(ack.control, AckControl::Acknowledged);
/// assert_eq!(ack.pgn, pgn::DM3);
/// ```
pub mod dm3 {
    use super::*;

    /// The Request that tells an ECU to clear its previously active trouble
    /// codes.
    ///
    /// Send it as PGN [`pgn::REQUEST`], addressed to the ECU you want cleared —
    /// or to [`Address::GLOBAL`] to clear the whole bus, which you should be
    /// deliberate about.
    pub const fn clear_request() -> Request {
        Request::new(pgn::DM3)
    }

    /// Whether an incoming [`Request`] is asking this ECU to clear its codes.
    pub fn is_clear_request(request: &Request) -> bool {
        request.pgn == pgn::DM3
    }

    /// The positive acknowledgement to send once the codes are cleared.
    pub const fn acknowledge(responder: Address) -> Acknowledgement {
        Acknowledgement::positive(pgn::DM3, responder)
    }

    /// The refusal to send when the codes cannot be cleared — typically because
    /// the vehicle is not in a safe state to do it.
    pub const fn refuse(responder: Address, reason: AckControl) -> Acknowledgement {
        Acknowledgement {
            control: reason,
            group_function: 0xFF,
            address: responder,
            pgn: pgn::DM3,
        }
    }
}

/// DM11 — clear *active* diagnostic trouble codes (PGN `0x00FED3`).
///
/// The counterpart to [`dm3`], which clears previously active codes. Like DM3
/// it carries no payload of its own: it is issued as a [`Request`], and the
/// target answers with an [`Acknowledgement`].
///
/// ```
/// use sae_j1939_rs::diagnostics::dm11;
/// use sae_j1939_rs::pgn;
///
/// assert_eq!(dm11::clear_request().pgn, pgn::DM11);
/// ```
///
/// # Clearing active codes is not a diagnostic step
///
/// A *previously active* code is history; an *active* one is a fault happening
/// now. Clearing it does not fix anything — the ECU will simply set it again if
/// the condition persists, and if it does not, you have destroyed the evidence.
/// Read the codes first.
pub mod dm11 {
    use super::*;

    /// The Request that tells an ECU to clear its active trouble codes.
    pub const fn clear_request() -> Request {
        Request::new(pgn::DM11)
    }

    /// Whether an incoming [`Request`] is asking this ECU to clear active codes.
    pub fn is_clear_request(request: &Request) -> bool {
        request.pgn == pgn::DM11
    }

    /// The positive acknowledgement to send once the codes are cleared.
    pub const fn acknowledge(responder: Address) -> Acknowledgement {
        Acknowledgement::positive(pgn::DM11, responder)
    }

    /// The refusal to send when the codes cannot be cleared — typically because
    /// the vehicle is not in a safe state for it.
    pub const fn refuse(responder: Address, reason: AckControl) -> Acknowledgement {
        Acknowledgement {
            control: reason,
            group_function: 0xFF,
            address: responder,
            pgn: pgn::DM11,
        }
    }
}

/// DM13 — stop/start broadcast (PGN `0x00DF00`).
///
/// Tells ECUs to pause their periodic broadcasts so a tool can work on a quiet
/// bus, then to resume. The payload holds a two-bit command per network, plus a
/// hold signal.
///
/// ```
/// use sae_j1939_rs::diagnostics::{BroadcastCommand, Dm13, Network};
///
/// // Quieten the vehicle bus, leave the others alone.
/// let stop = Dm13::new().with_command(Network::Vehicle, BroadcastCommand::Stop);
/// assert_eq!(stop.command(Network::Vehicle), BroadcastCommand::Stop);
/// assert_eq!(stop.command(Network::Implement), BroadcastCommand::DoNotCare);
/// assert_eq!(Dm13::decode(&stop.encode()), stop);
/// ```
///
/// # A stopped bus stays stopped
///
/// J1939-73 requires the tool to keep sending a hold signal roughly every
/// second; ECUs resume on their own if it stops arriving. That is a safety
/// interlock — a tool that crashes must not leave the vehicle silent. This type
/// encodes the messages; the repetition is the caller's, since the state
/// machines own no clock.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dm13 {
    /// Byte 0: two bits per network, in [`Network`] order.
    networks: u8,
    /// Byte 1: the hold signal.
    hold: u8,
}

/// Which network a [`Dm13`] command applies to.
///
/// The four J1939-73 names the payload's first byte carries, in order.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    /// The current data link the message arrived on.
    CurrentDataLink,
    /// The vehicle bus (J1939 network #1).
    Vehicle,
    /// The implement bus (J1939 network #2).
    Implement,
    /// A manufacturer-specific fifth network slot.
    Proprietary,
}

impl Network {
    /// Every network, in the order the payload packs them.
    pub const ALL: [Network; 4] = [
        Network::CurrentDataLink,
        Network::Vehicle,
        Network::Implement,
        Network::Proprietary,
    ];

    const fn shift(self) -> u8 {
        match self {
            Network::CurrentDataLink => 0,
            Network::Vehicle => 2,
            Network::Implement => 4,
            Network::Proprietary => 6,
        }
    }
}

/// What a [`Dm13`] asks a network to do.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BroadcastCommand {
    /// Stop broadcasting.
    Stop,
    /// Resume broadcasting.
    Start,
    /// Reserved by J1939-73.
    Reserved,
    /// Leave this network as it is — the default, so a command aimed at one bus
    /// does not silence the others.
    #[default]
    DoNotCare,
}

impl BroadcastCommand {
    const fn to_bits(self) -> u8 {
        match self {
            BroadcastCommand::Stop => 0,
            BroadcastCommand::Start => 1,
            BroadcastCommand::Reserved => 2,
            BroadcastCommand::DoNotCare => 3,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => BroadcastCommand::Stop,
            1 => BroadcastCommand::Start,
            2 => BroadcastCommand::Reserved,
            _ => BroadcastCommand::DoNotCare,
        }
    }
}

impl Dm13 {
    /// A message that asks nothing of any network.
    ///
    /// Every field defaults to [`BroadcastCommand::DoNotCare`], so building one
    /// up cannot silence a bus you did not name.
    pub const fn new() -> Self {
        // 0b11 in every slot is "do not care".
        Dm13 {
            networks: 0xFF,
            hold: 0xFF,
        }
    }

    /// What this message asks of one network.
    pub const fn command(&self, network: Network) -> BroadcastCommand {
        BroadcastCommand::from_bits(self.networks >> network.shift())
    }

    /// Set what this message asks of one network.
    #[must_use]
    pub const fn with_command(self, network: Network, command: BroadcastCommand) -> Self {
        let shift = network.shift();
        Dm13 {
            networks: (self.networks & !(0b11 << shift)) | (command.to_bits() << shift),
            hold: self.hold,
        }
    }

    /// The hold signal byte, which keeps a stopped bus stopped.
    pub const fn hold_signal(&self) -> u8 {
        self.hold
    }

    /// Set the hold signal byte.
    #[must_use]
    pub const fn with_hold_signal(self, hold: u8) -> Self {
        Dm13 {
            networks: self.networks,
            hold,
        }
    }

    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [self.networks, self.hold, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        Dm13 {
            networks: data[0],
            hold: data[1],
        }
    }
}

/// How thoroughly an ECU claims to meet on-board diagnostic regulations.
///
/// J1939-73 numbers a range of compliance levels. Only the two whose meaning is
/// unambiguous are named here; the rest are carried through as [`ObdCompliance::Other`]
/// rather than guessed at, since misreporting an emissions compliance level is
/// worse than reporting a number.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObdCompliance {
    /// The ECU is not intended to meet OBD requirements.
    NotIntended,
    /// The ECU does not report a compliance level.
    NotAvailable,
    /// A level defined by J1939-73 and carried through unmodified. Look it up
    /// in the standard rather than trusting an interpretation here.
    Other(u8),
}

impl ObdCompliance {
    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            ObdCompliance::NotIntended => 5,
            ObdCompliance::NotAvailable => 0xFF,
            ObdCompliance::Other(raw) => raw,
        }
    }

    /// Decode a wire byte.
    pub const fn from_u8(raw: u8) -> Self {
        match raw {
            5 => ObdCompliance::NotIntended,
            0xFF => ObdCompliance::NotAvailable,
            other => ObdCompliance::Other(other),
        }
    }
}

/// DM5 — diagnostic readiness (PGN `0x00FECE`).
///
/// How many faults an ECU is holding, and how far through its self-tests it is.
/// A service tool reads this first: the counts say whether to bother asking for
/// [`DM1`](crate::pgn::DM1) at all.
///
/// ```text
/// byte 0    active fault count
/// byte 1    previously active fault count
/// byte 2    OBD compliance level
/// bytes 3-7 monitor support and completion bitfields
/// ```
///
/// # The monitor bytes are not decoded
///
/// Bytes 3–7 say which self-tests an ECU supports and which have completed this
/// drive cycle. Their bit assignments are specific and this crate does not model
/// them — a wrong reading would say a catalyst monitor had passed when it had
/// not. [`Dm5::monitors`] hands back the raw bytes so a caller with the standard
/// to hand can interpret them.
///
/// ```
/// use sae_j1939_rs::diagnostics::{Dm5, ObdCompliance};
///
/// let readiness = Dm5::decode(&[2, 5, 0xFF, 0, 0, 0, 0, 0]);
/// assert_eq!(readiness.active_faults, 2);
/// assert_eq!(readiness.previously_active_faults, 5);
/// assert_eq!(readiness.obd_compliance, ObdCompliance::NotAvailable);
/// assert!(readiness.has_active_faults());
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dm5 {
    /// How many faults are active now.
    pub active_faults: u8,
    /// How many were active previously.
    pub previously_active_faults: u8,
    /// The compliance level the ECU claims.
    pub obd_compliance: ObdCompliance,
    /// Monitor support and completion, undecoded — see the type documentation.
    monitors: [u8; 5],
}

impl Dm5 {
    /// Report fault counts and a compliance level, with no monitor data.
    pub const fn new(
        active_faults: u8,
        previously_active_faults: u8,
        obd_compliance: ObdCompliance,
    ) -> Self {
        Dm5 {
            active_faults,
            previously_active_faults,
            obd_compliance,
            monitors: [0xFF; 5],
        }
    }

    /// The raw monitor support and completion bytes.
    ///
    /// Deliberately not decoded: see the type documentation.
    pub const fn monitors(&self) -> &[u8; 5] {
        &self.monitors
    }

    /// Set the monitor bytes verbatim.
    #[must_use]
    pub const fn with_monitors(mut self, monitors: [u8; 5]) -> Self {
        self.monitors = monitors;
        self
    }

    /// Whether this ECU is currently holding a fault.
    ///
    /// The question a tool asks before requesting the codes themselves.
    pub const fn has_active_faults(&self) -> bool {
        self.active_faults > 0
    }

    /// Encode to the eight-byte payload.
    pub const fn encode(&self) -> [u8; 8] {
        [
            self.active_faults,
            self.previously_active_faults,
            self.obd_compliance.as_u8(),
            self.monitors[0],
            self.monitors[1],
            self.monitors[2],
            self.monitors[3],
            self.monitors[4],
        ]
    }

    /// Decode an eight-byte payload.
    pub const fn decode(data: &[u8; 8]) -> Self {
        Dm5 {
            active_faults: data[0],
            previously_active_faults: data[1],
            obd_compliance: ObdCompliance::from_u8(data[2]),
            monitors: [data[3], data[4], data[5], data[6], data[7]],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm3_round_trips_as_a_request_and_acknowledgement() {
        let request = dm3::clear_request();
        assert_eq!(request.encode(), [0xCC, 0xFE, 0x00]);
        assert!(dm3::is_clear_request(
            &Request::decode(&request.encode()).unwrap()
        ));
        // A request for a different group must not be mistaken for DM3.
        assert!(!dm3::is_clear_request(&Request::new(pgn::DM1)));

        let ack = dm3::acknowledge(Address::new(0x80));
        assert!(ack.control.is_positive());
        assert_eq!(Acknowledgement::decode(&ack.encode()), ack);

        let refusal = dm3::refuse(Address::new(0x80), AckControl::Busy);
        assert_eq!(refusal.control, AckControl::Busy);
        assert!(!refusal.control.is_positive());
        assert_eq!(refusal.pgn, pgn::DM3);
    }

    #[test]
    fn dm11_round_trips_as_a_request_and_acknowledgement() {
        let request = dm11::clear_request();
        assert_eq!(request.pgn, pgn::DM11);
        assert_eq!(request.encode(), [0xD3, 0xFE, 0x00]);
        assert!(dm11::is_clear_request(
            &Request::decode(&request.encode()).unwrap()
        ));
        // DM3 clears previously active codes; DM11 clears active ones. Confusing
        // them would clear the wrong set.
        assert!(!dm11::is_clear_request(&dm3::clear_request()));
        assert!(!dm3::is_clear_request(&dm11::clear_request()));

        assert!(dm11::acknowledge(Address::new(0x80)).control.is_positive());
        assert_eq!(
            dm11::refuse(Address::new(0x80), AckControl::Busy).control,
            AckControl::Busy
        );
    }

    /// A command aimed at one bus must not silence the others, so every network
    /// this message does not name stays "do not care".
    #[test]
    fn dm13_leaves_unnamed_networks_alone() {
        let quiet = Dm13::new().with_command(Network::Vehicle, BroadcastCommand::Stop);
        assert_eq!(quiet.command(Network::Vehicle), BroadcastCommand::Stop);
        for other in [
            Network::CurrentDataLink,
            Network::Implement,
            Network::Proprietary,
        ] {
            assert_eq!(
                quiet.command(other),
                BroadcastCommand::DoNotCare,
                "{other:?} was not named and must be untouched"
            );
        }
        // A fresh message asks nothing of anyone.
        for network in Network::ALL {
            assert_eq!(Dm13::new().command(network), BroadcastCommand::DoNotCare);
        }
    }

    #[test]
    fn dm13_packs_every_network_independently() {
        let commands = [
            BroadcastCommand::Stop,
            BroadcastCommand::Start,
            BroadcastCommand::Reserved,
            BroadcastCommand::DoNotCare,
        ];
        for network in Network::ALL {
            for command in commands {
                let message = Dm13::new().with_command(network, command);
                assert_eq!(message.command(network), command);
                assert_eq!(Dm13::decode(&message.encode()), message);

                // Setting the same field twice replaces rather than ORs.
                let replaced = message.with_command(network, BroadcastCommand::Start);
                assert_eq!(replaced.command(network), BroadcastCommand::Start);
            }
        }
    }

    #[test]
    fn dm13_round_trips_including_the_hold_signal() {
        let message = Dm13::new()
            .with_command(Network::Vehicle, BroadcastCommand::Stop)
            .with_command(Network::Implement, BroadcastCommand::Start)
            .with_hold_signal(0x00);
        let bytes = message.encode();
        assert_eq!(&bytes[2..], &[0xFF; 6], "the tail is reserved filler");
        assert_eq!(Dm13::decode(&bytes), message);
        assert_eq!(Dm13::decode(&bytes).hold_signal(), 0x00);
    }

    /// The six groups differ in *which* faults they list, not in how, so the
    /// codec verified against the C reference for DM1 reads all of them.
    #[test]
    fn every_dtc_list_group_parses_with_the_same_codec() {
        let lamps = Lamps::new().with_status(Lamp::AmberWarning, LampStatus::On);
        let faults = [Dtc::new(299, 4, 3).unwrap(), Dtc::new(100, 1, 7).unwrap()];
        let mut payload = [0u8; 32];
        let len = encode(lamps, &faults, &mut payload).unwrap();

        for group in DTC_LIST_GROUPS {
            assert!(is_dtc_list(group), "{group:?} should be a DTC list");
            let message = Message::parse(&payload[..len]).unwrap();
            assert_eq!(message.lamps(), lamps, "{group:?}");
            assert_eq!(
                message.dtcs().collect::<std::vec::Vec<_>>(),
                faults,
                "{group:?}"
            );
        }

        // Groups that are a command or a different shape are not in the family.
        for other in [pgn::DM3, pgn::DM5, pgn::DM11, pgn::DM13, pgn::DM14] {
            assert!(!is_dtc_list(other), "{other:?} is not a DTC list");
        }
    }

    #[test]
    fn the_dtc_list_groups_are_the_pgns_they_claim_to_be() {
        // A wrong PGN here would silently ask an ECU for the wrong fault set.
        assert_eq!(pgn::DM6.as_u32(), 0x00FECF, "pending");
        assert_eq!(pgn::DM12.as_u32(), 0x00FED4, "emissions-related active");
        assert_eq!(pgn::DM23.as_u32(), 0x00FDB5, "previously active emissions");
        assert_eq!(pgn::DM27.as_u32(), 0x00FD82, "all pending");
        assert_eq!(pgn::DM4.as_u32(), 0x00FECD, "freeze frame");
        assert_eq!(pgn::DM5.as_u32(), 0x00FECE, "readiness");

        // DM1..DM6 run consecutively, which is a useful sanity check on all six.
        let sequence = [pgn::DM1, pgn::DM2, pgn::DM3, pgn::DM4, pgn::DM5, pgn::DM6];
        for pair in sequence.windows(2) {
            assert_eq!(
                pair[1].as_u32(),
                pair[0].as_u32() + 1,
                "{:?} should follow {:?}",
                pair[1],
                pair[0]
            );
        }

        // All six are distinct.
        for (i, a) in DTC_LIST_GROUPS.iter().enumerate() {
            for b in DTC_LIST_GROUPS.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn dm5_reports_counts_and_compliance() {
        let readiness = Dm5::new(2, 5, ObdCompliance::NotIntended).with_monitors([1, 2, 3, 4, 5]);
        let bytes = readiness.encode();
        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], 5);
        assert_eq!(bytes[2], 5, "NotIntended is compliance level 5");
        assert_eq!(&bytes[3..], &[1, 2, 3, 4, 5]);
        assert_eq!(Dm5::decode(&bytes), readiness);
        assert!(readiness.has_active_faults());

        // The question a tool asks before requesting the codes at all.
        assert!(!Dm5::new(0, 9, ObdCompliance::NotAvailable).has_active_faults());
    }

    #[test]
    fn dm5_carries_unknown_compliance_levels_through_unchanged() {
        // Misreporting a compliance level is worse than reporting a number, so
        // anything not unambiguous is passed along verbatim.
        for raw in 0..=255u8 {
            let decoded = ObdCompliance::from_u8(raw);
            assert_eq!(decoded.as_u8(), raw, "level {raw} must round-trip");
        }
        assert_eq!(ObdCompliance::from_u8(5), ObdCompliance::NotIntended);
        assert_eq!(ObdCompliance::from_u8(0xFF), ObdCompliance::NotAvailable);
        assert_eq!(ObdCompliance::from_u8(3), ObdCompliance::Other(3));
    }

    #[test]
    fn dm5_monitor_bytes_are_passed_through_untouched() {
        // They are not decoded, so they must at least survive intact — a wrong
        // reading would claim a monitor had passed when it had not.
        for pattern in [[0u8; 5], [0xFF; 5], [0xAA, 0x55, 0x00, 0xFF, 0x0F]] {
            let readiness = Dm5::new(0, 0, ObdCompliance::NotAvailable).with_monitors(pattern);
            assert_eq!(Dm5::decode(&readiness.encode()).monitors(), &pattern);
        }
    }

    /// The realistic exchange: read readiness, and only ask for codes if there
    /// are any.
    #[test]
    fn a_tool_reads_readiness_before_asking_for_codes() {
        let quiet = Dm5::decode(&[0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(!quiet.has_active_faults(), "nothing to ask for");

        let faulted = Dm5::decode(&[3, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(faulted.has_active_faults());
        assert_eq!(faulted.active_faults, 3);

        // Three active faults will not fit one frame, so the DM1 answering this
        // arrives over the transport protocol.
        let faults = [
            Dtc::new(100, 1, 2).unwrap(),
            Dtc::new(110, 0, 5).unwrap(),
            Dtc::new(1569, 31, 126).unwrap(),
        ];
        let mut payload = [0u8; 32];
        let len = encode(Lamps::new(), &faults, &mut payload).unwrap();
        assert!(len > 8, "three codes exceed a single frame");
        assert_eq!(
            Message::parse(&payload[..len]).unwrap().dtc_count(),
            faulted.active_faults as usize
        );
    }

    #[test]
    fn lamp_fields_are_independent() {
        let lamps = Lamps::new()
            .with_status(Lamp::MalfunctionIndicator, LampStatus::On)
            .with_status(Lamp::RedStop, LampStatus::NotAvailable)
            .with_status(Lamp::AmberWarning, LampStatus::Reserved)
            .with_status(Lamp::Protect, LampStatus::On)
            .with_flash_status(Lamp::AmberWarning, LampStatus::On);

        assert_eq!(lamps.status(Lamp::MalfunctionIndicator), LampStatus::On);
        assert_eq!(lamps.status(Lamp::RedStop), LampStatus::NotAvailable);
        assert_eq!(lamps.status(Lamp::AmberWarning), LampStatus::Reserved);
        assert_eq!(lamps.status(Lamp::Protect), LampStatus::On);
        assert_eq!(lamps.flash_status(Lamp::AmberWarning), LampStatus::On);
        // Setting the flash byte must not disturb the status byte.
        assert_eq!(lamps.flash_status(Lamp::RedStop), LampStatus::Off);

        // Byte layout: MIL<<6 | red<<4 | amber<<2 | protect.
        assert_eq!(lamps.encode()[0], (1 << 6) | (3 << 4) | (2 << 2) | 1);
        assert_eq!(Lamps::decode(&lamps.encode()), lamps);
    }

    #[test]
    fn setting_a_lamp_twice_replaces_rather_than_ors() {
        let lamps = Lamps::new()
            .with_status(Lamp::RedStop, LampStatus::NotAvailable)
            .with_status(Lamp::RedStop, LampStatus::Off);
        assert_eq!(lamps.status(Lamp::RedStop), LampStatus::Off);
        assert_eq!(lamps.encode()[0], 0);
    }

    #[test]
    fn any_on_reports_only_lit_lamps() {
        assert!(!Lamps::new().any_on());
        // "Not available" is not "on".
        assert!(!Lamps::new()
            .with_status(Lamp::RedStop, LampStatus::NotAvailable)
            .any_on());
        assert!(Lamps::new()
            .with_status(Lamp::Protect, LampStatus::On)
            .any_on());
    }

    /// The 19-bit SPN is split across three bytes with the top three bits in
    /// the high bits of byte 2 — the layout the C reference packs by hand.
    #[test]
    fn dtc_packs_a_19_bit_spn_across_three_bytes() {
        let dtc = Dtc {
            spn: MAX_SPN,
            fmi: MAX_FMI,
            occurrence_count: MAX_OCCURRENCE_COUNT,
            conversion_method: true,
        };
        assert_eq!(dtc.encode(), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(Dtc::decode(&dtc.encode()), dtc);

        // Only the top three SPN bits set: 0b111 << 16 = 0x70000.
        let high = Dtc::new(0x7_0000, 0, 0).unwrap();
        assert_eq!(high.encode(), [0x00, 0x00, 0xE0, 0x80]);
        assert_eq!(Dtc::decode(&high.encode()).spn, 0x7_0000);
    }

    #[test]
    fn dtc_round_trips_realistic_codes() {
        for (spn, fmi, count) in [
            (299u32, 4u8, 3u8),
            (100, 1, 7),
            (0, 0, 0),
            (524287, 31, 127),
        ] {
            let dtc = Dtc::new(spn, fmi, count).unwrap();
            let decoded = Dtc::decode(&dtc.encode());
            assert_eq!(decoded.spn, spn);
            assert_eq!(decoded.fmi, fmi);
            assert_eq!(decoded.occurrence_count, count);
        }
    }

    #[test]
    fn trouble_codes_print_the_way_a_service_tool_reads_them() {
        extern crate std;
        use std::format;

        let dtc = Dtc::new(100, 1, 2).unwrap();
        assert_eq!(format!("{dtc}"), "SPN 100 FMI 1 (x2)");
        assert_eq!(format!("{dtc:?}"), "Dtc(SPN 100 FMI 1 (x2))");

        // The placeholder an ECU sends when it has nothing to report.
        assert_eq!(format!("{}", Dtc::default()), "no active fault");

        let legacy = Dtc {
            conversion_method: false,
            ..dtc
        };
        assert_eq!(
            format!("{legacy:?}"),
            "Dtc(SPN 100 FMI 1 (x2), legacy conversion)"
        );
    }

    #[test]
    fn dtc_rejects_out_of_range_fields() {
        assert_eq!(Dtc::new(MAX_SPN + 1, 0, 0), Err(Error::InvalidDtc));
        assert_eq!(Dtc::new(0, MAX_FMI + 1, 0), Err(Error::InvalidDtc));
        assert_eq!(
            Dtc::new(0, 0, MAX_OCCURRENCE_COUNT + 1),
            Err(Error::InvalidDtc)
        );
        assert!(Dtc::new(MAX_SPN, MAX_FMI, MAX_OCCURRENCE_COUNT).is_ok());
    }

    #[test]
    fn conversion_method_occupies_the_top_bit_of_the_last_byte() {
        let legacy = Dtc {
            conversion_method: false,
            ..Dtc::new(299, 4, 3).unwrap()
        };
        assert_eq!(legacy.encode()[3], 3);
        assert!(!Dtc::decode(&legacy.encode()).conversion_method);
        assert_eq!(Dtc::new(299, 4, 3).unwrap().encode()[3], 0x80 | 3);
    }

    #[test]
    fn parses_a_single_frame_message_ignoring_reserved_bytes() {
        // Amber warning on, SPN 299 / FMI 4 / count 3, then two reserved bytes.
        let frame = [0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF];
        let dm = Message::parse(&frame).unwrap();

        assert_eq!(dm.lamps().status(Lamp::AmberWarning), LampStatus::On);
        assert_eq!(dm.dtc_count(), 1, "the 0xFF filler must not become a DTC");

        let dtc = dm.dtcs().next().unwrap();
        assert_eq!(dtc.spn, 299);
        assert_eq!(dtc.fmi, 4);
        assert_eq!(dtc.occurrence_count, 3);
        assert!(!dm.is_fault_free());
    }

    #[test]
    fn parses_a_multi_dtc_message() {
        let lamps = Lamps::new().with_status(Lamp::RedStop, LampStatus::On);
        let dtcs = [
            Dtc::new(299, 4, 3).unwrap(),
            Dtc::new(100, 1, 7).unwrap(),
            Dtc::new(524287, 31, 127).unwrap(),
        ];
        let mut buf = [0u8; 64];
        let len = encode(lamps, &dtcs, &mut buf).unwrap();
        assert_eq!(len, 2 + 3 * 4);

        let dm = Message::parse(&buf[..len]).unwrap();
        assert_eq!(dm.lamps(), lamps);
        assert_eq!(dm.dtc_count(), 3);
        let decoded: std::vec::Vec<Dtc> = dm.dtcs().collect();
        assert_eq!(decoded, dtcs);
    }

    #[test]
    fn a_fault_free_message_is_padded_to_a_full_frame() {
        let mut buf = [0u8; 8];
        let len = encode(Lamps::new(), &[], &mut buf).unwrap();
        assert_eq!(len, 8, "must fill a CAN frame even with no faults");
        assert_eq!(buf, [0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        // And reading it back must not invent a fault out of the padding —
        // 0xFF bytes decode to the all-ones "not available" code, which plenty
        // of real ECUs put in a fault-free DM1.
        let dm = Message::parse(&buf).unwrap();
        assert_eq!(dm.dtc_count(), 1);
        assert!(dm.is_fault_free());

        // With no DTC bytes at all there is nothing to report.
        let dm = Message::parse(&[0, 0]).unwrap();
        assert!(dm.is_fault_free());
        assert_eq!(dm.dtc_count(), 0);
    }

    #[test]
    fn a_single_zero_dtc_reads_as_fault_free() {
        let mut buf = [0u8; 8];
        let len = encode(Lamps::new(), &[Dtc::default()], &mut buf).unwrap();
        assert_eq!(len, 8);
        let dm = Message::parse(&buf[..len]).unwrap();
        assert_eq!(dm.dtc_count(), 1);
        assert!(dm.is_fault_free());
    }

    #[test]
    fn rejects_a_payload_without_lamp_bytes() {
        assert_eq!(
            Message::parse(&[0x00]),
            Err(Error::ShortPayload {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn encode_rejects_an_undersized_buffer() {
        let dtcs = [Dtc::new(299, 4, 3).unwrap(), Dtc::new(100, 1, 7).unwrap()];
        let mut small = [0u8; 8];
        assert_eq!(
            encode(Lamps::new(), &dtcs, &mut small),
            Err(Error::ShortPayload {
                expected: 10,
                actual: 8
            })
        );
    }

    /// The reason DM1 needs the transport protocol: two codes overflow a frame.
    /// Encode, ship it over BAM, reassemble, and read the codes back out.
    #[test]
    fn a_multi_dtc_dm1_survives_a_bam_round_trip() {
        use crate::pgn;
        use crate::tp::{Reassembler, Rx, Transmitter};
        use crate::types::Address;

        let lamps = Lamps::new()
            .with_status(Lamp::AmberWarning, LampStatus::On)
            .with_status(Lamp::RedStop, LampStatus::On);
        let dtcs = [
            Dtc::new(299, 4, 3).unwrap(),
            Dtc::new(100, 1, 7).unwrap(),
            Dtc::new(1569, 31, 126).unwrap(),
        ];

        let mut payload = [0u8; 64];
        let len = encode(lamps, &dtcs, &mut payload).unwrap();
        assert!(len > 8, "this message must not fit a single frame");

        let sender = Address::new(0x80);
        let mut tx = Transmitter::broadcast(pgn::DM1, &payload[..len]).unwrap();
        let mut rx = Reassembler::<256>::new();

        rx.on_tp_cm(sender, &tx.start());
        let mut received = None;
        while let Some(packet) = tx.next_packet() {
            if let Rx::Message { pgn, data, .. } = rx.on_tp_dt(sender, &packet) {
                assert_eq!(pgn, pgn::DM1);
                received = Some(data.to_vec());
            }
        }

        let received = received.expect("the message should reassemble");
        let dm = Message::parse(&received).unwrap();
        assert_eq!(dm.lamps(), lamps);
        assert_eq!(dm.dtc_count(), 3);
        assert_eq!(dm.dtcs().collect::<std::vec::Vec<_>>(), dtcs);
    }
}
