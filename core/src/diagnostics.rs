// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! J1939-73 diagnostics: DM1 and DM2 trouble codes.
//!
//! **DM1** (PGN `0x00FECA`) reports the faults an ECU currently has active;
//! **DM2** (PGN `0x00FECB`) reports faults that were active previously. Both
//! share a layout: two bytes of lamp status followed by a list of Diagnostic
//! Trouble Codes, four bytes each.
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

use crate::types::{Error, Result};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

    /// Whether this is the placeholder an ECU sends when it has no faults:
    /// SPN 0, FMI 0.
    pub const fn is_no_fault(&self) -> bool {
        self.spn == 0 && self.fmi == 0
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

#[cfg(test)]
mod tests {
    use super::*;

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
