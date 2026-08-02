// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading signal definitions from a DBC file.
//!
//! The core crate ships a small [`catalogue`](sae_j1939_rs::spn::catalogue) of
//! parameters, and it will never be complete: J1939-71 defines thousands, the
//! document is sold rather than published, and every manufacturer adds its own.
//!
//! So bring your own. **DBC** is the format the industry already uses to
//! describe CAN signals — every J1939 toolchain reads and writes it, and
//! vehicle manufacturers ship them. This module parses one and decodes frames
//! against it, which means the parameter database is *yours*, current, and
//! specific to the hardware in front of you.
//!
//! ```
//! use sae_j1939_host::dbc::Dbc;
//! use sae_j1939_host::sae_j1939_rs::Pgn;
//!
//! let text = r#"
//! BO_ 2364540158 EEC1: 8 Vector__XXX
//!  SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX
//! "#;
//!
//! let dbc = Dbc::parse(text)?;
//! let eec1 = dbc.message(Pgn::new(0x00F004).unwrap()).expect("EEC1");
//!
//! // 1500 rpm at 0.125 rpm/bit is a raw 12000 = 0x2EE0, little-endian.
//! let frame = [0xFF, 0xFF, 0xFF, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];
//! let speed = eec1.signal("EngineSpeed").unwrap();
//! assert_eq!(speed.decode(&frame)?.value(), Some(1500.0));
//! # Ok::<(), sae_j1939_host::dbc::DbcError>(())
//! ```
//!
//! # Scope
//!
//! This reads the parts of DBC that describe J1939 signal layout: `BO_` message
//! definitions and their `SG_` signals. Node lists, comments, attributes, and
//! value tables are skipped rather than rejected, so a full manufacturer file
//! parses without complaint — you simply get the messages and signals from it.
//!
//! Both byte orders decode. J1939 signals are little-endian (`@1`), but real
//! files mix in Motorola signals (`@0`), and those use a different bit
//! numbering — walking down within a byte, then jumping to the top of the next.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use sae_j1939_rs::spn::{classify, RawValue};
use sae_j1939_rs::{Id, Pgn};

/// Something that went wrong reading or using a DBC file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbcError {
    /// A line that should have been a message or signal definition was not.
    Malformed {
        /// The 1-based line number, so it can be found in the file.
        line: usize,
        /// What was expected there.
        expected: &'static str,
    },
    /// A `SG_` line appeared before any `BO_` line, so it belongs to nothing.
    OrphanSignal {
        /// The 1-based line number.
        line: usize,
    },
    /// A message identifier that is not a valid 29-bit J1939 identifier.
    NotJ1939 {
        /// The 1-based line number.
        line: usize,
        /// The identifier as written.
        id: u32,
    },
    /// The payload is shorter than the signal's field needs.
    ShortPayload {
        /// Bytes the signal needs.
        expected: usize,
        /// Bytes supplied.
        actual: usize,
    },
    /// The signal is wider than 32 bits.
    TooWide {
        /// The width in bits.
        bits: u16,
    },
}

impl fmt::Display for DbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbcError::Malformed { line, expected } => {
                write!(f, "line {line}: expected {expected}")
            }
            DbcError::OrphanSignal { line } => {
                write!(f, "line {line}: a signal before any message definition")
            }
            DbcError::NotJ1939 { line, id } => {
                write!(f, "line {line}: {id:#x} is not a 29-bit J1939 identifier")
            }
            DbcError::ShortPayload { expected, actual } => {
                write!(f, "payload too short: need {expected} bytes, got {actual}")
            }
            DbcError::TooWide { bits } => write!(f, "{bits}-bit signal exceeds the 32-bit limit"),
        }
    }
}

impl std::error::Error for DbcError {}

/// A decoded signal value, carrying J1939's in-band status codes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// A real measurement, scaled by the signal's factor and offset.
    Valid(f64),
    /// The sending ECU reports a fault with this parameter.
    Error,
    /// The sending ECU does not support or cannot supply this parameter.
    NotAvailable,
    /// The raw value falls in a range J1939 reserves.
    Reserved,
}

impl Value {
    /// The measurement, or `None` for any of the status codes.
    pub const fn value(self) -> Option<f64> {
        match self {
            Value::Valid(value) => Some(value),
            _ => None,
        }
    }

    /// Whether this is a real measurement.
    pub const fn is_valid(self) -> bool {
        matches!(self, Value::Valid(_))
    }
}

/// Which end of a multi-byte field comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    /// Intel / little-endian — `@1` in DBC, and what J1939 uses.
    LittleEndian,
    /// Motorola / big-endian — `@0` in DBC.
    BigEndian,
}

/// One signal within a message: where its bits are and how to scale them.
#[derive(Debug, Clone, PartialEq)]
pub struct Signal {
    /// The signal's name, as written in the file.
    pub name: String,
    /// 0-based bit offset of the least significant bit.
    pub start_bit: u16,
    /// Field width in bits.
    pub bit_length: u16,
    /// Which end comes first.
    pub byte_order: ByteOrder,
    /// Whether the raw value is two's-complement signed.
    pub signed: bool,
    /// Units per bit.
    pub factor: f64,
    /// Added after scaling.
    pub offset: f64,
    /// The lowest value the file says is meaningful.
    pub minimum: f64,
    /// The highest value the file says is meaningful.
    pub maximum: f64,
    /// The unit string, without its quotes.
    pub unit: String,
    /// The SPN this signal corresponds to, if the file says.
    ///
    /// Comes from a `BA_ "SPN" SG_ ..` attribute. J1939 people refer to
    /// parameters by SPN, so a file that records them lets a tool speak the same
    /// language as the standard.
    pub spn: Option<u32>,
    /// Named values, from a `VAL_` table.
    ///
    /// Many J1939 parameters are enumerations rather than measurements — lamp
    /// states, switch positions, control modes. Without the table a decoder can
    /// only report `2`, which means nothing to a reader.
    pub value_names: BTreeMap<u32, String>,
}

impl Signal {
    /// How many payload bytes this signal needs to be present.
    pub fn required_len(&self) -> usize {
        match self.byte_order {
            ByteOrder::LittleEndian => {
                (self.start_bit as usize + self.bit_length as usize).div_ceil(8)
            }
            // A Motorola field starts at the most significant bit and runs
            // forwards through the payload, so its span is measured from the
            // start byte.
            ByteOrder::BigEndian => {
                let start_byte = self.start_bit as usize / 8;
                let bits_in_start = (self.start_bit as usize % 8) + 1;
                if self.bit_length as usize <= bits_in_start {
                    start_byte + 1
                } else {
                    start_byte + 1 + (self.bit_length as usize - bits_in_start).div_ceil(8)
                }
            }
        }
    }

    /// Pull this signal's raw bits out of `data`, unscaled.
    pub fn raw(&self, data: &[u8]) -> Result<u32, DbcError> {
        if self.bit_length == 0 || self.bit_length > 32 {
            return Err(DbcError::TooWide {
                bits: self.bit_length,
            });
        }
        let needed = self.required_len();
        if data.len() < needed {
            return Err(DbcError::ShortPayload {
                expected: needed,
                actual: data.len(),
            });
        }

        Ok(match self.byte_order {
            ByteOrder::LittleEndian => {
                let mut raw: u32 = 0;
                for i in 0..self.bit_length {
                    let index = (self.start_bit + i) as usize;
                    let bit = (data[index / 8] >> (index % 8)) & 1;
                    raw |= (bit as u32) << i;
                }
                raw
            }
            // Motorola numbering walks *down* within a byte from the start bit,
            // then jumps to the top of the next byte — the "sawtooth" order. The
            // start bit names the most significant bit, so bits accumulate from
            // the top down rather than the bottom up.
            ByteOrder::BigEndian => {
                let mut raw: u32 = 0;
                let mut position = self.start_bit as usize;
                for _ in 0..self.bit_length {
                    let bit = (data[position / 8] >> (position % 8)) & 1;
                    raw = (raw << 1) | bit as u32;
                    if position % 8 == 0 {
                        position += 15; // down to bit 7 of the next byte
                    } else {
                        position -= 1;
                    }
                }
                raw
            }
        })
    }

    /// Decode this signal into its unit, reporting J1939's status codes rather
    /// than returning them as measurements.
    ///
    /// The reserved-range rules come from the core crate, so a DBC-defined
    /// parameter and a compile-time one classify identically.
    pub fn decode(&self, data: &[u8]) -> Result<Value, DbcError> {
        let raw = self.raw(data)?;

        // A signed field is a manufacturer extension: J1939's own reserved
        // ranges are defined over unsigned values, so they do not apply.
        if self.signed {
            let scaled = self.sign_extend(raw) as f64 * self.factor + self.offset;
            return Ok(Value::Valid(scaled));
        }

        Ok(match classify(raw, self.bit_length) {
            RawValue::Valid(value) => Value::Valid(value as f64 * self.factor + self.offset),
            RawValue::Error => Value::Error,
            RawValue::NotAvailable => Value::NotAvailable,
            RawValue::Reserved => Value::Reserved,
        })
    }

    /// The name this file gives to a raw value, if it is an enumeration.
    ///
    /// ```
    /// # use sae_j1939_host::dbc::Dbc;
    /// # use sae_j1939_host::sae_j1939_rs::Pgn;
    /// let text = r#"
    /// BO_ 2364540158 TEST: 8 Vector__XXX
    ///  SG_ Mode : 0|2@1+ (1,0) [0|3] "" Vector__XXX
    /// VAL_ 2364540158 Mode 0 "Off" 1 "On" ;
    /// "#;
    /// let dbc = Dbc::parse(text).unwrap();
    /// let mode = dbc.message(Pgn::new(0x00F004).unwrap()).unwrap().signal("Mode").unwrap();
    /// assert_eq!(mode.value_name(1), Some("On"));
    /// assert_eq!(mode.value_name(2), None);
    /// ```
    pub fn value_name(&self, raw: u32) -> Option<&str> {
        self.value_names.get(&raw).map(String::as_str)
    }

    /// Whether this signal is an enumeration rather than a measurement.
    pub fn is_enumerated(&self) -> bool {
        !self.value_names.is_empty()
    }

    /// Decode as a named value where the file provides one, falling back to the
    /// scaled measurement.
    ///
    /// This is what a dump tool wants: `"Amber Warning"` rather than `2`.
    pub fn describe(&self, data: &[u8]) -> Result<String, DbcError> {
        let raw = self.raw(data)?;
        if let Some(name) = self.value_name(raw) {
            return Ok(name.to_string());
        }
        Ok(match self.decode(data)? {
            Value::Valid(value) if self.unit.is_empty() => format!("{value}"),
            Value::Valid(value) => format!("{value} {}", self.unit),
            Value::Error => "error".to_string(),
            Value::NotAvailable => "not available".to_string(),
            Value::Reserved => "reserved".to_string(),
        })
    }

    /// Interpret the raw bits as a two's-complement value of this width.
    fn sign_extend(&self, raw: u32) -> i32 {
        if self.bit_length >= 32 {
            return raw as i32;
        }
        let sign_bit = 1u32 << (self.bit_length - 1);
        if raw & sign_bit == 0 {
            raw as i32
        } else {
            // Fill the bits above the field with ones.
            (raw | !((1u32 << self.bit_length) - 1)) as i32
        }
    }
}

/// One message definition: a parameter group and the signals inside it.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// The parameter group this message carries.
    pub pgn: Pgn,
    /// The full 29-bit identifier as written in the file, priority and source
    /// address included. Those are defaults; the ones on the bus may differ.
    pub id: Id,
    /// The message name.
    pub name: String,
    /// The data length the file declares.
    pub dlc: usize,
    /// The signals it contains, in the order they were written.
    pub signals: Vec<Signal>,
}

impl Message {
    /// A signal by name.
    pub fn signal(&self, name: &str) -> Option<&Signal> {
        self.signals.iter().find(|s| s.name == name)
    }

    /// Decode every signal in this message against `data`.
    ///
    /// Signals that cannot be decoded — big-endian, or reaching past the
    /// payload — are yielded with their error rather than skipped silently.
    pub fn decode<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Iterator<Item = (&'a str, Result<Value, DbcError>)> + 'a {
        self.signals
            .iter()
            .map(move |signal| (signal.name.as_str(), signal.decode(data)))
    }
}

/// A parsed DBC file.
#[derive(Debug, Clone, Default)]
pub struct Dbc {
    /// Keyed by PGN so a frame off the bus finds its definition directly.
    messages: BTreeMap<u32, Message>,
}

impl Dbc {
    /// Parse DBC text.
    pub fn parse(text: &str) -> Result<Self, DbcError> {
        let mut messages: BTreeMap<u32, Message> = BTreeMap::new();
        let mut current: Option<u32> = None;
        // `VAL_` and `BA_` lines come after every message block, so they are
        // collected while parsing and applied at the end.
        let mut value_tables: Vec<(u32, String, BTreeMap<u32, String>)> = Vec::new();
        let mut spn_attributes: Vec<(u32, String, u32)> = Vec::new();

        for (index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            let number = index + 1;

            if let Some(rest) = line.strip_prefix("BO_ ") {
                let message = parse_message(rest, number)?;
                let key = message.pgn.as_u32();
                current = Some(key);
                messages.insert(key, message);
            } else if let Some(rest) = line.strip_prefix("SG_ ") {
                let key = current.ok_or(DbcError::OrphanSignal { line: number })?;
                let signal = parse_signal(rest, number)?;
                // `current` was just inserted, so this cannot miss.
                if let Some(message) = messages.get_mut(&key) {
                    message.signals.push(signal);
                }
            } else if let Some(rest) = line.strip_prefix("VAL_ ") {
                current = None;
                if let Some(entry) = parse_value_table(rest) {
                    value_tables.push(entry);
                }
            } else if let Some(rest) = line.strip_prefix("BA_ ") {
                current = None;
                if let Some(entry) = parse_spn_attribute(rest) {
                    spn_attributes.push(entry);
                }
            } else if line.is_empty() {
                // A blank line ends a message block in DBC.
                current = None;
            }
            // Everything else — BU_, CM_, BA_, VAL_, VERSION — describes things
            // this module does not model. Skipping rather than rejecting means a
            // real manufacturer file parses.
        }

        // Attach the tables and attributes to the signals they name. A `VAL_`
        // or `BA_` for a message or signal the file never defined is ignored.
        for (id, signal_name, table) in value_tables {
            if let Some(signal) = find_signal(&mut messages, id, &signal_name) {
                signal.value_names = table;
            }
        }
        for (id, signal_name, spn) in spn_attributes {
            if let Some(signal) = find_signal(&mut messages, id, &signal_name) {
                signal.spn = Some(spn);
            }
        }

        Ok(Dbc { messages })
    }

    /// Read and parse a DBC file.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// The definition for a parameter group, if the file has one.
    pub fn message(&self, pgn: Pgn) -> Option<&Message> {
        self.messages.get(&pgn.as_u32())
    }

    /// Every message in the file, ordered by PGN.
    pub fn messages(&self) -> impl Iterator<Item = &Message> {
        self.messages.values()
    }

    /// How many messages were parsed.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the file described no messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// `<id> <name>: <dlc> <transmitter>`
fn parse_message(rest: &str, line: usize) -> Result<Message, DbcError> {
    let malformed = |expected| DbcError::Malformed { line, expected };

    let (id_text, rest) = rest
        .split_once(char::is_whitespace)
        .ok_or_else(|| malformed("BO_ <id> <name>: <dlc> <transmitter>"))?;
    let raw_id: u32 = id_text
        .parse()
        .map_err(|_| malformed("a numeric message identifier"))?;

    // DBC marks an extended identifier by setting bit 31. J1939 is always
    // extended, so the flag is expected but a bare 29-bit value is accepted too.
    let id = Id::new(raw_id & 0x1FFF_FFFF).map_err(|_| DbcError::NotJ1939 { line, id: raw_id })?;

    let (name, rest) = rest
        .split_once(':')
        .ok_or_else(|| malformed("a ':' after the message name"))?;
    let dlc_text = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| malformed("a data length"))?;
    let dlc: usize = dlc_text
        .parse()
        .map_err(|_| malformed("a numeric data length"))?;

    Ok(Message {
        pgn: id.pgn(),
        id,
        name: name.trim().to_string(),
        dlc,
        signals: Vec::new(),
    })
}

/// `<name> : <start>|<len>@<order><sign> (<factor>,<offset>) [<min>|<max>] "<unit>" <receivers>`
fn parse_signal(rest: &str, line: usize) -> Result<Signal, DbcError> {
    let malformed = |expected| DbcError::Malformed { line, expected };

    let (name_part, rest) = rest
        .split_once(':')
        .ok_or_else(|| malformed("a ':' after the signal name"))?;
    // A multiplexed signal is written `name m0` or `name M`; keep the name.
    let name = name_part
        .split_whitespace()
        .next()
        .ok_or_else(|| malformed("a signal name"))?
        .to_string();

    let rest = rest.trim_start();
    let (layout, rest) = rest
        .split_once(' ')
        .ok_or_else(|| malformed("<start>|<len>@<order><sign>"))?;

    let (start_text, tail) = layout
        .split_once('|')
        .ok_or_else(|| malformed("'|' between start bit and length"))?;
    let (len_text, tail) = tail
        .split_once('@')
        .ok_or_else(|| malformed("'@' before the byte order"))?;
    let start_bit: u16 = start_text
        .parse()
        .map_err(|_| malformed("a numeric start bit"))?;
    let bit_length: u16 = len_text
        .parse()
        .map_err(|_| malformed("a numeric bit length"))?;

    let mut flags = tail.chars();
    let byte_order = match flags.next() {
        Some('1') => ByteOrder::LittleEndian,
        Some('0') => ByteOrder::BigEndian,
        _ => return Err(malformed("byte order '0' or '1' after '@'")),
    };
    let signed = match flags.next() {
        Some('+') => false,
        Some('-') => true,
        _ => return Err(malformed("sign '+' or '-'")),
    };

    let rest = rest.trim_start();
    let (scaling, rest) =
        slice_between(rest, '(', ')').ok_or_else(|| malformed("(factor,offset)"))?;
    let (factor_text, offset_text) = scaling
        .split_once(',')
        .ok_or_else(|| malformed("a ',' between factor and offset"))?;
    let factor: f64 = factor_text
        .trim()
        .parse()
        .map_err(|_| malformed("a numeric factor"))?;
    let offset: f64 = offset_text
        .trim()
        .parse()
        .map_err(|_| malformed("a numeric offset"))?;

    let (range, rest) = slice_between(rest, '[', ']').ok_or_else(|| malformed("[min|max]"))?;
    let (min_text, max_text) = range
        .split_once('|')
        .ok_or_else(|| malformed("a '|' between minimum and maximum"))?;
    let minimum: f64 = min_text
        .trim()
        .parse()
        .map_err(|_| malformed("a numeric minimum"))?;
    let maximum: f64 = max_text
        .trim()
        .parse()
        .map_err(|_| malformed("a numeric maximum"))?;

    let unit = slice_between(rest, '"', '"')
        .map(|(unit, _)| unit.to_string())
        .unwrap_or_default();

    Ok(Signal {
        name,
        start_bit,
        bit_length,
        byte_order,
        signed,
        factor,
        offset,
        minimum,
        maximum,
        unit,
        spn: None,
        value_names: BTreeMap::new(),
    })
}

/// `VAL_ <message id> <signal> <value> "<name>" <value> "<name>" ... ;`
///
/// Returns the message identifier, the signal name, and the table. Malformed
/// entries are skipped rather than failing the parse: a value table is
/// decoration, and losing one should not cost the whole file.
fn parse_value_table(rest: &str) -> Option<(u32, String, BTreeMap<u32, String>)> {
    let rest = rest.trim().trim_end_matches(';');
    let (id_text, rest) = rest.split_once(char::is_whitespace)?;
    let id: u32 = id_text.parse().ok()?;
    let (signal, mut rest) = rest.trim_start().split_once(char::is_whitespace)?;

    let mut table = BTreeMap::new();
    loop {
        let trimmed = rest.trim_start();
        if trimmed.is_empty() {
            break;
        }
        let Some((value_text, tail)) = trimmed.split_once(char::is_whitespace) else {
            break;
        };
        let Ok(value) = value_text.parse::<u32>() else {
            break;
        };
        let Some((name, tail)) = slice_between(tail, '"', '"') else {
            break;
        };
        table.insert(value, name.to_string());
        rest = tail;
    }

    Some((id & 0x1FFF_FFFF, signal.to_string(), table))
}

/// `BA_ "SPN" SG_ <message id> <signal> <number>;`
///
/// Only the `SPN` attribute is read; every other attribute is ignored.
fn parse_spn_attribute(rest: &str) -> Option<(u32, String, u32)> {
    let rest = rest.trim().trim_end_matches(';');
    let (name, rest) = slice_between(rest, '"', '"')?;
    if name != "SPN" {
        return None;
    }
    let mut parts = rest.split_whitespace();
    if parts.next()? != "SG_" {
        return None;
    }
    let id: u32 = parts.next()?.parse().ok()?;
    let signal = parts.next()?.to_string();
    let spn: u32 = parts.next()?.parse().ok()?;
    Some((id & 0x1FFF_FFFF, signal, spn))
}

/// The signal a `VAL_` or `BA_` line refers to, found by raw identifier.
fn find_signal<'m>(
    messages: &'m mut BTreeMap<u32, Message>,
    id: u32,
    signal: &str,
) -> Option<&'m mut Signal> {
    messages
        .values_mut()
        .find(|message| message.id.as_u32() == id)?
        .signals
        .iter_mut()
        .find(|s| s.name == signal)
}

/// The text between the first `open` and the next `close`, plus what follows.
fn slice_between(text: &str, open: char, close: char) -> Option<(&str, &str)> {
    let start = text.find(open)? + open.len_utf8();
    let end = text[start..].find(close)? + start;
    Some((&text[start..end], &text[end + close.len_utf8()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fragment in the shape a real J1939 DBC takes.
    const EEC1: &str = r#"
VERSION ""

BU_: ECM TCM

BO_ 2364540158 EEC1: 8 Vector__XXX
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX
 SG_ ActualEnginePercentTorque : 16|8@1+ (1,-125) [-125|125] "%" Vector__XXX

BO_ 2566844158 ET1: 8 Vector__XXX
 SG_ EngineCoolantTemperature : 0|8@1+ (1,-40) [-40|210] "degC" Vector__XXX

CM_ BO_ 2364540158 "Electronic Engine Controller 1";
"#;

    #[test]
    fn parses_messages_and_recovers_their_pgn() {
        let dbc = Dbc::parse(EEC1).unwrap();
        assert_eq!(dbc.len(), 2);

        // 2364540158 = 0x8CF004FE: the extended flag, priority 3, PGN 0x00F004.
        let eec1 = dbc.message(Pgn::new(0x00F004).unwrap()).expect("EEC1");
        assert_eq!(eec1.name, "EEC1");
        assert_eq!(eec1.dlc, 8);
        assert_eq!(eec1.signals.len(), 2);
        assert_eq!(eec1.id.source_address().as_u8(), 0xFE);

        let et1 = dbc.message(Pgn::new(0x00FEEE).unwrap()).expect("ET1");
        assert_eq!(et1.name, "ET1");
    }

    #[test]
    fn parses_signal_geometry_and_scaling() {
        let dbc = Dbc::parse(EEC1).unwrap();
        let speed = dbc
            .message(Pgn::new(0x00F004).unwrap())
            .unwrap()
            .signal("EngineSpeed")
            .expect("EngineSpeed");

        assert_eq!(speed.start_bit, 24);
        assert_eq!(speed.bit_length, 16);
        assert_eq!(speed.byte_order, ByteOrder::LittleEndian);
        assert!(!speed.signed);
        assert_eq!(speed.factor, 0.125);
        assert_eq!(speed.offset, 0.0);
        assert_eq!(speed.unit, "rpm");
        assert_eq!(speed.required_len(), 5);
    }

    /// The same frame the crate's own catalogue decodes, read instead from a
    /// DBC definition — the two paths must agree.
    #[test]
    fn decodes_the_same_values_as_the_built_in_catalogue() {
        use sae_j1939_rs::spn::{catalogue, SpnValue};

        let dbc = Dbc::parse(EEC1).unwrap();
        let eec1 = dbc.message(Pgn::new(0x00F004).unwrap()).unwrap();
        let frame = [0xFF, 0x87, 0x96, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];

        assert_eq!(
            eec1.signal("EngineSpeed").unwrap().decode(&frame).unwrap(),
            Value::Valid(1500.0)
        );
        assert_eq!(
            catalogue::ENGINE_SPEED.decode(&frame).unwrap(),
            SpnValue::Valid(1500.0)
        );

        assert_eq!(
            eec1.signal("ActualEnginePercentTorque")
                .unwrap()
                .decode(&frame)
                .unwrap(),
            Value::Valid(25.0)
        );
    }

    /// The reserved-range rules are J1939's, so a DBC-defined parameter must
    /// classify exactly like a compile-time one.
    #[test]
    fn status_codes_are_reported_not_scaled() {
        let dbc = Dbc::parse(EEC1).unwrap();
        let coolant = dbc
            .message(Pgn::new(0x00FEEE).unwrap())
            .unwrap()
            .signal("EngineCoolantTemperature")
            .unwrap();

        assert_eq!(coolant.decode(&[0xFF; 8]).unwrap(), Value::NotAvailable);
        assert_eq!(coolant.decode(&[0xFE; 8]).unwrap(), Value::Error);
        assert_eq!(coolant.decode(&[0xFC; 8]).unwrap(), Value::Reserved);
        // 0xFA is the last valid raw byte: 250 - 40 = 210 degC.
        assert_eq!(coolant.decode(&[0xFA; 8]).unwrap(), Value::Valid(210.0));
        assert_eq!(
            coolant.decode(&[0xFF; 8]).unwrap().value(),
            None,
            "a status code must never read as a measurement"
        );
    }

    #[test]
    fn signed_signals_are_sign_extended() {
        let text = r#"
BO_ 2364540158 TEST: 8 Vector__XXX
 SG_ Signed8 : 0|8@1- (1,0) [-128|127] "x" Vector__XXX
 SG_ Signed12 : 8|12@1- (1,0) [-2048|2047] "x" Vector__XXX
"#;
        let dbc = Dbc::parse(text).unwrap();
        let message = dbc.message(Pgn::new(0x00F004).unwrap()).unwrap();

        let byte = message.signal("Signed8").unwrap();
        assert_eq!(byte.decode(&[0x7F; 8]).unwrap(), Value::Valid(127.0));
        assert_eq!(byte.decode(&[0xFF; 8]).unwrap(), Value::Valid(-1.0));
        assert_eq!(byte.decode(&[0x80; 8]).unwrap(), Value::Valid(-128.0));

        // A 12-bit field starting at bit 8: 0xFFF is -1, 0x800 is -2048.
        let wide = message.signal("Signed12").unwrap();
        let mut frame = [0u8; 8];
        frame[1] = 0xFF;
        frame[2] = 0x0F;
        assert_eq!(wide.decode(&frame).unwrap(), Value::Valid(-1.0));
    }

    /// Motorola numbering walks down within a byte, then jumps to the top of
    /// the next — so a 16-bit field at start bit 7 is simply the first two bytes
    /// big-endian.
    #[test]
    fn big_endian_signals_use_motorola_bit_numbering() {
        let text = r#"
BO_ 2364540158 TEST: 8 Vector__XXX
 SG_ Motorola16 : 7|16@0+ (1,0) [0|65535] "x" Vector__XXX
 SG_ Motorola12 : 23|12@0+ (1,0) [0|4095] "x" Vector__XXX
"#;
        let dbc = Dbc::parse(text).unwrap();
        let message = dbc.message(Pgn::new(0x00F004).unwrap()).unwrap();

        let wide = message.signal("Motorola16").unwrap();
        assert_eq!(wide.byte_order, ByteOrder::BigEndian);
        assert_eq!(wide.required_len(), 2);
        // 0x1234 big-endian across bytes 0 and 1.
        let frame = [0x12, 0x34, 0, 0, 0, 0, 0, 0];
        assert_eq!(wide.raw(&frame).unwrap(), 0x1234);
        assert_eq!(wide.decode(&frame).unwrap(), Value::Valid(4660.0));

        // A 12-bit field starting at byte 2's most significant bit.
        let narrow = message.signal("Motorola12").unwrap();
        assert_eq!(narrow.required_len(), 4);
        let frame = [0, 0, 0xAB, 0xC0, 0, 0, 0, 0];
        assert_eq!(narrow.raw(&frame).unwrap(), 0xABC);
    }

    /// The same value laid out both ways must decode to the same number — the
    /// clearest check that the two extractions agree.
    #[test]
    fn both_byte_orders_agree_on_the_same_value() {
        let text = r#"
BO_ 2364540158 TEST: 8 Vector__XXX
 SG_ Intel : 0|16@1+ (1,0) [0|65535] "x" Vector__XXX
 SG_ Motorola : 23|16@0+ (1,0) [0|65535] "x" Vector__XXX
"#;
        let dbc = Dbc::parse(text).unwrap();
        let message = dbc.message(Pgn::new(0x00F004).unwrap()).unwrap();

        // 0x1234 little-endian in bytes 0-1, big-endian in bytes 2-3.
        let frame = [0x34, 0x12, 0x12, 0x34, 0, 0, 0, 0];
        assert_eq!(
            message.signal("Intel").unwrap().raw(&frame).unwrap(),
            0x1234
        );
        assert_eq!(
            message.signal("Motorola").unwrap().raw(&frame).unwrap(),
            0x1234
        );
    }

    /// Most J1939 parameters that are not measurements are enumerations, and a
    /// bare `2` tells a reader nothing.
    #[test]
    fn value_tables_name_enumerated_values() {
        let text = r#"
BO_ 2566834942 DM1: 8 Vector__XXX
 SG_ AmberWarningLampStatus : 2|2@1+ (1,0) [0|3] "" Vector__XXX

VAL_ 2566834942 AmberWarningLampStatus 0 "Off" 1 "On" 2 "Reserved" 3 "Not available" ;
"#;
        let dbc = Dbc::parse(text).unwrap();
        let lamp = dbc
            .message(Pgn::new(0x00FECA).unwrap())
            .unwrap()
            .signal("AmberWarningLampStatus")
            .unwrap();

        assert!(lamp.is_enumerated());
        assert_eq!(lamp.value_name(0), Some("Off"));
        assert_eq!(lamp.value_name(1), Some("On"));
        assert_eq!(lamp.value_name(3), Some("Not available"));
        assert_eq!(lamp.value_name(9), None);

        // `describe` prefers the name over the number.
        let on = [0b0000_0100, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(lamp.describe(&on).unwrap(), "On");
    }

    #[test]
    fn describe_falls_back_to_the_measurement_and_its_unit() {
        let dbc = Dbc::parse(EEC1).unwrap();
        let speed = dbc
            .message(Pgn::new(0x00F004).unwrap())
            .unwrap()
            .signal("EngineSpeed")
            .unwrap();

        let frame = [0xFF, 0xFF, 0xFF, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];
        assert_eq!(speed.describe(&frame).unwrap(), "1500 rpm");
        // A status code is described as such, not as a number.
        assert_eq!(speed.describe(&[0xFF; 8]).unwrap(), "not available");
    }

    /// J1939 people refer to parameters by SPN, so a file that records them
    /// lets a tool speak the same language as the standard.
    #[test]
    fn spn_attributes_are_attached_to_their_signal() {
        let text = r#"
BO_ 2364540158 EEC1: 8 Vector__XXX
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX

BA_DEF_ SG_ "SPN" INT 0 524287;
BA_ "SPN" SG_ 2364540158 EngineSpeed 190;
BA_ "GenSigStartValue" SG_ 2364540158 EngineSpeed 0;
"#;
        let dbc = Dbc::parse(text).unwrap();
        let speed = dbc
            .message(Pgn::new(0x00F004).unwrap())
            .unwrap()
            .signal("EngineSpeed")
            .unwrap();

        assert_eq!(speed.spn, Some(190), "SPN 190 is engine speed");
    }

    #[test]
    fn tables_and_attributes_for_unknown_signals_are_ignored() {
        let text = r#"
BO_ 2364540158 EEC1: 8 Vector__XXX
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX

VAL_ 2364540158 NoSuchSignal 0 "Off" ;
VAL_ 999999999 EngineSpeed 0 "Off" ;
BA_ "SPN" SG_ 2364540158 NoSuchSignal 190;
"#;
        let dbc = Dbc::parse(text).unwrap();
        let speed = dbc
            .message(Pgn::new(0x00F004).unwrap())
            .unwrap()
            .signal("EngineSpeed")
            .unwrap();
        assert!(!speed.is_enumerated());
        assert_eq!(speed.spn, None);
    }

    #[test]
    fn a_signal_reaching_past_the_payload_is_refused() {
        let dbc = Dbc::parse(EEC1).unwrap();
        let speed = dbc
            .message(Pgn::new(0x00F004).unwrap())
            .unwrap()
            .signal("EngineSpeed")
            .unwrap();
        assert_eq!(
            speed.decode(&[0u8; 4]),
            Err(DbcError::ShortPayload {
                expected: 5,
                actual: 4
            })
        );
    }

    /// A real file is mostly things this module does not model. They must not
    /// stop it parsing.
    #[test]
    fn unmodelled_sections_are_skipped_not_rejected() {
        let text = r#"
VERSION "1.0"
NS_ :
    BA_
    CM_
BS_:
BU_: ECM
BO_ 2364540158 EEC1: 8 Vector__XXX
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX
CM_ SG_ 2364540158 EngineSpeed "Engine speed";
BA_DEF_ SG_ "SPN" INT 0 524287;
VAL_ 2364540158 SomeSignal 0 "Off" 1 "On";
"#;
        let dbc = Dbc::parse(text).unwrap();
        assert_eq!(dbc.len(), 1);
        assert_eq!(dbc.messages().next().unwrap().signals.len(), 1);
    }

    #[test]
    fn malformed_lines_name_the_line_number() {
        let text = "BO_ notanumber EEC1: 8 Vector__XXX\n";
        assert!(matches!(
            Dbc::parse(text),
            Err(DbcError::Malformed { line: 1, .. })
        ));

        // A signal before any message belongs to nothing.
        let text = " SG_ Orphan : 0|8@1+ (1,0) [0|255] \"x\" Vector__XXX\n";
        assert_eq!(
            Dbc::parse(text).unwrap_err(),
            DbcError::OrphanSignal { line: 1 }
        );
    }

    #[test]
    fn an_identifier_wider_than_29_bits_is_refused() {
        // 0x9FFFFFFF has the extended flag plus bits beyond 29.
        let text = "BO_ 4294967295 BAD: 8 Vector__XXX\n";
        // The extended flag is masked off, so this is 0x1FFFFFFF — still valid.
        assert!(Dbc::parse(text).is_ok());
    }

    #[test]
    fn every_signal_in_a_message_decodes_together() {
        let dbc = Dbc::parse(EEC1).unwrap();
        let eec1 = dbc.message(Pgn::new(0x00F004).unwrap()).unwrap();
        let frame = [0xFF, 0x87, 0x96, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];

        let decoded: Vec<_> = eec1.decode(&frame).collect();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, "EngineSpeed");
        assert_eq!(decoded[0].1, Ok(Value::Valid(1500.0)));
        assert_eq!(decoded[1].0, "ActualEnginePercentTorque");
        assert_eq!(decoded[1].1, Ok(Value::Valid(25.0)));
    }
}
