// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # sae-j1939-rs
//!
//! A `no_std`-first [SAE J1939] protocol stack in Rust — the CAN-based
//! protocol used across trucks, agricultural equipment, construction
//! machinery, and marine engines.
//!
//! This core crate is transport-agnostic and allocation-free: it decodes and
//! encodes the 29-bit J1939 identifier, models parameter groups, and (as the
//! stack grows) drives the transport, network management, and diagnostic
//! layers. It is designed to run unchanged on a bare-metal ECU and on a host
//! (Linux/SocketCAN) via the companion `sae-j1939-host` crate.
//!
//! CAN frames are represented through the [`embedded_can`] traits, so any
//! controller or socket that implements them can carry J1939 traffic.
//!
//! # Example: decode a frame off the bus
//!
//! ```
//! use sae_j1939_rs::{pgn, Address, Id, Priority};
//!
//! // A DM1 (active diagnostic trouble codes) broadcast from ECU 0x80.
//! let id = Id::new(0x18FECA80).unwrap();
//!
//! assert_eq!(id.pgn(), pgn::DM1);
//! assert_eq!(id.priority(), Priority::DEFAULT);
//! assert_eq!(id.source_address(), Address::new(0x80));
//! assert!(id.is_broadcast());
//!
//! // DM1 is a PDU2 parameter group, so it has no destination address —
//! // every ECU on the bus should process it.
//! assert_eq!(id.destination_address(), None);
//! assert!(id.is_addressed_to(Address::new(0x27)));
//! ```
//!
//! # Example: address a request to one ECU
//!
//! ```
//! use sae_j1939_rs::{pgn, Address, Id, Priority};
//!
//! // Request the Software Identification PGN from ECU 0x90.
//! let id = Id::from_parts(
//!     Priority::DEFAULT,
//!     pgn::REQUEST,
//!     Address::new(0x90),
//!     Address::new(0x80),
//! )
//! .unwrap();
//!
//! assert_eq!(id.as_u32(), 0x18EA9080);
//! ```
//!
//! # Example: reassemble a multi-packet message
//!
//! Messages longer than eight bytes arrive as a sequence of transport-protocol
//! frames. [`Reassembler`](tp::Reassembler) puts them back together, bounded by
//! a buffer size you choose so an MCU can never be overrun.
//!
//! ```
//! use sae_j1939_rs::tp::{Reassembler, Rx, TpCm, TpDt};
//! use sae_j1939_rs::{pgn, Address};
//!
//! let mut rx = Reassembler::<256>::new();
//! let sender = Address::new(0x80);
//!
//! rx.on_tp_cm(sender, &TpCm::bam(12, pgn::DM1).unwrap());
//! rx.on_tp_dt(sender, &TpDt::new(1, &[1, 2, 3, 4, 5, 6, 7]));
//!
//! if let Rx::Message { pgn, data, .. } = rx.on_tp_dt(sender, &TpDt::new(2, &[8, 9, 10, 11, 12])) {
//!     assert_eq!(pgn, pgn::DM1);
//!     assert_eq!(data, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
//! }
//! ```
//!
//! ## Module map
//!
//! | Module | J1939 part | What it covers |
//! |--------|-----------|----------------|
//! | [`id`], [`pgn`], [`frame`] | J1939-21 | The 29-bit identifier, parameter groups, single frames |
//! | [`tp`] | J1939-21 | Transport protocol: BAM and RTS/CTS, up to 1785 bytes |
//! | [`etp`] | J1939-21 | Extended transport protocol: up to 117 MB |
//! | [`name`] | J1939-81 | The 64-bit ECU NAME |
//! | [`address_claim`] | J1939-81 | Claiming, defending, and relocating an address |
//! | [`diagnostics`] | J1939-73 | DM1/DM2 trouble codes and lamp status |
//! | [`fault_log`] | J1939-73 | The fault state an ECU reports about itself |
//! | [`memory_access`] | J1939-73 | DM14/DM15/DM16 memory read, write, and data transfer |
//! | [`identification`] | J1939-71 | Software, ECU, and component identification |
//! | [`spn`] | J1939-71 | Suspect Parameter Numbers: payload bytes to engineering units |
//! | [`proprietary`] | J1939-21 | Manufacturer-specific Proprietary A and B groups |
//! | [`iso11783`] | ISO 11783 | Tractor/implement auxiliary and general purpose valves |
//! | [`request`] | J1939-21 | The Request and Acknowledgement parameter groups |
//! | [`node`] | — | A whole ECU: claiming, reassembly, and dispatch in one type |
//! | [`can`] | — | Bridge to the [`embedded_can`] traits |
//!
//! Note that [`can`] — not `transport` — holds the CAN frame bridge, because in
//! J1939 "transport protocol" means [`tp`] specifically.
//!
//! ## Status
//!
//! Early development. The API will change. The identifier, PGN, transport
//! protocol, NAME, address-claiming, diagnostic, identification, and ISO 11783
//! valve layers are implemented and tested against known-good frames. A broader
//! PGN/SPN parameter database is next — see the roadmap in the workspace
//! `README.md`.
//!
//! [SAE J1939]: https://www.sae.org/standards/development/ground-vehicle-standards/j1939
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

// `std` is available to the test harness regardless of the feature, so tests
// may use `Vec` and friends while the library itself stays `no_std`.
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod address_claim;
pub mod can;
pub mod diagnostics;
pub mod etp;
pub mod fault_log;
pub mod frame;
pub mod id;
pub mod identification;
pub mod iso11783;
pub mod memory_access;
pub mod name;
pub mod node;
pub mod pgn;
pub mod proprietary;
pub mod request;
pub mod spn;
pub mod tp;
pub mod types;

pub use address_claim::{AddressClaimer, ClaimState};
pub use frame::Frame;
pub use id::Id;
pub use name::Name;
pub use node::Node;
pub use pgn::Pgn;
pub use request::{Acknowledgement, Request};
pub use types::{Address, Error, Priority, Result};
