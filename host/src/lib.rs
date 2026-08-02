// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # sae-j1939-host
//!
//! Host-side (`std`) transport and tooling for [`sae_j1939_rs`]: a Linux
//! SocketCAN transport built on top of the `no_std` core.
//!
//! The core protocol logic lives in [`sae_j1939_rs`] and is re-exported here
//! for convenience, so a host application needs only this one dependency.

pub use sae_j1939_rs;

/// The transport boundary: what an [`ecu::Ecu`] needs from a CAN bus.
pub mod bus;

/// Reading signal definitions from a DBC file.
///
/// The industry-standard way to describe CAN signals, so the parameter database
/// is yours rather than whatever the crate happened to hardcode. Cross-platform:
/// a DBC file is text and carries no OS dependency.
pub mod dbc;

/// A running ECU: a bus and the protocol stack wired together.
///
/// Start here unless you need the pieces separately. Generic over
/// [`bus::Bus`], so it is not tied to SocketCAN or to Linux.
pub mod ecu;

/// Linux SocketCAN transport (compiled only on `target_os = "linux"`).
#[cfg(target_os = "linux")]
pub mod transport;
