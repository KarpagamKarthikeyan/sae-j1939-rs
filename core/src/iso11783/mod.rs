// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ISO 11783 (ISOBUS): agricultural tractors and their implements.
//!
//! ISO 11783 builds on J1939. The physical layer, the 29-bit identifier,
//! address claiming, and the transport protocols are all shared — everything in
//! [`crate::id`], [`crate::address_claim`], [`crate::tp`], and [`crate::etp`]
//! applies unchanged. What ISOBUS adds is the agricultural application layer,
//! and that is what lives here.
//!
//! | Module | ISO 11783 part | What it covers |
//! |--------|----------------|----------------|
//! | [`valve`] | -7 | Auxiliary and general purpose hydraulic valves |
//! | [`working_set`] | -7 | Declaring how many ECUs form one implement |
//! | [`task_controller`] | -10 | Process data between a task controller and an implement |
//!
//! # How a season's work actually flows
//!
//! A tractor tows an implement; the implement is one or more ECUs that together
//! form a **working set**, announced with [`working_set::WorkingSetMaster`].
//! The implement uploads a **device descriptor object pool** describing what it
//! can measure and control — a structure far larger than 1785 bytes, which is
//! why [`crate::etp`] exists. From then on the task controller and the implement
//! exchange [`task_controller::ProcessData`] messages: request this value, here
//! is that value, tell me when this changes by more than so much.
//!
//! # Verification status
//!
//! The valve messages were cross-checked against the MIT-licensed
//! Open-SAE-J1939 C implementation. The working set and task controller
//! messages were not — that project does not cover them — so they are built
//! from the structure ISO 11783 describes and have not been checked against a
//! real terminal. Please report anything that disagrees with your hardware.

pub mod task_controller;
pub mod valve;
pub mod working_set;

// The valve API was at `iso11783::*` before this module grew submodules;
// re-exporting keeps every existing path working.
pub use valve::{
    AuxiliaryValveCommand, AuxiliaryValveEstimatedFlow, AuxiliaryValveMeasuredPosition,
    FailSafeMode, GeneralPurposeValveCommand, GeneralPurposeValveEstimatedFlow, ValveNumber,
    ValveState, AUX_VALVE_COMMAND_BASE, AUX_VALVE_ESTIMATED_FLOW_BASE,
    AUX_VALVE_MEASURED_POSITION_BASE, GENERAL_PURPOSE_VALVE_COMMAND,
    GENERAL_PURPOSE_VALVE_ESTIMATED_FLOW, LIMIT_NOT_USED, MAX_VALVE_NUMBER, VALVE_PRIORITY,
};
