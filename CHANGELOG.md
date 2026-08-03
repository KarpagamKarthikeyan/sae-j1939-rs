# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `log` (host) — read `candump` captures and replay them through the stack.
  Three modules (`etp`, `iso11783::working_set`, `iso11783::task_controller`)
  have no reference implementation to check against, and tests can only prove
  they are self-consistent. Replaying a real capture is how anyone with hardware
  can tell us whether they are *right*, and it needs no CAN interface, no Linux,
  and no second machine.
  - `parse_line` handles the `candump -l` format. Traffic the stack cannot use —
    11-bit identifiers from a CANopen device sharing the bus, remote frames,
    CAN FD — is skipped rather than rejected, so a mixed capture replays without
    being edited first.
  - `Replay` drives `Node::tick` from the **capture's own timestamps**, so a
    transfer that stalled on the real bus stalls here at the same point and a
    session that timed out times out. Only possible because the state machines
    own no clock.
  - `Replay::claimed_addresses` reports the bus inventory. Address claims are
    network management, so a node consumes them and they never surface as
    messages — but "who is on this bus" is the first thing a capture is opened
    to answer.
  - `Replay::transmitted` records what the node would have sent, so a capture's
    own responses can be compared against what this stack would have replied.
- `replay` example — a working analyser: reassembles, decodes parameters into
  engineering units, reads trouble codes, and prints a bus inventory.
  Cross-platform, since a capture is text.
- Four more trouble-code lists: **DM6** (pending), **DM12** (emissions-related
  active), **DM23** (previously active emissions-related), **DM27** (all
  pending). They differ from DM1 and DM2 only in *which* faults they report, not
  in how, so `Message` reads all six — this extends a codec already cross-checked
  against the C reference rather than adding another unverified one.
  `is_dtc_list` and `DTC_LIST_GROUPS` say which parameter groups they are.
- **DM5** — diagnostic readiness: active and previously active fault counts, and
  the OBD compliance level. A tool reads this first, since the counts say whether
  to ask for DM1 at all.
  - The five monitor bytes are **not decoded**. Their bit assignments are
    specific, and a wrong reading would report a catalyst monitor as passed when
    it had not; `monitors()` returns them raw for a caller with the standard.
  - Compliance levels other than the two unambiguous ones are carried through as
    `ObdCompliance::Other` rather than guessed at.
- `pgn::DM4` — the freeze-frame PGN only. The payload is a variable-length,
  ECU-specific structure this crate does not model, and the constant says so.
- The `replay` example recognises all of them.

- A **`defmt`** feature on the core crate, off by default. Embedded Rust logs
  with `defmt`, and without `defmt::Format` these types could not be printed on
  a microcontroller at all — the audience the crate is aimed at.
  - Derived on the plain types; hand-written for the seven with custom `Debug`
    (`Id`, `Pgn`, `Address`, `Priority`, `Frame`, `Name`, `Dtc`), so a `defmt`
    log line and a host `Debug` line say the same thing.
  - `Frame` logs in `candump` form, so a frame captured from an MCU replays with
    `cansend` exactly as one from a host does.
- `tools/check.sh` and CI now walk the **feature matrix** rather than relying on
  `--all-features`, which enables everything at once and so cannot catch a
  feature that breaks only in isolation. Verified by breaking the `defmt` path
  alone: a plain build still passed, and the gate failed.

## [0.3.0] - 2026-08-02

Additive throughout: no breaking changes since 0.2.0.

### Added

- `dbc` (host) — read signal definitions from a **DBC file**, the format the
  industry already uses to describe CAN signals. This answers the "comprehensive
  SPN database" question without shipping thousands of values that cannot be
  checked against a document sold rather than published: the database is the
  user's, current, and specific to their hardware.
  - `BO_` messages map to a `Pgn`; `SG_` signals carry geometry, scaling, sign,
    and unit. Sections the module does not model — node lists, comments,
    attributes, value tables — are skipped, so a real manufacturer file parses.
  - Signals decode through the core's reserved-range rules, so a runtime-loaded
    parameter reports *not available* and *error* exactly like a compile-time
    one.
  - Both byte orders decode. J1939 is little-endian, but real files mix in
    Motorola signals, which use a different bit numbering — walking down within
    a byte, then jumping to the top of the next.
  - `VAL_` value tables name enumerated values, so a decoder reports
    `"Amber Warning"` rather than `2`; `Signal::describe` prefers the name and
    falls back to the scaled measurement with its unit.
  - `BA_ "SPN"` attributes attach the SPN number to its signal, so a tool can
    speak the same language as the standard. Tables and attributes naming
    signals the file never defined are ignored rather than failing the parse.
- `spn::classify` is now public, so a definition from any source can reuse
  J1939's reserved-range rules instead of reimplementing them.
- `etp` — the **Extended Transport Protocol**, for messages past the 1785-byte
  ceiling `tp` imposes. Carries up to 117,440,505 bytes. ISOBUS object pools and
  task data routinely exceed 1785 bytes, so this was the gap that stopped the
  crate being usable for that work at all.
  - A data packet's sequence number is still one byte, so the sender precedes
    each block with a **Data Packet Offset** and the sequence numbers that
    follow are relative to it. A receiver that ignores the offset writes every
    block over the first, so the reassembler refuses data that arrives without
    one, and refuses an offset that does not match the block it granted.
  - `Reassembler<BUF, SESSIONS>` and `Transmitter`, matching `tp`'s shape.
    `progress` reports bytes received against the total, because these transfers
    take long enough to be worth showing.
  - **Unverified against hardware.** Every other wire format here was
    cross-checked against the Open-SAE-J1939 C implementation; that project does
    not cover ETP, so this is built from the J1939-21 and ISO 11783-3 structure
    alone. It is the least-proven part of the crate.
- `Ecu` reassembles ETP transfers up to `ETP_BUFFER` (64 KiB) and expires stalled
  ones on `T3`. `Node` deliberately does not: a 117 MB ceiling has no place on an
  MCU, and a host has the memory to spare.
- `pgn::ETP_CM` and `pgn::ETP_DT`.

- `diagnostics::dm11` — clear *active* trouble codes, the counterpart to `dm3`.
  Documented with why that is rarely the right thing to do: an active code is a
  fault happening now, and clearing it destroys evidence without fixing
  anything.
- `diagnostics::Dm13` — stop/start broadcast, for quietening a bus so a tool can
  work. Every network defaults to "do not care", so a command aimed at one bus
  cannot silence the others by omission.
- `pgn::DM11` and `pgn::DM13`.

- `iso11783` became a directory module as it grew: `valve` (the existing
  hydraulics), plus `working_set` and `task_controller`. Every previous path
  still resolves — the valve API is re-exported at `iso11783::*`.
- `iso11783::working_set` — a seed drill is three ECUs that a task controller
  must see as one implement. `WorkingSetMaster` declares how many. A count of
  zero is refused: the master is itself a member, so zero is malformed rather
  than "no members".
- `iso11783::task_controller` — ISO 11783-10 process data, the one parameter
  group a task controller and an implement use for everything. `ProcessData`
  carries an element (12 bits, split awkwardly across two bytes), a DDI, a
  command, and a signed 32-bit value. `Command::is_measurement_trigger`
  distinguishes the five commands that set up reporting from those that ask
  once — the reason a task controller does not have to poll.
- `DeviceDescriptor::needs_extended_transport` — an implement's object pool runs
  to tens of kilobytes, which is the practical reason ISOBUS needs `etp` at all.
  Tested end to end: a 40 KiB pool crosses the bus and arrives intact.
- **Neither is cross-checked against hardware.** The Open-SAE-J1939 C reference
  does not cover working sets or the task controller, so both are built from the
  ISO 11783 structure alone, as `etp` is.

### Planned

- The ISO 11783-6 virtual terminal (an object-pool protocol in its own right).

## [0.2.0] - 2026-08-01

Everything below landed after 0.1.0 went to crates.io. It is a large release
for a 0.x: two new protocol areas, a runtime layer for both crates, eight
protocol defects fixed, and several breaking API changes — listed first.

### Breaking

- `Ecu` is generic over a new `bus::Bus` trait (`Ecu<B, BUF, SESSIONS>`), so the
  host stack is no longer tied to SocketCAN or to Linux. `SocketCanEcu` is the
  alias for the Linux case; `Ecu::open` still works through it.
- `SocketCan` is now a frame transport only. `recv_message`, `send_tp_cm`,
  `send_tp_dt`, `request`, `transfers_in_flight`, and `abandon_transfer` are
  gone — they duplicated protocol logic that belongs in the core. Use `Ecu`.
- `tp::Reassembler` gained a second const parameter, `SESSIONS`. It defaults to
  1, so `Reassembler::<N>` still compiles.
- `AddressClaimer::give_up` returns `Claim` rather than a `ClaimAction` whose
  `Idle` variant was unreachable.
- `memory_access::Dm14::decode` returns `Self` rather than an always-`Ok`
  `Result`, matching `Dm15::decode`.
- `Frame::new` pads unused payload bytes with `0xFF` as J1939 specifies, not
  zero. `Frame::payload()` therefore reads differently for short frames.
- `tp::packet_count` saturates at 255 above 1785 bytes instead of wrapping to 0.
- `Display` and `Debug` on `Id`, `Pgn`, `Address`, `Priority`, `Frame`, `Name`,
  and `Dtc` are hand-written now. Anything parsing their old derived output
  will need updating.

### Added

- **`sae-j1939-rs` (`no_std` core)**

  *J1939-21 — data link layer*
  - `Id` — 29-bit J1939 CAN identifier decode and encode: priority, extended
    data page, data page, PDU format, PDU specific, and source address.
  - `Pgn` — 18-bit parameter group number with correct PDU1/PDU2 semantics. PDU1
    PGNs normalise away the destination byte; PDU2 PGNs retain the group
    extension. Constants for the well-known parameter groups.
  - `Id::is_addressed_to` — the receive filter an ECU applies to incoming frames.
  - `Frame` — a single J1939 CAN frame (identifier plus up to eight bytes).
  - `tp` — the transport protocol, both directions:
    - `TpCm` (RTS / CTS / EndOfMsgAck / BAM / Abort) and `TpDt` codecs, with the
      standard `AbortReason` set.
    - `Reassembler<N, SESSIONS>` — receives BAM and RTS/CTS transfers up to 1785
      bytes, generic over both the largest message it will accept and how many
      peers may be mid-transfer, so an MCU bounds its own memory. Interleaved
      transfers from different ECUs are reassembled independently. Oversized
      transfers are refused with an abort, out-of-order packets abort the
      session, and a peer opening a second session is rejected.
    - `Reassembler::tick` — expires sessions that go quiet longer than `T1`
      (750 ms), yielding the abort to send back. The caller supplies elapsed
      time, so no clock is forced on `no_std` users. `T1`–`T4` are exposed as
      constants.
    - `Transmitter` — drives a BAM or an RTS/CTS handshake, borrowing the
      payload so a large message costs no extra RAM.

  - `request` — the Request (`0x00EA00`) and Acknowledgement (`0x00E800`)
    parameter groups, with the four standard control bytes.
  - `proprietary` — Proprietary A (addressed) and Proprietary B (broadcast, 256
    group extensions across two data pages), with the addressing rules enforced
    by the type.

  *J1939-81 — network management*
  - `Name` — the 64-bit ECU NAME, all nine fields, each masked to its bit width.
  - `address_claim::AddressClaimer` — claim, defend, relocate, or give up an
    address; tracks which addresses are in use so an arbitrary-address-capable
    ECU can pick a free one. Handles Commanded Address.

  *J1939-73 — diagnostics*
  - `diagnostics` — DM1/DM2: `Lamps` (four lamps, status and flash status),
    `Dtc` (19-bit SPN, 5-bit FMI, occurrence count, conversion method), a
    borrowing `Message` parser, and `encode`. `dm3` covers the clear-codes
    request/acknowledge exchange.
  - `memory_access` — DM14 (request), DM15 (response), and DM16 (binary data
    transfer), including the 11-bit byte count split across two bytes and the
    24-bit pointer and EDC parameter fields.

  *J1939-71 — application layer*
  - `identification` — Software, ECU, and Component Identification: an iterator
    over the `*`-delimited ASCII fields the standard specifies, named accessors
    per parameter group, and encoders. Software Identification's leading count
    byte is parsed and can be checked against the fields actually present.

  - `spn` — Suspect Parameter Numbers: bit-field extraction (including fields
    that straddle byte boundaries), resolution and offset scaling, and
    `bit_position` for transcribing SAE `byte.bit` notation. `SpnValue`
    distinguishes a measurement from J1939's in-band *not available*, *error*,
    and *reserved* codes at every field width, so a status byte cannot be read
    as a reading. `catalogue` carries 13 widely published definitions.

  *ISO 11783 (ISOBUS)*
  - `iso11783` — the auxiliary valve groups (command, estimated flow, measured
    position) for all sixteen valves, and the general purpose valve command and
    estimated flow. `ValveNumber` maps a valve to its three PGN blocks and back,
    including the measured position block that overlaps the Proprietary B range.

  *Putting it together*
  - `node::Node<BUF, SESSIONS>` — a whole ECU in one type: address claiming and
    defence, the receive filter, transport-protocol reassembly, and the
    CTS/acknowledgement handshakes. `on_frame` returns what to transmit and what
    arrived; `tick` closes the 250 ms contention window and expires stalled
    transfers. Still sans-I/O — it owns no bus and no clock.
  - `node::Outgoing` — the transmit counterpart to `Node`. Decides between a
    single frame, a BAM, and an RTS/CTS handshake, and yields frames; the caller
    never builds a TP.CM or TP.DT by hand. `needs_pacing` reports when J1939-21's
    50–200 ms BAM spacing applies. Borrows the payload, so a 1785-byte message
    costs no extra RAM.
  - `Frame::from_payload` — infallible constructor for the common case of a full
    eight-byte parameter group.

  *Formatting*
  - `Display` and a domain-appropriate `Debug` on the wire-shaped types, because
    the derived ones were unreadable — a CAN identifier is not a decimal number
    and a packed NAME is not a `u64`:
    - `Frame` prints in `candump` format (`18FECA80#04002B`), so a logged frame
      replays with `cansend` verbatim and compares against a capture by eye.
    - `Id` prints as the eight hex digits every tool shows; its `Debug` also
      decodes priority, PGN, source, and destination.
    - `Pgn` prints both hex and decimal, since J1939 documentation uses both.
    - `Address` names the two reserved values (`0xFF (global)`, `0xFE (null)`).
    - `Name`'s `Debug` shows all nine fields rather than the packed integer.
    - `Dtc` prints the way a service tool reads a fault: `SPN 100 FMI 1 (x2)`.

  *Transport-agnostic plumbing*
  - `can` — bridge to the `embedded-can` traits (`frame_from`, `j1939_id`,
    `decode`, `encode`).
  - `std` feature enabling `std::error::Error` for `Error`.

- **`sae-j1939-host` (`std` host layer)**
  - `bus::Bus` — the transport boundary, two methods wide. `Ecu` is generic over
    it, so the host stack is not tied to SocketCAN or to Linux: an adapter SDK,
    a simulator, a log replay, or a test double all work.
  - `SocketCanEcu` — `Ecu<SocketCan, 1785, 8>`. Const-generic defaults do not
    apply to associated-function calls, so this alias is what makes
    `SocketCanEcu::open("can0", ..)` work without a turbofish.
  - `Ecu` — a running node: owns the bus and the clock, claims an address,
    reassembles incoming multi-packet transfers, and splits outgoing messages
    over the transport protocol (BAM with J1939-21 pacing for broadcasts, the
    full RTS/CTS handshake for addressed sends). Traffic arriving mid-handshake
    is queued rather than dropped. `claim_address` waits for arbitration to
    *settle*, including the fresh contention window that opens when a competing
    claim forces a relocation, and queues any ordinary traffic that arrives
    during the window rather than discarding it. Transmitting before an address
    is claimed is refused, per J1939-81.
  - `SocketCan` — the Linux SocketCAN implementation of `Bus`, and nothing
    more: `open`, `send`, `send_frame`, `recv` (skipping remote, error, and
    11-bit frames), and the two timeout controls. Reassembly and address
    management deliberately live in the core instead, so each protocol rule has
    exactly one implementation.
  - `vcan_dump` example — decode live traffic, reassemble multi-packet
    messages, and pretty-print NAME, DM1/DM2, and engine parameters in
    engineering units.
  - `vcan_ecu` example — a complete virtual ECU built on `Node`: claims an
    address, answers requests, and reports three trouble codes over a BAM.

- **CI** — the on-bus job now asserts on real traffic rather than just starting
  the examples: a virtual ECU must claim `0x80`, and must answer a DM1 request
  with a BAM plus TP.DT packets; the decoder must read 1500 rpm from a live
  engine frame.

- **Examples** — `mcu_node` shows the shape of a bare-metal ECU: fixed buffers
  sized by const parameters, a CAN peripheral behind the `embedded-can` traits,
  and a counter standing in for `SysTick`. It runs on a host so the logic can be
  watched without hardware.

- **Documentation** — `ARCHITECTURE.md`: the system in 16 diagrams, covering the
  crate split, the layering against J1939-21/-71/-73/-81 and ISO 11783, the
  29-bit identifier and its PDU1/PDU2 trap, receive and transmit data flows,
  BAM and RTS/CTS sequences with their abort paths, the address-claiming state
  machine, the reassembler session model, and the memory and sans-I/O rationale.

### Fixed during pre-release validation

Eight defects, each now covered by a test that fails without the fix. Five share
a root cause worth naming: **two ECUs frequently have transfers open in both
directions at once**, and the code assumed any connection-management frame from a
peer belonged to the transfer in hand.

- `Reassembler` tore down a receive session on an abort naming a *different*
  parameter group — that is, the peer aborting the transfer it was sending.
- `Transmitter::on_tp_cm` let a peer's CTS, acknowledgement, or abort for another
  parameter group grant, complete, or tear down an unrelated transfer.
- `Node` answered a *globally addressed* RTS with a CTS. An RTS is
  destination-specific by definition; one malformed frame would have made every
  ECU on the bus emit a CTS at once and hold a session slot until `T1`.
- `Ecu::send_to(Address::GLOBAL, ..)` sent a long message as an unpaced BAM and
  then waited for a CTS that cannot come, so it also timed out. It now defers to
  `broadcast`.
- `AddressClaimer::claim` on an ECU that had given up would announce a claim
  *from* the null address and, once the window closed, leave it believing it held
  `0xFE`.
- `on_commanded_address` accepted `0xFE`/`0xFF`, leaving the ECU transmitting
  from a reserved address.
- A repeated TP.DT packet and a skipped one aborted with the same reason;
  J1939-21 distinguishes them, because they indicate different faults.
- `packet_count` wrapped to `0` above 1785 bytes — the one answer that is
  actively dangerous, since it reads as "no packets needed". It now saturates.

- **Testing** — `tools/check.sh` runs every gate and fails on the first problem.
  `core/tests/codec_sweep.rs` sweeps the whole input space where feasible: all
  262,144 PGNs, every identifier prefix, every bit-packed field value, and the
  reserved-range boundary at all 32 SPN widths. `core/tests/robustness.rs`
  asserts that arbitrary bytes cannot panic any decoder or the top-level
  dispatch. `core/tests/wire_conformance.rs` checks byte layouts against the
  Open-SAE-J1939 C reference, rebuilding its shift/mask arithmetic longhand so
  the comparison is independent rather than a round trip of our own encoder.
  `core/tests/multi_node.rs` covers several ECUs interacting: address contention
  between three nodes, transfers running in both directions at once, four peers
  broadcasting with interleaved packets, and a node relocating mid-transfer.

- **Project setup** — dual MIT/Apache-2.0 licensing, DCO-based contribution
  policy, Contributor Covenant code of conduct, issue and PR templates
  (including a licensing-provenance checkbox), and CI covering tests, lint,
  docs, `no_std`, MSRV 1.75, and an on-bus decode.

[Unreleased]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/compare/v0.2.0...v0.3.0
[0.1.0]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/releases/tag/v0.1.0

## [0.1.0] - 2026-07-31

First release to crates.io: the J1939-21 data link and transport layers,
J1939-81 network management, J1939-73 diagnostics, the J1939-71 identification
parameter groups, and a frame-level Linux SocketCAN transport.

Modules: `types`, `id`, `pgn`, `frame`, `can`, `tp`, `name`, `address_claim`,
`diagnostics`, `memory_access`, `identification`, `request`; host `transport`.

[0.2.0]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/compare/v0.1.0...v0.2.0
