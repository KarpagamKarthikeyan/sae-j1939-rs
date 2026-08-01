# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- A comprehensive SPN database. The decoding machinery and a starter catalogue
  ship in 0.1; how a full parameter list should be carried in a `no_std` crate
  is still open (feature-gated static, build-time generation, or a companion
  crate).
- More of ISO 11783 beyond the valve groups (task controller, virtual terminal).

## [0.1.0] - unreleased

Initial release: the workspace, the J1939-21 data link and transport layers,
J1939-81 network management, J1939-73 diagnostics, the J1939-71 identification
parameter groups, the ISO 11783 valve groups, and a SocketCAN transport.

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
  - `Frame::from_payload` — infallible constructor for the common case of a full
    eight-byte parameter group.

  *Transport-agnostic plumbing*
  - `can` — bridge to the `embedded-can` traits (`frame_from`, `j1939_id`,
    `decode`, `encode`).
  - `std` feature enabling `std::error::Error` for `Error`.

- **`sae-j1939-host` (`std` host layer)**
  - `SocketCan` — Linux SocketCAN transport: `send`, `send_frame`, `recv`
    (skipping non-J1939 traffic), and `request` for the J1939 Request PGN.
  - `SocketCan::recv_message` — returns whole J1939 messages, transparently
    reassembling multi-packet transfers from up to eight peers at once and
    sending the CTS and end-of-message acknowledgements an RTS/CTS transfer
    needs. `transfers_in_flight` and `abandon_transfer` expose the reassembly
    state.
  - `vcan_dump` example — decode live traffic, reassemble multi-packet
    messages, and pretty-print NAME, DM1/DM2, and engine parameters in
    engineering units.
  - `vcan_ecu` example — a complete virtual ECU built on `Node`: claims an
    address, answers requests, and reports three trouble codes over a BAM.

- **Project setup** — dual MIT/Apache-2.0 licensing, DCO-based contribution
  policy, Contributor Covenant code of conduct, issue and PR templates
  (including a licensing-provenance checkbox), and CI covering tests, lint,
  docs, `no_std`, MSRV 1.75, and an on-bus decode.

[Unreleased]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/releases/tag/v0.1.0
