# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- A broader PGN/SPN parameter database (J1939-71).
- ISO 11783 tractor/implement extensions (stretch goal).
- Session timeout helpers (J1939-21 `T1`–`T4`) for callers that want them
  prebuilt rather than driven from their own clock.

## [0.1.0] - unreleased

Initial release: the workspace, the J1939-21 data link and transport layers,
J1939-81 network management, J1939-73 diagnostics, the J1939-71 identification
parameter groups, and a SocketCAN transport.

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
    - `Reassembler<N>` — receives BAM and RTS/CTS transfers up to 1785 bytes,
      generic over the largest message it will accept so an MCU bounds its own
      memory. Oversized transfers are refused with an abort, out-of-order
      packets abort the session, and a second concurrent session is rejected.
    - `Transmitter` — drives a BAM or an RTS/CTS handshake, borrowing the
      payload so a large message costs no extra RAM.

  - `request` — the Request (`0x00EA00`) and Acknowledgement (`0x00E800`)
    parameter groups, with the four standard control bytes.

  *J1939-81 — network management*
  - `Name` — the 64-bit ECU NAME, all nine fields, each masked to its bit width.
  - `address_claim::AddressClaimer` — claim, defend, relocate, or give up an
    address; tracks which addresses are in use so an arbitrary-address-capable
    ECU can pick a free one. Handles Commanded Address.

  *J1939-73 — diagnostics*
  - `diagnostics` — DM1/DM2: `Lamps` (four lamps, status and flash status),
    `Dtc` (19-bit SPN, 5-bit FMI, occurrence count, conversion method), a
    borrowing `Message` parser, and `encode`.
  - `memory_access` — DM14 (request), DM15 (response), and DM16 (binary data
    transfer), including the 11-bit byte count split across two bytes and the
    24-bit pointer and EDC parameter fields.

  *J1939-71 — application layer*
  - `identification` — Software, ECU, and Component Identification: an iterator
    over the `*`-delimited ASCII fields the standard specifies, named accessors
    per parameter group, and encoders. Software Identification's leading count
    byte is parsed and can be checked against the fields actually present.

  *Transport-agnostic plumbing*
  - `can` — bridge to the `embedded-can` traits (`frame_from`, `j1939_id`,
    `decode`, `encode`).
  - `std` feature enabling `std::error::Error` for `Error`.

- **`sae-j1939-host` (`std` host layer)**
  - `SocketCan` — Linux SocketCAN transport: `send`, `send_frame`, `recv`
    (skipping non-J1939 traffic), and `request` for the J1939 Request PGN.
  - `SocketCan::recv_message` — returns whole J1939 messages, transparently
    reassembling multi-packet transfers and sending the CTS and end-of-message
    acknowledgements an RTS/CTS transfer needs.
  - `vcan_dump` example — decode live traffic, reassemble multi-packet
    messages, and pretty-print NAME and DM1/DM2 payloads.

- **Project setup** — dual MIT/Apache-2.0 licensing, DCO-based contribution
  policy, Contributor Covenant code of conduct, issue and PR templates
  (including a licensing-provenance checkbox), and CI covering tests, lint,
  docs, `no_std`, MSRV 1.75, and an on-bus decode.

[Unreleased]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/KarpagamKarthikeyan/sae-j1939-rs/releases/tag/v0.1.0
