# sae-j1939-rs

[![CI](https://github.com/KarpagamKarthikeyan/sae-j1939-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpagamKarthikeyan/sae-j1939-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sae-j1939-rs.svg)](https://crates.io/crates/sae-j1939-rs)
[![docs.rs](https://docs.rs/sae-j1939-rs/badge.svg)](https://docs.rs/sae-j1939-rs)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

A **`no_std`-first [SAE J1939] protocol stack in Rust**, built to run unchanged
on a bare-metal ECU *and* on a host (Linux/SocketCAN).

J1939 is the CAN-based protocol behind heavy vehicles: trucks, agricultural and
construction equipment, and marine engines.

> **Status: early development (0.1).** The API will change. The J1939-21 data
> link and transport layers, J1939-81 network management, J1939-73 diagnostics,
> the J1939-71 identification groups, and the ISO 11783 valve groups are
> implemented and tested — see below.

## Why

J1939 is more than a frame format. A useful stack has to reassemble multi-packet
messages, negotiate an address with the other ECUs on the bus, and speak the
diagnostic parameter groups a service tool expects — and it has to do all of that
on a microcontroller with no allocator, as well as on a laptop.

`sae-j1939-rs` is built for both from the same source:

- **The whole protocol, not just the identifier.** The transport protocol in both
  directions, address claiming, diagnostics, and identification.
- **`no_std` and allocation-free.** The core compiles for bare metal, holds no
  hidden buffers, and lets you set both the largest message an ECU will accept
  and how many peers may be mid-transfer at once — so its memory use is a
  number you choose, not a surprise.
- **Sans-I/O.** The state machines consume and produce frames and own no clock,
  so they are deterministic and testable, and the same code runs on an MCU and
  on a host.
- **Permissively licensed.** Dual MIT/Apache-2.0, so it fits commercial and
  open-source projects alike.

## What works today

| Area | J1939 part | Status |
|------|-----------|--------|
| 29-bit identifier decode/encode (priority, EDP/DP, PF/PS, SA) | -21 | ✅ |
| PGN model with correct PDU1/PDU2 handling, well-known PGN constants | -21 | ✅ |
| Destination vs. group-extension disambiguation; ECU receive filter | -21 | ✅ |
| **Transport Protocol: BAM + RTS/CTS/EOM, receive *and* transmit, to 1785 bytes** | -21 | ✅ |
| Concurrent transfers from multiple peers; `T1` session timeouts | -21 | ✅ |
| Connection abort with the standard reason codes | -21 | ✅ |
| **Proprietary A and B** manufacturer-specific groups | -21 | ✅ |
| **NAME** (64-bit ECU identity, all nine fields) | -81 | ✅ |
| **Address claiming**: contention, defence, relocation, commanded address | -81 | ✅ |
| **DM1 / DM2**: lamp status + trouble codes (SPN/FMI/occurrence) | -73 | ✅ |
| **DM3**: clear previously active trouble codes | -73 | ✅ |
| **`Node`**: one type doing claiming, filtering, reassembly, and dispatch | — | ✅ |
| **`Ecu`**: `Node` on any `Bus` — clock, BAM pacing, RTS/CTS handshake | — | ✅ |
| Pluggable transport (`Bus` trait): SocketCAN, an adapter SDK, or a simulator | — | ✅ |
| `embedded-can` bridge + a frame-level Linux SocketCAN transport | — | ✅ |
| **Request and Acknowledgement** parameter groups | -21 | ✅ |
| **DM14/DM15/DM16**: memory read, write, and binary data transfer | -73 | ✅ |
| **Software / ECU / component identification** (`*`-delimited fields) | -71 | ✅ |
| **ISO 11783 valves**: auxiliary (×16) and general purpose, command/flow/position | ISOBUS | ✅ |
| **SPN decoding**: bit extraction, scaling, and J1939's status codes | -71 | ✅ |
| A comprehensive SPN database (only a starter catalogue today) | -71 | planned |

Everything in the core is `#![no_std]`, `#![deny(unsafe_code)]`, allocation-free,
and builds for `thumbv7em-none-eabihf`. Every codec is validated against
known-good byte sequences — see [Testing & validation](#testing--validation).

## Install

```toml
[dependencies]
sae-j1939-rs = "0.1"      # no_std core: identifiers, PGNs, transport protocol, NAME, diagnostics
sae-j1939-host = "0.1"    # std host layer: SocketCAN transport
```

The core is `no_std` by default; enable `std` for `std::error::Error` impls
(`sae-j1939-rs = { version = "0.1", features = ["std"] }`). On a microcontroller,
depend only on `sae-j1939-rs` and drive it with your HAL's [`embedded-can`]
implementation — no host crate needed. In `sae-j1939-host`, the SocketCAN
transport is compiled only on Linux. **MSRV: Rust 1.75.**

## Quickstart

### Run a whole ECU on Linux

`Ecu` is the shortest path to a working node: it owns the socket and the clock,
claims an address, reassembles multi-packet traffic, and splits long messages
across the transport protocol on the way out.

```rust
use sae_j1939_host::ecu::SocketCanEcu;
use sae_j1939_host::sae_j1939_rs::{pgn, Address, Name};

let name = Name::new().with_manufacturer_code(300).with_identity_number(4242);
let mut ecu = SocketCanEcu::open("can0", name, Address::new(0x80))?;

ecu.claim_address()?;                                  // blocks 250 ms, handles contention
ecu.request(Address::GLOBAL, pgn::ADDRESS_CLAIMED)?;   // who else is here?

loop {
    // `poll` returns None whenever the bus is quiet — drive it in a loop, not
    // `while let Some(..)`, which would stop at the first gap in traffic.
    if let Some(message) = ecu.poll()? {
        println!("{:#08x} from {:#04x}", message.pgn.as_u32(), message.source.as_u8());
    }
}

// Longer than eight bytes? It goes out over the transport protocol, paced.
let mut dm1 = [0u8; 64];
let len = diagnostics::encode(lamps, &three_faults, &mut dm1)?;   // 14 bytes
ecu.broadcast(pgn::DM1, &dm1[..len])?;
```

### ...or drive the protocol yourself

`Node` is the same logic without the I/O: `no_std`, no clock, no socket. It
filters frames by destination, claims and defends an address, routes
transport-protocol traffic to a reassembler, and answers the CTS and
end-of-message handshakes itself. Feed it frames; it tells you what to send and
what arrived.

```rust
use sae_j1939_rs::node::{Event, Node};
use sae_j1939_rs::{Address, Name};

let name = Name::new()
    .with_manufacturer_code(300)
    .with_identity_number(4242)
    .with_arbitrary_address_capable(true);

// Accept messages up to 1785 bytes from up to four peers at once.
let mut node = Node::<1785, 4>::new(name, Address::new(0x80));

bus.send(node.start())?;                  // announce ourselves

loop {
    match node.on_frame(&bus.recv()?) {
        Event::Idle => {}
        Event::Transmit(frame) => bus.send(frame)?,
        Event::Message { pgn, source, data, reply } => {
            // `data` is a whole message — multi-packet transfers are already
            // reassembled, and `reply` is the acknowledgement to send back.
            println!("{pgn:?} from {source:?}: {} bytes", data.len());
        }
    }
    node.tick(elapsed_ms, |frame| bus.send(frame).unwrap());
}
```

This is what runs on a microcontroller, and it is what `Ecu` is built from.
Everything below is the layer underneath again, for when you want only part of
it.

### Decode a frame off the bus

```rust
use sae_j1939_rs::{pgn, Address, Id, Priority};

// A DM1 (active diagnostic trouble codes) broadcast from ECU 0x80.
let id = Id::new(0x18FECA80)?;

assert_eq!(id.pgn(), pgn::DM1);
assert_eq!(id.priority(), Priority::DEFAULT);
assert_eq!(id.source_address(), Address::new(0x80));

// DM1 is a PDU2 parameter group: no destination address, every ECU processes it.
assert_eq!(id.destination_address(), None);
assert!(id.is_addressed_to(Address::new(0x27)));
```

### Address a message to one ECU

```rust
use sae_j1939_rs::{pgn, Address, Id, Priority};

// Request the Software Identification PGN from ECU 0x90.
let id = Id::from_parts(Priority::DEFAULT, pgn::REQUEST, Address::new(0x90), Address::new(0x80))?;
assert_eq!(id.as_u32(), 0x18EA9080);
```

`Id` enforces the rule that trips up most J1939 code: the PDU specific byte is a
**destination address** for PDU1 parameter groups (PF `0x00..=0xEF`) but a
**group extension that belongs to the PGN** for PDU2 (PF `0xF0..=0xFF`).
Addressing a PDU2 PGN to a specific ECU is rejected rather than silently
corrupting the PGN.

### Reassemble a multi-packet message

Anything longer than eight bytes arrives as a transport-protocol transfer. The
reassembler is generic over the largest message it will accept, so an MCU bounds
its own memory — an oversized transfer is refused with an abort rather than
overflowing a buffer.

```rust
use sae_j1939_rs::tp::{Reassembler, Rx, TpCm, TpDt};
use sae_j1939_rs::{pgn, Address};

let mut rx = Reassembler::<256>::new();          // this ECU accepts up to 256 bytes
let sender = Address::new(0x80);
// (`Reassembler::<1785, 8>` would track eight peers at once, for a host.)

rx.on_tp_cm(sender, &TpCm::bam(12, pgn::DM1)?);  // BAM: 12 bytes coming
rx.on_tp_dt(sender, &TpDt::new(1, &[1, 2, 3, 4, 5, 6, 7]));

if let Rx::Message { pgn, data, ack, .. } = rx.on_tp_dt(sender, &TpDt::new(2, &[8, 9, 10, 11, 12])) {
    assert_eq!(data, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert!(ack.is_none());                      // a BAM is never acknowledged
}
```

Sending works the same way. `Transmitter` drives either a BAM or the full
RTS/CTS handshake, borrowing the payload so a 1785-byte message costs no extra
RAM. (J1939-21 requires 50–200 ms between BAM packets; the type is sans-I/O and
owns no clock, so that pacing is yours.)

### Claim an address, and defend it

```rust
use sae_j1939_rs::address_claim::{AddressClaimer, ClaimAction, ClaimState};
use sae_j1939_rs::{Address, Name};

let name = Name::new()
    .with_manufacturer_code(300)
    .with_identity_number(100)
    .with_arbitrary_address_capable(true);

let mut ecu = AddressClaimer::new(name, Address::new(0x80));
let claim = ecu.claim();                  // broadcast this as PGN 0x00EE00
ecu.contention_window_elapsed();          // 250 ms later, uncontested
assert_eq!(ecu.state(), ClaimState::Claimed);

// Another ECU with a lower NAME wants 0x80. Ours is arbitrary-address-capable,
// so it relocates to a free address instead of dropping off the bus.
if let ClaimAction::Announce(new_claim) = ecu.on_address_claimed(Address::new(0x80), rival) {
    assert_ne!(new_claim.source, Address::new(0x80));
}
```

### Read a parameter in engineering units

A PGN tells you which message arrived; an SPN tells you which parameter sits
where inside it and how to scale it.

```rust
use sae_j1939_rs::spn::{catalogue, SpnValue};

// An Electronic Engine Controller 1 frame.
let payload = [0xFF, 0x87, 0x96, 0xE0, 0x2E, 0xFF, 0xFF, 0xFF];
assert_eq!(catalogue::ENGINE_SPEED.decode(&payload)?, SpnValue::Valid(1500.0));
```

The reason this returns an `SpnValue` rather than an `f32` is the mistake it
prevents: J1939 reserves the top of every parameter's range for status, so a
one-byte parameter reading `0xFF` means **not available** and `0xFE` means
**error**. A decoder that ignores that reports a disconnected coolant sensor as
215 °C.

```rust
assert_eq!(catalogue::ENGINE_COOLANT_TEMPERATURE.decode(&[0xFF; 8])?, SpnValue::NotAvailable);
```

The catalogue is a starter set of widely published parameters, not the full
J1939-71 database — `Spn::new` and `bit_position` let you transcribe your own
definitions straight from a datasheet's `byte.bit` notation.

### Read diagnostic trouble codes

```rust
use sae_j1939_rs::diagnostics::{Lamp, LampStatus, Message};

// A single-frame DM1: amber warning lamp on, one fault.
let dm = Message::parse(&[0x04, 0x00, 0x2B, 0x01, 0x04, 0x83, 0xFF, 0xFF])?;
assert_eq!(dm.lamps().status(Lamp::AmberWarning), LampStatus::On);

for dtc in dm.dtcs() {
    println!("SPN {} FMI {} seen {}x", dtc.spn, dtc.fmi, dtc.occurrence_count);
}
```

Two or more trouble codes overflow a CAN frame, which is exactly why DM1 needs
the transport protocol — `encode` produces the payload and `Transmitter` ships it.

### Bring your own transport

`Ecu` is generic over a two-method `Bus` trait, so it is not tied to SocketCAN or
to Linux — an adapter SDK, a simulator, a log being replayed, or a test double
all work:

```rust
use sae_j1939_host::bus::Bus;
use sae_j1939_host::sae_j1939_rs::Frame;

impl Bus for MyAdapter {
    fn send_frame(&self, frame: &Frame) -> std::io::Result<()> { /* ... */ }
    fn recv_frame(&self) -> std::io::Result<Option<Frame>> { /* None when quiet */ }
}

let mut ecu = Ecu::<_, 1785, 8>::new(MyAdapter::new()?, name, Address::new(0x80));
```

`SocketCan` is simply the implementation that ships. It is a frame layer and
nothing more — every protocol rule lives in the core, so there is only ever one
implementation of each to get right.

On a microcontroller, skip the host crate entirely: use
`sae_j1939_rs::can::{frame_from, j1939_id}` with any HAL implementing the
[`embedded-can`] traits. The protocol code is identical.

## Testing & validation

```bash
cargo test --workspace                                       # unit + integration + doc tests
cargo build -p sae-j1939-rs --target thumbv7em-none-eabihf   # confirm the core stays no_std
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- **Known-good byte vectors.** Every codec asserts against bytes derived from
  the spec layout, cross-checked with the [Open-SAE-J1939] C reference: the
  identifier tests are table-driven over frames that reference builds literally
  (Address Claimed `0x18EEFF..`, TP.CM `0x1CEC....`, Request `0x18EA....`, DM1
  `0x18FECA..`), the NAME test reproduces the reference's bit-packing field by
  field, and the TP.CM control bytes match J1939-21 exactly.

- **Exhaustive sweeps, not just examples.** `core/tests/codec_sweep.rs` walks
  the whole input space where that is feasible: all 262,144 PGNs, every
  identifier prefix, every value of every bit-packed field, and the reserved-range
  boundary at all 32 SPN field widths. Bit-packing bugs hide in the values nobody
  picks as an example, and this sweep found one the day it was written.

- **The two halves are tested against each other.** `Transmitter` drives a real
  `Reassembler` across every message size from 9 to 1785 bytes and the original
  payload comes back out; a 3-code DM1, a DM16 memory read, and an ECU
  identification each make the same round trip.

- **End-to-end sessions.** `core/tests/ecu_session.rs` drives the whole stack
  through the public API only: two ECUs claim addresses and discover each other,
  a global request makes both announce themselves, an unsupported request is
  NACKed, a three-fault DM1 crosses the bus over BAM, and a bandwidth-limited
  sender is never asked for more packets than it allowed.

- **On-bus decode (Linux, no hardware).** Watch the stack reassemble real
  traffic over a virtual CAN interface:

  ```bash
  sudo tools/vcan_setup.sh                            # bring up vcan0

  # A traffic decoder:
  cargo run -p sae-j1939-host --example vcan_dump
  # in another terminal — a 3-code DM1 spread over a BAM:
  cansend vcan0 1CECFF80#200E0002FFCAFE00
  cansend vcan0 1CEBFF80#0104002B01048364
  cansend vcan0 1CEBFF80#0200018721061FFE

  # ...an engine controller frame, decoded into rpm and percent:
  cansend vcan0 0CF00400#FF8796E02EFFFFFF

  # ...or a complete virtual ECU that claims an address and answers requests:
  cargo run -p sae-j1939-host --example vcan_ecu
  cansend vcan0 18EAFFF9#00EE00        # who is on the bus?
  cansend vcan0 18EA80F9#CAFE00        # what faults do you have?
  ```

## Design

- **`core` (`sae-j1939-rs`)** — `no_std`, allocation-free, transport-agnostic.
  Identifier and PGN codecs, the transport protocol, NAME and address claiming,
  and diagnostics. Everything is **sans-I/O**: it consumes and produces frames
  but never touches a bus and owns no clock, so the same logic runs on host and
  MCU. CAN frames flow through the [`embedded-can`] traits.
- **`host` (`sae-j1939-host`)** — `std` layer on the core. `Ecu` adds the clock
  and the message splitting a host program would otherwise write itself, over
  anything implementing the two-method `Bus` trait. The SocketCAN implementation
  of `Bus` is gated to Linux; `Ecu` itself is not, so it can be driven by a
  simulator, an adapter SDK, or a test double on any platform.

| Module | J1939 part | What it covers |
|--------|-----------|----------------|
| `id`, `pgn`, `frame` | -21 | The 29-bit identifier, parameter groups, single frames |
| `tp` | -21 | Transport protocol: BAM and RTS/CTS, up to 1785 bytes |
| `name` | -81 | The 64-bit ECU NAME |
| `address_claim` | -81 | Claiming, defending, and relocating an address |
| `request` | -21 | The Request and Acknowledgement parameter groups |
| `proprietary` | -21 | Manufacturer-specific Proprietary A and B groups |
| `iso11783` | ISOBUS | Tractor/implement auxiliary and general purpose valves |
| `node` | — | A whole ECU: claiming, reassembly, and dispatch in one type |
| `diagnostics` | -73 | DM1/DM2 trouble codes and lamp status |
| `memory_access` | -73 | DM14/DM15/DM16 memory read, write, and data transfer |
| `identification` | -71 | Software, ECU, and component identification |
| `spn` | -71 | Suspect Parameter Numbers: payload bytes to engineering units |
| `can` | — | Bridge to the `embedded-can` traits |

Note that `can` — not `transport` — holds the CAN frame bridge, because in J1939
"transport protocol" means something specific, and that is `tp`.

```
sae-j1939-rs/
├── core/   # no_std core protocol stack  (crate: sae-j1939-rs)
└── host/   # std host transport          (crate: sae-j1939-host)
```

This mirrors the split in [`canopen-rs`], its companion project for industrial
automation. Both sit on `embedded-can` and target the same physical CAN bus, so
the two transport layers are designed to converge on shared code.

## References

- The **SAE J1939** standard documents (published by SAE International) are the
  authoritative source of truth for every wire format here.
- [Open-SAE-J1939] — a thorough, MIT-licensed C implementation covering the
  transport protocol, diagnostics, network management, and ISO 11783. Studied as
  a structural reference and a source of known-good frames; not copied.

Where the two disagree, the standard wins — see the note in
`core/src/identification.rs` for one case where it did.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
workflow (DCO sign-off, local checks, the `no_std` core vs `host` split, and code
provenance). Good entry points are issues labelled
[`good first issue`](https://github.com/KarpagamKarthikeyan/sae-j1939-rs/labels/good%20first%20issue).
Questions and ideas are welcome in
[Discussions](https://github.com/KarpagamKarthikeyan/sae-j1939-rs/discussions).
Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option. Unless you explicitly state otherwise, any contribution you submit
for inclusion shall be dual-licensed as above, without additional terms.

Copyright (c) 2026 Karpagam Karthikeyan.

[SAE J1939]: https://www.sae.org/standards/development/ground-vehicle-standards/j1939
[`embedded-can`]: https://docs.rs/embedded-can
[Open-SAE-J1939]: https://github.com/DanielMartensson/Open-SAE-J1939
[`canopen-rs`]: https://github.com/KarpagamKarthikeyan/canopen-rs
