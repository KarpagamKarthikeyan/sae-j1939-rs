# Contributing to sae-j1939-rs

Thanks for your interest — contributions of all sizes are welcome, from fixing a
typo to implementing a new protocol layer.

## Where to start

- Browse the [open issues](https://github.com/KarpagamKarthikeyan/sae-j1939-rs/issues).
  Anything labelled **`good first issue`** is scoped to be approachable without
  deep knowledge of the codebase; **`help wanted`** marks things we'd love a hand
  with.
- Have an idea that isn't filed? Please **open an issue first** so we can agree on
  the approach before you write code — it saves everyone rework.
- Questions or "how would I use this for X?" — open a
  [Discussion](https://github.com/KarpagamKarthikeyan/sae-j1939-rs/discussions);
  no need to file a formal issue.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. It's a lightweight statement that you have the right to submit
your contribution under the project's license.

**Every commit must be signed off.** Add a `Signed-off-by` line with:

```bash
git commit -s -m "your message"
```

which appends, using your `git config` name and email:

```
Signed-off-by: Your Name <you@example.com>
```

By signing off you certify the DCO. PRs whose commits aren't signed off can't be
merged. To fix an existing commit: `git commit --amend -s` (or
`git rebase --signoff` for several).

## Licensing hygiene — please read

This project is deliberately **permissively licensed (MIT OR Apache-2.0)** so that
companies can embed it in proprietary firmware. Protecting that requires one rule:

> **Do not read, port, or copy from GPL- or otherwise copyleft-licensed J1939
> implementations** when writing code for this project. In particular, do not
> study the internals of the GPL-3.0 `j1939` crate
> ([yorickdewid/J1939](https://github.com/yorickdewid/J1939)).

Our design references are the MIT-licensed
[Open-SAE-J1939](https://github.com/DanielMartensson/Open-SAE-J1939) C
implementation and the public structure of the SAE J1939 standard. If you
contribute code derived from any other source, say so in the PR so we can check
the license before merging.

## Building and testing

```bash
cargo test --workspace                                        # unit + integration + doctests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo build -p sae-j1939-rs --target thumbv7em-none-eabihf    # confirm the core stays no_std
```

On Linux you can also exercise the transport on a virtual CAN bus, no hardware
required:

```bash
sudo tools/vcan_setup.sh && cargo run -p sae-j1939-host --example vcan_dump
```

## Where code belongs

The workspace has two crates, and it matters which one your change goes in:

- **`core` (`sae-j1939-rs`)** — `#![no_std]`, allocation-free, transport-agnostic.
  All protocol logic (identifier/PGN codecs, transport protocol, network
  management, diagnostics, application-layer parameter groups) lives here. New
  protocol features almost always go here.
- **`host` (`sae-j1939-host`)** — `std`. The Linux SocketCAN transport and host
  tooling. Anything that needs `std`, an allocator, or an OS goes here (or behind
  a Cargo feature on the core).

If you're unsure, ask in the issue — "core vs host" is the most common question.

## What a good PR looks like

- **Focused** — one logical change per PR.
- **Tested** — unit tests for logic; for any wire-format codec, assert against
  **known-good byte sequences** (see `core/src/id.rs` for the style — the
  identifier tests are table-driven against frames the Open-SAE-J1939 C reference
  builds literally).
- **Clean** — `cargo fmt` and `clippy -D warnings` pass; the core still builds for
  `thumbv7em-none-eabihf`.
- **Documented** — public APIs have doc comments; a runnable doctest is a plus.
  Cite the relevant J1939 part (e.g. "J1939-21 §5.10.1") where it clarifies intent.
- **Signed off** — DCO (`git commit -s`).

CI enforces the test/lint/fmt/no_std/MSRV gates, so you'll get fast feedback.

## License

By contributing, you agree that your work is dual-licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at the user's option, matching
the rest of the project.
