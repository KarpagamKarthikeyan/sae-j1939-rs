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

## Code provenance — please read

This project is licensed **MIT OR Apache-2.0**, and we need every line in it to
be safe to distribute under those terms. So, one rule:

> **Contribute only code you wrote yourself, or code whose license is compatible
> with MIT/Apache-2.0 — and say where it came from.**

If a change is adapted from another project, a datasheet, a vendor SDK, or
generated from a source you did not write, note that in the pull request so the
license can be checked before merging. If you are unsure whether something is
compatible, ask in the issue first; it is much easier to answer beforehand than
to untangle afterwards.

Our own references are the SAE J1939 standard documents and the MIT-licensed
[Open-SAE-J1939](https://github.com/DanielMartensson/Open-SAE-J1939) C
implementation, used for structure and for known-good frames.

## Building and testing

One command runs every gate CI enforces, and fails on the first problem:

```bash
tools/check.sh            # fmt, clippy, tests (incl. doctests), docs, no_std
tools/check.sh --full     # ...plus MSRV, a Linux cross-lint, and packaging
```

Use `--full` before opening a PR. The cross-target steps matter if you are not
on Linux: the SocketCAN transport is `cfg`-gated, so on macOS or Windows it is
never compiled, never linted, and its doc examples are never checked. `--full`
cross-compiles to catch all three.

One residual gap, since cross-compiled binaries cannot run here: a *runnable*
doctest on a Linux-only item is compile-checked but not executed locally. Mark
such examples `no_run` where you can — CI runs them natively either way.

The individual steps, if you prefer to run them piecemeal:

```bash
cargo test --workspace --all-features                         # unit + integration + doctests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo build -p sae-j1939-rs --target thumbv7em-none-eabihf    # confirm the core stays no_std
```

Note that `cargo test` covers **doctests**, and the examples in doc comments are
real assertions — a wrong number in a doc comment is a failing test, not a typo.

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

  Two things that will fail CI if you miss them:
  - **Doc examples are real tests.** A wrong number in a doc comment is a
    failing test, not a typo. `cargo test` runs them.
  - **Fully qualify intra-doc links in `//!` module docs** — write
    ``[`Bus`](crate::bus::Bus)``, not ``[`Bus`]``. Bare names resolve
    inconsistently there, and a broken link fails `cargo doc -D warnings`.
- **Signed off** — DCO (`git commit -s`).

CI enforces the test/lint/fmt/no_std/MSRV gates, so you'll get fast feedback.

## License

By contributing, you agree that your work is dual-licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at the user's option, matching
the rest of the project.
