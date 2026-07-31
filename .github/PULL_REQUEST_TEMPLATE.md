<!--
Thanks for contributing! Please keep PRs focused on one logical change.
See CONTRIBUTING.md for details.
-->

## What this does

Briefly describe the change and link the issue it addresses (e.g. `Closes #12`).

## Checklist

- [ ] Commits are **signed off** (DCO): `git commit -s`
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo fmt --all --check` is clean
- [ ] The core still builds `no_std`: `cargo build -p sae-j1939-rs --target thumbv7em-none-eabihf`
- [ ] New wire-format codecs assert against known-good bytes
- [ ] Public API changes are documented (doc comment; a doctest if it helps)

## Licensing

- [ ] This work is my own, and I have **not** copied from or studied the internals
      of any copyleft-licensed J1939 implementation (see
      [CONTRIBUTING.md](../CONTRIBUTING.md#licensing-hygiene--please-read))
- [ ] If derived from another source, I've named it above so the license can be
      checked

## Notes for reviewers

Anything worth calling out — design trade-offs, follow-ups, open questions.
