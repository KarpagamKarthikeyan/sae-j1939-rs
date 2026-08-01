#!/usr/bin/env bash
#
# Every gate CI enforces, in one command. Exits non-zero on the first failure.
#
#   tools/check.sh              # the standard gates
#   tools/check.sh --full       # ...plus MSRV and a cross-target lint
#
# Run this before pushing. It is deliberately fail-fast and does not summarise
# or filter output: a check that can only report success is not a check.
set -euo pipefail

MSRV="1.75.0"
NO_STD_TARGET="thumbv7em-none-eabihf"
CROSS_TARGET="x86_64-unknown-linux-gnu"

full=0
[[ "${1:-}" == "--full" ]] && full=1

step() {
    printf '\n\033[1m==> %s\033[0m\n' "$1"
}

step "cargo fmt --all --check"
cargo fmt --all --check

step "cargo clippy (workspace, all targets, all features)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

step "cargo test (workspace, all features) — unit, integration, and doctests"
cargo test --workspace --all-features

step "cargo doc (warnings denied)"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

step "no_std build for $NO_STD_TARGET"
if rustup target list --installed | grep -qx "$NO_STD_TARGET"; then
    cargo build -p sae-j1939-rs --target "$NO_STD_TARGET"
else
    echo "SKIPPED: run 'rustup target add $NO_STD_TARGET' to enable" >&2
    exit 1
fi

if (( full )); then
    step "MSRV $MSRV"
    if rustup toolchain list | grep -q "^$MSRV"; then
        cargo "+$MSRV" test --workspace --all-features
    else
        echo "SKIPPED: run 'rustup toolchain install $MSRV' to enable" >&2
        exit 1
    fi

    # The host crate's SocketCAN transport only compiles on Linux, so on any
    # other host it is never linted unless we cross-check it explicitly.
    step "clippy + doc for $CROSS_TARGET (compiles the SocketCAN transport)"
    if rustup target list --installed | grep -qx "$CROSS_TARGET"; then
        cargo clippy --workspace --all-targets --all-features \
            --target "$CROSS_TARGET" -- -D warnings
        RUSTDOCFLAGS="-D warnings" cargo doc -p sae-j1939-host --no-deps \
            --target "$CROSS_TARGET"
    else
        echo "SKIPPED: run 'rustup target add $CROSS_TARGET' to enable" >&2
        exit 1
    fi

    step "cargo package (both crates)"
    cargo package -p sae-j1939-rs --allow-dirty --no-verify
fi

printf '\n\033[1;32mAll checks passed.\033[0m\n'
