---
name: Bug report
about: Report incorrect behaviour in sae-j1939-rs
title: ""
labels: bug
assignees: ""
---

## Summary

A clear, one-sentence description of the bug.

## Target

- [ ] `no_std` core (`sae-j1939-rs`)
- [ ] host (`sae-j1939-host` — SocketCAN)
- Which crate version? (e.g. `0.1.0`)
- If relevant: Rust version, target triple, OS.

## Steps to reproduce

1. …
2. …

A minimal code snippet or, ideally, a failing test is the fastest path to a fix.

## Expected behaviour

What you expected to happen — cite the relevant J1939 part (e.g. J1939-21
transport protocol, J1939-81 address claiming) if it's a spec conformance issue.

## Actual behaviour

What actually happened. For a wire-format issue, include the **exact 29-bit CAN
identifier and payload bytes** involved (e.g. `18FECA80#0000000000000000`), plus
any panic or error output.

## Additional context

Anything else that might help — a `candump` capture, the ECU or tool on the other
end of the bus, etc.
