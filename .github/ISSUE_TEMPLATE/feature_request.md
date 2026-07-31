---
name: Feature request
about: Propose a new capability or improvement
title: ""
labels: enhancement
assignees: ""
---

## What

A clear description of the feature or improvement.

## Why

The use case — what does this unblock, and for whom (embedded ECU, host
diagnostic tool, test rig)?

## Spec reference

Which part of J1939 does this implement? (J1939-21 transport, J1939-71
application layer, J1939-73 diagnostics, J1939-81 network management, or the
ISO 11783 extensions.) A PGN/SPN number is ideal.

## Where it belongs

- [ ] `no_std` core (`sae-j1939-rs`) — protocol logic
- [ ] host (`sae-j1939-host`) — transport / std tooling
- [ ] not sure (happy to discuss)

## Notes on approach

Which existing module would this extend? Any API or design considerations
(especially anything affecting `no_std`, `Copy`, or allocation — the core is
allocation-free and must stay that way)? What would the tests look like, and is
there a source of known-good frame bytes to validate against?
