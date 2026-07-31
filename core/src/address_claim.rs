// Copyright (c) 2026 Karpagam Karthikeyan
// SPDX-License-Identifier: MIT OR Apache-2.0

//! J1939-81 network management: claiming and defending an ECU address.
//!
//! J1939 addresses are not configured, they are *claimed*. On power-up an ECU
//! broadcasts an Address Claimed message (PGN `0x00EE00`) carrying its
//! [`Name`] and its desired address as the source address. If two ECUs want the
//! same address, the one with the numerically **lower** NAME keeps it. The
//! loser either moves to a different address — if its NAME says it is
//! *arbitrary address capable* — or broadcasts Cannot Claim Address from the
//! null address `0xFE` and stays off the bus.
//!
//! [`AddressClaimer`] is a sans-I/O state machine for that protocol. It also
//! keeps a map of every address it has seen claimed, so an
//! arbitrary-address-capable ECU can pick a free one without guessing.
//!
//! ```
//! use sae_j1939_rs::address_claim::{AddressClaimer, ClaimAction, ClaimState};
//! use sae_j1939_rs::{Address, Name};
//!
//! let name = Name::new().with_identity_number(100).with_manufacturer_code(300);
//! let mut ecu = AddressClaimer::new(name, Address::new(0x80));
//!
//! // Announce the claim, then wait out the 250 ms contention window.
//! let claim = ecu.claim();
//! assert_eq!(claim.source, Address::new(0x80));
//! assert_eq!(ecu.state(), ClaimState::Claiming);
//!
//! ecu.contention_window_elapsed();
//! assert_eq!(ecu.state(), ClaimState::Claimed);
//! ```
//!
//! # Timing
//!
//! J1939-81 gives a 250 ms window after a claim in which another ECU may
//! contest it. This type owns no clock — call
//! [`AddressClaimer::contention_window_elapsed`] when your timer fires.

use crate::name::Name;
use crate::types::{Address, Error, Result};

/// The first address in the self-configurable range an arbitrary-address-capable
/// ECU may move into.
pub const DYNAMIC_ADDRESS_START: u8 = 128;

/// The last address in the self-configurable range.
pub const DYNAMIC_ADDRESS_END: u8 = 247;

/// The length of a Commanded Address message: an eight-byte NAME plus the
/// commanded address.
pub const COMMANDED_ADDRESS_LEN: usize = 9;

/// Where an ECU stands in the address-claiming protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimState {
    /// No claim has been made yet.
    Idle,
    /// A claim has been broadcast; the 250 ms contention window is open.
    Claiming,
    /// The address is held and may be defended.
    Claimed,
    /// Arbitration was lost and this ECU cannot move: it must stay silent
    /// except to answer with Cannot Claim Address.
    CannotClaim,
}

/// An Address Claimed broadcast: a NAME announced from a source address.
///
/// A claim whose `source` is [`Address::NULL`] is the *Cannot Claim Address*
/// message — the same PGN, sent from `0xFE`, telling the bus this ECU has given
/// up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
    /// The address being claimed, or [`Address::NULL`] for Cannot Claim.
    pub source: Address,
    /// The NAME of the claiming ECU.
    pub name: Name,
}

impl Claim {
    /// The eight-byte payload of the Address Claimed message.
    pub const fn payload(&self) -> [u8; 8] {
        self.name.to_bytes()
    }

    /// Whether this is a Cannot Claim Address message.
    pub const fn is_cannot_claim(&self) -> bool {
        self.source.is_null()
    }
}

/// What the caller should put on the bus after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimAction {
    /// Nothing to do.
    Idle,
    /// Broadcast this Address Claimed message (PGN `0x00EE00`, destination
    /// [`Address::GLOBAL`]), using `claim.source` as the frame's source address.
    Announce(Claim),
}

/// The J1939-81 address claiming state machine for one ECU.
#[derive(Debug, Clone)]
pub struct AddressClaimer {
    name: Name,
    address: Address,
    state: ClaimState,
    /// One bit per address, set when that address has been seen claimed.
    seen: [u8; 32],
}

impl AddressClaimer {
    /// Create a claimer for `name` that will try to take `preferred`.
    pub const fn new(name: Name, preferred: Address) -> Self {
        AddressClaimer {
            name,
            address: preferred,
            state: ClaimState::Idle,
            seen: [0; 32],
        }
    }

    /// This ECU's NAME.
    pub const fn name(&self) -> Name {
        self.name
    }

    /// The address currently held or being claimed.
    ///
    /// This is [`Address::NULL`] once the ECU has given up
    /// ([`ClaimState::CannotClaim`]).
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Where this ECU stands in the protocol.
    pub const fn state(&self) -> ClaimState {
        self.state
    }

    /// Whether an address has been observed in use by another ECU.
    pub const fn is_address_taken(&self, address: Address) -> bool {
        let index = address.as_u8() as usize;
        self.seen[index / 8] & (1 << (index % 8)) != 0
    }

    /// Broadcast the initial claim.
    ///
    /// The returned [`Claim`] must be sent as PGN `0x00EE00` to
    /// [`Address::GLOBAL`]. The ECU then enters [`ClaimState::Claiming`] until
    /// [`AddressClaimer::contention_window_elapsed`] is called.
    pub fn claim(&mut self) -> Claim {
        self.state = ClaimState::Claiming;
        self.current_claim()
    }

    /// Called when the 250 ms contention window closes without a competing
    /// claim: the address is now held.
    pub fn contention_window_elapsed(&mut self) {
        if self.state == ClaimState::Claiming {
            self.state = ClaimState::Claimed;
        }
    }

    /// Handle an Address Claimed message from another ECU.
    ///
    /// Records the address as in use, and — if it collides with ours — settles
    /// the contention by comparing NAMEs.
    pub fn on_address_claimed(&mut self, source: Address, name: Name) -> ClaimAction {
        if name == self.name {
            // Our own claim echoed back by the bus.
            return ClaimAction::Idle;
        }
        if source.is_specific() {
            self.mark_seen(source);
        }
        if source != self.address || self.state == ClaimState::CannotClaim {
            return ClaimAction::Idle;
        }

        if self.name.wins_arbitration_against(name) {
            // We hold the lower NAME: defend the address by re-announcing.
            return ClaimAction::Announce(self.current_claim());
        }

        // We lost. Move if we can, otherwise go quiet.
        if self.name.arbitrary_address_capable() {
            if let Some(next) = self.next_free_address() {
                self.address = next;
                self.state = ClaimState::Claiming;
                return ClaimAction::Announce(self.current_claim());
            }
        }
        self.give_up()
    }

    /// Handle a request for the Address Claimed PGN.
    ///
    /// Every ECU must answer, including one that has given up — which replies
    /// with Cannot Claim Address.
    pub fn on_request(&mut self) -> ClaimAction {
        ClaimAction::Announce(self.current_claim())
    }

    /// Handle a Commanded Address message (PGN `0x00FED8`).
    ///
    /// The nine-byte payload is a NAME followed by the address that ECU is
    /// being told to take. Because it exceeds eight bytes it always arrives via
    /// the transport protocol — feed the reassembled bytes here.
    ///
    /// A command naming a different ECU is ignored ([`ClaimAction::Idle`]).
    ///
    /// Returns [`Error::ShortPayload`] if fewer than nine bytes are supplied.
    pub fn on_commanded_address(&mut self, data: &[u8]) -> Result<ClaimAction> {
        if data.len() < COMMANDED_ADDRESS_LEN {
            return Err(Error::ShortPayload {
                expected: COMMANDED_ADDRESS_LEN,
                actual: data.len(),
            });
        }
        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&data[..8]);
        if Name::from_bytes(&name_bytes) != self.name {
            // Addressed to a different ECU.
            return Ok(ClaimAction::Idle);
        }
        self.address = Address::new(data[8]);
        self.state = ClaimState::Claiming;
        Ok(ClaimAction::Announce(self.current_claim()))
    }

    /// Give up the address: enter [`ClaimState::CannotClaim`] and produce the
    /// Cannot Claim Address message.
    pub fn give_up(&mut self) -> ClaimAction {
        self.state = ClaimState::CannotClaim;
        self.address = Address::NULL;
        ClaimAction::Announce(Claim {
            source: Address::NULL,
            name: self.name,
        })
    }

    /// The claim this ECU would announce right now.
    fn current_claim(&self) -> Claim {
        Claim {
            source: self.address,
            name: self.name,
        }
    }

    fn mark_seen(&mut self, address: Address) {
        let index = address.as_u8() as usize;
        self.seen[index / 8] |= 1 << (index % 8);
    }

    /// The lowest address in the self-configurable range not yet seen in use.
    fn next_free_address(&self) -> Option<Address> {
        (DYNAMIC_ADDRESS_START..=DYNAMIC_ADDRESS_END)
            .map(Address::new)
            .find(|&candidate| candidate != self.address && !self.is_address_taken(candidate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_with(identity: u32) -> Name {
        Name::new()
            .with_manufacturer_code(300)
            .with_identity_number(identity)
    }

    /// A NAME that outranks everything `name_with` produces, because a lower
    /// manufacturer code dominates the identity number.
    fn stronger() -> Name {
        Name::new().with_manufacturer_code(1)
    }

    /// A NAME that loses to everything `name_with` produces.
    fn weaker() -> Name {
        Name::new().with_manufacturer_code(2000)
    }

    #[test]
    fn claims_then_holds_an_uncontested_address() {
        let mut ecu = AddressClaimer::new(name_with(100), Address::new(0x80));
        assert_eq!(ecu.state(), ClaimState::Idle);

        let claim = ecu.claim();
        assert_eq!(claim.source, Address::new(0x80));
        assert_eq!(claim.payload(), name_with(100).to_bytes());
        assert!(!claim.is_cannot_claim());
        assert_eq!(ecu.state(), ClaimState::Claiming);

        ecu.contention_window_elapsed();
        assert_eq!(ecu.state(), ClaimState::Claimed);
        assert_eq!(ecu.address(), Address::new(0x80));
    }

    #[test]
    fn ignores_claims_on_other_addresses_but_remembers_them() {
        let mut ecu = AddressClaimer::new(name_with(100), Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        assert_eq!(
            ecu.on_address_claimed(Address::new(0x90), weaker()),
            ClaimAction::Idle
        );
        assert_eq!(ecu.state(), ClaimState::Claimed);
        assert!(ecu.is_address_taken(Address::new(0x90)));
        assert!(!ecu.is_address_taken(Address::new(0x91)));
    }

    #[test]
    fn defends_its_address_against_a_higher_name() {
        let mut ecu = AddressClaimer::new(name_with(100), Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        // A competing ECU with a worse (higher) NAME wants our address.
        let action = ecu.on_address_claimed(Address::new(0x80), weaker());
        assert_eq!(
            action,
            ClaimAction::Announce(Claim {
                source: Address::new(0x80),
                name: name_with(100),
            }),
            "we must re-announce to defend the address"
        );
        assert_eq!(ecu.address(), Address::new(0x80));
        assert_eq!(ecu.state(), ClaimState::Claimed);
    }

    #[test]
    fn a_fixed_address_ecu_gives_up_when_it_loses() {
        let name = name_with(100); // not arbitrary address capable
        assert!(!name.arbitrary_address_capable());
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        let action = ecu.on_address_claimed(Address::new(0x80), stronger());
        assert_eq!(
            action,
            ClaimAction::Announce(Claim {
                source: Address::NULL,
                name,
            })
        );
        match action {
            ClaimAction::Announce(claim) => assert!(claim.is_cannot_claim()),
            other => panic!("expected an announcement, got {other:?}"),
        }
        assert_eq!(ecu.state(), ClaimState::CannotClaim);
        assert_eq!(ecu.address(), Address::NULL);
    }

    #[test]
    fn an_arbitrary_address_capable_ecu_moves_when_it_loses() {
        let name = name_with(100).with_arbitrary_address_capable(true);
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        // Someone stronger takes 0x80; we should relocate rather than give up.
        let action = ecu.on_address_claimed(Address::new(0x80), stronger());
        let ClaimAction::Announce(claim) = action else {
            panic!("expected a new claim, got {action:?}");
        };
        assert!(!claim.is_cannot_claim());
        assert_ne!(claim.source, Address::new(0x80));
        assert!(
            (DYNAMIC_ADDRESS_START..=DYNAMIC_ADDRESS_END).contains(&claim.source.as_u8()),
            "must relocate inside the self-configurable range, got {:#04x}",
            claim.source.as_u8()
        );
        assert_eq!(ecu.state(), ClaimState::Claiming);
    }

    #[test]
    fn relocation_skips_addresses_already_seen_in_use() {
        let name = name_with(100).with_arbitrary_address_capable(true);
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        // 0x80..0x82 are all taken by other ECUs.
        ecu.on_address_claimed(Address::new(0x81), weaker());
        ecu.on_address_claimed(Address::new(0x82), weaker());

        let ClaimAction::Announce(claim) = ecu.on_address_claimed(Address::new(0x80), stronger())
        else {
            panic!("expected a new claim");
        };
        // 0x80 is contested, 0x81 and 0x82 are known busy, so 0x83 is next.
        assert_eq!(claim.source, Address::new(0x83));
    }

    #[test]
    fn gives_up_when_the_whole_dynamic_range_is_occupied() {
        let name = name_with(100).with_arbitrary_address_capable(true);
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        for address in DYNAMIC_ADDRESS_START..=DYNAMIC_ADDRESS_END {
            if address != 0x80 {
                ecu.on_address_claimed(Address::new(address), weaker());
            }
        }
        let action = ecu.on_address_claimed(Address::new(0x80), stronger());
        assert_eq!(
            action,
            ClaimAction::Announce(Claim {
                source: Address::NULL,
                name,
            })
        );
        assert_eq!(ecu.state(), ClaimState::CannotClaim);
    }

    #[test]
    fn our_own_claim_echoed_back_is_not_contention() {
        let name = name_with(100);
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();
        assert_eq!(
            ecu.on_address_claimed(Address::new(0x80), name),
            ClaimAction::Idle
        );
        assert_eq!(ecu.state(), ClaimState::Claimed);
    }

    #[test]
    fn answers_a_request_even_after_giving_up() {
        let name = name_with(100);
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();
        assert_eq!(
            ecu.on_request(),
            ClaimAction::Announce(Claim {
                source: Address::new(0x80),
                name,
            })
        );

        ecu.give_up();
        assert_eq!(
            ecu.on_request(),
            ClaimAction::Announce(Claim {
                source: Address::NULL,
                name,
            })
        );
    }

    #[test]
    fn takes_a_commanded_address_meant_for_it() {
        let name = name_with(100);
        let mut ecu = AddressClaimer::new(name, Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        let mut command = [0u8; COMMANDED_ADDRESS_LEN];
        command[..8].copy_from_slice(&name.to_bytes());
        command[8] = 0x42;

        assert_eq!(
            ecu.on_commanded_address(&command).unwrap(),
            ClaimAction::Announce(Claim {
                source: Address::new(0x42),
                name,
            })
        );
        assert_eq!(ecu.address(), Address::new(0x42));
        // A new address must be re-claimed, not assumed.
        assert_eq!(ecu.state(), ClaimState::Claiming);
    }

    #[test]
    fn ignores_a_commanded_address_meant_for_another_ecu() {
        let mut ecu = AddressClaimer::new(name_with(100), Address::new(0x80));
        ecu.claim();
        ecu.contention_window_elapsed();

        let mut command = [0u8; COMMANDED_ADDRESS_LEN];
        command[..8].copy_from_slice(&name_with(999).to_bytes());
        command[8] = 0x42;

        assert_eq!(
            ecu.on_commanded_address(&command).unwrap(),
            ClaimAction::Idle
        );
        assert_eq!(ecu.address(), Address::new(0x80));
    }

    #[test]
    fn rejects_a_short_commanded_address() {
        let mut ecu = AddressClaimer::new(name_with(100), Address::new(0x80));
        assert_eq!(
            ecu.on_commanded_address(&[0u8; 8]),
            Err(Error::ShortPayload {
                expected: 9,
                actual: 8
            })
        );
    }

    /// Two ECUs contending for one address must converge: exactly one keeps it.
    #[test]
    fn two_ecus_contending_converge_on_one_winner() {
        let strong = name_with(10);
        let weak = name_with(20);
        assert!(strong.wins_arbitration_against(weak));

        let mut a = AddressClaimer::new(strong, Address::new(0x80));
        let mut b = AddressClaimer::new(weak, Address::new(0x80));

        let claim_a = a.claim();
        let claim_b = b.claim();

        // Each hears the other's claim.
        let action_a = a.on_address_claimed(claim_b.source, claim_b.name);
        let action_b = b.on_address_claimed(claim_a.source, claim_a.name);

        // The lower NAME defends; the higher one steps aside.
        assert!(matches!(action_a, ClaimAction::Announce(c) if c.source == Address::new(0x80)));
        assert!(matches!(action_b, ClaimAction::Announce(c) if c.is_cannot_claim()));

        a.contention_window_elapsed();
        assert_eq!(a.state(), ClaimState::Claimed);
        assert_eq!(a.address(), Address::new(0x80));
        assert_eq!(b.state(), ClaimState::CannotClaim);
    }
}
