//! Transaction-scope validity policy for the swap relay directory, the chain
//! relays list themselves on for takers to find.
//!
//! One key, `relay/<a>`: `<a>` is an account address, and `<a>` must sign,
//! so only an account writes or deletes its own key. Its value is the
//! relay's `https://` base URL, which means nothing else to the chain: a
//! reader skips a value that is not one.
//!
//! Writes may be free, and what they store every node keeps for good, so a
//! key is at most `MAX_KEY_BYTES` and a value written at most
//! `MAX_VALUE_BYTES`.
//!
//! Coin actions pass untouched.
#![cfg_attr(not(test), no_std)]

use lattice_policy_rules::{is_address, transaction_body, Body};

lattice_policy_rules::lattice_policy_abi!(crate::validate);

pub const MAX_KEY_BYTES: usize = 512;
pub const MAX_VALUE_BYTES: usize = 16 * 1024;

/// The verdict for one policy context, with `scratch` for the signer tree.
/// Anything malformed is a rejection.
pub fn validate(context: &[u8], scratch: &mut [u32]) -> bool {
    transaction_body(context)
        .and_then(|body| check_body(body, scratch))
        .is_some()
}

fn check_body(bytes: &[u8], scratch: &mut [u32]) -> Option<()> {
    let body = Body::parse(bytes)?;
    let signers = body.signers(scratch)?;
    for action in body.actions()? {
        let action = action?;
        if action.key.len() > MAX_KEY_BYTES
            || action
                .new_value
                .is_some_and(|value| value.len() > MAX_VALUE_BYTES)
        {
            return None;
        }
        let account = action.key.strip_prefix(b"relay/")?;
        is_address(account).then_some(())?;
        signers.is_signer(account)?;
    }
    Some(())
}

#[cfg(test)]
mod tests;
