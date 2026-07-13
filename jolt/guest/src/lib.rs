#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use frost_core::{FrostPayload, ProofOutputs, SIGNATURE_LEN, VERIFYING_KEY_LEN};
use frost_ed25519 as frost;
use jolt::PrivateInput;
use tiny_keccak::{Hasher, Keccak};

#[jolt::provable(
    stack_size = 131072,
    heap_size = 33554432,
    max_input_size = 0,
    max_untrusted_advice_size = 131072,
    max_output_size = 4096,
    max_trace_length = 16777216
)]
pub fn frost_aggregate(payload: PrivateInput<FrostPayload>) -> Vec<u8> {
    let FrostPayload {
        message,
        pubkey_package,
        commitments,
        signature_shares,
    } = (*payload).clone();

    let signing_package = frost::SigningPackage::new(commitments, &message);
    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .unwrap_or_else(|e| {
            panic!(
                "guest: FROST aggregate failed: {e} (culprits: {:?})",
                e.culprits()
            )
        });
    let verifying_key = pubkey_package.verifying_key();

    let message_hash = {
        let mut h = Keccak::v256();
        h.update(&message);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    };

    let group_pubkey: [u8; VERIFYING_KEY_LEN] = verifying_key
        .serialize()
        .expect("guest: serialize verifying key")
        .try_into()
        .expect("guest: verifying key wrong length");

    let signature_bytes: [u8; SIGNATURE_LEN] = signature
        .serialize()
        .expect("guest: serialize aggregated signature")
        .try_into()
        .expect("guest: signature wrong length");

    ProofOutputs {
        message_hash,
        group_pubkey,
        signature: signature_bytes,
    }
    .to_bytes()
    .to_vec()
}
