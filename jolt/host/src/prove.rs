use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use frost_core::{storage, FrostPayload, ProofOutputs};
use guest::{
    analyze_frost_aggregate, build_prover_frost_aggregate, build_verifier_frost_aggregate,
    compile_frost_aggregate, preprocess_prover_frost_aggregate, preprocess_shared_frost_aggregate,
    preprocess_verifier_frost_aggregate,
};
use jolt::PrivateInput;
use tiny_keccak::{Hasher, Keccak};

const GUEST_TARGET_DIR: &str = "/tmp/jolt-frost-guest-targets";

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProofType {
    Core,
    Compressed,
    Groth16,
}

pub fn run(message: String, _proof_type: ProofType, execute_only: bool) -> Result<()> {
    let pubkey_package = storage::load_pubkey_package()
        .context("loading group public-key package; run `setup` first")?;

    let collected =
        storage::collect_signers().context("scanning state directory for signature shares")?;
    if collected.is_empty() {
        return Err(anyhow!(
            "no signature shares found on disk; run `commit` and `sign` for each participant first"
        ));
    }

    let signer_ids: Vec<u16> = collected.iter().map(|(id, ..)| *id).collect();
    let (commitments, signature_shares): (BTreeMap<_, _>, BTreeMap<_, _>) = collected
        .into_iter()
        .map(|(_, ident, c, s)| ((ident, c), (ident, s)))
        .unzip();
    let payload = FrostPayload {
        message: message.as_bytes().to_vec(),
        pubkey_package,
        commitments,
        signature_shares,
    };

    println!("payload: {} signers {signer_ids:?}", signer_ids.len(),);

    if execute_only {
        let summary = analyze_frost_aggregate(PrivateInput::new(payload));
        println!("cycles: {}", summary.trace_len());
        return Ok(());
    }

    let mut program = compile_frost_aggregate(GUEST_TARGET_DIR);
    let shared =
        preprocess_shared_frost_aggregate(&mut program).context("Jolt preprocess_shared failed")?;
    let prover_preprocessing = preprocess_prover_frost_aggregate(shared.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let blindfold_setup = prover_preprocessing.blindfold_setup();
    let verifier_preprocessing =
        preprocess_verifier_frost_aggregate(shared, verifier_setup, Some(blindfold_setup));

    let prove = build_prover_frost_aggregate(program, prover_preprocessing);
    let verify = build_verifier_frost_aggregate(verifier_preprocessing);

    let (guest_out, proof, program_io) = prove(PrivateInput::new(payload));
    let is_valid = verify(guest_out.clone(), program_io.panic, proof);
    if !is_valid {
        bail!("Jolt verify() rejected the freshly generated proof");
    }

    let outputs = ProofOutputs::from_bytes(&guest_out)
        .map_err(|e| anyhow!("invalid public output from guest: {e}"))?;

    let msg_hash = {
        let mut h = Keccak::v256();
        h.update(message.as_bytes());
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    };

    if outputs.message_hash != msg_hash {
        return Err(anyhow!(
            "message hash in proof does not match expected hash of `{message}`"
        ));
    }

    println!(
        "\nmessage    {message:?}\nmsg_hash   0x{}\ngroup_pk   0x{}\nsignature  0x{}",
        hex::encode(outputs.message_hash),
        hex::encode(outputs.group_pubkey),
        hex::encode(outputs.signature),
    );
    Ok(())
}
