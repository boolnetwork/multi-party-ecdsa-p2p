#![allow(non_snake_case)]
/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/
//!
//!
//! Using a couple of tests this module demonstrates a way that you could use the library
//! and build an actual application out of the implementation.
//! Both the Key Generation and Signing operations are divided into different stages.
//!
//! All the stages are sequential.
//! Usually the input of one stage is one of the output values of a prior stage.
//!
//! Each input and output for a stage is defined as a structure.
//! Using serde_json this could easily be made a json.
//!
//! Then each stage API basically resembles an HTTP API for a server that would be one of the
//! parties to this Distributed Key Generation or Signing Protocol.
//!
//! A note: _l or _s after many variable names in this API is to make rust_analyzer happy.
//! If We initiaize a structure using vars with names same as member names, rust analyzer complains
//! with:
//!     shorthand struct initiailization error.
//!
//! Another Note: If you set the WRITE_FILE env variable.. the tests in this file will write
//!               jsons keygen.txt and sign.txt which will contain keygen and sign json
//!               input/output pairs for all the stages.
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::*;

use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::mta::{MessageA, MessageB};
use crate::Error;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::{FE, GE};
use paillier::*;
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::DLogStatement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage1Input {
    pub index: usize, // participant indexes start from zero.
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage1Result {
    pub party_keys_l: Keys,
    pub bc_com1_l: KeyGenBroadcastMessage1,
    pub decom1_l: KeyGenDecommitMessage1,
    pub h1_h2_N_tilde_l: DLogStatement,
}
//
// As per page13 https://eprint.iacr.org/2020/540.pdf:
// This step will:
// 1. This participant will create a Commitment, Decommitment pair on a scalar
//    ui and then publish the Commitment part.
// 2. It will create a Paillier Keypair and publish the public key for that.
//
pub fn keygen_stage1(input: &KeyGenStage1Input) -> KeyGenStage1Result {
    // Paillier keys and various other values
    // party_keys.ek is a secret value and it should be encrypted
    // using a key that is owned by the participant who creates it. Right now it's plaintext but
    // this is test.
    //
    let party_keys = Keys::create(input.index);
    let (bc1, decom) =
        party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
    let h1_h2_N_tilde = bc1.dlog_statement.clone();
    KeyGenStage1Result {
        party_keys_l: party_keys,
        bc_com1_l: bc1,
        decom1_l: decom,
        h1_h2_N_tilde_l: h1_h2_N_tilde,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage2Input {
    pub index: usize,
    pub params_s: Parameters,
    pub party_keys_s: Keys,
    pub bc1_vec_s: Vec<KeyGenBroadcastMessage1>,
    pub decom1_vec_s: Vec<KeyGenDecommitMessage1>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage2Result {
    pub vss_scheme_s: VerifiableSS,
    pub secret_shares_s: Vec<FE>,
    pub index_s: usize,
}
//
// As per page 13 on https://eprint.iacr.org/2020/540.pdf:
// 1. Decommit the value obtained in stage1.
// 2. Perform a VSS on that value.

pub fn keygen_stage2(input: &KeyGenStage2Input) -> Result<KeyGenStage2Result, ErrorType> {
    let vss_result = input
        .party_keys_s
        .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
            &input.params_s,
            &input.decom1_vec_s,
            &input.bc1_vec_s,
        )?;
    let (vss_scheme, secret_shares, index) = vss_result;
    Ok(KeyGenStage2Result {
        vss_scheme_s: vss_scheme,
        secret_shares_s: secret_shares,
        index_s: index,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage3Input {
    pub party_keys_s: Keys,
    pub vss_scheme_vec_s: Vec<VerifiableSS>,
    pub secret_shares_vec_s: Vec<FE>,
    pub y_vec_s: Vec<GE>,
    pub params_s: Parameters,
    pub index_s: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage3Result {
    pub shared_keys_s: SharedKeys,
    pub dlog_proof_s: DLogProof,
}
//
// As per page 13 on https://eprint.iacr.org/2020/540.pdf:
// 1. Participant adds there private shares to obtain their final share of the keypair.
// 2. Calculate the corresponding public key for that share.
// 3. Generate the dlog proof which the orchestrator would check later.
//
// Important to note that all the stages are sequential. Unless all the messages from the previous
// stage are not delivered, you cannot jump on the next stage.

pub fn keygen_stage3(input: &KeyGenStage3Input) -> Result<KeyGenStage3Result, ErrorType> {
    let res = input
        .party_keys_s
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &input.params_s,
            &input.y_vec_s,
            &input.secret_shares_vec_s,
            &input.vss_scheme_vec_s,
            &input.index_s + 1,
        )?;
    let (shared_keys, dlog_proof) = res;
    Ok(KeyGenStage3Result {
        shared_keys_s: shared_keys,
        dlog_proof_s: dlog_proof,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage4Input {
    pub params_s: Parameters,
    pub dlog_proof_vec_s: Vec<DLogProof>,
    pub y_vec_s: Vec<GE>,
}

//
// Final stage of key generation. All parties must execute this.
// Unless this is successful the protocol is not complete.
//
pub fn keygen_stage4(input: &KeyGenStage4Input) -> Result<(), ErrorType> {
    let result = Keys::verify_dlog_proofs(&input.params_s, &input.dlog_proof_vec_s, &input.y_vec_s);
    if let Err(err) = result {
        println!("KeyGen phase 3 checks failed. {:?}", &err);
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
macro_rules! write_input {
    ($index: expr, $stage: expr, $op: expr, $json: expr) => {{
        if var_os("WRITE_FILE").is_some() {
            use std::fs::OpenOptions;
            let mut json_file = OpenOptions::new()
                .append(true)
                .open(&format!("{}.txt", $op))
                .unwrap();
            let index = $index;
            let stage = $stage;
            let op = $op;
            let json = $json;
            json_file
                .write_all(format!("Input {} stage {} index {}\n", op, stage, index).as_bytes())
                .unwrap();
            json_file
                .write_all(format!("{}\n", json).as_bytes())
                .unwrap();
        }
    }};
}
#[cfg(test)]
macro_rules! write_output {
    ($index: expr, $stage: expr, $op: expr, $json: expr) => {{
        if var_os("WRITE_FILE").is_some() {
            use std::fs::OpenOptions;
            let mut json_file = OpenOptions::new()
                .append(true)
                .open(&format!("{}.txt", $op))
                .unwrap();
            let index = $index;
            let stage = $stage;
            let op = $op;
            let json = $json;
            json_file
                .write_all(format!("Output {} stage {} index {}\n", op, stage, index).as_bytes())
                .unwrap();
            json_file
                .write_all(format!("{}\n", json).as_bytes())
                .unwrap();
        }
    }};
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPairResult {
    pub party_keys_vec: Vec<Keys>,
    pub shared_keys_vec: Vec<SharedKeys>,
    pub pk_vec: Vec<GE>,
    pub y_sum: GE,
    pub vss_scheme: VerifiableSS,
    pub e_vec: Vec<EncryptionKey>,
    pub h1_h2_N_tilde_vec: Vec<DLogStatement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage1Input {
    pub vss_scheme: VerifiableSS,
    pub index: usize,
    pub s_l: Vec<usize>,
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage1Result {
    pub sign_keys: SignKeys,
    pub party_private: PartyPrivate,
    pub bc1: SignBroadcastPhase1,
    pub decom1: SignDecommitPhase1,
    pub m_a: (MessageA, BigInt),
}
// Signing stage 1.
// A sign operation happens between t+1 parties.
// The way the protocol works needs a t,t+1 share of the secret shares for all
// the participants taking part in signing.
// It also creates all the ephemeral values required for signing namely gamma_i, w_i. Those are represented by the
// SignKeys structure.
// It also creates the C, D messages for gamma_i and encrypts k_i with the Paillier key.
// Arguments:
//  pk: Public key corresponding to the keypair
//  vss_scheme_vec: Generated during keypair generation
//  index: 0 based index for the partipant.
//  s: list of participants taking part in signing.
//  keypair_result: output of the key generation protocol.
pub fn sign_stage1(input: &SignStage1Input) -> SignStage1Result {
    //t,n to t,t for it's share.
    let l_party_private =
        PartyPrivate::set_private(input.party_keys.clone(), input.shared_keys.clone());
    //ephemeral keys. w_i, gamma_i and k_i and the curve points for the same.
    let l_sign_keys = SignKeys::create(
        &l_party_private,
        &input.vss_scheme,
        input.index,
        &input.s_l[..],
    );
    // Commitment for g^gamma_i
    let (l_bc1, l_decom1) = l_sign_keys.phase1_broadcast();
    // encryption of k_i
    let ek = input.party_keys.ek.clone();
    let l_m_a = MessageA::a(&l_sign_keys.k_i, &ek);
    SignStage1Result {
        sign_keys: l_sign_keys,
        party_private: l_party_private,
        bc1: l_bc1,
        decom1: l_decom1,
        m_a: l_m_a,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage2Input {
    pub m_a_vec: Vec<MessageA>,
    pub gamma_i: FE,
    pub w_i: FE,
    pub ek_vec: Vec<EncryptionKey>,
    pub index: usize,
    pub l_ttag: usize,
    pub l_s: Vec<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage2Result {
    pub gamma_i_vec: Vec<(MessageB, FE, BigInt, BigInt)>,   // TODO: phase5 blame
    pub w_i_vec: Vec<(MessageB, FE)>,
}
// This API will carry our the MtA for gamma_i MtAwc(Check happens later in stage3) for w_i
// This is basically a P2P between a participant and all it's peers.
pub fn sign_stage2(input: &SignStage2Input) -> Result<SignStage2Result, ErrorType> {
    let mut res_gamma_i = vec![];
    let mut res_w_i = vec![];
    for j in 0..input.l_ttag - 1 {
        let ind = if j < input.index { j } else { j + 1 };
        let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) = MessageB::b(
            &input.gamma_i,
            &input.ek_vec[input.l_s[ind]],
            input.m_a_vec[ind].clone(),
        );
        // beta_gamma is  secret value and needs to be encrypted with a key only know to party ind.
        // See gg20_sign_client.rs for a demo of how this value is encrypted using a key shared
        // between party input.index and party ind.
        res_gamma_i.push((m_b_gamma, beta_gamma, beta_randomness, beta_tag));
        let (m_b_w, beta_wi, _beta_randomness, _beta_tag) = MessageB::b(
            &input.w_i,
            &input.ek_vec[input.l_s[ind]],
            input.m_a_vec[ind].clone(),
        );
        // beta_wi is  secret value and needs to be encrypted with a key only know to party ind.
        // See gg20_sign_client.rs for a demo of how this value is encrypted using a key shared
        // between party input.index and party ind.
        res_w_i.push((m_b_w, beta_wi));
    }
    Ok(SignStage2Result {
        gamma_i_vec: res_gamma_i,
        w_i_vec: res_w_i,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage3Result {
    pub alpha_vec_gamma: Vec<FE>,
    pub alpha_vec_w: Vec<(FE, BigInt)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage3Input {
    pub dk_s: DecryptionKey,
    pub k_i_s: FE,
    pub m_b_gamma_s: Vec<MessageB>,
    pub m_b_w_s: Vec<MessageB>,
    pub g_w_i_s: Vec<GE>,
    pub index_s: usize,
    pub ttag_s: usize,
}
pub fn sign_stage3(input: &SignStage3Input) -> Result<SignStage3Result, ErrorType> {
    let mut res_alpha_vec_gamma = vec![];
    let mut res_alpha_vec_w = vec![];
    for i in 0..input.ttag_s - 1 {
        let ind = if i < input.index_s { i } else { i + 1 };
        let res = input.m_b_gamma_s[i].verify_proofs_get_alpha(&input.dk_s, &input.k_i_s);
        if let Err(err) = res {
            return Err(ErrorType {
                error_type: format!("{:?}", err),
                bad_actors: vec![i],
            });
        }
        let res = res.unwrap();
        res_alpha_vec_gamma.push(res.0);
        let res = input.m_b_w_s[i].verify_proofs_get_alpha(&input.dk_s, &input.k_i_s);
        if let Err(err) = res {
            return Err(ErrorType {
                error_type: format!("{:?}", err),
                bad_actors: vec![i],
            });
        }
        let res = res.unwrap();
        if input.g_w_i_s[ind] != input.m_b_w_s[i].b_proof.pk {
            // println!("MtAwc did not work i = {} ind ={}", i, ind);
            // return Err(Error::InvalidCom);  // TODO
            return Err(ErrorType {
                error_type: format!("Error Type: {:?}, MtAwc did not work i = {} ind ={}",
                    Error::InvalidCom, i, ind),
                bad_actors: vec![i],
            });
        }
        res_alpha_vec_w.push(res);
    }
    Ok(SignStage3Result {
        alpha_vec_gamma: res_alpha_vec_gamma,
        alpha_vec_w: res_alpha_vec_w,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage4Result {
    pub delta_i: FE,
    pub sigma_i: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage4Input {
    pub alpha_vec_s: Vec<FE>,
    pub beta_vec_s: Vec<FE>,
    pub miu_vec_s: Vec<FE>,
    pub ni_vec_s: Vec<FE>,
    pub sign_keys_s: SignKeys,
}
pub fn sign_stage4(input: &SignStage4Input) -> Result<SignStage4Result, ErrorType> {
    Ok(SignStage4Result {
        delta_i: input
            .sign_keys_s
            .phase2_delta_i(&input.alpha_vec_s[..], &input.beta_vec_s[..]),
        sigma_i: input
            .sign_keys_s
            .phase2_sigma_i(&input.miu_vec_s[..], &input.ni_vec_s[..]),
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage5Input {
    pub m_b_gamma_vec: Vec<MessageB>,
    pub delta_inv: FE,
    pub decom_vec1: Vec<SignDecommitPhase1>,
    pub bc1_vec: Vec<SignBroadcastPhase1>,
    pub index: usize,
    pub sign_keys: SignKeys,
    pub s_ttag: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage5Result {
    pub R: GE,
    pub R_dash: GE,
}
pub fn sign_stage5(input: &SignStage5Input) -> Result<SignStage5Result, ErrorType> {
    let b_proof_vec = (0..input.s_ttag - 1)
        .map(|j| &input.m_b_gamma_vec[j].b_proof)
        .collect::<Vec<&DLogProof>>();
    let check_Rvec_i = SignKeys::phase4(
        &input.delta_inv,
        &b_proof_vec,
        input.decom_vec1.clone(),
        &input.bc1_vec,
        input.index,
    );  // return R
    if let Err(err) = check_Rvec_i {
        println!("Error->{:?}", &err);
        return Err(err);    // TODO
    }

    let Rvec_i = check_Rvec_i.unwrap();
    let Rdash_vec_i = Rvec_i * input.sign_keys.k_i;
    Ok(SignStage5Result {
        R: Rvec_i,
        R_dash: Rdash_vec_i,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage6Input {
    pub R: GE,
    pub sigma_i: FE,
    pub T_i: GE,
    pub l_i: FE,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage6Result {
    pub S_i: GE,
    pub proof: HomoELGamalProof,
}
pub fn sign_stage6(input: &SignStage6Input) -> Result<SignStage6Result, ErrorType> {
    let (S, proof) = LocalSignature::
        phase6_compute_S_i_and_proof_of_consistency(
            &input.R, 
            &input.T_i, 
            &input.sigma_i, 
            &input.l_i
        );
    Ok(SignStage6Result {
            S_i: S,
            proof: proof,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage7Input {
    pub R_dash_vec: Vec<GE>,
    pub R: GE,
    pub m_a: MessageA,
    pub randomness: BigInt,
    pub e_k: EncryptionKey,
    pub k_i: FE,
    pub party_keys: Keys,
    pub h1_h2_N_tilde_vec: Vec<DLogStatement>,
    pub s: Vec<usize>,
    pub index: usize,
    pub sign_key: SignKeys,
    pub message_bn: BigInt,
    pub sigma: FE,
    pub ysum: GE,
    // TODO: for phase 6 check
    pub S_vec: Vec<GE>,
    pub homo_elgamal_proof_vec: Vec<HomoELGamalProof>,
    pub R_vec: Vec<GE>,
    pub T_vec: Vec<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage7Result {
    pub local_sig: LocalSignature,
}
pub fn sign_stage7(input: &SignStage7Input) -> Result<SignStage7Result, ErrorType> {
    let mut proof_vec = vec![];
    for j in 0..input.s.len() - 1 {
        let ind = if j < input.index { j } else { j + 1 };
        let proof = LocalSignature::phase5_proof_pdl(
            &input.R_dash_vec[input.index],
            &input.R,
            &input.m_a.c,
            &input.e_k,
            &input.k_i,
            &input.randomness,
            &input.party_keys,
            &input.h1_h2_N_tilde_vec[input.s[ind]],
        );

        proof_vec.push(proof);
    }
    let phase5_verify_zk = LocalSignature::phase5_verify_pdl(
        &proof_vec,
        &input.R_dash_vec[input.index],
        &input.R,
        &input.m_a.c,
        &input.e_k,
        &input.h1_h2_N_tilde_vec[..],
        &input.s,
        input.index,
    );
    if phase5_verify_zk.is_err() {
        return Err(phase5_verify_zk.err().unwrap());
    }

    let phase5_check = LocalSignature::phase5_check_R_dash_sum(&input.R_dash_vec);
    if phase5_check.is_err() {
        return Err(ErrorType {
            // TODO: blame
            error_type: format!("phase5 R_dash_sum check failed {:?}", phase5_check),
            bad_actors: vec![],
        });
    }
    // TODO: phase 6 check
    let phase6_verify_zk = LocalSignature::phase6_verify_proof(
        &input.S_vec, 
        &input.homo_elgamal_proof_vec, 
        &input.R_vec, 
        &input.T_vec
    );
    if phase6_verify_zk.is_err() {
        return Err(phase5_verify_zk.err().unwrap());
    }

    let phase6_check = LocalSignature::phase6_check_S_i_sum(&input.ysum, &input.S_vec);
    if phase6_check.is_err() {
        // TODO: blame
        return Err(ErrorType {
            error_type: format!("phase6 S_i sum check failed {:?}", phase6_check),
            bad_actors: vec![],
        });
    }

    Ok(SignStage7Result {
        local_sig: LocalSignature::phase7_local_sig(
            &input.sign_key.k_i,
            &input.message_bn,
            &input.R,
            &input.sigma,
            &input.ysum,
        ),
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage8Input {
    pub local_sig_vec: Vec<LocalSignature>,
    pub ysum: GE,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage8Result {
    pub local_sig: SignatureRecid,
}
pub fn sign_stage8(input: &SignStage8Input) -> Result<SignStage8Result, ErrorType> {
    let s_vec: Vec<FE> = input.local_sig_vec.iter().map(|a| a.s_i).collect();
    let res_sig = input.local_sig_vec[0].output_signature(&s_vec[1..]);
    if res_sig.is_err() {
        // TODO: blame
        println!("error in combining sigs {:?}", res_sig.unwrap_err());
        return Err(ErrorType {
            error_type: "error in combining signatures".to_string(),
            bad_actors: vec![],
        });
    }
    let sig: SignatureRecid = res_sig.unwrap();
    input
        .local_sig_vec
        .iter()
        .for_each(|a| check_sig(&sig.r, &sig.s, &a.m, &input.ysum));

    Ok(SignStage8Result { local_sig: sig })
}
pub fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_vec(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let slice = pk.pk_to_key_slice();
    let mut raw_pk = Vec::new();
    if slice.len() != 65 {
        // after curv's pk_to_key_slice return 65 bytes, this can be removed
        raw_pk.insert(0, 4u8);
        raw_pk.extend(vec![0u8; 64 - slice.len()]);
        raw_pk.extend(slice);
    } else {
        raw_pk.extend(slice);
    }

    assert_eq!(raw_pk.len(), 65);

    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}
