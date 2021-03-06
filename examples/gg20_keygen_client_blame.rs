#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate_blame::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters, SharedKeys,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use paillier::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{env, fs, time};
use zk_paillier::zkproofs::DLogStatement;

mod common;
use common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params,
    PartySignup, AEAD,
};

impl From<Params> for Parameters {
    fn from(item: Params) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}

fn main() -> Result<(), ErrorType> {
    if env::args().nth(3).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(2).is_none() {
        panic!("too few arguments")
    }

    let params: Parameters = serde_json::from_str::<Params>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    )
    .unwrap()
    .into();

    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let delay = time::Duration::from_millis(25);
    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };

    // res_stage1 = { party_key, bc_com1_l, decom1_l, h1_h2_N_tilde_l }
    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);

    // phase 1: broadcast commmitment KGC_i
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        uuid.clone()
    )
    .is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round1",
        uuid.clone(),
    );

    // public information: the vector contains KGC_i
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    // insert my commitment
    bc1_vec.insert(party_num_int as usize - 1, res_stage1.bc_com1_l);

    // Phase 2: broadcast decommitment KGD_i
    assert!(broadcast(
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round2",
        uuid.clone(),
    );
    // public information: the vector contains KGD_i
    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    decom1_vec.insert(party_num_int as usize - 1, res_stage1.decom1_l);

    let input_stage2 = KeyGenStage2Input {
        index: (party_num_int - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };
    // Probable aborts: 1. Paillier cryptosystem key's consistency
    //                  2. Consistency between Commitment KGC_i and Decommitment KGD_i
    //                  3. Composite discrete log proof validity
    // Doing Feldman-VSS of u_i => { secret share of u_i, corresponding vss-scheme to verify the secret share }
    // let res_stage2 = keygen_stage2(&input_stage2).expect("keygen stage 2 failed.");

    // TODO: key generation blame
    let res_stage2 = keygen_stage2(&input_stage2)?;

    // point_vec: to memory y_i of each party
    // enc_keys: the symmetric encryption key use to send Feldman-VSS secret share in broadcast channel
    let mut point_vec: Vec<GE> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for i in 1..=params.share_count {
        point_vec.push(decom1_vec[(i - 1) as usize].y_i);
        if i != party_num_int {
            enc_keys.push(
                (decom1_vec[(i - 1) as usize].y_i.clone() * res_stage1.party_keys_l.u_i) // y_j * u_i = g^{u_i·u_j} as aes encryption key  
                    .x_coor()
                    .unwrap(),
            );
        }
    }

    // generate the public key {y_sum=\sum y_i} of signature
    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    // P_i sends secret share to P_j
    // using corresponding aes encryption key between P_i and P_j to encrypt 
    // the secret share
    let mut j = 0;
    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let plaintext = BigInt::to_vec(&res_stage2.secret_shares_s[k].to_big_int());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext);
            // This client does not implement the identifiable abort protocol.
            // If it were these secret shares would need to be broadcasted to indetify the
            // malicious party.
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
            .is_ok());
            j += 1;
        }
    }
    // P_i get encrypted secret share from P_j
    // get shares from other parties.
    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round3",
        uuid.clone(),
    );

    // P_i using corresponding aes encryption key between P_i and P_j
    // to decrypt the ciphertext from P_j to get secret share
    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_vec(&enc_keys[j]);   // y_j * u_i
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round4",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            vss_scheme_vec.push(res_stage2.vss_scheme_s.clone());
        } else {
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }
    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l.clone(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        secret_shares_vec_s: party_shares,
        y_vec_s: point_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        params_s: params.clone(),
    };
    // 1. Verify the correctness of each VSS secret share
    // 2. Generate y and x_i for each party
    // 3. Generate discrete log proof of x_i
    // TODO: key generation blame
    // let res_stage3 = keygen_stage3(&input_stage3).expect("stage 3 keygen failed.");
    
    let res_stage3 = keygen_stage3(&input_stage3)?;

    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            dlog_proof_vec.push(res_stage3.dlog_proof_s.clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec.clone(),
        y_vec_s: point_vec.clone(),
    };
    // Verify other parties' discrete log proof of their x_i
    // TODO: key generation blame
    // let _ = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");

    let _ = keygen_stage4(&input_stage4)?;

    //save key to file:
    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();
    let party_key_pair = PartyKeyPair {
        party_keys_s: res_stage1.party_keys_l.clone(),
        shared_keys: res_stage3.shared_keys_s.clone(),
        party_num_int_s: party_num_int,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde_vec_s: h1_h2_N_tilde_vec,
    };
    fs::write(
        &env::args().nth(2).unwrap(),
        serde_json::to_string(&party_key_pair).unwrap(),
    )
    .expect("Unable to save !");

    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde_vec_s: Vec<DLogStatement>,
}
pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-keygen".to_string();

    let res_body = postb(&client, "signupkeygen", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
