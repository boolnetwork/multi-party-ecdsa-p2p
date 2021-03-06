#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate_blame::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    Keys, LocalSignature, Parameters, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::blame::{
    GlobalStatePhase5, GlobalStatePhase6, GlobalStatePhase7, LocalStatePhase5, LocalStatePhase6,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use multi_party_ecdsa::Error::{self};
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParamsFile {
    pub parties: String,
    pub threshold: String,
}

impl From<ParamsFile> for Parameters {
    fn from(item: ParamsFile) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
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
    let key = "signup-sign".to_string();

    let res_body = postb(&client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
#[allow(clippy::cognitive_complexity)]
fn main() -> Result<(), ErrorType> {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }
    let message_str = env::args().nth(3).unwrap_or_else(|| "".to_string());
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let client = Client::new();
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let keypair: PartyKeyPair = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round0",
        uuid.clone(),
    );

    let mut j = 0;
    //0 indexed vec containing ids of the signing parties.
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == party_num_int {
            signers_vec.push((keypair.party_num_int_s - 1) as usize);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j += 1;
        }
    }

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[(party_num_int - 1) as usize]].clone(),
        index: signers_vec[(party_num_int - 1) as usize],
        s_l: signers_vec.clone(),
        party_keys: keypair.party_keys_s.clone(),
        shared_keys: keypair.shared_keys,
    };

    // generate { sign_keys: {w_i, g_w_i, k_i, gamma_i, g_gamma_i},
    //            private_secret: {u_i, x_i, dk}, C_i, D_i,
    //            message c_A from P_i to P_j to do MtAwc }
    let res_stage1 = sign_stage1(&input_stage1);
    // publish message A  and Commitment and then gather responses from other parties.
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&(
            res_stage1.bc1.clone(),
            res_stage1.m_a.0.clone(),
            res_stage1.sign_keys.g_w_i
        ))
        .unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut g_w_i_vec: Vec<GE> = vec![];

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(res_stage1.bc1.clone());
            g_w_i_vec.push(res_stage1.sign_keys.g_w_i.clone());
            m_a_vec.push(res_stage1.m_a.0.clone());
        } else {
            let (bc1_j, m_a_party_j, g_w_i): (SignBroadcastPhase1, MessageA, GE) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            g_w_i_vec.push(g_w_i);
            m_a_vec.push(m_a_party_j);

            j += 1;
        }
    }
    // generate aes encryption key between P_i and P_j
    // encryption key is (g^{w_j})^{w_i} = g^{w_i·w_j}
    let mut enc_key: Vec<Vec<u8>> = vec![];
    for (i, k) in signers_vec.iter().enumerate() {
        if *k != (party_num_int - 1) as usize {
            enc_key.push(BigInt::to_vec(
                &(g_w_i_vec[i as usize] * res_stage1.sign_keys.w_i.clone())
                    .x_coor()
                    .unwrap(),
            ));
        }
    }
    assert_eq!(signers_vec.len() - 1, enc_key.len());
    assert_eq!(signers_vec.len(), bc1_vec.len());

    let input_stage2 = SignStage2Input {
        m_a_vec: m_a_vec.clone(),
        gamma_i: res_stage1.sign_keys.gamma_i.clone(),
        w_i: res_stage1.sign_keys.w_i.clone(),
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    // generate message B for P_j to P_i in MtAwc :{ proof of b/beta_tag, and c_B, which called as gamma_i or w_i }
    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate there alpha values.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let beta_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage2.gamma_i_vec[j].1.to_big_int()),
            );
            let ni_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage2.w_i_vec[j].1.to_big_int()),
            );

            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(
                    res_stage2.gamma_i_vec[j].0.clone(),
                    beta_enc,
                    res_stage2.w_i_vec[j].0.clone(),
                    ni_enc,
                    // TODO: phase 5 blame
                    res_stage2.gamma_i_vec[j].2.clone(),
                    res_stage2.gamma_i_vec[j].3.clone(),
                ))
                .unwrap(),
                uuid.clone()
            )
            .is_ok());
            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    // Will store the decrypted values received from other parties.
    let mut beta_vec: Vec<FE> = vec![];
    let mut ni_vec: Vec<FE> = vec![];

    // TODO: phase 5 blame 
    let mut beta_randomness_vec = vec![];
    let mut beta_tag_vec = vec![];

    for i in 0..THRESHOLD {
        let (l_mb_gamma, l_enc_beta, l_mb_w, l_enc_ni, l_beta_randomness, l_beta_tag): 
            (MessageB, AEAD, MessageB, AEAD, BigInt, BigInt) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
        
        // TODO: phase 5 blame
        beta_randomness_vec.push(l_beta_randomness);
        beta_tag_vec.push(l_beta_tag);

        let out = aes_decrypt(&enc_key[i as usize], l_enc_beta);
        let bn = BigInt::from(&out[..]);
        beta_vec.push(ECScalar::from(&bn));

        let out = aes_decrypt(&enc_key[i as usize], l_enc_ni);
        let bn = BigInt::from(&out[..]);
        ni_vec.push(ECScalar::from(&bn));
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i.clone(),
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        m_b_w_s: m_b_w_rec_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: g_w_i_vec.clone(),
    };

    // P_i verify the proof of c_B send from P_j to P_i
    // encrypted the value of alpha or miu, which equals k_i·gamma_i(w_i)+beta'_ij(nu'_ij)
    // and send back to P_j
    // let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");

    // TODO: error handling
    let res_stage3 = sign_stage3(&input_stage3)?;

    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let alpha_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage3.alpha_vec_gamma[j].to_big_int()),
            );
            let miu_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage3.alpha_vec_w[j].0.to_big_int()),
            );

            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&(alpha_enc, miu_enc)).unwrap(),
                uuid.clone()
            )
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round3",
        uuid.clone(),
    );
    let mut alpha_vec = vec![];
    let mut miu_vec = vec![];
    for i in 0..THRESHOLD {
        let (l_alpha_enc, l_miu_enc): (AEAD, AEAD) =
            serde_json::from_str(&round3_ans_vec[i as usize]).unwrap();
        let out = aes_decrypt(&enc_key[i as usize], l_alpha_enc);
        let bn = BigInt::from(&out[..]);
        alpha_vec.push(ECScalar::from(&bn));

        let out = aes_decrypt(&enc_key[i as usize], l_miu_enc);
        let bn = BigInt::from(&out[..]);
        miu_vec.push(ECScalar::from(&bn));
    }

    let input_stage4 = SignStage4Input {
        alpha_vec_s: alpha_vec.clone(),
        beta_vec_s: beta_vec.clone(),
        miu_vec_s: miu_vec.clone(),
        ni_vec_s: ni_vec.clone(),
        sign_keys_s: res_stage1.sign_keys.clone(),
    };

    // generate sigma_i and delta_i from alpha,miu,beta,nu's vector
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    // broadcast decommitment from stage1 and delta_i
    // TODO: need broadcast res_stage4.sigma_i
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        // serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i,)).unwrap(),
        serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i, res_stage4.sigma_i,)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round4",
        uuid.clone(),
    );

    // TODO: need memory sigma_i
    let mut sigma_i_vec = vec![];

    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            delta_i_vec.push(res_stage4.delta_i.clone());
            decom1_vec.push(res_stage1.decom1.clone());
            // TODO: push P_i's sigma_i
            sigma_i_vec.push(res_stage4.sigma_i.clone());
        } else {
            // let (decom_l, delta_l): (SignDecommitPhase1, FE) =
            //     serde_json::from_str(&round4_ans_vec[j]).unwrap();
            
            let (decom_l, delta_l, sigma_l): (SignDecommitPhase1, FE, FE) =
            serde_json::from_str(&round4_ans_vec[j]).unwrap();
            
            delta_i_vec.push(delta_l);
            decom1_vec.push(decom_l);
            
            // TODO: push P_j's sigma_j
            sigma_i_vec.push(sigma_l);

            j += 1;
        }
    }
    // Compute delta^{-1}
    let delta_inv_l = SignKeys::phase3_reconstruct_delta(&delta_i_vec);

    // TODO: Compute T_i
    // phase3_compute_t_i(sig)
    let T_i = SignKeys::phase3_compute_t_i(&res_stage4.sigma_i.clone());
    // TODO: broadcast T_i with
    let input_stage5 = SignStage5Input {
        m_b_gamma_vec: m_b_gamma_rec_vec.clone(),
        delta_inv: delta_inv_l.clone(),
        decom_vec1: decom1_vec.clone(),
        bc1_vec: bc1_vec.clone(),
        index: (party_num_int - 1) as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };

    // generate R and \overline{R}_i
    let res_stage5 = sign_stage5(&input_stage5)?;
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&(res_stage5.R_dash.clone(), res_stage5.R.clone(), T_i.0.clone())).unwrap(),  // TODO: broadcast T_i
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round5",
        uuid.clone(),
    );
    // TODO: save T_i for phase 6
    let mut T_vec = vec![];

    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_vec.push(res_stage5.R.clone());
            R_dash_vec.push(res_stage5.R_dash.clone());

            T_vec.push(T_i.0.clone());  // TODO: push t_i for itself
        } else {
            let (R_dash, R, t_j): (GE, GE, GE) = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);

            T_vec.push(t_j);        // TODO: push t_j from others
            j += 1;
        }
    }

    // TODO: generate S_i and broadcast i
    let input_stage6 = SignStage6Input {
        R: res_stage5.R.clone(),
        sigma_i: res_stage4.sigma_i.clone(),
        T_i: T_i.0.clone(),
        l_i: T_i.1.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed");
    assert!(broadcast(&client, 
        party_num_int, 
        "round6", 
        serde_json::to_string(&(res_stage6.S_i.clone(), res_stage6.proof.clone())).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round6",
        uuid.clone(),
    );
    let mut S_i_vec = vec![];
    let mut homo_elgamal_proof_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
           S_i_vec.push(res_stage6.S_i.clone());
           homo_elgamal_proof_vec.push(res_stage6.proof.clone());
        } else {
            let (S_i, homo_elgamal_proof): (GE, HomoELGamalProof) = 
                serde_json::from_str(&round6_ans_vec[j]).unwrap();
            S_i_vec.push(S_i);
            homo_elgamal_proof_vec.push(homo_elgamal_proof);
            j += 1;
        }
    }

    // m = Hash(M), M=message
    let message_bn = HSha256::create_hash(&[&BigInt::from(message)]);
    let input_stage7 = SignStage7Input {
        R_dash_vec: R_dash_vec.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(party_num_int - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i.clone(),
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i.clone(),
        ysum: keypair.y_sum_s.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        message_bn: message_bn.clone(),
        S_vec: S_i_vec.clone(),
        homo_elgamal_proof_vec: homo_elgamal_proof_vec.clone(),
        R_vec: R_vec.clone(),
        T_vec: T_vec.clone(),
    };

    // check the consistency between R_i and E_i(k_i)
    // check the production of \overline{R}_i is equal with g 
    // TODO: check the production of S_i is equal wiht y_sum
    // return with local signature s_i

    // let res_stage7 = sign_stage7(&input_stage7).expect("stage7 sign failed.");

    // TODO: phase 5 error blame
    // generate local state for each party
    let res_stage7 = sign_stage7(&input_stage7);
    if let Err(err) = res_stage7.clone() {
        match err.error_type() {
            s if s == format!("phase5 R_dash_sum check failed {:?}", Error::Phase5BadSum) => {
                // phase 5 error
                let mut beta_randomness_blame = vec![];
                let mut beta_tag_blame = vec![];
                for i in 0..signers_vec.len()-1 {
                    beta_randomness_blame.push(res_stage2.gamma_i_vec[i].2.clone());
                    beta_tag_blame.push(res_stage2.gamma_i_vec[i].3.clone());
                }
                let local_state = LocalStatePhase5 {
                    k: res_stage1.sign_keys.k_i,
                    k_randomness: res_stage1.m_a.1.clone(),
                    gamma: res_stage1.sign_keys.gamma_i,
                    beta_randomness: beta_randomness_blame,
                    beta_tag: beta_tag_blame,
                    encryption_key: keypair.party_keys_s.ek.clone(),
                };
                assert!(broadcast(
                    &client,
                    party_num_int,
                    "phase5_blame",
                    serde_json::to_string(&local_state.clone()).unwrap(),
                    uuid.clone()
                )
                .is_ok());
                let phase5_blame_ans_vec = poll_for_broadcasts(
                    &client,
                    party_num_int,
                    THRESHOLD + 1,
                    delay,
                    "phase5_blame",
                    uuid.clone(),
                );
                let mut local_state_vec = vec![];
                let mut j = 0;
                for i in 1..THRESHOLD + 2 {
                    if i == party_num_int {
                        local_state_vec.push(local_state.clone());
                    } else {
                        let local_state_i: LocalStatePhase5 = serde_json::from_str(&phase5_blame_ans_vec[j]).unwrap();
                        local_state_vec.push(local_state_i.clone());
                        j += 1;
                    }
                }
                let mut ek_vec = vec![];
                for i in 0..THRESHOLD+1 {
                    ek_vec.push(keypair.paillier_key_vec_s[signers_vec[i as usize]].clone());
                }
                let g_gamma_vec = (0..decom1_vec.len())
                    .map(|i| decom1_vec[i].g_gamma_i)
                    .collect::<Vec<GE>>();
                let mut m_b_gamma_vec_all = vec![];
                for i in 1..THRESHOLD+2 {
                    let m_b_gamma_vec = poll_for_p2p(
                            &client, 
                            i, 
                            THRESHOLD+1, 
                            delay, 
                            "round2", 
                            uuid.clone(),
                        );
                    let mut m_b_gamma_vec_blame = vec![];
                    for data in m_b_gamma_vec.iter() {
                        let (l_mb_gamma, _, _, _, _, _): 
                            (MessageB, AEAD, MessageB, AEAD, BigInt, BigInt) =
                            serde_json::from_str(&data).unwrap();
                        m_b_gamma_vec_blame.push(l_mb_gamma);
                    }
                    m_b_gamma_vec_all.push(m_b_gamma_vec_blame);
                }
                let global_state = GlobalStatePhase5::local_state_to_global_state(
                    &ek_vec[..],
                    &delta_i_vec[..],
                    &g_gamma_vec[..],
                    &m_a_vec[..],
                    m_b_gamma_vec_all,
                    &local_state_vec[..],
                );
                let bad_actors = global_state.phase5_blame().expect_err("No Bad Actors Found");
                return Err(bad_actors);
            },
            s if s == "bad gamma_i decommit".to_string() => {
                return Err(err);
            },
            s if s == "phase6".to_string() => {
                return Err(err);
            },
            s if s == format!("phase6 S_i sum check failed {:?}", Error::Phase6Error) => {
                let mut miu_randomness_vec = vec![];
                for i in 0..signers_vec.len()-1 {
                    let rand = GlobalStatePhase6::extract_paillier_randomness(
                        &m_b_w_rec_vec[i].c,
                        &keypair.party_keys_s.dk,
                    );
                    miu_randomness_vec.push(rand);
                }
                let proof = GlobalStatePhase6::ecddh_proof(
                    &res_stage4.sigma_i,
                    &res_stage5.R,
                    &res_stage6.S_i,
                );
                let miu_bigint_vec = (0..THRESHOLD)
                    .map(|i|
                        res_stage3.alpha_vec_w[i as usize].1.clone()
                    ).collect::<Vec<BigInt>>();
                let local_state = LocalStatePhase6 {
                    k: res_stage1.sign_keys.k_i,
                    k_randomness: res_stage1.m_a.1.clone(),
                    miu: miu_bigint_vec.clone(),
                    miu_randomness: miu_randomness_vec.clone(),
                    proof_of_eq_dlog: proof,
                };
                assert!(broadcast(
                    &client,
                    party_num_int,
                    "phase6_blame",
                    serde_json::to_string(&local_state.clone()).unwrap(),
                    uuid.clone()
                )
                .is_ok());
                let phase5_blame_ans_vec = poll_for_broadcasts(
                    &client,
                    party_num_int,
                    THRESHOLD + 1,
                    delay,
                    "phase6_blame",
                    uuid.clone(),
                );
                let mut local_state_vec = vec![];
                let mut j = 0;
                for i in 1..THRESHOLD + 2 {
                    if i == party_num_int {
                        local_state_vec.push(local_state.clone());
                    } else {
                        let local_state_i: LocalStatePhase6 = 
                            serde_json::from_str(&phase5_blame_ans_vec[j]).unwrap();
                        local_state_vec.push(local_state_i.clone());
                        j += 1;
                    }
                }
                let mut ek_vec = vec![];
                for i in 0..THRESHOLD+1 {
                    ek_vec.push(keypair.paillier_key_vec_s[signers_vec[i as usize]].clone());
                }
                let mut m_b_w_vec_all = vec![];
                for i in 1..THRESHOLD+2 {
                    let m_b_w_vec = poll_for_p2p(
                        &client, 
                        i, 
                        THRESHOLD+1, 
                        delay, 
                        "round2", 
                        uuid.clone(),
                    );
                    let mut m_b_w_vec_blame = vec![];
                    for data in m_b_w_vec.iter() {
                        let (_, _, l_m_b_w, _, _, _): 
                            (MessageB, AEAD, MessageB, AEAD, BigInt, BigInt) =
                            serde_json::from_str(&data).unwrap();
                            m_b_w_vec_blame.push(l_m_b_w);
                    }
                    m_b_w_vec_all.push(m_b_w_vec_blame);
                }
                let global_state = GlobalStatePhase6::local_state_to_global_state(
                    &ek_vec[..],
                    &S_i_vec[..],
                    &g_w_i_vec[..],
                    &m_a_vec[..],
                    m_b_w_vec_all,
                    &local_state_vec[..],
                );
                let bad_actors = global_state.phase6_blame(&res_stage5.R).expect_err("No Bad Actors Found");
                return Err(bad_actors);
            },
            _ => unreachable!("Unknown error in sign_stage7 {:?}", err)
        } // match end
    } // Error execution complete

    let res_stage7 = res_stage7.unwrap();

    assert!(broadcast(
        &client,
        party_num_int,
        "round7",
        serde_json::to_string(&res_stage7.local_sig.clone()).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round7_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round7",
        uuid.clone(),
    );
    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            local_sig_vec.push(res_stage7.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round7_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig.clone());
            j += 1;
        }
    }
    let input_stage8 = SignStage8Input {
        local_sig_vec: local_sig_vec.clone(),
        ysum: keypair.y_sum_s.clone(),
    };
    // generate the joint signature, if it is correct
    // let res_stage8 = sign_stage8(&input_stage8).expect("sign stage 8 failed");

    // TODO: phase 7 blame
    let res_stage8 = sign_stage8(&input_stage8);
    if let Err(_) = res_stage8.clone() {
        let s_vec = (0..THRESHOLD+1)
            .map(|i|
                local_sig_vec[i as usize].s_i.clone()
            ).collect::<Vec<_>>();
        let global_state = GlobalStatePhase7 {
            s_vec,
            r: res_stage7.local_sig.r,
            R_dash_vec,
            m: res_stage7.local_sig.m.clone(),
            R: res_stage7.local_sig.R,
            S_vec: S_i_vec,
        };
        let bad_actors = global_state.phase7_blame().expect_err("No Bad Actors Found");
        return Err(bad_actors);
    }

    let res_stage8 = res_stage8.unwrap();
    
    let sig = res_stage8.local_sig;
    println!(
        "party {:?} Output Signature: \nR: {:?}\ns: {:?} \nrecid: {:?} \n",
        party_num_int,
        sig.r.get_element(),
        sig.s.get_element(),
        sig.recid.clone()
    );

    let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
        "s",
        (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
    ))
    .unwrap();

    fs::write("signature".to_string(), sign_json).expect("Unable to save !");
    Ok(())
}
