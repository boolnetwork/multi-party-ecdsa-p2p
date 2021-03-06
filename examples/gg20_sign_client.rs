#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    Keys, LocalSignature, Parameters, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use paillier::*;
use serde::{Deserialize, Serialize};
use std::{env, fs, time};
use zk_paillier::zkproofs::DLogStatement;
// p2p module
use libp2p::gossipsub::protocol::MessageId;
use libp2p::gossipsub::{GossipsubEvent, GossipsubMessage, MessageAuthenticity, Topic};
use libp2p::{gossipsub, identity, PeerId, Multiaddr};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::{Duration, SystemTime};
use std::task::{Context, Poll};
use std::hash::{Hash as Orhash, Hasher};
use async_std::task;
use futures::prelude::*;
use futures::stream::StreamExt;

mod common;
use common::{aes_decrypt, aes_encrypt, Params, AEAD, Entry, Key,
             poll_for_broadcasts_ch, poll_for_p2p_ch, broadcast_ch, sendp2p_ch, get_party_num};
use crate::common::AES_KEY_BYTES_LEN;

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

#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(3).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(2).is_none() {
        panic!("too few arguments")
    }
    let totaltime = SystemTime::now();
    let message_str = env::args().nth(2).unwrap_or_else(|| "".to_string());
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let data = fs::read_to_string(env::args().nth(1).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let keypair: PartyKeyPair = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();
    let THRESHOLD_LIS = THRESHOLD.clone();
    // data base to save data from other nodes
    let db_mtx: Arc<RwLock<HashMap<Key, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let db_mtx_lis = db_mtx.clone();
    // local party number
    let party_num_int: Arc<RwLock<u16>> = Arc::new(RwLock::new(0));
    let party_num_int_lis = party_num_int.clone();
    // create a channel between swarm and main thread
    let (tx, rx): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel();
    let (tx1, rx1): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel();

    // create a listener thread
    let listen_thread = thread::spawn(move || -> Result<(), ()>{
        // use p2p to build a swarm
        let mut peer_ids: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id: PeerId = PeerId::from(local_key.public());
        peer_ids.insert(local_peer_id.clone().as_bytes().to_vec(), local_peer_id.clone().as_bytes().to_vec());
        println!("Local peer id: {:?}", local_peer_id);

        let transport = libp2p::build_development_transport(local_key.clone()).expect("transport error");

        let topic0 = Topic::new("sign_peer_num".into());
        let topic1 = Topic::new("sign_chat".into());
        let topic_str0 = String::from("sign_peer_num");
        let topic_str1 = String::from("sign_chat");

        let mut swarm = {
            let message_id_fn = |message: &GossipsubMessage| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::GossipsubConfigBuilder::new()
                .heartbeat_interval(Duration::from_millis(10))
                .heartbeat_initial_delay(Duration::from_millis(10))
                .message_id_fn(message_id_fn)
                .max_transmit_size(50000)
                .build();
            let mut gossipsub =
                gossipsub::Gossipsub::new(MessageAuthenticity::Signed(local_key), gossipsub_config);
            gossipsub.subscribe(topic0.clone());
            gossipsub.subscribe(topic1.clone());
            libp2p::Swarm::new(transport, gossipsub, local_peer_id.clone())
        };
        // create local swarm and listener swarm
        libp2p::Swarm::listen_on(&mut swarm, "/ip4/127.0.0.1/tcp/23334".parse().unwrap()).unwrap();
        let to_dial: Multiaddr = "/ip4/127.0.0.1/tcp/23334".parse().unwrap();
        libp2p::Swarm::dial_addr(&mut swarm, to_dial).expect("first peer");

        let mut publish_peer_id = false;
        let mut connected: u16 = 1;
        task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
            // get message from other peers
            loop {
                match swarm.poll_next_unpin(cx) {
                    Poll::Ready(Some(gossip_event)) => {
                        match gossip_event {
                            GossipsubEvent::Message(_peer_id, _id, message) => {
                                match message.topics[0].as_str() {
                                    s if s == topic_str0 => {
                                        let peer_id = message.source.unwrap();
                                        connected = THRESHOLD_LIS.clone() + 1;
                                        if (peer_ids.len() as u16) < THRESHOLD_LIS + 1 {
                                            peer_ids.insert(peer_id.clone().as_bytes().to_vec(), peer_id.as_bytes().to_vec());
                                            if (peer_ids.len() as u16) == THRESHOLD_LIS + 1 {
                                                loop {
                                                    if let Ok(mut pnil) = party_num_int_lis.try_write() {
                                                        *pnil = get_party_num(&peer_ids, &local_peer_id.as_bytes().to_vec());
                                                        println!("my party_num_int is: {}", *pnil);
                                                        tx1.send("prepared".to_string()).unwrap();
                                                        drop(pnil);
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    s if s == topic_str1 => {
                                        let body = String::from_utf8_lossy(&message.data);
                                        let entry: Entry = serde_json::from_str(&body).unwrap();
                                        loop {
                                            if let Ok(mut db) = db_mtx_lis.try_write() {
                                                db.insert(entry.key.clone(), entry.value.clone());
                                                break;
                                            }
                                        }
                                    },
                                    _ => ()
                                }
                            },
                            GossipsubEvent::Subscribed{ peer_id: _, topic } => {
                                if topic.as_str() == topic0.no_hash().as_str() {
                                    connected += 1;
                                }
                            },
                            _ => ()
                        }
                    }
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }

            // get message to publish from channel and publish it
            if let Ok(data) = rx.try_recv() {
                swarm.publish(&topic1, data.as_bytes()).expect("publish chat failed");
            }

            // publish local_peer_id
            if !publish_peer_id && connected == THRESHOLD_LIS + 1 {
                swarm.publish(&topic0, local_peer_id.clone().as_bytes()).expect("publish peer_id failed");
                publish_peer_id = true;
            }
            Poll::Pending
        }))
    });

    // wait for all peers' connection
    if let Ok(_) = rx1.recv() {}

    // round 0: collect signers IDs
    broadcast_ch(
        &tx,
        *party_num_int.read().unwrap(),
        "round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap()
    );
    let round0_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round0"
    );

    let mut j = 0;
    //0 indexed vec containing ids of the signing parties.
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == *party_num_int.read().unwrap() {
            signers_vec.push((keypair.party_num_int_s - 1) as usize);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j += 1;
        }
    }

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[(*party_num_int.read().unwrap() - 1) as usize]].clone(),
        index: signers_vec[(*party_num_int.read().unwrap() - 1) as usize],
        s_l: signers_vec.clone(),
        party_keys: keypair.party_keys_s.clone(),
        shared_keys: keypair.shared_keys,
    };
    let res_stage1 = sign_stage1(&input_stage1);
    // publish message A  and Commitment and then gather responses from other parties.
    broadcast_ch(
        &tx,
        *party_num_int.read().unwrap(),
        "round1",
        serde_json::to_string(&(
            res_stage1.bc1.clone(),
            res_stage1.m_a.0.clone(),
            res_stage1.sign_keys.g_w_i
        ))
        .unwrap()
    );
    let round1_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round1"
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut g_w_i_vec: Vec<GE> = vec![];

    for i in 1..THRESHOLD + 2 {
        if i == *party_num_int.read().unwrap() {
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
    let mut enc_key: Vec<Vec<u8>> = vec![];
    for (i, k) in signers_vec.iter().enumerate() {
        if *k != signers_vec[*party_num_int.read().unwrap() as usize - 1] as usize {
            let key_bn: BigInt = (g_w_i_vec[i as usize] * res_stage1.sign_keys.w_i.clone())
                .x_coor()
                .unwrap();
            let key_bytes = BigInt::to_vec(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_key.push(template);
        }
    }

    assert_eq!(signers_vec.len() - 1, enc_key.len());
    assert_eq!(signers_vec.len(), bc1_vec.len());

    let input_stage2 = SignStage2Input {
        m_a_vec: m_a_vec.clone(),
        gamma_i: res_stage1.sign_keys.gamma_i.clone(),
        w_i: res_stage1.sign_keys.w_i.clone(),
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: (*party_num_int.read().unwrap() - 1) as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate there alpha values.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != *party_num_int.read().unwrap() {
            let beta_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage2.gamma_i_vec[j].1.to_big_int()),
            );
            let ni_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage2.w_i_vec[j].1.to_big_int()),
            );

            sendp2p_ch(
                &tx,
                *party_num_int.read().unwrap(),
                i,
                "round2",
                serde_json::to_string(&(
                    res_stage2.gamma_i_vec[j].0.clone(),
                    beta_enc,
                    res_stage2.w_i_vec[j].0.clone(),
                    ni_enc,
                ))
                .unwrap()
            );
            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round2"
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    // Will store the decrypted values received from other parties.
    let mut beta_vec: Vec<FE> = vec![];
    let mut ni_vec: Vec<FE> = vec![];

    for i in 0..THRESHOLD {
        let (l_mb_gamma, l_enc_beta, l_mb_w, l_enc_ni): (MessageB, AEAD, MessageB, AEAD) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
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
        index_s: (*party_num_int.read().unwrap() - 1) as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: g_w_i_vec.clone(),
    };

    let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");
    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != *party_num_int.read().unwrap() {
            let alpha_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage3.alpha_vec_gamma[j].to_big_int()),
            );
            let miu_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage3.alpha_vec_w[j].to_big_int()),
            );

            sendp2p_ch(
                &tx,
                *party_num_int.read().unwrap(),
                i,
                "round3",
                serde_json::to_string(&(alpha_enc, miu_enc)).unwrap()
            );
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round3"
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
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    //broadcast decommitment from stage1 and delta_i
    broadcast_ch(
        &tx,
        *party_num_int.read().unwrap(),
        "round4",
        serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i,)).unwrap()
    );
    let round4_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round4"
    );
    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == *party_num_int.read().unwrap() {
            delta_i_vec.push(res_stage4.delta_i.clone());
            decom1_vec.push(res_stage1.decom1.clone());
        } else {
            let (decom_l, delta_l): (SignDecommitPhase1, FE) =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            delta_i_vec.push(delta_l);
            decom1_vec.push(decom_l);
            j += 1;
        }
    }

    let delta_inv_l = SignKeys::phase3_reconstruct_delta(&delta_i_vec);
    let input_stage5 = SignStage5Input {
        m_b_gamma_vec: m_b_gamma_rec_vec.clone(),
        delta_inv: delta_inv_l.clone(),
        decom_vec1: decom1_vec.clone(),
        bc1_vec: bc1_vec.clone(),
        index: (*party_num_int.read().unwrap() - 1) as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    broadcast_ch(
        &tx,
        *party_num_int.read().unwrap(),
        "round5",
        serde_json::to_string(&(res_stage5.R_dash.clone(), res_stage5.R.clone(),)).unwrap()
    );
    let round5_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round5"
    );
    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == *party_num_int.read().unwrap() {
            R_vec.push(res_stage5.R.clone());
            R_dash_vec.push(res_stage5.R_dash.clone());
        } else {
            let (R_dash, R): (GE, GE) = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);
            j += 1;
        }
    }

    let message_bn = HSha256::create_hash(&[&BigInt::from(message)]);
    let input_stage6 = SignStage6Input {
        R_dash_vec: R_dash_vec.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(*party_num_int.read().unwrap() - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i.clone(),
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: (*party_num_int.read().unwrap() - 1) as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i.clone(),
        ysum: keypair.y_sum_s.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        message_bn: message_bn.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    broadcast_ch(
        &tx,
        *party_num_int.read().unwrap(),
        "round6",
        serde_json::to_string(&res_stage6.local_sig.clone()).unwrap()
    );
    let round6_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        THRESHOLD + 1,
        delay,
        "round6"
    );
    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == *party_num_int.read().unwrap() {
            local_sig_vec.push(res_stage6.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round6_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig.clone());
            j += 1;
        }
    }
    let input_stage7 = SignStage7Input {
        local_sig_vec: local_sig_vec.clone(),
        ysum: keypair.y_sum_s.clone(),
    };
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");
    let sig = res_stage7.local_sig;
    println!(
        "party {:?} Output Signature: \nR: {:?}\ns: {:?} \nrecid: {:?} \n",
        *party_num_int.read().unwrap(),
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
    let tt = SystemTime::now();
    let difference = tt.duration_since(totaltime).unwrap().as_secs_f32();
    println!("total time: {:?}", difference);
    listen_thread.join().expect("join failed");
}
