#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters, SharedKeys,
};
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
use std::hash::{Hash, Hasher};
use async_std::task;
use futures::prelude::*;
use futures::stream::StreamExt;

mod common;
use common::{aes_decrypt, aes_encrypt, Params, AEAD, Entry, Key, AES_KEY_BYTES_LEN,
            poll_for_broadcasts_ch, poll_for_p2p_ch, broadcast_ch, sendp2p_ch, get_party_num};

impl From<Params> for Parameters {
    fn from(item: Params) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}

fn main() {
    if env::args().nth(2).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(1).is_none() {
        panic!("too few arguments")
    }
    let totaltime = SystemTime::now();

    let params: Parameters = serde_json::from_str::<Params>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    ).unwrap().into();
    let params_lis = params.clone();

    let db_mtx: Arc<RwLock<HashMap<Key, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let db_mtx_lis = db_mtx.clone();
    let party_num_int: Arc<RwLock<u16>> = Arc::new(RwLock::new(0));
    let party_num_int_lis = party_num_int.clone();
    // create channel between swarm and main thread
    let (tx, rx): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel();
    let (tx1, rx1): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel();

    let delay = time::Duration::from_millis(25);

    // create a listener thread
    let listen_thread = thread::spawn(move || -> Result<(), ()>{
        // use p2p to build a swarm
        let mut peer_ids: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id: PeerId = PeerId::from(local_key.public());
        peer_ids.insert(local_peer_id.clone().as_bytes().to_vec(), local_peer_id.clone().as_bytes().to_vec());
        println!("Local peer id: {:?}", local_peer_id);

        let transport = libp2p::build_development_transport(local_key.clone()).expect("transport error");

        let topic0 = Topic::new("keygen_peer_num".into());
        let topic1 = Topic::new("keygen_chat".into());
        let topic_str0 = String::from("keygen_peer_num");
        let topic_str1 = String::from("keygen_chat");

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
        libp2p::Swarm::listen_on(&mut swarm, "/ip4/127.0.0.1/tcp/23333".parse().unwrap()).unwrap();
        let to_dial: Multiaddr = "/ip4/127.0.0.1/tcp/23333".parse().unwrap();
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
                                        connected = params_lis.share_count.clone();
                                        if (peer_ids.len() as u16) < params_lis.share_count {
                                            peer_ids.insert(peer_id.clone().as_bytes().to_vec(), peer_id.as_bytes().to_vec());
                                            if (peer_ids.len() as u16) == params_lis.share_count {
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
            if !publish_peer_id && connected == params_lis.share_count {
                swarm.publish(&topic0, local_peer_id.clone().as_bytes()).expect("publish peer_id failed");
                publish_peer_id = true;
            }
            Poll::Pending
        }))
    });

    // wait for all peers' connection
    if let Ok(_) = rx1.recv(){}

    let input_stage1 = KeyGenStage1Input {
        index: (*(*party_num_int).read().unwrap() - 1) as usize,
    };
    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);

    // broadcast test
    broadcast_ch(
        & tx,
        *party_num_int.read().unwrap(),
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap()
    );

    let round1_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        params.share_count,
        delay,
        "round1"
    );
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(*(*party_num_int).read().unwrap() as usize - 1, res_stage1.bc_com1_l);

    broadcast_ch(
        & tx,
        *party_num_int.read().unwrap(),
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap()
    );
    let round2_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        params.share_count,
        delay,
        "round2"
    );
    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    decom1_vec.insert(*(*party_num_int).read().unwrap() as usize - 1, res_stage1.decom1_l);
    let input_stage2 = KeyGenStage2Input {
        index: (*(*party_num_int).read().unwrap() - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };
    let res_stage2 = keygen_stage2(&input_stage2).expect("keygen stage 2 failed.");

    let mut point_vec: Vec<GE> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=params.share_count {
        point_vec.push(decom1_vec[(i - 1) as usize].y_i);
        if i != *party_num_int.read().unwrap() {
            let key_bn: BigInt = (decom1_vec[(i - 1) as usize].y_i.clone()
                * res_stage1.party_keys_l.u_i)
                .x_coor()
                .unwrap();
            let key_bytes = BigInt::to_vec(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let mut j = 0;
    for (k, i) in (1..=params.share_count).enumerate() {
        if i != *party_num_int.read().unwrap() {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_vec(&res_stage2.secret_shares_s[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            // This client does not implement the identifiable abort protocol.
            // If it were these secret shares would need to be broadcasted to indetify the
            // malicious party.
            sendp2p_ch(
                & tx,
                *party_num_int.read().unwrap(),
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap()
            );
            j += 1;
        }
    }
    // get shares from other parties.
    let round3_ans_vec = poll_for_p2p_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        params.share_count,
        delay,
        "round3"
    );
    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == *party_num_int.read().unwrap() {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    broadcast_ch(
        & tx,
        party_num_int.read().unwrap().clone(),
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap()
    );

    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        params.share_count,
        delay,
        "round4"
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=params.share_count {
        if i == *party_num_int.read().unwrap() {
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
        index_s: (*(*party_num_int).read().unwrap() - 1) as usize,
        params_s: params.clone(),
    };
    let res_stage3 = keygen_stage3(&input_stage3).expect("stage 3 keygen failed.");
    // round 5: send dlog proof
    broadcast_ch(
        & tx,
        *party_num_int.read().unwrap(),
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap()
    );

    let round5_ans_vec = poll_for_broadcasts_ch(
        &db_mtx,
        *party_num_int.read().unwrap(),
        params.share_count,
        delay,
        "round5"
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=params.share_count {
        if i == *party_num_int.read().unwrap() {
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
    let _ = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");
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
        party_num_int_s: *party_num_int.read().unwrap(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde_vec_s: h1_h2_N_tilde_vec,
    };
    fs::write(
        &env::args().nth(1).unwrap(),
        serde_json::to_string(&party_key_pair).unwrap(),
    )
    .expect("Unable to save !");

    let tt = SystemTime::now();
    let difference = tt.duration_since(totaltime).unwrap().as_secs_f32();
    println!("total time: {:?}", difference);
    listen_thread.join().expect("join failed");
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
