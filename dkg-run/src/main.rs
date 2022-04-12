use aggregatable_dkg::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        node::Node,
        participant::{Participant, ParticipantState},
        share::DKGTranscript,
        srs::SRS as DkgSRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::SignatureScheme,
        algebraic::{keypair::Keypair, public_key::ProvenPublicKey, signature::Signature, srs::SRS as SigSRS}, //srs as SigSRS
    },
};
use ark_bls12_381::{Bls12_381, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{UniformRand, Zero};
use ark_serialize::*;
use ark_serialize::Write;
use rand::{thread_rng};
use std::{marker::PhantomData, env};

use sha2::{Sha256, Digest}; //hash final signature

// use extra functions we created
use dkg_run::sig_srs::{SigSRSExt, KeypairExt};
use dkg_run::keys::NodeExt;


fn _dkg_vuf_runthrough() {
    //cm sends nodes
    const NODES: usize = 4; 

    let rng = &mut thread_rng(); //rng
    let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();
    let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: dkg_srs.h_g2,
            g_signature: dkg_srs.g_g1,
        },
    };
    let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> { //proof of knowledge
        srs: BLSSRS {
            g_public_key: dkg_srs.g_g1,
            g_signature: dkg_srs.h_g2,
        },
    };

    let u_1 = G2Projective::rand(rng).into_affine();
    let degree = 3; //degree t polynomial - for threshold

    //CM sends this
    let dkg_config = Config {
        srs: dkg_srs.clone(),
        u_1,
        degree: degree,
    };

    //each node generates their dealer struct
    let mut dealers = vec![];
    for i in 0..NODES {
        let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
        let participant = Participant {
            pairing_type: PhantomData,
            id: i,                                          //cm gets list and sends it out with dkg_init
            public_key_sig: dealer_keypair_sig.1,
            state: ParticipantState::Dealer,
        };
        let dealer = Dealer {
            private_key_sig: dealer_keypair_sig.0,
            accumulated_secret: G2Projective::zero().into_affine(),
            participant,
        };

        dealers.push(dealer);
    }

    // send to config manager and they do this for all participants
    let participants = dealers
        .iter()
        .map(|d| d.participant.clone())
        .collect::<Vec<_>>(); //collect clones of dealer.participant into a vector, Vec<Participants>
    let num_participants = participants.len();
    assert_eq!(num_participants, NODES);
    
    // each node computes their Node struct
    let mut nodes = vec![];
    for i in 0..NODES {
        let degree = dkg_config.degree;
        let node = Node {
            aggregator: DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: bls_pok.clone(),
                scheme_sig: bls_sig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer: dealers[i].clone(),
        };
        nodes.push(node);
    }

    // "gossip phase" - for each node, each other node receives a share from it
    for i in 0..NODES {
        let node = &mut nodes[i];
        let share = node.share(rng).unwrap();       // note: a node needs receive it's own share too
        for j in 0..NODES {
            nodes[j]
                .receive_share_and_decrypt(rng, share.clone())
                .unwrap();
        }
    }

    //pk - G1Affine
    let pk = nodes[0].get_public_key().unwrap();
    let pk2 = nodes[1].get_public_key().unwrap();
    println!("node0: {:?}\n", &pk);
    println!("node1: {:?}\n", &pk2);

    //sk - G2Affine
    let sk1 = nodes[0].get_secret_key_share().unwrap();
    let sk2 = nodes[1].get_secret_key_share().unwrap();

    //--------------------------------------------------------------------------------
    //VUF
    
    //cm needs to send this
    let vuf_srs = SigSRS::<Bls12_381>::setup_from_dkg(rng, dkg_srs.clone()).unwrap();
    let message = b"hello";

    //each node computes a keypair based on the VUF SRS
    let keypair1 = Keypair::generate_keypair_from_dkg(rng, vuf_srs.clone(), pk, sk1).unwrap(); 
    let keypair2 = Keypair::generate_keypair_from_dkg(rng, vuf_srs.clone(), pk, sk2).unwrap();
    
    //each node computes their proven public key
    let proven_public_key1 = keypair1.prove_key().unwrap();
    //proven_public_key1.verify().unwrap(); //error here with the dkg key outputs!

    let proven_public_key2 = keypair2.prove_key().unwrap();
    //proven_public_key2.verify().unwrap();

    //each node signs a message using their private key
    // other nodes can verify this sigature against the public key of the node that made it
    let signature1 = keypair1.sign(&message[..]).unwrap();
    signature1
        .verify_and_derive(proven_public_key1.clone(), &message[..])
        .unwrap();

    let signature2 = keypair2.sign(&message[..]).unwrap();
    signature2
        .verify_and_derive(proven_public_key2.clone(), &message[..]) //1
        .unwrap();

    // do we send the pk with each sig to aggregate them both?
    let aggregated_pk =
        ProvenPublicKey::aggregate(&[proven_public_key1, proven_public_key2], vuf_srs.clone()) //1
            .unwrap();

    let aggregated_sig = Signature::aggregate(&[signature1, signature2]).unwrap();
    aggregated_sig
        .verify_and_derive(aggregated_pk, message)
        .unwrap();

    let sz = aggregated_sig.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _s = aggregated_sig.serialize(buf_ref);
    
    println!("buffer: {:?}", &buffer);
    println!("size: {:?}", &sz);

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();
    println!("sha256(sigma)= {:?}", result);
}

fn dkg_vuf_runthrough2() {
    //CM sends these NODES and rng (degree sent later)
    //eg) NODES=4, degree=3
    let args: Vec<String> = env::args().collect();
    let n = &args[1];
    let NODES: usize = n.parse().unwrap();
    let rng = &mut thread_rng();

    let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();

    let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: dkg_srs.h_g2,
            g_signature: dkg_srs.g_g1,
        },
    };
    let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: dkg_srs.g_g1,
            g_signature: dkg_srs.h_g2,
        },
    };

    let u_1 = G2Projective::rand(rng).into_affine();
    let degree = (2 * NODES + 2) / 3; //degree t polynomial - for threshold
    //let degree = 5;
    println!("degree={}", &degree);
    //let degree = 3;

    //CM sends this
    let dkg_config = Config {
        srs: dkg_srs.clone(),
        u_1,
        degree: degree,
    };

    //each node generates their dealer struct
    let mut dealers = vec![];
    for i in 0..NODES {
        println!("i={}", i);
        let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
        let participant = Participant {
            pairing_type: PhantomData,
            id: i,
            public_key_sig: dealer_keypair_sig.1,
            state: ParticipantState::Dealer,
        };
        let dealer = Dealer {
            private_key_sig: dealer_keypair_sig.0,
            accumulated_secret: G2Projective::zero().into_affine(),
            participant,
        };

        dealers.push(dealer);
    }

    // send to config manager and they do this for all participants
    let participants = dealers
        .iter()
        .map(|d| d.participant.clone())
        .collect::<Vec<_>>(); //collect clones of dealer.participant into a vector
    let num_participants = participants.len();
    assert_eq!(num_participants, NODES);
    
    // each node computes their Node struct
    let mut nodes = vec![];
    for i in 0..NODES {
        let degree = dkg_config.degree;
        let node = Node {
            aggregator: DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: bls_pok.clone(),
                scheme_sig: bls_sig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer: dealers[i].clone(),
        };
        nodes.push(node);
    }

    // "gossip phase" - for each node, each other node receives a share from it
    for i in 0..NODES {
        let node = &mut nodes[i];
        let share = node.share(rng).unwrap();
        for j in 0..NODES {
            if i == j{
                continue;
            }
            nodes[j]
                .receive_share_and_decrypt(rng, share.clone())
                .unwrap();
        }
    }

    //master pk - G1Affine
    let _master_pk = nodes[0].get_master_public_key().unwrap();

    //node's pk - G1Affine
    let mut pks = vec![];
    for i in 0..NODES {
        let pk = nodes[i].get_public_key().unwrap();
        println!("node{}'s pk: {:?}\n", i, &pk);
        pks.push(pk);
    }

    //sk - G2Affine
    let mut sks = vec![];
    for i in 0..NODES {
        let sk = nodes[i].get_secret_key_share().unwrap();
        sks.push(sk);
    }

    //--------------------------------------------------------------------------------
    //VUF
    
    //cm needs to send this
    let vuf_srs = SigSRS::<Bls12_381>::setup_from_dkg(rng, dkg_srs.clone()).unwrap();
    let message = b"hello";

    //each node computes a keypair based on the VUF SRS + public key
    let mut keypairs = vec![];
    let mut proven_public_keys = vec![];
    for i in 0..NODES {
        let keypair = Keypair::generate_keypair_from_dkg(rng, vuf_srs.clone(), pks[i], sks[i]).unwrap(); // node generate this
        let proven_public_key = keypair.prove_key().unwrap();                                            // node generate this + sends to cm

        proven_public_key.verify().unwrap(); 

        keypairs.push(keypair);
        proven_public_keys.push(proven_public_key);
    }

    //each node signs a message using thier private key
    // other nodes can verify this sigature against the public key of the node that made it    
    let mut signatures = vec![];
    for i in 0..NODES {
        let signature = keypairs[i].sign(&message[..]).unwrap();                // node generates this + sends to cm

        proven_public_keys[i].verify().unwrap();                               //receiving cm checks this
        signature                                                              //receiving cm checks this 
            .verify_and_derive(proven_public_keys[i].clone(), &message[..])      
            .unwrap();
        signatures.push(signature);                                            //cm does this
        //proven_public_keys.push(proven_public_key);                          //cm does this
    }

    //agrregation step
    //let threshold = NODES;
    let threshold = degree;

    //let master_keypair = Keypair::generate_keypair_from_dkg(rng, vuf_srs.clone(), master_pk, sks[0]).unwrap(); 
    //let master_proven_public_key = master_keypair.prove_key().unwrap();
    //signatures[0]
    //    .verify_and_derive(master_proven_public_key, message)
    //    .unwrap();

    let aggregated_pk =
        ProvenPublicKey::aggregate(&proven_public_keys[0..threshold], vuf_srs.clone())   //cm does this 
            .unwrap();

    let aggregated_sig = Signature::aggregate(&signatures[0..threshold]).unwrap();
    aggregated_sig
        .verify_and_derive(aggregated_pk, message)
        .unwrap();
    //aggregated_sig
    //    .verify_and_derive(master_proven_public_key, message)
    //    .unwrap();

    let sz = aggregated_sig.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _s = aggregated_sig.serialize(buf_ref);
    
    println!("buffer: {:?}", &buffer);
    println!("size: {:?}", &sz);

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();
    println!("sha256(sigma)= {:?}", result);
}


fn main() {
    //dkg_vuf_runthrough();
    dkg_vuf_runthrough2();
}
