
#![allow(dead_code)]
#![allow(unused_variables)]
#[allow(unused_imports)]

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
use ark_ec::{ProjectiveCurve, PairingEngine};
use ark_ff::{UniformRand, Zero};
use ark_serialize::*;
use ark_serialize::Write;
use std::marker::PhantomData;
use rand::{thread_rng};
use libp2p::PeerId;


#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct DKGInit<E: PairingEngine> {
    pub num_nodes: usize,
    pub peers: Vec<Vec<u8>>,
    pub dkg_config: Config<E>,
}

impl Default for DKGInit<Bls12_381>{

    //init with dummy data - CHANGE THIS TO OPTION ENUM
    fn default() -> DKGInit<Bls12_381> {
        let rng = &mut thread_rng();
        let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();
        let u_1 = G2Projective::rand(rng).into_affine();
        let v: Vec<Vec<u8>> = vec![vec![0]];

        let c = Config{
            srs: dkg_srs,
            u_1: u_1,
            degree: 0,
        };

        Self{
            num_nodes: 0,
            peers: v,
            dkg_config: c,
        }
    }
}