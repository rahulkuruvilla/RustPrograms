use super::srs::SRS;
use ark_ec::PairingEngine;
use ark_serialize::*;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Config<E: PairingEngine> {
    pub srs: SRS<E>,
    pub u_1: E::G2Affine,
    pub degree: usize,
}
