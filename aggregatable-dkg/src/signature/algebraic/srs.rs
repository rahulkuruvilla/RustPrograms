use crate::signature::utils::errors::SignatureError;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::Rng;

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SRS<E: PairingEngine> {
    pub g_1_g2: E::G2Affine,
    pub h_g1: E::G1Affine,

    pub g_2_g2: E::G2Affine,
    pub g_3_g2: E::G2Affine,
    pub g_4_g2: E::G2Affine,
}

impl<E: PairingEngine> SRS<E> {
    pub fn setup<R: Rng>(rng: &mut R) -> Result<Self, SignatureError> {
        let srs = Self {
            //both like in DKG so use these from the DKG
            g_1_g2: E::G2Affine::prime_subgroup_generator(), //g_1 from G_2 - USED FOR PRIVATE KEY so must be h_1
            h_g1: E::G1Affine::prime_subgroup_generator(),   //h from G_1 - USED FOR PUBLIC KEY so must be g_1^a

            // make new of these on the original rng
            g_2_g2: E::G2Projective::rand(rng).into_affine(), // must be h_2
            g_3_g2: E::G2Projective::rand(rng).into_affine(), // h_3
            g_4_g2: E::G2Projective::rand(rng).into_affine(), // h_4
        };
        Ok(srs)
    }
}
