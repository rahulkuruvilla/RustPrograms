use aggregatable_dkg::signature::{
    utils::errors::SignatureError,
    algebraic::{
        keypair::{Keypair, PrivateKey}, 
        public_key::PublicKey,  
        srs::SRS as SigSRS
    },
};
use aggregatable_dkg::dkg::srs::SRS as DkgSRS;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use rand::Rng;

pub trait SigSRSExt<E: PairingEngine>{
    fn setup_from_dkg<R: Rng>(rng: &mut R, dkg_srs: DkgSRS<E>) 
                            -> Result<SigSRS<E>, SignatureError>;
}

pub trait KeypairExt<E: PairingEngine>{
    fn generate_keypair_from_dkg<R: Rng>(rng: &mut R, srs: SigSRS<E>, pk: E::G1Affine, sk: E::G2Affine) 
                            -> Result<Keypair<E>, SignatureError>;
}


impl<E: PairingEngine>SigSRSExt<E> for SigSRS<E>{

    //my defn. to setup from dkg
    // VUF.Setup()
    fn setup_from_dkg<R: Rng>(rng: &mut R, dkg_srs: DkgSRS<E>) -> Result<SigSRS<E>, SignatureError> {
        let srs = SigSRS{
            //both like in DKG so use these from the DKG
            //g_1_g2: E::G2Affine::prime_subgroup_generator(),
            //h_g1: E::G1Affine::prime_subgroup_generator(),   
            g_1_g2: dkg_srs.h_g2, 
            h_g1: dkg_srs.g_g1,  

            // make new of these on the original rng
            g_2_g2: E::G2Projective::rand(rng).into_affine(),
            g_3_g2: E::G2Projective::rand(rng).into_affine(),
            g_4_g2: E::G2Projective::rand(rng).into_affine(),
        };
        Ok(srs)
    }
}


impl<E: PairingEngine>KeypairExt<E> for Keypair<E> {

    // VUF.Gen
    fn generate_keypair_from_dkg<R: Rng>(rng: &mut R, srs: SigSRS<E>, pk: E::G1Affine, sk: E::G2Affine) -> Result<Keypair<E>, SignatureError> {
        let _a = E::Fr::rand(rng);

        let _a_g2 = srs.g_1_g2.mul(_a.clone());
        let private_key = PrivateKey {
            //sk: a_g2.into_affine(),
            sk: sk,
        };
        let _a_g1 = srs.h_g1.mul(_a);
        let public_key = PublicKey {
            srs: srs.clone(),
            //pk: a_g1.into_affine(),
            pk: pk,
        };
        let keypair = Keypair {
            alpha: E::Fr::rand(rng),
            beta: E::Fr::rand(rng),
            srs: srs.clone(),
            private: private_key,
            public: public_key,
        };
        Ok(keypair)
    }
}