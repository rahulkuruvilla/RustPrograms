

use aggregatable_dkg::{
    dkg::{
        errors::DKGError,
        node::Node,
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Zero, Field, PrimeField};

pub trait NodeExt<E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
>{
    fn get_secret_key_share(&mut self) -> Result<<E as ark_ec::PairingEngine>::G2Affine, DKGError<E>>;
    fn get_public_key(&mut self) -> Result<<E as ark_ec::PairingEngine>::G1Affine, DKGError<E>>;
}


impl<E: PairingEngine,
     SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
     SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
    >NodeExt<E, SPOK, SSIG> for Node<E, SPOK, SSIG>
{
    fn get_public_key(&mut self) -> Result<<E as ark_ec::PairingEngine>::G1Affine, DKGError<E>> {
        let mut c = E::G1Projective::zero();

        for (participant_id, contribution) in self.aggregator.transcript.contributions.iter() {
            let _participant = self
                .aggregator
                .participants
                .get(participant_id)
                .ok_or(DKGError::<E>::InvalidParticipantId(*participant_id))?;

            c += &contribution
                .c_i
                .mul(<E::Fr as From<u64>>::from(contribution.weight));// c is here 
        }

        Ok(c.into_affine())
    }
    fn get_secret_key_share(&mut self) -> Result<<E as ark_ec::PairingEngine>::G2Affine, DKGError<E>>{

        let secret = self.aggregator.transcript.pvss_share.y_i[self.dealer.participant.id]
                .mul(self.dealer.private_key_sig.inverse().unwrap().into_repr())
                .into_affine();
        Ok(secret)
    }
}