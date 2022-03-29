use crate::signature::scheme::BatchVerifiableSignatureScheme;
use ark_ec::PairingEngine;

use ark_serialize::*;
use serde::{Serialize, Deserialize}; 
use serde_json;

#[derive(Clone, Serialize, Deserialize)]
pub enum ParticipantState {
    Dealer,         //0
    DealerShared,   //1
    Initial,        //2
    Verified,       //3
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Participant<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub pairing_type: std::marker::PhantomData<E>,
    pub id: usize,
    pub public_key_sig: SSIG::PublicKey,
    //pub state: ParticipantState,
    pub state: usize,
}

// my code
impl CanonicalSerialize for ParticipantState{
    //convert to bytes and put into writer
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        let as_string = serde_json::to_string(&self).unwrap();
        let as_bytes = as_string.as_bytes();
        Ok(writer.write_all(&as_bytes)?)
    }

    fn serialized_size(&self) -> usize {
        let as_string = serde_json::to_string(&self).unwrap();
        let as_bytes = as_string.as_bytes();
        as_bytes.len()
    }
}

impl CanonicalDeserialize for ParticipantState{
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let as_string = String::from_utf8(CanonicalDeserialize::deserialize(&mut reader)?).unwrap();   //error here 
        let as_data = serde_json::from_str::<ParticipantState>(&as_string).unwrap();
        //let as_data: Foo = serde_json::from_slice(as_data).unwrap();
        Ok(as_data)
    }
}