
#![allow(dead_code)]
#![allow(unused_variables)]
#[allow(unused_imports)]

// aggregatable dkg imports--------------------------------------------------------
use aggregatable_dkg::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        node::Node,
        participant::{Participant, ParticipantState},
        share::{DKGTranscript, DKGShare},
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
use rand::{thread_rng};
use std::marker::PhantomData;

// libp2p imports--------------------------------------------------------
use libp2p::{
    core::upgrade,
    floodsub::{self, Floodsub, FloodsubEvent, Topic},
    futures::StreamExt,
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise,
    swarm::{NetworkBehaviourEventProcess, SwarmEvent, Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    NetworkBehaviour, PeerId, Transport,
};
use log::{error, info};
use std::error::Error;
use std::collections::HashSet;
use once_cell::sync::Lazy;
use tokio::{fs, io::AsyncBufReadExt, sync::mpsc};

use rand_beacon::data::DKGInit;

static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("dkg"));

// data that gets sent to main loop
pub enum ChannelData{
    Party(Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>),
    Share(DKGShare::<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>>),
}

#[derive(Clone)]
pub struct NodeInfo{
    bls_sig: Option<BLSSignature::<BLSSignatureG1<Bls12_381>>>,
    bls_pok: Option<BLSSignature::<BLSSignatureG2<Bls12_381>>>,
    dealer: Option<Dealer<Bls12_381,BLSSignature<BLSSignatureG1<Bls12_381>>>>,
    participants: Option<Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>>,
    node: Option<Node<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>>>,
}

// We create a custom network behaviour that combines floodsub and mDNS.
// The derive generates a delegating `NetworkBehaviour` impl which in turn
// requires the implementations of `NetworkBehaviourEventProcess` for
// the events of each behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct NodeBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns,

    #[behaviour(ignore)]
    pub response_sender: mpsc::UnboundedSender<ChannelData>,

    #[behaviour(ignore)]
    pub state: usize,

    #[behaviour(ignore)]
    pub dkg_init: DKGInit<Bls12_381>,

    #[behaviour(ignore)]
    pub cm_id: PeerId,

    #[behaviour(ignore)]
    pub node_id: PeerId,

    #[behaviour(ignore)]
    pub participant_id: usize,

    #[behaviour(ignore)]
    pub node_list: Vec<PeerId>,

    #[behaviour(ignore)]
    pub node_extra: NodeInfo,
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for NodeBehaviour {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        //message is a Vec<u8>
        if let FloodsubEvent::Message(message) = message {

            if let Ok(dkg_init) = DKGInit::<Bls12_381>::deserialize(&*message.data) {
                if self.state == 0 {
                    println!("num_nodes: {}", dkg_init.num_nodes);
                    println!("cm_id: {:?}", message.source);
                    let mut peer_ids: Vec<PeerId> = vec![];
                    dkg_init.peers.iter().for_each(|p| peer_ids.push(PeerId::from_bytes(&p).unwrap())); 
                    println!("Final peers: ");
                    peer_ids.iter().for_each(|p| println!("{}", p)); 
                    self.node_list = peer_ids;

                    let index = self.node_list.iter().position(|&id| id == self.node_id).unwrap();
                    self.participant_id = index;
                    println!("this participant.id: {}", &index);
                    
                    self.dkg_init = dkg_init.clone();
                    self.state = 1;
                    self.cm_id = message.source;

                    let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
                        srs: BLSSRS {
                            g_public_key: dkg_init.dkg_config.srs.h_g2,
                            g_signature: dkg_init.dkg_config.srs.g_g1,
                        },
                    };
                    let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
                        srs: BLSSRS {
                            g_public_key: dkg_init.dkg_config.srs.g_g1,
                            g_signature: dkg_init.dkg_config.srs.h_g2,
                        },
                    };

                    let rng = &mut thread_rng();
                    let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
                    let participant = Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>> {
                        pairing_type: PhantomData,
                        id: self.participant_id,               //cm gets list and sends it out with dkg_init
                        public_key_sig: dealer_keypair_sig.1,
                        state: 0,
                    };
                    let dealer = Dealer {
                        private_key_sig: dealer_keypair_sig.0,
                        accumulated_secret: G2Projective::zero().into_affine(),
                        participant: participant.clone(),
                    };

                    self.node_extra.bls_pok = Some(bls_pok);
                    self.node_extra.bls_sig = Some(bls_sig);
                    self.node_extra.dealer = Some(dealer);

                    // send participant to loop via channel
                    stage_channel_data(
                        self.response_sender.clone(), 
                        ChannelData::Party(participant)
                    )
                }
            }
            if let Ok(ps) = Vec::<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>::deserialize(&*message.data) {
                if self.state == 2{
                    println!("Received participants struct from cm "); //some of these are empty
                    ps.iter().for_each(|p| println!("{}", p.id));
                    println!("ps.len()={}", ps.len());


                    let node_data = self.node_extra.clone();
                    let pok = node_data.bls_pok.unwrap();
                    let sig = node_data.bls_sig.unwrap();
                    let this_dealer = node_data.dealer.unwrap();

                    let degree: usize = self.dkg_init.dkg_config.degree.clone();
                    let num_sz: usize = self.dkg_init.num_nodes.clone();
                    let mut this_node: Node<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>> = Node {
                        aggregator: DKGAggregator {
                            config: self.dkg_init.dkg_config.clone(),
                            scheme_pok: pok,
                            scheme_sig: sig,
                            participants: ps.clone().into_iter().enumerate().collect(),
                            transcript: DKGTranscript::empty(degree, num_sz),
                        },
                        dealer: this_dealer,
                    };

                    println!("ps len: {}", this_node.aggregator.participants.len());
                    let rng = &mut thread_rng();
                    //let ref_node = &mut this_node;
                    let share = this_node.share(rng).unwrap();
                    println!("idss{}", &share.participant_id);
                    this_node.receive_share_and_decrypt(rng, share.clone()).unwrap();
                    self.node_extra.node = Some(this_node);
                    // send out this share to the swarm
                    stage_channel_data(
                        self.response_sender.clone(), 
                        ChannelData::Share(share)
                    )
                    
                }
            }
            
            
            //println!("Received: '{:?}' from {:?}",
            //    String::from_utf8_lossy(&message.data),
            //    message.source
            //);
        }
    }
}

impl NetworkBehaviourEventProcess<MdnsEvent> for NodeBehaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

fn stage_channel_data(sender: mpsc::UnboundedSender<ChannelData>, data: ChannelData) {
    tokio::spawn(async move {
        if let Err(e) = sender.send(data) {
            error!("ERROR (Channel data not sent): {}", e);
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    pretty_env_logger::init();

    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

    // setup swarm variables
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();
    let state: usize = 0;
    let dkg_init = DKGInit::<Bls12_381>::default();

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("Signing libp2p-noise static DH keypair failed.");

    // Create a tokio-based TCP transport use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    // Create a Swarm to manage peers and events.
    let this_id = peer_id.clone();
    let mut swarm = {
        let mdns = Mdns::new(Default::default()).await?;
        let mut behaviour = NodeBehaviour{
            floodsub: Floodsub::new(peer_id.clone()),
            mdns,
            response_sender,
            state,
            dkg_init,
            cm_id: this_id,
            node_id: this_id,
            participant_id: 0,
            node_list: [this_id].to_vec(),
            node_extra: NodeInfo{
                bls_sig: None,
                bls_pok: None,
                dealer: None,
                participants: None,
                node: None,
            },
        };

        behaviour.floodsub.subscribe(TOPIC.clone());

        // We want the connection background tasks to be spawned
        // onto the tokio runtime.
        SwarmBuilder::new(transport, behaviour, peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    // Read full lines from stdin
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    //info!("sending init event");
    //let sender = swarm.behaviour_mut().response_sender.clone();
    //tokio::spawn(async move {
    //    let data = "test".to_string();
    //    sender.send(data).expect("can send init event"); //-- this needs receive end in tokio select!
        //swarm.behaviour_mut().floodsub.publish(TOPIC.clone(), "test".as_bytes());
    //});
  
    loop {
        tokio::select! {
            //received from stdin
            line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                println!("line: {:?}", &line);
                //swarm.behaviour_mut().floodsub.publish(TOPIC.clone(), line.as_bytes());
                if line == "start"{
                    let peers = list_peers(&mut swarm).await;
                    init_dkg(peers, &mut swarm).await;
                }else if line == "check"{
                    check_state(&mut swarm).await;
                }else if line == "ls"{
                    list_peers(&mut swarm).await;
                }
            }
            
            // received from the channel
            response = response_rcv.recv() => {
                //let json = serde_json::to_string(&response).expect("can jsonify response");
                println!("received");
                //swarm.behaviour_mut().floodsub.publish(TOPIC.clone(), json.into_bytes());

                //match on 
                match response {
                    Some(ChannelData::Party(participant)) => {
                        println!("participant is going to be sent");
                        send_participant(participant, &mut swarm).await;
                    }
                    Some(ChannelData::Share(dkg_share)) => {
                        println!("dkg_share going to be sent");
                        send_dkg_share(dkg_share, &mut swarm).await;
                    }
                    _ => {}
                }
            }

            //event on the swarm
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr {address, .. } = event {
                    println!("Listening on {:?}", address);
                }
            }
        }
    }
    
}


async fn list_peers(swarm: &mut Swarm<NodeBehaviour>) -> Vec<Vec<u8>>{
    println!("Discovered Peers:");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut bytes = vec![];
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }

    let all_nodes = Vec::from_iter(unique_peers);
    println!("{:?}", all_nodes);
    all_nodes.iter().for_each(|p| bytes.push(p.to_bytes())); 
    bytes
}

// for debugging purposes
async fn check_state(swarm: &mut Swarm<NodeBehaviour>) {
    println!("Checking state");
    let behaviour = swarm.behaviour_mut();
    println!("This node's state is {}", behaviour.state);
}


// cm runs this when all nodes connected
async fn init_dkg(connected_peers: Vec<Vec<u8>>, swarm: &mut Swarm<NodeBehaviour>){
    let behaviour = swarm.behaviour_mut();
    if behaviour.state != 0 {
        return
    }

    println!("This config manager is starting the DKG!");
    let num_nodes: usize = 2; 
    let rng = &mut thread_rng();
    let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();
    let u_1 = G2Projective::rand(rng).into_affine();
    let degree = 3;

    let dkg_config = Config {
        srs: dkg_srs.clone(),
        u_1,
        degree: degree,
    };

    let cm_dkg_init = DKGInit {
        num_nodes: num_nodes,
        peers: connected_peers,
        dkg_config: dkg_config,
    };

    let sz = cm_dkg_init.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = cm_dkg_init.serialize(buf_ref);
    
    behaviour.floodsub.publish(TOPIC.clone(), buffer);
    behaviour.state = 1;
    behaviour.dkg_init = cm_dkg_init;

}

async fn send_participant(
    party: Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>, 
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();

    let sz = party.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = party.serialize(buf_ref);
    
    if behaviour.state == 1 {
        behaviour.floodsub.publish(TOPIC.clone(), buffer);
        behaviour.state = 2;
    }
}

async fn send_dkg_share(
    share: DKGShare::<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>>,
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();

    let sz = share.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = share.serialize(buf_ref);
    
    if behaviour.state == 3 {
        behaviour.floodsub.publish(TOPIC.clone(), buffer);
        behaviour.state = 4;
    }
}