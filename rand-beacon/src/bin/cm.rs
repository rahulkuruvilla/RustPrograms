
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
use rand::{thread_rng};
use std::{
    error::Error,
    collections::HashSet,
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

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
use once_cell::sync::Lazy;
use tokio::{fs, io::AsyncBufReadExt, sync::mpsc};

use rand_beacon::data::DKGInit;

static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("dkg"));

// data that gets sent to main loop
pub enum ChannelData{
    Participants(Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>),
    Empty,
}

// We create a custom network behaviour that combines floodsub and mDNS.
// The derive generates a delegating `NetworkBehaviour` impl which in turn
// requires the implementations of `NetworkBehaviourEventProcess` for
// the events of each behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct NodeBehaviour<E: PairingEngine> {
    pub floodsub: Floodsub,
    pub mdns: Mdns,

    #[behaviour(ignore)]
    pub response_sender: mpsc::UnboundedSender<ChannelData>,

    #[behaviour(ignore)]
    pub state: usize,

    #[behaviour(ignore)]
    pub dkg_init: DKGInit<E>,

    #[behaviour(ignore)]
    pub cm_id: PeerId,

    #[behaviour(ignore)]
    pub node_id: PeerId,

    #[behaviour(ignore)]
    pub participant_id: usize,

    #[behaviour(ignore)]
    pub node_list: Vec<PeerId>,

    #[behaviour(ignore)]
    pub nodes_received: Vec<PeerId>,

    #[behaviour(ignore)]
    //pub participants: ParticipantsData,
    pub participants: Option<Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>>
    //pub participants: CMData,
}

impl<E: PairingEngine> NetworkBehaviourEventProcess<FloodsubEvent> for NodeBehaviour<E> {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        //message is a Vec<u8>
        if let FloodsubEvent::Message(message) = message {

            if let Ok(a_participant) = Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>::deserialize(&*message.data) {
                let received_peer_id: PeerId = message.source;
                let received_before = self.nodes_received.iter().any(|&p| p == received_peer_id);
                println!("Participant received from:{}, received_before:{}", &received_peer_id, &received_before);
                //if not rec before then append to self.nodes_rec

                // if haven't received this participant struct before
                if self.state == 1 && !received_before {
                    println!("In this section");
                    self.nodes_received.push(received_peer_id);
                    match self.participants.clone(){
                        Some(ps) => {
                            let mut ps_updated = ps.clone();
                            ps_updated.push(a_participant);
                            ps_updated.sort_by(|a, b| a.id.cmp(&b.id));
                            ps_updated.iter().for_each(|p| println!("{}", p.id)); 
                            self.participants = Some(ps_updated.clone());
                            //self.nodes_received.push(received_peer_id);
                            
                            // check if received all participants structs from all nodes
                            //println!("\n{} {}", &self.nodes_received.len(), &self.dkg_init.num_nodes);
                            if self.nodes_received.len() == self.dkg_init.num_nodes{
                                //print ps here + sort ps here
                                //p.sort_by(|a, b| b.age.cmp(&a.age));

                                self.nodes_received = [].to_vec();
                                stage_channel_data(
                                    self.response_sender.clone(), 
                                    ChannelData::Participants(ps_updated),
                                );
                            }

                        }
                        None => {
                            let mut ps = Vec::new();
                            ps.push(a_participant);
                            self.participants = Some(ps)
                            //assume 1 node cannot do a DKG on their own
                        }
                    }
                }
            }
        }
    }
        
}


impl<E: PairingEngine> NetworkBehaviourEventProcess<MdnsEvent> for NodeBehaviour<E> {
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
        let mut behaviour = NodeBehaviour::<Bls12_381> {
            floodsub: Floodsub::new(peer_id.clone()),
            mdns,
            response_sender,
            state,
            dkg_init,
            cm_id: this_id,
            node_id: this_id,
            participant_id: 0,
            node_list: [this_id].to_vec(),
            nodes_received: [].to_vec(),
            participants: None,
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
                    let peers = handle_list_peers(&mut swarm).await;
                    init_dkg(peers, &mut swarm).await;
                }else if line == "check"{
                    check_state(&mut swarm).await;
                }else if line == "ls"{
                    handle_list_peers(&mut swarm).await;
                }
            }
            
            // received from the channel
            response = response_rcv.recv() => {
                //let json = serde_json::to_string(&response).expect("can jsonify response");
                println!("received");
                //swarm.behaviour_mut().floodsub.publish(TOPIC.clone(), json.into_bytes());

                //match on 
                match response {
                    Some(ChannelData::Participants(participants)) => {
                        println!("participants being sent to nodes");
                        send_participants(participants, &mut swarm).await;
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


async fn handle_list_peers(swarm: &mut Swarm<NodeBehaviour<Bls12_381>>) -> Vec<Vec<u8>>{
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
async fn check_state<E: PairingEngine>(swarm: &mut Swarm<NodeBehaviour<E>>) {
    println!("Checking state");
    let behaviour = swarm.behaviour_mut();
    println!("This node's state is {}", behaviour.state);
}


// cm runs this when all nodes connected
async fn init_dkg(connected_peers: Vec<Vec<u8>>, swarm: &mut Swarm<NodeBehaviour<Bls12_381>>){
    let behaviour = swarm.behaviour_mut();
    if behaviour.state != 0 {
        return
    }

    println!("This config manager is starting the DKG!");
    let num_nodes: usize = 2; 
    let rng = &mut thread_rng();
    let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();
    let u_1 = G2Projective::rand(rng).into_affine();
    let degree = 2;

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

async fn send_participants(
    participants: Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>, 
    swarm: &mut Swarm<NodeBehaviour<Bls12_381>>
){
    let behaviour = swarm.behaviour_mut();

    // THIS NEEDS TO BE DONE FOR ALL ITEMS IN THE PARTICIPANTS LIST!!!!
    let sz = participants.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = participants.serialize(buf_ref);
    
    if behaviour.state == 1 {
        behaviour.floodsub.publish(TOPIC.clone(), buffer);
        behaviour.state = 2;
        println!("published");
    }
}
