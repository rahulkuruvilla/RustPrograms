
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
use ark_ec::ProjectiveCurve;
use ark_ff::UniformRand;
use ark_serialize::*;
use rand::{thread_rng};
use std::{
    error::Error,
    collections::{HashSet, hash_map::DefaultHasher},
    time::{Instant, Duration},
    hash::{Hash, Hasher},
    env,
};

// libp2p imports--------------------------------------------------------
use libp2p::{
    core::upgrade,
    //floodsub::{Floodsub, FloodsubEvent, Topic},
    gossipsub::{
        Gossipsub, GossipsubEvent, GossipsubConfigBuilder, 
        GossipsubMessage, IdentTopic as Topic,
        MessageAuthenticity, ValidationMode, MessageId},
    futures::StreamExt,
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise,
    swarm::{NetworkBehaviourEventProcess, SwarmEvent, Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    NetworkBehaviour, PeerId, Transport,
    multihash::{Code, MultihashDigest},
};
use log::error;
use once_cell::sync::Lazy;
use tokio::{io::AsyncBufReadExt, sync::mpsc};

use rand_beacon::data::{DKGInit, VUFInit, VUFNodeData, VUFNodesData};
use rand_beacon::sig_srs::SigSRSExt;

static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("dkg"));

// data that gets sent to main loop
pub enum ChannelData{
    Participants(Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>),
    StartAggregation(String),
    VUFData(VUFInit<Bls12_381>),
    Empty,
}

// We create a custom network behaviour that combines floodsub and mDNS.
// The derive generates a delegating `NetworkBehaviour` impl which in turn
// requires the implementations of `NetworkBehaviourEventProcess` for
// the events of each behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct NodeBehaviour {
    pub gossipsub: Gossipsub,
    pub mdns: Mdns,

    #[behaviour(ignore)]
    pub response_sender: mpsc::UnboundedSender<ChannelData>,

    #[behaviour(ignore)]
    pub state: usize,

    #[behaviour(ignore)]
    pub start_time: Option<Instant>,

    #[behaviour(ignore)]
    pub dkg_init: DKGInit<Bls12_381>,       //USE OPTION ENUM HERE AND REMOVE DEFAULT() TRAIT/pass in n,t

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
    pub participants: Option<Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>>,

    #[behaviour(ignore)]
    pub vuf_data: Option<VUFInit::<Bls12_381>>,

    #[behaviour(ignore)]
    pub vuf_sigs_pks: VUFNodesData::<Bls12_381>,
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for NodeBehaviour{
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: GossipsubEvent) {
        //message is a Vec<u8>
        if let GossipsubEvent::Message{propagation_source, message_id, message} = message {
            println!("Received gossipsub message from {:?}", message.source.unwrap());

            if let Ok(a_participant) = Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>::deserialize(&*message.data) {
                let received_peer_id: PeerId = message.source.unwrap();
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
                            
                            // check if received all participants structs from all nodes
                            println!("\n{} {}", &self.nodes_received.len(), &self.dkg_init.num_nodes);
                            if self.nodes_received.len() == self.dkg_init.num_nodes{

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

            if let Ok(msg) = serde_json::from_slice::<String>(&message.data) {
                let received_peer_id: PeerId = message.source.unwrap();
                println!("current nodes_received: {:?}", self.nodes_received.len());
                let received_before = self.nodes_received.iter().any(|&p| p == received_peer_id);
                println!("received msg={}", msg);
                match msg.as_str() {
                    "Ready to aggregate" => {
                        println!("been received before: {}", received_before);
                        if self.state == 2 && !received_before {
                            self.nodes_received.push(received_peer_id);
                            if self.nodes_received.len() == self.dkg_init.num_nodes{
                            //if self.nodes_received.len() == self.dkg_init.dkg_config.degree{
                                self.nodes_received = [].to_vec();
                                stage_channel_data(
                                    self.response_sender.clone(), 
                                    ChannelData::StartAggregation("Begin Aggregation".to_string()),
                                );
                            }
                        }

                    }
                    "Ready for VUF" => {
                        if self.state == 3 && !received_before {
                            self.nodes_received.push(received_peer_id);
                            if self.nodes_received.len() == self.dkg_init.num_nodes{
                                self.nodes_received = [].to_vec();

                                /*
                                let rng = &mut thread_rng();
                                let dkg_srs = self.dkg_init.dkg_config.srs.clone();
                                let vuf_srs = SigSRS::<Bls12_381>::setup_from_dkg(rng, dkg_srs.clone()).unwrap();
                                let vuf_msg = b"hello";
                                let vuf_init = VUFInit {
                                    vuf_srs: vuf_srs,
                                    message: vuf_msg.to_vec(),
                                };
                                self.vuf_data = Some(vuf_init.clone());

                                stage_channel_data(
                                    self.response_sender.clone(), 
                                    ChannelData::VUFData(vuf_init),
                                );
                                */
                                self.state = 4;
                                println!("DKG protocol completed.");

                                // get time elapsed from start of DKG
                                let start_time = self.start_time.clone();
                                let this_start_time = start_time.unwrap();
                                let elapsed = this_start_time.elapsed();
                                println!("Time taken for DKG: {:?}", elapsed);
                            }
                        }
                    }
                    _ => {}
                }
            }

            if let Ok(node_sig) = VUFNodeData::<Bls12_381>::deserialize(&*message.data) {
                let received_peer_id: PeerId = message.source.unwrap();
                let received_before = self.nodes_received.iter().any(|&p| p == received_peer_id);

                if self.state == 5 && !received_before {
                    println!("Received signature and proven pk from node!");
                    self.nodes_received = vec![];
                    let cm_vuf_data = self.vuf_data.clone();
                    let vuf_data = cm_vuf_data.unwrap();
                    let vuf_msg = vuf_data.message;
                    let msg = &vuf_msg[..];

                    let this_proven_pk = node_sig.proven_pk;
                    let this_sig = node_sig.signature;

                    // TO DO: MATCH ON THIS UNWRAP                                                                                                                                  
                    this_proven_pk.verify().unwrap();
                    this_sig.verify_and_derive(this_proven_pk.clone(), &msg[..]).unwrap();

                    let mut current_proven_pks = self.vuf_sigs_pks.proven_pks.clone();
                    let mut current_sigs = self.vuf_sigs_pks.signatures.clone();
                    current_sigs.push(this_sig);
                    current_proven_pks.push(this_proven_pk); 
                    self.vuf_sigs_pks.signatures = current_sigs.clone();
                    self.vuf_sigs_pks.proven_pks = current_proven_pks.clone();

                    // threshold of signatures reached
                    let threshold = self.dkg_init.dkg_config.degree;
                    if self.vuf_sigs_pks.signatures.len() == threshold {
                        let vuf_srs = vuf_data.vuf_srs;
                        let aggregated_pk = ProvenPublicKey::aggregate(&current_proven_pks[0..threshold], vuf_srs.clone()).unwrap();
                        let aggregated_sig = Signature::aggregate(&current_sigs[0..threshold]).unwrap();

                        aggregated_sig.verify_and_derive(aggregated_pk, msg).unwrap();

                        let mut buffer = Vec::new(); 
                        aggregated_sig.serialize(&mut buffer).unwrap();
                        println!("sigma={:?}\n", &buffer);

                        // get time elapsed from start of DKG
                        let start_time = self.start_time.clone();
                        let this_start_time = start_time.unwrap();
                        let elapsed = this_start_time.elapsed();

                        // hash buffer containing aggregated signature
                        let to_hash = &buffer[..];
                        let multi_hash = Code::Sha2_256.digest(to_hash);
                        let hash = multi_hash.digest();
                        println!("sha2_256(sigma)={:02x?}", hash);
                        println!("Total time taken for VUF: {:?}", elapsed);

                        self.vuf_sigs_pks.signatures = vec![];
                        self.vuf_sigs_pks.proven_pks = vec![];
                        self.state = 4;
                    }
                }
            }
        }
    }
        
}


impl NetworkBehaviourEventProcess<MdnsEvent> for NodeBehaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    self.gossipsub.add_explicit_peer(&peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        self.gossipsub.remove_explicit_peer(&peer);
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
    let args: Vec<String> = env::args().collect();
    let t = &args[1];
    let n = &args[2];
    let degree: usize = t.parse().unwrap();
    let num_nodes: usize = n.parse().unwrap();

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

        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &GossipsubMessage| {
            let mut h = DefaultHasher::new();
            let mut source = message.source.unwrap().to_bytes();
            let mut data = message.data.clone();
            source.append(&mut data);
            source.hash(&mut h);
            MessageId::from(h.finish().to_string())
        };

        // Set a custom gossipsub
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
            .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .build()
            .expect("Valid config");

        // build a gossipsub network behaviour
        let gossipsub: Gossipsub =
            Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
                .expect("Correct configuration");

        let mut behaviour = NodeBehaviour {
            gossipsub,
            mdns,
            response_sender,
            state,
            start_time: None,
            dkg_init,
            cm_id: this_id,
            node_id: this_id,
            participant_id: 0,
            node_list: vec![this_id],
            nodes_received: vec![],
            participants: None,
            vuf_data: None,
            vuf_sigs_pks: VUFNodesData {
                proven_pks: vec![],
                signatures: vec![],
            },
        };

        behaviour.gossipsub.subscribe(&TOPIC).unwrap();

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
  
    loop {
        tokio::select! {
            //received from stdin
            line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                println!("line: {:?}", &line);
                let input: Vec<&str> = line.as_str().split(" ").collect();
                let first_cmd = input.get(0).unwrap().clone();
                match first_cmd {
                    "start"  => {
                        let start = Instant::now();
                        swarm.behaviour_mut().start_time = Some(start);
                        let peers = handle_list_peers(&mut swarm, &num_nodes).await;
                        init_dkg(degree, num_nodes, peers, &mut swarm).await;
                    },
                    "sign" => {
                        let start = Instant::now();
                        swarm.behaviour_mut().start_time = Some(start);
                        let to_sign = input.get(1..input.len()); 
                        match to_sign {
                            Some(msg) => {
                                let data: String = msg.join(" ");
                                println!("msg={}", data);
                                init_vuf(data.as_bytes().to_vec(), &mut swarm).await;
                            }
                            None => {
                                println!("ERROR: No message to sign found!");
                            }
                        }
                    },
                    "check" => {
                        check_state(&mut swarm).await;
                    },
                    "ls" => {
                        handle_list_peers(&mut swarm, &num_nodes).await;
                    },
                    _ => {},
                }
            }
            
            // received from the channel
            response = response_rcv.recv() => {
                println!("received");
                match response {
                    Some(ChannelData::Participants(participants)) => {
                        println!("participants being sent to nodes");
                        send_participants(participants, &mut swarm).await;
                    }
                    Some(ChannelData::StartAggregation(msg)) => {
                        println!("start agg. msg being sent to nodes");
                        send_message(msg, &mut swarm, 2, 3).await;
                    }
                    //Some(ChannelData::VUFData(vuf_init)) => {
                    //    println!("vuf_init data being sent to nodes");
                    //    send_vuf_init(vuf_init, &mut swarm).await;
                    //}
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

async fn handle_list_peers(
    swarm: &mut Swarm<NodeBehaviour>, 
    num_nodes: &usize
) -> Vec<Vec<u8>>{
    println!("Discovered Peers:");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut bytes = vec![];
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }

    let all_nodes = Vec::from_iter(unique_peers);
    println!("{:?}", all_nodes);
    println!("Connected to {:?} Nodes!", all_nodes.len());
    //assert_eq!(all_nodes.len(), *num_nodes);
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
async fn init_dkg(
    degree: usize, 
    num_nodes: usize, 
    connected_peers: Vec<Vec<u8>>, 
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();
    if behaviour.state != 0 {
        return
    }

    println!("This config manager is starting the DKG!");
    let rng = &mut thread_rng();
    let dkg_srs = DkgSRS::<Bls12_381>::setup(rng).unwrap();
    let u_1 = G2Projective::rand(rng).into_affine();

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
    
    if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), buffer){
        error!("ERROR: DKGInit not published! {:?}", e);
    }
    println!("published");

    behaviour.state = 1;
    behaviour.dkg_init = cm_dkg_init;

}

async fn send_participants(
    participants: Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>, 
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();

    let sz = participants.serialized_size();
    println!("This Size(Participants)={:?}", sz);
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = participants.serialize(buf_ref);
    
    if behaviour.state == 1 {
        if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), buffer){
            error!("ERROR: Participants not published! {:?}", e);
        }
        behaviour.state = 2;
        println!("published");
    }
}

async fn send_message(
    msg: String,
    swarm: &mut Swarm<NodeBehaviour>,
    start_state: usize,
    end_state: usize
){
    let behaviour = swarm.behaviour_mut();
    let json_data = serde_json::to_string(&msg).expect("Can't serialize to json!");
    
    if behaviour.state == start_state {
        if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), json_data.as_bytes()){
            error!("ERROR: Message not published! {:?}", e);
        }
        behaviour.state = end_state;
    }
}

async fn init_vuf(
    vuf_msg: Vec<u8>,
    swarm: &mut Swarm<NodeBehaviour>,
){
    let behaviour = swarm.behaviour_mut();
    if behaviour.state != 4 {
        return
    }
    println!("This config manager is starting the VUF!");

    let rng = &mut thread_rng();
    let dkg_srs = behaviour.dkg_init.dkg_config.srs.clone();
    let vuf_srs = SigSRS::<Bls12_381>::setup_from_dkg(rng, dkg_srs.clone()).unwrap();
    //let vuf_msg = b"hello";
    let vuf_init = VUFInit {
        vuf_srs: vuf_srs,
        message: vuf_msg,
    };
    behaviour.vuf_data = Some(vuf_init.clone());
    
    let sz = vuf_init.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = vuf_init.serialize(buf_ref);
    
    if behaviour.state == 4{
        if let Err(e) = behaviour.gossipsub.publish(TOPIC.clone(), buffer){
            error!("ERROR: VUFInit not published! {:?}", e);
        }
        behaviour.state = 5;
    }
}