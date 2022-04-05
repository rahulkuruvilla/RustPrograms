
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
        algebraic::{
            keypair::Keypair, 
            public_key::ProvenPublicKey, 
            signature::Signature, 
            srs::SRS as SigSRS
        },
    },
};
use ark_bls12_381::{Bls12_381, G2Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{UniformRand, Zero};
use ark_serialize::*;
use rand::{thread_rng};
use std::marker::PhantomData;

// libp2p imports--------------------------------------------------------
use libp2p::{
    core::upgrade,
    floodsub::{Floodsub, FloodsubEvent, Topic},
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
use tokio::{io::AsyncBufReadExt, sync::mpsc};

use rand_beacon::data::{DKGInit, VUFInit, VUFNodeData};
use rand_beacon::sig_srs::{SigSRSExt, KeypairExt};
use rand_beacon::keys::NodeExt;

static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("dkg"));

// data that gets sent to main loop
pub enum ChannelData{
    Party(Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>),
    Share(DKGShare::<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>>),
    AggregationReady(String),
    VUFReady(String),
    VUFData(VUFNodeData<Bls12_381>),
}

#[derive(Clone)]
pub struct NodeInfo{
    bls_sig: Option<BLSSignature::<BLSSignatureG1<Bls12_381>>>,
    bls_pok: Option<BLSSignature::<BLSSignatureG2<Bls12_381>>>,
    dealer: Option<Dealer<Bls12_381,BLSSignature<BLSSignatureG1<Bls12_381>>>>,
    participants: Option<Vec<Participant::<Bls12_381, BLSSignature<BLSSignatureG1<Bls12_381>>>>>,
    node: Option<Node<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>>>,
    share: Option<DKGShare::<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, BLSSignature<BLSSignatureG1<Bls12_381>>>>,
    dkg_pk_share: Option<ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g1::Parameters>>,
    dkg_sk_share: Option<ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bls12_381::g2::Parameters>>,
    vuf_init: Option<VUFInit<Bls12_381>>,
    vuf_keypair: Option<Keypair<Bls12_381>>,
    vuf_data: Option<VUFNodeData<Bls12_381>>,
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
    pub nodes_received: Vec<PeerId>,

    #[behaviour(ignore)]
    pub node_extra: NodeInfo,
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for NodeBehaviour {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        //message is a Vec<u8>
        if let FloodsubEvent::Message(message) = message {

            //assume this msg only comes from config manager only
            if let Ok(dkg_init) = DKGInit::<Bls12_381>::deserialize(&*message.data) {
                println!("rec dkg_init");
                println!("cm_id: {:?}", self.cm_id);
                println!("message.source: {:?}", message.source);
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
                    let participant = Participant::<Bls12_381, 
                        BLSSignature<BLSSignatureG1<Bls12_381>>> {
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
            
            if let Ok(ps) = Vec::<Participant::<Bls12_381, 
                BLSSignature<BLSSignatureG1<Bls12_381>>>>::deserialize(&*message.data) {
                if self.state == 2 && message.source == self.cm_id {
                    println!("Received participants struct from cm "); 
                    ps.iter().for_each(|p| println!("{}", p.id));
                    println!("ps.len()={}", ps.len());
                    println!("ps[0].id={}", ps[0].id);

                    self.state = 3;
                    let node_data = self.node_extra.clone();
                    let pok = node_data.bls_pok.unwrap();
                    let sig = node_data.bls_sig.unwrap();
                    let this_dealer = node_data.dealer.unwrap();

                    let degree: usize = self.dkg_init.dkg_config.degree.clone();
                    let num_sz: usize = self.dkg_init.num_nodes.clone();
                    let mut this_node: Node<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, 
                        BLSSignature<BLSSignatureG1<Bls12_381>>> = Node {
                        aggregator: DKGAggregator {
                            config: self.dkg_init.dkg_config.clone(),
                            scheme_pok: pok,
                            scheme_sig: sig,
                            participants: ps.clone().into_iter().enumerate().collect(),
                            transcript: DKGTranscript::empty(degree, num_sz),
                        },
                        dealer: this_dealer,
                    };
                    
                    let rng = &mut thread_rng();
                    let share = this_node.share(rng).unwrap();
                    this_node.receive_share_and_decrypt(rng, share.clone()).unwrap();
                    self.node_extra.node = Some(this_node);
                    self.node_extra.share = Some(share);

                    stage_channel_data(
                        self.response_sender.clone(), 
                        ChannelData::AggregationReady("Ready to aggregate".to_string())
                    )
                    
                }
            }

            if let Ok(msg) = serde_json::from_slice::<String>(&message.data) {
                match msg.as_str() {
                    "Begin Aggregation" => {
                        if self.state == 4 && message.source == self.cm_id {
                            let node_data = self.node_extra.clone();
                            let node_share = node_data.share.unwrap();
                            println!("staging dkg share");
                            stage_channel_data(
                                self.response_sender.clone(), 
                                ChannelData::Share(node_share),
                            );
                        }
                    }
                    _ => {}
                }
            }

            //aggregate received DKG share
            if let Ok(dkg_share) = DKGShare::<Bls12_381, BLSSignature<BLSSignatureG2<Bls12_381>>, 
                    BLSSignature<BLSSignatureG1<Bls12_381>>>::deserialize(&*message.data){
                let received_peer_id: PeerId = message.source;
                let received_before = self.nodes_received.iter().any(|&p| p == received_peer_id);

                println!("current state={}", self.state);
                if (self.state == 4 || self.state == 5) && !received_before {
                    println!("received fresh dkg share");
                    let rng = &mut thread_rng();
                    let node_data = self.node_extra.clone();
                    let mut node = node_data.node.unwrap();
                    node.receive_share_and_decrypt(rng, dkg_share).unwrap();

                    self.node_extra.node = Some(node.clone());
                    self.nodes_received.push(received_peer_id);
                    if self.nodes_received.len() == self.dkg_init.num_nodes{
                        self.nodes_received = [].to_vec();
                        println!("getting this node's pk and sk");

                        let pk = node.get_public_key().unwrap();
                        let sk = node.get_secret_key_share().unwrap();
                        self.node_extra.dkg_pk_share = Some(pk);
                        self.node_extra.dkg_sk_share = Some(sk);

                        //send msg to cm, ready to receive vuf_srs
                        stage_channel_data(
                          self.response_sender.clone(), 
                          ChannelData::VUFReady("Ready for VUF".to_string())
                        )
                    }
                }
            }

            // recv. vuf_srs and message from config manager
            if let Ok(vuf_init) = VUFInit::<Bls12_381>::deserialize(&*message.data) {
                if self.state == 6 && message.source == self.cm_id {
                    let node_pk = self.node_extra.dkg_pk_share.unwrap();
                    let node_sk = self.node_extra.dkg_sk_share.unwrap();
                    let vuf_msg = vuf_init.message.clone();
                    let msg = &vuf_msg[..];

                    let rng = &mut thread_rng();
                    let this_keypair = Keypair::generate_keypair_from_dkg(rng, vuf_init.vuf_srs.clone(), node_pk, node_sk).unwrap();
                    let this_proven_pk = this_keypair.prove_key().unwrap();  
                    let this_signature = this_keypair.sign(&msg[..]).unwrap();

                    self.node_extra.vuf_init = Some(vuf_init.clone());
                    let vuf_node_data = VUFNodeData{
                        proven_pk: this_proven_pk,
                        signature: this_signature,
                    };
                    self.node_extra.vuf_keypair = Some(this_keypair);
                    self.node_extra.vuf_data = Some(vuf_node_data.clone());

                    //send msg to cm, ready to receive vuf_srs
                    stage_channel_data(
                        self.response_sender.clone(), 
                        ChannelData::VUFData(vuf_node_data)
                    )
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
            nodes_received: [this_id].to_vec(),
            node_extra: NodeInfo{
                bls_sig: None,
                bls_pok: None,
                dealer: None,
                participants: None,
                node: None,
                share: None,
                dkg_pk_share: None,
                dkg_sk_share: None,
                vuf_init: None,
                vuf_keypair: None,
                vuf_data: None,
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
    //let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
  
    loop {
        tokio::select! {
            //received from stdin 
            /*line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                println!("line: {:?}", &line);
                //swarm.behaviour_mut().floodsub.publish(TOPIC.clone(), line.as_bytes());
                match line.as_str(){
                    "check" => {
                        check_state(&mut swarm).await;
                    },
                    "ls" => {
                        list_peers(&mut swarm).await;
                    },
                    _ => {},
                }
            }*/
            
            // received from the channel
            response = response_rcv.recv() => {
                //let json = serde_json::to_string(&response).expect("can jsonify response");
                println!("received data on channel");
                //swarm.behaviour_mut().floodsub.publish(TOPIC.clone(), json.into_bytes());

                //match on 
                match response {
                    Some(ChannelData::Party(participant)) => {
                        println!("participant is going to be sent");
                        send_participant(participant, &mut swarm).await;
                    }
                    Some(ChannelData::AggregationReady(msg)) => {
                        println!("AggregationReady msg going to be sent");
                        send_message(msg, &mut swarm, 3, 4).await;
                    }
                    Some(ChannelData::Share(dkg_share)) => {
                        println!("dkg_share going to be sent");
                        send_dkg_share(dkg_share, &mut swarm).await;
                    }
                    Some(ChannelData::VUFReady(msg)) => {
                        println!("ready for vuf going to be sent");
                        send_message(msg, &mut swarm, 5, 6).await; //needs to be in state 4 or 5
                    }
                    Some(ChannelData::VUFData(vuf_node_data)) => {
                        println!("proven pk and sig going to be sent");
                        send_vuf_data(vuf_node_data, &mut swarm).await;
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

async fn send_message(
    msg: String,
    swarm: &mut Swarm<NodeBehaviour>,
    start_state: usize,
    end_state: usize
){
    let behaviour = swarm.behaviour_mut();
    let json_data = serde_json::to_string(&msg).expect("Can't serialize to json!");
    
    println!("current node state ={}", behaviour.state);
    if behaviour.state == start_state {
        println!("going to be published to the network: {}", msg);
        behaviour.floodsub.publish(TOPIC.clone(), json_data.as_bytes());
        behaviour.state = end_state;
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
    
    //these states need to be changed
    println!("state before sending dkg share out (should be 4): {}", behaviour.state);
    if behaviour.state == 4 {
        behaviour.floodsub.publish(TOPIC.clone(), buffer);
        println!("dkg share sent out");
        behaviour.state = 5;
    }
}

async fn send_vuf_data(
    vuf_data: VUFNodeData<Bls12_381>,
    swarm: &mut Swarm<NodeBehaviour>
){
    let behaviour = swarm.behaviour_mut();

    let sz = vuf_data.serialized_size();
    let mut buffer = Vec::with_capacity(sz); 
    let buf_ref = buffer.by_ref();
    let _ = vuf_data.serialize(buf_ref);
    
    if behaviour.state == 6 {
        behaviour.floodsub.publish(TOPIC.clone(), buffer);
    }
}
