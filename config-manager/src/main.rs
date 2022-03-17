use serde_json::Value;
use std::fs::File;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::broadcast,
};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct NodeAddresses{
    ports: Vec<i64>,
}

const CONFIG_FILE_PATH: &str = "src/config.json";
const CONFIG_MANAGER_ADDR: &str = "localhost:8080";

fn get_node_list() -> Vec<i64>{
    let config_file = File::open(CONFIG_FILE_PATH).expect("File should open in read-only mode.");
    let ports_json: NodeAddresses = serde_json::from_reader(config_file).expect("File is not a JSON file.");
    //let ports = &ports_json["ports"];
    let ports = &ports_json.ports;
    //let num_nodes = ports.as_object().unwrap().len();
    println!("ports {:?}", ports.clone()[0]);
    ports.to_vec()
}


//TO DO:
// completed when len(nodes) have sent back an acknowledgement message

#[tokio::main]
async fn main() {
    
    // await - suspend current task until this future is ready do be acted on
    let listener = TcpListener::bind(CONFIG_MANAGER_ADDR).await.unwrap(); 

    // broadcast channel - mpmc
    //let (tx, _rx) = broadcast::channel::<String>(10);
    let (tx, _rx) = broadcast::channel(10);

    loop{
        // accept - accepts this new incoming connection from the listener
        let (mut socket, addr) = listener.accept().await.unwrap();

        //get rx out of tx - using _rx doesn't work
        let tx = tx.clone();
        let mut rx = tx.subscribe();
        let node_list = get_node_list();
        tx.send((node_list.clone(), addr)).unwrap();

        //spawn a new tokio task
        tokio::spawn(async move {
            let (_reader, mut writer) = socket.split();
            
            loop{
                //SELECT good when you need to operate on same shared state
                // and finite number of things
                tokio::select!{
                    result = rx.recv() => {
                        let (msg, _addr) = result.unwrap();
                        let msg2 = msg as u8;
                        //write back to client, if not from this addr
                        writer.write_all(&msg).await.unwrap();  
                    }
                }
            }
        });
    }
}