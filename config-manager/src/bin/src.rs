use std::fs::File;
use serde::{Serialize, Deserialize};
use serde_json::Result;

#[derive(Serialize, Deserialize)]
struct NodeAddresses{
    ports: Vec<i64>,
}

const CONFIG_FILE_PATH: &str = "src/config.json";
const CONFIG_MANAGER_ADDR: &str = "localhost:8080";

fn main() -> Result<()>{
    let config_file = File::open(CONFIG_FILE_PATH).expect("File should open in read-only mode.");
    let ports_json: NodeAddresses = serde_json::from_reader(config_file).expect("File is not a JSON file.");
    //let ports = &ports_json["ports"];
    let ports = &ports_json.ports;
    //let num_nodes = ports.as_object().unwrap().len();
    println!("ports {:?}", ports.clone());
    ports.to_vec();

    Ok(())
    
}
