use tokio::net::{TcpStream, TcpListener};
use tokio::io::AsyncReadExt;
use std::error::Error;
use std::str;

const CONFIG_MANAGER_ADDR: &str = "localhost:8080";
const NODE_ADDR: &str = "localhost:5443";

// FIRST: CONNECT TO CONFIG MANAGER & GET NODE LIST (DONE)
// SECOND: NODE STARTS ITS OWN TCP SERVER
// THIRD: NODE TELLS CONFIG MANAGER IT'S READY

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to a peer
    let stream = TcpStream::connect(CONFIG_MANAGER_ADDR).await?;

    // Wait for the socket to be readable
    // Good if config manager not ready yet
    stream.readable().await?;

    // Creating the buffer the await
    let mut buffer = Vec::with_capacity(4096);

    // Try to read data, this may still fail with `WouldBlock`
    // if the readiness event is a false positive.
    match stream.try_read_buf(&mut buffer) {
        Ok(n) => {
            println!("read {} bytes", n);
        }
        Err(e) => {
            return Err(e.into());
        }
    }

    let ports = str::from_utf8(&buffer).unwrap();
    println!("Recieved from config manager {:?}", ports);

    // NODE STARTS ITS OWN TCP SERVER
    //let node_listener = TcpListener::bind(NODE_ADDR).await.unwrap(); 

    Ok(())
}
