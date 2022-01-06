
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::broadcast,
};

// BASIC ASYNCHRONOUS TCP ECHO SERVER
// server can be run with: $ cargo run server
// server can be tested with multiple client instances of: $ telnet localhost 8080 
// messages made to the server by a single client will be broadcasted to all other client instances

//future - doesn't have a known value yet (pending) but may later
#[tokio::main]
async fn main() {
    
    // await - suspend current task until this future is ready do be acted on
    let listener = TcpListener::bind("localhost:8080").await.unwrap(); 

    // broadcast channel - mpmc
    //let (tx, _rx) = broadcast::channel::<String>(10);
    let (tx, _rx) = broadcast::channel(10);

    loop{
        // accept - accepts this new incoming connection from the listener
        let (mut socket, addr) = listener.accept().await.unwrap();

        //get rx out of tx - using _rx doesn't work
        let tx = tx.clone();
        let mut rx = tx.subscribe();

        //spawn a new tokio task
        tokio::spawn(async move {
            let (reader, mut writer) = socket.split();
            let mut reader = BufReader::new(reader);
            let mut line  = String::new();

            loop{
                //SELECT good when you need to operate on same shared state
                // and finite number of things
                tokio::select!{
                    //SELECT: do after =, assign value, then run code block
                    //read line from client
                    result = reader.read_line(&mut line) => {
                         // reader reached eof
                        if result.unwrap() == 0{
                            break;
                        }

                        tx.send((line.clone(), addr)).unwrap();
                        line.clear();
                    }
                    result = rx.recv() => {
                        let (msg, other_addr) = result.unwrap();
                        
                        //write back to client, if not from this addr
                        if addr != other_addr{
                            writer.write_all(msg.as_bytes()).await.unwrap();
                        }
                    }
                }
            }
        });
    }
}
