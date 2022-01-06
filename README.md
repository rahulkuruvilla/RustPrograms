# RustPrograms
Collection of Rust programs

To run enum-passing:

 ```bash
$ cd enum-passing && cargo run 
 ```

To run  broadcaster: 

```bash
$ cd broadcaster && cargo run
```

The server will appear to hang, this means the server is running. Leave the server running in the background.

In a new terminal instance, connect to the TCP server:

```bash
$ telnet localhost 8080
```

Note: telnet needs to be installed for this to work.

Multiple clients can connect to the server, by running the previous command as many times as needed, in a fresh terminal window.

The TCP server will broadcast messages it recieves from a single client to all client instances connected to it.

