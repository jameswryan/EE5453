use std::fs;
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;

use clap::Parser;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key,
};

// Alias all cryptography behind 'Crypto<TYPE>',
// so it can be changed easily
type CryptoAead = ChaCha20Poly1305;

#[derive(Parser)]
struct Cli {
    /// Port to listen on.
    #[clap(short, long, value_parser, default_value_t = 0xBEEF)]
    port: u16,
}

fn handle_connection(mut stream: TcpStream, key: Key) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut stream);

    // Read path from stream
    let mut buf = String::new();
    match reader.read_line(&mut buf) {
        Ok(_) => {
            /* Don't care about size of fpath */
            // Strip trailing newline
            buf = buf[..buf.len() - 1].into();
            eprintln!("Client asked for {buf:#?}");
        }
        Err(e) => return Err(e),
    }

    // Convert received string to path
    let fpath = PathBuf::from(buf.clone());

    // We only serve files in the cwd, so strip to just the filename
    // If no filename (i.e., fpath ends in '/'), print to stderr and don't send anything
    let fname = match fpath.file_name() {
        Some(name) => name,
        None => {
            eprintln!("Couldn't find a filename in {}", fpath.display());
            return Ok(());
        }
    };

    // If the file is present in the cwd, send it over.
    let file_bytes = fs::read(fname)?;

    let payload = Payload {
        msg: &file_bytes,
        aad: buf.as_bytes(),
    };

    let cipher = CryptoAead::new(&key);
    let nonce = CryptoAead::generate_nonce(&mut OsRng);
    let ciphertext = match cipher.encrypt(&nonce, payload) {
        Ok(ct) => ct,
        Err(e) => {
            eprintln!("ERROR in encryption: {e}");
            return Ok(());
        }
    };

    // Byte string to be sent over network
    // Consists of 24-byte nonce, followed by ciphertext
    let mut network_bytes = Vec::new();
    network_bytes.extend(nonce);
    network_bytes.extend(ciphertext);

    stream.write_all(&network_bytes)?;

    Ok(())
}

fn main() {
    // Check cli args for port to listen on
    let args = Cli::parse();
    let port = args.port;

    let sckt_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

    // Generate secure random bytes for key
    // OsRng uses /dev/(u)random, which on linux 5.18+ is really good.
    let key = CryptoAead::generate_key(&mut OsRng);

    // Write hex encoded key to stdout for use in clients
    let key_hex = hex::encode(key);
    println!("Key: {key_hex}");

    // Client -> Server listener
    let in_listener = TcpListener::bind(sckt_addr).expect("Binding Failed!");

    for stream in in_listener.incoming() {
        match stream {
            Ok(stream) => match handle_connection(stream, key) {
                Ok(_) => { /* Another job well done! */ }
                Err(e) => eprintln!("ERROR: {e}"),
            },
            Err(e) => {
                eprintln!("ERROR: Bad Connection\n{e}");
            }
        }
    }
}
