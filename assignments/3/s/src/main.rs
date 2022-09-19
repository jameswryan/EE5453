use std::fs;
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;

use aes_gcm::{
    aead::{consts::U12, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json;

// Alias all cryptography behind 'Crypto<TYPE>',
// so it can be changed easily
type CryptoAead = Aes256Gcm;
type CryptoKey = Key<CryptoAead>;

// Key / nonce size for AES-GCM
const NONCE_SIZE: usize = 12;
type NonceSize = U12;

#[derive(Parser)]
struct Cli {
    /// Port to listen on.
    #[clap(short, long, value_parser, default_value_t = 0xBEEF)]
    port: u16,
}

#[derive(Serialize, Deserialize)]
struct FileWithName {
    name: String,
    contents: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum Request {
    Put(FileWithName),
    Get(String),
}

fn handle_get_request(
    mut stream: TcpStream,
    name: String,
    cipher: CryptoAead,
) -> std::io::Result<()> {
    // Convert received string to path
    let fpath = PathBuf::from(name);

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

    let nonce = CryptoAead::generate_nonce(&mut OsRng);
    let ciphertext = match cipher.encrypt(&nonce, file_bytes.as_slice()) {
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

fn handle_put_request(file: FileWithName) -> std::io::Result<()> {
    // Extract name from FileWithName
    let fpath = PathBuf::from(file.name);

    // We only serve files in the cwd, so strip to just the filename
    // If no filename (i.e., fpath ends in '/'), print to stderr and stop
    let fname = match fpath.file_name() {
        Some(name) => name,
        None => {
            eprintln!("Couldn't find a filename in {}", fpath.display());
            return Ok(());
        }
    };

    //
    fs::write(fname, file.contents)?;

    Ok(())
}

fn handle_connection(mut stream: TcpStream, key: CryptoKey) -> std::io::Result<()> {
    // Read encrypted request from stream
    let mut buf = Vec::<u8>::new();
    stream.read_to_end(&mut buf)?;

    eprintln!("{}", buf.len());
    // Make sure we were sent at least a nonce
    if buf.len() < NONCE_SIZE {
        eprintln!("Received short message!");
        return Ok(());
    }

    // Extract nonce & ciphertext (first NONCE_SIZE bytes) from buf
    let (nonce, ciphertext): (Nonce<NonceSize>, Vec<u8>) = (
        *Nonce::from_slice(&buf[..NONCE_SIZE]),
        buf[NONCE_SIZE..].into(),
    );

    // Decrypt received request
    let cipher = CryptoAead::new(&key);
    let request_bytes = match cipher.decrypt(&nonce, ciphertext.as_slice()) {
        Ok(pt) => pt,
        Err(e) => {
            eprintln!("Decryption Error {e}!");
            return Ok(());
        }
    };

    // received ciphertext has been authenticated, safe to use plaintext

    // Deserialize request
    let request = serde_json::from_slice(request_bytes.as_slice())?;

    // Handle request
    match request {
        Request::Get(name) => handle_get_request(stream, name, cipher),
        Request::Put(file) => handle_put_request(file),
    }
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
