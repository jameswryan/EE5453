use std::fs;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};

use aes_gcm::{
    aead::{consts::U12, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json;

// Alias all cryptography behind 'Crypto<TYPE>'
// so it can be changed easily
type CryptoAead = Aes256Gcm;

// Key / nonce size for AES-GCM
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
type NonceSize = U12;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum RequestType {
    Put,
    Get,
}
#[derive(Parser)]
struct Cli {
    /// Type of request to make
    #[clap(short, long, arg_enum, value_parser)]
    request: RequestType,

    /// File to put/get
    #[clap(short, long, value_parser)]
    file: String,

    /// Shared secret from server
    #[clap(short, long, value_parser)]
    secret: String,

    /// IPv4 address to connect to.
    #[clap(short, long, value_parser, default_value_t=Ipv4Addr::new(0,0,0,0))]
    address: Ipv4Addr,

    /// Port to connect to.
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

/// Parse hex string into key for CryptoAead
/// If a bad key string is given, nothing useful can be done, so this function panics on error
fn hex_to_key(s: String) -> Key<CryptoAead> {
    let key_bytes = match hex::decode(s) {
        Ok(k) => k,
        Err(e) => panic!("ERROR when parsing secret: {e}"),
    };

    if key_bytes.len() != KEY_SIZE {
        panic!("ERROR: Incorrect key size!");
    }

    let key = *Key::<CryptoAead>::from_slice(&key_bytes);

    key
}

/// Encrypt payload with key, send over stream
/// Panics if error occurs in encryption or when writing to stream
fn send_encrypted_bytes(stream: &mut TcpStream, payload: &[u8], key: Key<CryptoAead>) {
    let cipher = CryptoAead::new(&key);
    // No AD, only payload
    let nonce = CryptoAead::generate_nonce(OsRng);
    let ciphertext = cipher.encrypt(&nonce, payload).expect("Encryption Error!");

    // Send to server
    let mut network_bytes = Vec::new();
    network_bytes.extend(nonce);
    network_bytes.extend(ciphertext);
    println!("{}", network_bytes.len());
    stream
        .write_all(&network_bytes)
        .expect("Stream write Error!");
}

/// Get the file 'filename' from the server, and write it to the cwd
fn get_from_server(
    mut stream: TcpStream,
    filename: String,
    key: Key<CryptoAead>,
) -> std::io::Result<()> {
    // Construct GET request
    let request = Request::Get(filename.clone());

    let request_bytes = serde_json::to_vec(&request)?;
    // Send request to server
    send_encrypted_bytes(&mut stream, request_bytes.as_slice(), key);

    // Don't need to write again, close client side of connection
    stream.shutdown(Shutdown::Write)?;

    // Get file contents from server
    let mut buf = Vec::<u8>::new();
    stream.read_to_end(&mut buf)?;

    // Make sure we were sent at least a nonce
    if buf.len() < NONCE_SIZE {
        eprintln!("The server closed the connecting without sending anything!");
        return Ok(());
    }

    // Extract nonce & ciphertext (first CryptoAead::NONCE_size bytes) from buf
    // We know we have at least NONCE_SIZE bytes from the check before
    let (nonce, ciphertext): (Nonce<NonceSize>, Vec<u8>) = (
        *Nonce::from_slice(&buf[..NONCE_SIZE]),
        buf[NONCE_SIZE..].into(),
    );

    // Decrypt payload
    let cipher = CryptoAead::new(&key);
    let file_bytes = match cipher.decrypt(&nonce, ciphertext.as_slice()) {
        Ok(pt) => pt,
        Err(e) => {
            panic!("ERROR in Decryption: {e}");
        }
    };

    // Payload has been authenticated, safe to use plaintext

    // Write decrypted file to filesystem
    fs::write(filename, file_bytes)?;
    Ok(())
}

/// Put the file 'filename' on the server
fn put_to_server(
    mut stream: TcpStream,
    filename: String,
    key: Key<CryptoAead>,
) -> std::io::Result<()> {
    // Read file, construct PUT request
    let contents = fs::read(filename.clone())?;
    let req_inner = FileWithName {
        name: filename,
        contents,
    };
    let request = Request::Put(req_inner);

    let request_bytes = serde_json::to_vec(&request)?;

    // Encrypt request to server
    send_encrypted_bytes(&mut stream, request_bytes.as_slice(), key);

    // Server doesn't respond, so nothing else to do
    Ok(())
}
fn main() -> std::io::Result<()> {
    // Parse args
    let args = Cli::parse();
    let key = hex_to_key(args.secret);
    let sckt_addr = SocketAddr::new(IpAddr::V4(args.address), args.port);

    // Setup Client <-> Server stream
    let stream = TcpStream::connect(sckt_addr).expect("Failed to connect!");

    // Deliver request, handle response
    match args.request {
        RequestType::Get => get_from_server(stream, args.file, key),
        RequestType::Put => put_to_server(stream, args.file, key),
    }
}
