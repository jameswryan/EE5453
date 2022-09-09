use std::fs;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

use serde::Deserialize;
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    Key, Nonce, XSalsa20Poly1305, KEY_SIZE, NONCE_SIZE,
};

// Alias all cryptography behind 'Crypto<TYPE>'
// so it can be changed easily
type CryptoAead = XSalsa20Poly1305;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    /// File to request
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

/// Wrapper to hold filename and file contents
#[derive(Clone, Debug, Deserialize)]
struct FileWithName {
    /// Name of the file
    name: String,
    /// File contents
    contents: Vec<u8>,
}

/// Parse hex string into key for CryptoAead
/// If a bad key string is given, nothing useful can be done, so this function panics on error
fn hex_to_key(s: String) -> Key {
    let key_bytes = match hex::decode(s) {
        Ok(k) => k,
        Err(e) => panic!("ERROR when parsing secret: {e}"),
    };

    if key_bytes.len() != KEY_SIZE {
        panic!("ERROR: Key too short!");
    }

    let key = *Key::from_slice(&key_bytes);

    key
}

fn main() -> std::io::Result<()> {
    let args = Cli::parse();
    let key = hex_to_key(args.secret);
    let sckt_addr = SocketAddr::new(IpAddr::V4(args.address), args.port);

    // Client <-> Server stream
    let mut stream = TcpStream::connect(sckt_addr).expect("Failed to connect!");
    // Send filename to server
    // Server expects file request to be newline terminated
    let request = args.file.clone() + "\n";
    stream
        .write_all(request.as_bytes())
        .expect("Failed to send filename!");

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
    let (nonce, ciphertext): (Nonce, Vec<u8>) = (
        *Nonce::from_slice(&buf[..NONCE_SIZE]),
        buf[NONCE_SIZE..].into(),
    );

    // Decrypt buffer
    let cipher = CryptoAead::new(&key);
    let plaintext = match cipher.decrypt(&nonce, ciphertext.as_slice()) {
        Ok(pt) => pt,
        Err(e) => {
            panic!("ERROR in Decryption: {e}");
        }
    };

    let file: FileWithName = match serde_json::from_slice(&plaintext) {
        Ok(f) => f,
        Err(e) => {
            panic!("ERROR in deserialization: {e}");
        }
    };

    // If the name of the file we got doesn't match what was requested, error and _don't_ write to filesystem
    if file.name != args.file {
        panic!("ERROR Received different filename than requested!");
    }

    // Write decrypted file to filesystem
    fs::write(file.name, file.contents)?;

    Ok(())
}
