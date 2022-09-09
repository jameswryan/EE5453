use std::fs;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

// Alias all cryptography behind 'Crypto<TYPE>'
// so it can be changed easily
type CryptoAead = ChaCha20Poly1305;

// chacha20poly1305 crate doesn't provide key & nonce sizes
const KEY_SIZE: usize = 32; // ChaCha20Poly1305 uses 256-bit key
const NONCE_SIZE: usize = 12; // ChaCha20Poly1305 uses 96-bit nonce

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

    // Authenticate & decrypt payload
    let cipher = CryptoAead::new(&key);
    // Server uses filename as aad, so must we
    let filename = args.file;
    let file_bytes = match cipher.decrypt(
        &nonce,
        Payload {
            msg: &ciphertext,
            aad: filename.as_bytes(),
        },
    ) {
        Ok(pt) => pt,
        Err(e) => {
            panic!("ERROR in Decryption: {e}");
        }
    };

    // Payload has been authenticated, safe to use additional data & plaintext

    // Write decrypted file to filesystem
    fs::write(filename, file_bytes)?;

    Ok(())
}
