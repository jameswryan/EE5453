use std::fs;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};

use clap::Parser;
use openssl::{bn::BigNum, dh::Dh, pkey::PKey};
use sha2::{Digest, Sha512};

use c::*;

#[derive(Parser)]
struct Cli {
    /// Type of request to make
    #[clap(short, long, arg_enum, value_parser)]
    request: RequestType,

    /// File to put/get
    #[clap(short, long, value_parser)]
    file: String,

    /// IPv4 address to connect to.
    #[clap(short, long, value_parser, default_value_t=Ipv4Addr::new(0,0,0,0))]
    address: Ipv4Addr,

    /// Port to connect to.
    #[clap(short, long, value_parser, default_value_t = 0xBEEF)]
    port: u16,
}

/// Does Diffie-Hellman key exchange with the server, returns the shared secret
/// Panics if anything goes wrong
fn get_shared_secret(stream: &mut TcpStream) -> [u8; KEY_SIZE] {
    // Ok to unwrap, because we can't do anything if either returns an error
    // FFDH generator 'g'
    let ffdh_g: BigNum = BigNum::from_u32(2).unwrap();
    // FFDH prime modulus 'p'
    let ffdh_p: BigNum = BigNum::get_rfc3526_prime_4096().unwrap();

    // Configure ffdh context
    let ffdh_ctx = Dh::from_pqg(ffdh_p, None, ffdh_g).unwrap();

    // Generate client secret, configure ffdh object
    let ffdh = ffdh_ctx.generate_key().unwrap();
    let client_privk = ffdh.private_key().to_owned().unwrap();

    // We need to clone ffdh.
    // But Dh isn't Clone (or Copy), so we do it this way
    // WTF
    let ffdh_pub = Dh::from_pqg(
        BigNum::get_rfc3526_prime_4096().unwrap(),
        None,
        BigNum::from_u32(2).unwrap(),
    )
    .unwrap();
    let ffdh_pub = ffdh_pub.set_private_key(client_privk).unwrap();

    let client_pubk = PKey::from_dh(ffdh_pub)
        .unwrap()
        .public_key_to_pem()
        .unwrap();

    // Send public key to server
    stream
        .write_all(&client_pubk)
        .expect("Network Write Error!");

    // Read public key from server
    let server_pk = read_all(stream).expect("Network Read Error!");

    // We need to extract the BigNum from the PEM encoded public key
    let server_pk = PKey::public_key_from_pem(&server_pk).unwrap();
    let server_pk = server_pk.dh().unwrap();
    let server_pk = server_pk.public_key();

    // Compute shared secret
    let shared_secret = ffdh.compute_key(server_pk).unwrap();

    // Compute keys from shared secret
    let mut hasher = Sha512::new();
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Get the file 'filename' from the server, and write it to the cwd
fn get_from_server(
    stream: &mut TcpStream,
    filename: String,
    key: [u8; KEY_SIZE],
) -> std::io::Result<()> {
    // Construct GET request
    let request = Request::Get(filename.clone());

    let request_bytes = serde_json::to_vec(&request)?;
    // Send request to server
    send_encrypted_bytes(stream, request_bytes.as_slice(), key);

    // Don't need to write again, close client side of connection
    stream.shutdown(Shutdown::Write)?;

    // Get file contents from server
    let buf = read_all(stream).expect("Network Read Error");

    // Make sure we were sent at least a nonce
    if buf.len() < NONCE_SIZE {
        eprintln!("The server closed the connecting without sending anything!");
        return Ok(());
    }

    let file_bytes = match mac_decrypt(&buf, key) {
        Ok(pt) => pt,
        Err(_) => {
            panic!("ERROR in Decryption!");
        }
    };

    // Payload has been authenticated, safe to use plaintext

    // Write decrypted file to filesystem
    fs::write(filename, file_bytes)?;
    Ok(())
}

/// Put the file 'filename' on the server
fn put_to_server(
    stream: &mut TcpStream,
    filename: String,
    key: [u8; KEY_SIZE],
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
    send_encrypted_bytes(stream, request_bytes.as_slice(), key);

    // Server doesn't respond, so nothing else to do
    Ok(())
}

fn main() -> std::io::Result<()> {
    // Parse args
    let args = Cli::parse();
    let sckt_addr = SocketAddr::new(IpAddr::V4(args.address), args.port);

    // Setup Client <-> Server stream
    let mut stream = TcpStream::connect(sckt_addr).expect("Failed to connect!");

    // Diffie-Hellman key exchange
    let key = get_shared_secret(&mut stream);

    // Deliver request, handle response
    match args.request {
        RequestType::Get => get_from_server(&mut stream, args.file, key),
        RequestType::Put => put_to_server(&mut stream, args.file, key),
    }
}
