use std::fs;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};

use clap::Parser;

use c::*;
use rsa::{
    pss::{SigningKey, VerifyingKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

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

    /// PKCS8-encoded client decryption key
    #[clap(long, value_parser)]
    client_dec_key: String,

    /// PKCS8-encoded client signing key
    #[clap(long, value_parser)]
    client_sig_key: String,

    /// SPKI-encoded server encryption key
    #[clap(long, value_parser)]
    server_enc_key: String,

    /// SPKI-encoded server verification key
    #[clap(long, value_parser)]
    server_vrf_key: String,
}

/// Get the file 'filename' from the server, and write it to the cwd
fn get_from_server(
    stream: &mut TcpStream,
    filename: String,
    server_pubk: &RsaPublicKey,
    server_vrfk: &VerifyingKey<Sha256>,
    client_deck: &RsaPrivateKey,
    client_sigk: &SigningKey<Sha256>,
) -> std::io::Result<()> {
    // Construct GET request
    let request = Request::Get(filename.clone());

    let request_bytes = serde_json::to_vec(&request)?;
    // Send request to server
    send_encrypted_bytes(stream, request_bytes.as_slice(), server_pubk, client_sigk);

    // Don't need to write again, close client side of connection
    stream.shutdown(Shutdown::Write)?;

    // Get file contents from server
    let buf = read_all(stream).expect("Network Read Error");

    // Make sure we were sent at least a signature
    if buf.len() < SIG_SIZE {
        eprintln!("The server closed the connecting without sending anything!");
        return Ok(());
    }

    let file_bytes = match decrypt_from_to(&buf, client_deck, server_vrfk) {
        Ok(pt) => pt,
        Err(e) => {
            panic!("ERROR in Decryption: {}", e);
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
    server_pubk: &RsaPublicKey,
    client_sigk: &SigningKey<Sha256>,
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
    send_encrypted_bytes(stream, request_bytes.as_slice(), server_pubk, client_sigk);

    // Server doesn't respond, so nothing else to do
    Ok(())
}

fn main() -> std::io::Result<()> {
    // Parse args
    let args = Cli::parse();

    // Read keys
    let (client_deck, client_sigk, server_enck, server_vrfk) = get_keys_from_files(
        args.client_dec_key,
        args.client_sig_key,
        args.server_enc_key,
        args.server_vrf_key,
    );

    let sckt_addr = SocketAddr::new(IpAddr::V4(args.address), args.port);

    // Setup Client <-> Server stream
    let mut stream = TcpStream::connect(sckt_addr).expect("Failed to connect!");

    // Deliver request, handle response
    match args.request {
        RequestType::Get => get_from_server(
            &mut stream,
            args.file,
            &server_enck,
            &server_vrfk,
            &client_deck,
            &client_sigk,
        ),
        RequestType::Put => put_to_server(&mut stream, args.file, &server_enck, &client_sigk),
    }
}
