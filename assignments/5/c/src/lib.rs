#![feature(split_array)]
#![feature(iterator_try_collect)]
#![feature(slice_flatten)]

use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    pss,
    pss::{SigningKey, VerifyingKey},
    PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey,
};

use sha2::Sha256;
use signature::{RandomizedSigner, Signature, Verifier};

/// Size of RSA-PKCS1 signature
pub const SIG_SIZE: usize = 512;

/// Size of blocks being encrypted by RSA-OAEP
const ENC_BLOCK_SIZE: usize = 128;

/// Size of blocks being decrypted by RSA-OAEP
const DEC_BLOCK_SIZE: usize = 512;

/// Unpack signature & ciphertext from payload
/// Extract 256 byte signature from payload, rest is ciphertext
fn unpack_sig_ct(pyld: &[u8]) -> signature::Result<(pss::Signature, &[u8])> {
    let (sig_bytes, ct) = pyld.split_array_ref::<SIG_SIZE>();
    let sig = pss::Signature::from_bytes(sig_bytes)?;

    Ok((sig, ct))
}

/// Encrypt `pt` to public key `target_pubk` w/ RSA-OAEP
/// Then sign the SHA-256 of the result using private key `sigk` w/ RSA-PKCS1
/// Signs
/// {<BE verifying pubkey modulus bytes> || <BE target pubk modulus bytes> || <enc'd msg>}
/// If no errors, returns {<sig> || <enc'd msg>}
pub fn encrypt_to_from(
    pt: &[u8],
    target_enck: &RsaPublicKey,
    sigk: &SigningKey<Sha256>,
) -> rsa::errors::Result<Vec<u8>> {
    // Unsigned ciphertext
    let encd = pt
        .chunks(ENC_BLOCK_SIZE)
        .map(|blk| target_enck.encrypt(&mut OsRng, PaddingScheme::new_oaep::<Sha256>(), blk))
        .try_collect::<Vec<Vec<u8>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();

    // Get modulus bytes of keys
    let sigk_vrfk_nbytes = RsaPublicKey::from(VerifyingKey::from(sigk))
        .n()
        .to_bytes_be();
    let target_enck_nbytes = target_enck.n().to_bytes_be();

    // Sign msg
    let to_sign = [&sigk_vrfk_nbytes, &target_enck_nbytes, encd.as_slice()].concat();
    let sig: &[_] = &sigk.sign_with_rng(&mut OsRng, &to_sign);

    Ok([sig, &encd].concat())
}

/// Decrypt `ct` with private key `target_privk` w/ RSA-OAEP
/// Expects input in the form {<sig> || ct}
/// Before that, verify the signature with `vrfk` w/ RSA-PKCS1
/// Verifies the signature of
/// {<BE verifying key modulus bytes> || <BE target pubk modulus bytes> || ct}
/// If no errors, returns decrypted plaintext
pub fn decrypt_from_to(
    pyld: &[u8],
    target_privk: &RsaPrivateKey,
    vrfk: &VerifyingKey<Sha256>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Extract signature, ct
    let (sig, ct) = unpack_sig_ct(pyld)?;

    // Get modulus bytes of keys
    let target_pubk_nbytes = RsaPublicKey::from(target_privk).n().to_bytes_be();
    let sigk_vrfk_nbytes = RsaPublicKey::from(vrfk.clone()).n().to_bytes_be();

    // Verify signature
    let to_check = [&sigk_vrfk_nbytes, &target_pubk_nbytes, ct].concat();
    vrfk.verify(&to_check, &sig)?;

    // If we didn't return an error, then we successfully verified the signature

    // Decrypt with privk, return error if decryption fails, plaintext if successful
    Ok(ct
        .chunks(DEC_BLOCK_SIZE)
        .map(|blk| target_privk.decrypt(PaddingScheme::new_oaep::<Sha256>(), blk))
        .try_collect::<Vec<Vec<u8>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>())
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RequestType {
    Put,
    Get,
}

#[derive(Serialize, Deserialize)]
pub struct FileWithName {
    pub name: String,
    pub contents: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    Put(FileWithName),
    Get(String),
}

/// Encrypt a payload, send it over the network
/// Panics if anything goes wrong
pub fn send_encrypted_bytes(
    stream: &mut TcpStream,
    payload: &[u8],
    target_pubk: &RsaPublicKey,
    sigk: &SigningKey<Sha256>,
) {
    let encrypted_payload = encrypt_to_from(payload, target_pubk, sigk).expect("Encryption Error!");

    // Send to server
    stream
        .write_all(&encrypted_payload)
        .expect("Stream write Error!");
}

pub fn read_all(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    const BUF_LEN: usize = 100;
    let mut buf = vec![0; BUF_LEN];

    let mut red = stream.read(&mut buf)?;
    let mut recvd = buf.clone();

    while red >= BUF_LEN {
        let mut buf = [0; BUF_LEN];
        red = match stream.read(&mut buf) {
            Ok(amt) => {
                recvd.extend(&buf[0..amt]);
                amt
            }
            Err(e) => {
                return Err(e);
            }
        };
    }
    Ok(recvd)
}

/// Read client & server keys from files
/// Panics w/ error message when something goes wrong
pub fn get_keys_from_files(
    client_deck_path: impl AsRef<Path>,
    client_sigk_path: impl AsRef<Path>,
    server_enck_path: impl AsRef<Path>,
    server_vrfk_path: impl AsRef<Path>,
) -> (
    RsaPrivateKey,
    SigningKey<Sha256>,
    RsaPublicKey,
    VerifyingKey<Sha256>,
) {
    let client_deck = RsaPrivateKey::read_pkcs8_pem_file(client_deck_path)
        .expect("Error reading client decryption key");

    let client_sigk_privk = RsaPrivateKey::read_pkcs8_pem_file(client_sigk_path)
        .expect("Error reading client signing key");

    let client_sigk = SigningKey::from(client_sigk_privk);

    let server_enck = RsaPublicKey::read_public_key_pem_file(server_enck_path)
        .expect("Error reading server encryption key");

    let server_vrfk_pubk = RsaPublicKey::read_public_key_pem_file(server_vrfk_path)
        .expect("Error reading server verification key");

    let server_vrfk = VerifyingKey::from(server_vrfk_pubk);

    (client_deck, client_sigk, server_enck, server_vrfk)
}
