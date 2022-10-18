#![feature(split_array)]
#![feature(array_chunks)]

use std::io::prelude::*;
use std::net::TcpStream;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use hex;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::{rngs::OsRng, RngCore};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Size of encryption key for AES256CBC/CBCMAC
const ENC_KEY_SIZE: usize = 32;
/// Size of MAC key for AES256CBC/CBCMAC
const MAC_KEY_SIZE: usize = 32;
/// Size of key for AES256CBC/CBCMAC
pub const KEY_SIZE: usize = ENC_KEY_SIZE + MAC_KEY_SIZE;

/// Block size for AES256CBC/CBCMAC
pub const BLOCK_SIZE: usize = 16;
/// Nonce size for AES256CBC/CBCMAC
pub const NONCE_SIZE: usize = BLOCK_SIZE;
/// Tag size for AES256CBC/CBCMAC
pub const TAG_SIZE: usize = BLOCK_SIZE;

/// Generate a nonce using the system RNG
fn gen_nonce<const N: usize>() -> [u8; N] {
    let mut nonce = [0u8; N];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Unwrap `KEY_SIZE` sized key into `ENC_KEY_SIZE` sized and `MAC_KEY_SIZE` sized
/// enc and mac keys respectively
fn key_unwrap(key: [u8; KEY_SIZE]) -> ([u8; ENC_KEY_SIZE], [u8; MAC_KEY_SIZE]) {
    let (ekey, mkey) = key.split_array_ref::<ENC_KEY_SIZE>();
    // OK to unwrap here b/c KEY_SIZE == ENC_KEY_SIZE + MAC_KEY_SIZE
    (ekey.to_owned(), mkey.try_into().unwrap())
}

/// Encrypt-Then-MAC w/ AES256CBC/CBCMAC
/// Returns {IV || CIPHERTEXT || TAG}
/// Uses same nonce for ENC/MAC
pub fn mac_encrypt(pt: &[u8], key: [u8; KEY_SIZE]) -> Vec<u8> {
    // Extract keys
    let (ekey, mkey) = key_unwrap(key);

    // Generate nonce
    let nonce = gen_nonce::<NONCE_SIZE>();

    // Encrypt
    let encd = Aes256CbcEnc::new(&ekey.into(), &nonce.into()).encrypt_padded_vec_mut::<Pkcs7>(pt);

    // MAC
    let macd =
        Aes256CbcEnc::new(&mkey.into(), &nonce.into()).encrypt_padded_vec_mut::<Pkcs7>(&encd);
    // TAG is last block of macd
    let tag = macd.array_chunks::<BLOCK_SIZE>().nth_back(1).unwrap();

    // out = {IV || CIPHERTEXT}
    let mut out = Vec::<u8>::new();
    out.extend(nonce);
    out.extend(encd);
    out.extend(tag);
    out
}

/// MAC-Then-Decrypt w/ AES256CBC/CBCMAC
/// Expects input as {IV || CIPHERTEXT || MAC}
/// Returns opaque error if something goes wrong
/// Returns plaintext if successful
/// Uses same nonce for ENC/MAC
#[allow(clippy::result_unit_err)]
pub fn mac_decrypt(payload: &[u8], key: [u8; KEY_SIZE]) -> Result<Vec<u8>, ()> {
    // Extract keys
    let (ekey, mkey) = key_unwrap(key);

    // Extract nonce, ciphertext, tag
    // If someone passed bad data, return an error

    // Take the first block as IV
    let (nonce, rest) = payload.split_array_ref::<NONCE_SIZE>();

    // Take the last block as tag, and the rest as ciphertext
    let (ct, tag) = rest.rsplit_array_ref::<TAG_SIZE>();

    // Verify MAC
    let macd = Aes256CbcEnc::new(&mkey.into(), nonce.into()).encrypt_padded_vec_mut::<Pkcs7>(ct);
    let tag_cmptd = macd.array_chunks::<BLOCK_SIZE>().last();

    if tag_cmptd != Some(tag) {
        // Tag doesn't match, something bad has happened
        return Err(());
    }

    // Tag is verified, so we can safely decrypt
    // Kind of clunky, but we're converting the `Result<T, E>` into a `Result<T, ()>`
    match Aes256CbcDec::new(&ekey.into(), nonce.into()).decrypt_padded_vec_mut::<Pkcs7>(ct) {
        Ok(pt) => Ok(pt),
        Err(_) => Err(()),
    }
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

pub fn send_encrypted_bytes(stream: &mut TcpStream, payload: &[u8], key: [u8; KEY_SIZE]) {
    let encrypted_payload = mac_encrypt(payload, key);

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
