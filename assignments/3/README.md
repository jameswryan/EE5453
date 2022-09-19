# EE5453 Assignment 2 - File Transfer Service

## Introduction
  We discuss and address here the security and design considerations for a file transfer service.
  The file transfer service operates over an untrusted network, and consists of client and server applications.
  
  It is important to note that while this was optionally a group assignment, this submission was developed solely by James Ryan.
  
## The File Transfer Service
  The description below reflects our interpretation of the loose specification from the assignment.
  
### Specification
  The service operates follows, with all communication happening over a network:
    - Clients 'request' a file from the server by sending a plaintext filename to the server.
    - Servers reply by sending the contents of the requested file, encrypted under a symmetric key cryptosystem.
    - Clients can decrypt the received file if they know the key used by the server.
    
  Additionally, the assignment makes it clear that its purpose is to understand the use of secret-key crypto libraries in our chosen programing language.

## Ambiguities
  There are clearly several ambiguities in the above specification.
  The most important are:

  * The particular programming language used
  * The method of network communication used
  * The structure of the requests from the client to the server
  * The symmetric key cryptosystem used
  * How the symmetric keys are generated and shared between server and client
  * The presence or absence of error messages from server to client

## Implementation
  In our implementation, we resolve the ambiguities above as follows:
  
### Programming Language Used
  We used the [Rust programming language](rust-lang.org).
  The version of rustc used was: 

      smntr:assignments/2  % rustc --version
      rustc 1.65.0-nightly (b44197abb 2022-09-05)

  Versions of each crate (Rust's name for libraries) used can be seen in the Cargo.lock files in each directory.
  These programs should be cross-platform across operating systems, but they have only been tested on Fedora 36 with the above version of rustc.

### Network Communication
  Because there was no limit given on the size of files, we used the [Rust Standard Libraries' TCP API](https://doc.rust-lang.org/stable/std/net/index.html).
  This frees us from limits on the size of UDP packets, and also allows a simple method of error communication from server to client.

### Client Requests
  Client's requests to the server for a file are to be valid UTF-8 strings, terminated with a newline.
  The [Rust Standard Libraries' filesystem API](https://doc.rust-lang.org/stable/std/fs/index.html) is used to determine the name of the file the client is requesting,
  and only the current working directory is searched by the server for that file.
  
### Symmetric Key Cryptosystem
  For the cryptosystem, the [ChaCha20Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) AEAD scheme was used.

  [ChaCha20](https://cr.yp.to/chacha/chacha-20080120.pdf) is a stream cipher designed by Daniel J. Bernstein.
  It is based on the earlier Salsa20 stream cipher, and like its predecessor is designed to be fast in software (as opposed to the AES, which is slow in software),
  and simple to implement in a constant-time manner (again as opposed to the AES).
  
  The [Poly1305-AES Message Authentication Code](https://doi.org/10.1007/11502760_3) is a MAC also designed by Daniel J. Bernstein.
  It is intended to be fast on processors with AES acceleration instructions, and its sits security depends on that of the AES.

  The ChaCha20Poly1305 AEAD was chosen as it is well-understood, widely used, and easy to implement securely.
  The AEAD scheme provides not only confidentiality, but also integrity of the client's request as well as the server's response
  The specific implementation used is in [RustCrypto implementation](https://crates.io/crates/chacha20poly1305), which has been audited for security and traces its roots back to implementations by Daniel J. Bernstein.
  However, a faster implementation of ChaCha20 for ARM processors with NEON SIMD instructions, based on the RustCrypto implementation, is available [here](https://github.com/jameswryan/stream-ciphers), and is preferred where useable.

  When the server sends the file contents to the client, it uses the request it received as the Additional Data for the AEAD.
  The client uses the request that it sent to the server as Additional Data when it decrypts the encrypted file.
  If the request was modified after being sent by the client, or the encrypted payload is modified after being sent by the server, then a decryption failure will occur.
  This ensures that an adversary cannot learn the contents of the file requested, nor change the request before the server receives it.
  
### Symmetric Key Generation and Distribution
  For an AEAD such as ChaCha20Poly1305, it is critical to have access to secure randomness for generation of the nonce.
  Additionally, it is critical to generate the symmetric key in a secure manner, as failure to do so reduces the cost of a brute-force attack.
  
  For that reason, the [OsRng](https://docs.rs/aead/0.5.1/aead/struct.OsRng.html) secure random number generator is used for both the key and nonce on the server.
  This provides access to the Operating System's random number generator, which on Linux 5.18+ is designed by Jason Donenfeld and is considered very secure.

  To distribute the symmetric key, it is important to use an out-of-band distribution method.
  If in-band distribution is used, then any passive adversaries can discover the key being passed in plaintext over the network, and the systems entire security is compromised.
  So, the preferred (and easiest!) method of key distribution is to copy the key -- which is written to stdout by the server on startup -- by hand from the server to the client.
  
  This is an ideal area for future work, as a KEM such as [CRYSTALS-KYBER](https://pq-crystals.org/kyber/) could be used to securely exchange a key over an insecure channel.
  
### Error Messages
  To minimize the possibility of information leakage, no error messages are sent by the server to the client.
  If errors occur, such as when the client requests a file that does not exist, or the request sent is invalid, the server will immediately close the connection.
  As mentioned before, TCP connections 'know' when the other end is closed, so this will inform the client that an unrecoverable error has occured without leaking unnecessary information.


