# EE5453 Assignment 3 - File Transfer Service

## Introduction
  We discuss here the updates made to the File Transfer Service (FTS) developed in Assignment 2.
  The file transfer service operates over an untrusted network, and consists of client and server applications.
  The FTS retains many properties from Assignment 2, and so only differences from the previous submission are mentioned
  
  It is important to note that while this was optionally a group assignment, this submission was developed solely by James Ryan.
  
## The File Transfer Service
  The description below reflects our interpretation of the loose specification from Assignments 2 and 3.
  [Old Specifications](#old-specifications) are specifications taken from Assignment 2.
  [New Specifications](#new-specifications) are specifications taken from Assignment 3.
  
### Old Specifications
  In the (original) FTS:
  
  - A client should send a request for a file to a server
  - A server should respond with the contents of that file encrypted under a secret-key cryptographic scheme
  - The client should decrypt that file under the same secret-key cryptographic scheme, using the same key as the server
  
### New Specifications
  In the (new) FTS:
  
  - A client should send a file transfer request to the server. The request can be for transfer from the server to the client, or from the client to the server.
  - A server should handle both types of request, transferring requested files to the client, or receiving files transferred from the client.
  - All communication should be encrypted under a secret-key cryptosystem based on the AES that provides both confidentiality and integrity.

## Implementation
  In Assignment 2, we provide in our implementation resolutions to ambiguities in the above specification.
  Herein we only mention new questions about the [New Specifications](#new-specifications).
  
  - What should the structure of the requests be?
  - What particular cryptosystem should be chosen?
  
  We will discuss how the implementation answers these questions.

### Requests
  Requests are defined by the following Rust datatypes:
  
  ``` Rust
    struct FileWithName {
      name: String,
      contents: Vec<u8>,
    }

    enum Request {
      Put(FileWithName),
      Get(String),
    }

  ```
  
  A *PUT* request contains a name for a file and contents for that file, while a *GET* request contains a name for a file.
  
  Requests are serialized/deserialized into/from JSON using [serde_json 1.0](https://crates.io/crates/serde_json).
  Serialized requests are encrypted before being transmitted over the network.
  
### Cryptosystems
  The symmetric-key cryptosystem used is [AES-GCM](https://doi.org/10.6028/NIST.SP.800-38D), an AEAD scheme based on the AES.
  AES-GCM is extremely fast on modern computers, many of which have AES acceleration as well as polynomial multplication acceleration.

  The AES-GCM library used is available [here](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm).
  The library has [received a security audit](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/) with no significant findings.
  
 
