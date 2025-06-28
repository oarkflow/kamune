# Kamune

Secure communication over untrusted networks.  
Kamune provides `Ed25519_ML-KEM-768_HKDF_SHA512_XChaCha20-Poly1305` security
suite.

## Features

- Message signing and verification using **Ed25519**
- Ephemeral, quantum-resistant key encapsulation with **ML-KEM-768**
- Key derivation via **HKDF-SHA512** (HMAC-based extract-and-expand)
- End-to-End, bidirectional symmetric encryption using **XChaCha20-Poly1305**
- **Replay attack protection** via message sequence numbering
- Lightweight, custom **TCP-based protocol (STP)** for minimal overhead
- **Real-time messaging** over socket-based connection
- **Direct peer-to-peer communication**, no intermediary server required
- **Protobuf** for fast, compact binary message encoding

## How does it work?

The communication happens in three stages.

### Introduction

To start, client sends its public key (think of it like an ID card) to the
server and server, in return, responds with its own public key (ID card). If
both parties verify the other one's identity, handshake process gets started.

### Handshake

Client creates a new, ephemeral ml-kem key. Its public key, alongside randomly
generated salt and nonce (a nonce prefix, to be exact) values, are sent to the
server.

Server uses that public key to derive a secret (as well as a ciphertext that
we'll get to in a minute). With the secret and the provided salt, a decryption
cipher is created. The message sequence number, alongside the random prefix will
be used to guarantee the nonce's uniqueness. An encryption cipher is also
created with new salt and nonce values. The ciphertext, salt and nonce are sent
back to the client.

Client uses the received ciphertext and its private key that was previously
generated, to derive the same exact secret as the client. Then, encryption and
decryption ciphers are created.

Finally, to make sure everyone is on the same page, a static message is sent to 
the other party. They should decrypt the message, encrypt it again with their
own encryption cipher, and send it back. If each side receive and successfully
decrypt the message, handshake is deemed complete!

### Communication

Imagine a post office. You give them your cargo, and it is placed inside a box,
alongside some other data such as timestamp and a message number (sequence). A
unique signature is generated based on the contents and your specific identity,
and is placed on the box. Then, that box is placed inside another container,
gets locked and is sealed. At last, it is sent.

At destination, the seal is checked to verify it hasn't been tampered with, and
the lock is opened. Then, the inner box contents and the signature are checked
to match. Also, the message sequence number is compared against the recorded
count, to reject possibly old or copied parcels (OK, this isn't plausible in
real life, but it's known as replay attack in cryptography).  
If all checks were successful, the cargo (message) is delivered.
