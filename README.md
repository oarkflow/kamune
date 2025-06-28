# Kamune

Secure communication over untrusted networks.  
Kamune provides `Ed25519_ML-KEM-768_HKDF_SHA512_XChaCha20-Poly1305` suite.

## Features

- Message signing and verification using **Ed25519**
- Ephemeral, quantum-resistant key encapsulation with **ML-KEM-768**
- Key derivation via **HKDF-SHA512** (HMAC-based extract-and-expand)
- End-to-End, bidirectional symmetric encryption using **XChaCha20-Poly1305**
- **Replay attack protection** via message sequence numbering
- Lightweight, custom **TCP-based protocol (STP)** for minimal overhead
- **Real-time messaging** over socket-based connections
- **Direct peer-to-peer communication**, no intermediary server required
- **Protobuf** for fast, compact binary message encoding

