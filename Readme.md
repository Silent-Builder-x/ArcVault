# ArcVault: MPC-Powered Private Data Access Control 🔐

## 🌐 Overview

**ArcVault** is a decentralized "Key Management as a Service" protocol built on **Arcium**. It allows users to store data on public networks (like IPFS or Arweave) while enforcing strict, cryptographic access control.

In traditional systems, you either rely on a centralized server to hold decryption keys or use crude "Token-Gating" where the key is shared among all holders. **ArcVault** introduces **"Ghost Keys"**: Decryption keys that are split into secret shares and stored on the Arcium network. These keys are only reconstructed for a user if they satisfy the encrypted policy (e.g., Payment, Time, Identity) verified by the MPC cluster.

## 🚀 Live Demo

[Launch Data Vault Interface](https://www.google.com/search?q=./index.html)

## 🧠 Core Innovation: "Ghost Keys"

ArcVault implements a programmable access layer:

1. **Secret-Shared Keys:** When a creator uploads a file, the AES decryption key is generated locally, split into secret shares, and sent to Arcium nodes. The full key never touches the blockchain or any server.
2. **Encrypted Policies:** Access rules (e.g., "Must pay 5 USDC" or "Access valid until Dec 2026") are also stored as ciphertexts.
3. **Oblivious Release:** When a user requests access, the Arcis circuit verifies their credentials against the policy inside the MPC environment. If valid, the key shares are returned to the user; otherwise, the output is null.

## 🛠 Architecture

```
graph LR
    Creator[Data Owner] -- 1. Encrypt Key & Policy --> Solana[Vault Account]
    User[Consumer] -- 2. Request Access (Encrypted Pay/Time) --> Arcium[MXE Cluster]
    
    Arcium -- 3. Verify Policy (MPC) --> Arcium
    Arcium -- 4. If Valid: Release Key --> User
    
    User -- 5. Decrypt IPFS Data --> Content[File]

```

## ⚙️ Build & Deploy

```
# Prerequisites: Solana Agave (v1.18+), Arcium CLI
arcium build

# Deploy to Devnet
arcium deploy --cluster-offset 456 -u d

```

## 📄 Technical Specification

- **Circuit:** `verify_and_release` (Arcis-MPC)
- **State:** `DataVault` Account (stores policy & key shares)
- **Security:** Access control logic is executed blindly; nodes cannot see the key or the user's payment details.