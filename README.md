# Decentralized Blockchain Messaging Platform

A secure, decentralized messaging system built on blockchain technology that enables private communication between users while maintaining the integrity and authenticity of messages.

## Overview

This project implements a decentralized messaging platform that leverages blockchain technology to provide secure, encrypted communication between users. Unlike traditional blockchain implementations focused on financial transactions, this system is specifically designed for secure message exchange.

## Schema
![Image Description](SchemaDecentralizedLogic.png)


## Visual Explanation

![Image Description](SchemaIdeaExplained.png)


## Key Features

- Double encryption using public/private key pairs
- Decentralized message broadcasting and storage
- Merkle root verification for message blocks
- Mempool management for pending messages
- Proof of Work consensus mechanism
- Secure message retrieval system

## Architecture

### Message Structure
- Sender's public key
- Receiver's public key
- Message content (encrypted)
- Timestamp
- Signature
- Nonce

### Message Block Structure
- Sender public key
- Receiver public key
- Sender
- Receiver
- Message
- Nonce
- Timestamp
- Signature
- Merkle root

## Core Components

### User Module
- Message creation and encryption
- Signature generation
- Message broadcasting
- Community participation

### Miner Module
- Block creation and validation
- Proof of Work verification
- Message verification
- Block broadcasting

### Message Management
- Mempool operations
- Message serialization
- Message verification
- Block creation triggers

## Security Features

1. **Double Encryption Process**
   - Initial encryption with sender's private key
   - Secondary encryption with receiver's public key
   - Ensures both authenticity and privacy

2. **Signature Verification**
   - Digital signatures verify message authenticity
   - Public key verification ensures correct recipient
   - Maintains message integrity throughout transmission

3. **Block Validation**
   - Merkle root verification
   - Block hash validation
   - Consensus mechanism verification

## Message Flow

1. **Message Creation**
   - User composes message
   - System adds metadata (public keys, nonce, timestamp)
   - Message is signed and encrypted

2. **Message Broadcasting**
   - Serialization for network transmission
   - Peer selection for message distribution
   - Network broadcasting

3. **Message Reception**
   - Deserialization and verification
   - Signature validation
   - Mempool storage

4. **Block Creation**
   - Message accumulation in mempool
   - Merkle tree generation
   - Block formation and validation

5. **Message Retrieval**
   - Query blockchain for relevant blocks
   - Message decryption
   - Verification of intended recipient

