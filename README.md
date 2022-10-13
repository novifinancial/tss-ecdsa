# tss-ecdsa

This repo is a work-in-progress implementation of the ECDSA signing protocol described in "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts" [CGGMP] which can be found at https://eprint.iacr.org/2021/060.pdf.

Specifically, we are targeting the three-round presigning protocol (with quadratic overhead for identifying faulty actors).

This codebase is generally intended to be network-agnostic. Programs take messages as input and potentially output some outgoing messages in response. The relaying of these messages is assumed to happen externally. However, a proof-of-concept example of such networking code can be found in examples/network.

##  What's Implemented

### Key Generation (Figure 5 of CGGMP)

KeyGen generates a threshold signing key, shares of which are distributed to each node. Every node outputs a private key along with the public keys of all other nodes. This only needs to be run once for a given set of nodes. 

### Auxinfo (CGGMP Figure 6, minus the key refreshing)

Auxinfo generates the auxilary information (such as Paillier keys) needed in order to compute presignatures. In CGGMP, this is done in parallel with key refreshing, however this codebase currently only implements the generation of auxilary information. This is run after KeyGen and only needs to be run once.

### Three Round Pre-signing (Figure 7 of CGGMP)

Presign is a protocol to calculate pre-signatures, which can be computed before the message to be signed is known. Once a pre-signature is computed, a threshold signature can be easily calculated in one round of interaction. This protocol must be run for every message which is to be signed.

### Other

KeyGen, Auxinfo, and Presign are the three protocols needed in order to do threshold signing. All of the zero-knowledge proofs that underpin these protocols have been implemented, as has a echo-broadcast protocol which is needed in order to enforce non-equivocation of message contents.

protocol.rs contains a test program for running a full protocol instance, which includes the KeyGen, Auxinfo, and Presign stages. Each of these protocols can also be run independently with their own tests.

## What's Not Implemented

Currently, the codebase only implements n-out-of-n sharing. While t-out-of-n sharing is not formally specified in the paper, we expect the transformation to be relatively straightforward.

Additionally, no notions of Identifiable Aborts are implemented. If a node crashes, the protocol will halt until that node comes back online. In addition to implementing the necessary cryptographic checks to identify and attribute malicious behavior, some notion of synchronous timeouts is also required.

While some thought has been put into handling invalid messages (duplicate messages are ignored, as are some malformed ones), this has not been evaluated fully. Additionally, message authenticity (i.e. that a given message is actually coming from the sender in the "sender" field) is currently assumed to be handled outside of the protocol, by whatever networking code is shuttling messages around.