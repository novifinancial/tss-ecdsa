# tss-ecdsa

This repo is a work-in-progress implementation of Canetti et al.'s threshold ECDSA protocol described in

[CGGMP20] R. Canetti, R. Gennaro, S. Goldfeder, N. Makriyannis, and U. Peled. UC non-interactive, proactive,  threshold ECDSA with identifiable aborts. In  ACM CCS 2020, pp. 1769–1787. ACM Press, 2020.

For details, see the [paper](https://eprint.iacr.org/2021/060.pdf).

Specifically, we are targeting the three-round presigning protocol (with quadratic overhead for identifying faulty actors).

This codebase is generally intended to be network-agnostic. Programs take messages as input and potentially output some outgoing messages in response. The relaying of these messages is assumed to happen externally. However, a proof-of-concept example of such networking code can be found in examples/network.

## Project Dependencies
This project relies on the `libpaillier` Rust crate using the GMP backend. GMP should be available during build-time.  

### Rust Dependencies and Versions

The preferred Rust version is cargo 1.68.2. 
The preferred GMP version is 6.2.1.

##  What's Implemented

### Key Generation (Figure 5 of CGGMP20)

KeyGen generates a threshold signing key, shares of which are distributed to each node. Every node outputs a private key along with the public keys of all other nodes. This only needs to be run once for a given set of nodes. 

### Auxinfo (CGGMP20 Figure 6, minus the key refreshing)

Auxinfo generates the auxiliary information (Paillier keys and ring-Pedersen parameters) needed in order to compute presignatures. In CGGMP20, this is done in parallel with key refreshing, however this codebase currently only implements the generation of auxiliary information. This is run after KeyGen and only needs to be run once.

### Three Round Pre-signing (Figure 7 of CGGMP20)

Presign is a protocol to calculate pre-signatures, which can be computed before the message to be signed is known. Once a pre-signature is computed, a threshold signature can be easily calculated in one round of interaction. This protocol must be run for every message which is to be signed.

### Other

KeyGen, Auxinfo, and Presign are the three protocols needed in order to do threshold signing. All of the zero-knowledge proofs that underpin these protocols have been implemented, as has an echo-broadcast protocol which is needed in order to enforce non-equivocation of message contents.

protocol.rs contains a test program for running a full protocol instance, which includes the KeyGen, Auxinfo, and Presign stages. Each of these protocols can also be run independently with their own tests.

## What's Not Implemented

Currently, the codebase only implements n-out-of-n sharing. While t-out-of-n sharing is not formally specified in the paper, we expect the transformation to be relatively straightforward.

Additionally, no notions of Identifiable Aborts are implemented. If a node crashes, the protocol will halt until that node comes back online. In addition to implementing the necessary cryptographic checks to identify and attribute malicious behavior, some notion of synchronous timeouts is also required.

Furthermore, the Key Refreshing portion of Auxiliary Info & Key Refresh (CGGMP20 Figure 6) is not yet implemented.

While some thought has been put into handling invalid messages (duplicate messages are ignored, as are some malformed ones), this has not been evaluated fully. Additionally, message authenticity (i.e. that a given message is actually coming from the sender in the "sender" field) is currently assumed to be handled outside of the protocol, by whatever networking code is shuttling messages around.


## How to Build and Run

You should try to build and run using the stable version of Rust instead of nightly. You can switch using the following:

`rustup default stable` 
`rustup update`

If you want to build the library, then do:

`cargo build`

If you want to run the basic tests, then do:

`cargo make ci`

## Benchmarks

The benchmarks are found in the benches folder. The end to end benchmarks are situated inside that folder at e2e_benchmark.rs. Benchmarks on different components in the main protocol like keygen, auxinfo, pre-sign and sign can be run seperately. You should type the following for generating the actual benchmarks:

`cargo bench e2e_benchmark`

For generating benchmarks related to the bignumber operations, run:

`cargo bench bignumber_benchmark`

Please refer to flamegraphs if you want to see the relative costs of some function calls in a given test. Information to run that can be found in stats/README.md.

## Examples

An example can be found in the `examples` folder. Please navigate to the `network` folder under it. There are instructions for running the example. 