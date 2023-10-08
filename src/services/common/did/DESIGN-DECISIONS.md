# Design Documentation for DID Hackathon

This documentation provides an overview of the design decisions, simplifications, and future opportunities related to the implementation of two DID (Decentralized Identifier) methods: `did:web` and `did:pkh`.

## Table of Contents

- [Design Documentation for DID Hackathon](#design-documentation-for-did-hackathon)
  - [Table of Contents](#table-of-contents)
  - [Why did:web and did:pkh](#why-didweb-and-didpkh)
    - [did:web](#didweb)
    - [did:pkh](#didpkh)
  - [Design Decisions](#design-decisions)
    - [did:pkh Network Support](#didpkh-network-support)
    - [did:web Configuration](#didweb-configuration)
    - [Other Simplifications and Assumptions](#other-simplifications-and-assumptions)
    - [Summary of Key and Verification Method Mapping](#summary-of-key-and-verification-method-mapping)
  - [Future Opportunities](#future-opportunities)
    - [did-pkh](#did-pkh)
    - [did:web](#didweb-1)
    - [General](#general)
  - [References](#references)


## Why did:web and did:pkh

The addition of `did:web` and `did:pkh` rounds out Onyx's built-in did method options to a powerful foundation. 

### did:web

[did:web](https://w3c-ccg.github.io/did-method-web/), which associates a DID with a DID document hosted on a web domain, is commonly by organizations (governments and companies) as a DID for issuing Verifiable Credentials. Because organizations typically manage a web domain, and have the necessarily controls to securely manage and update web content,  did:web provides an easy way for orgs to bootstrap into the decentralized identity ecosystem. 

Adding did:web support to the onyx library will alow organizational issuers to get started issuing VCs with full-featured DIDs (supporting key rotation and deletion), without needing to introduce or rely on additional blockchain utilities.

### did:pkh

[did:pkh](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md) is similar to did:key in that it is generative, and doesn't support update or delete. It's become increasingly popular in the web3 community because it's designed to integrate with crypto wallet's built in key management while facilitating secure, chain-agnostic communication between dapps and wallets.

Described as an "upgradeable" or "composable" DID method ([Upgradeable Decentralized Identity](https://blog.spruceid.com/upgradeable-decentralized-identity/)), did:pkh start as an Ethereum-account based `did:pkh`, and later upgraded to a DID method that supports key rotation, such as `did:ethr`, `did:ens`, or `did:ion`.

`did-pkh` relies on Chain Agnostic Standards Alliance specifications to ensure uniqueness and interoperability.

## Design Decisions

### did:pkh Network Support

The `did:pkh` method spec supports a range of networks, but this starts with use of `eip155`, specifically Ethereum, for create and update scenarios. However, note that the `pkh-did-resolver` library, which used in this implementation, supports resolution of all the following:

- eip155: eth, celo, poly
- tezos: tezos (tz1, tz2, tz3) 
- bip122: btc, doge

`pkh-did-resolver` does not currently support resolution of Arweave or Solana.

### did:web Configuration

did:web requires did documents to be available at a specific url, which often must be done as a separate process. did:web provider implementations typically choose 1 of 2 paths:
1. Generate a DID document and call out a separate hosting step, or
2. Assume that the service is capable of making updates. 

For Onyx, neither seemed appropriate, due to the existing design and semantics of `DIDMethod`, and its utility as a platform library:

- Choosing the first option would either require changing the design and semantics of `DIDMethod` (e.g. to return a formatted DID Document) for subsequent hosting or throwing exceptions with instructions to call a different method. Neither seemed especially desirable
- Assuming the service is capable of making updates also seems restrictive. It _could_ be useful for cases where an organization is creating and managing DIDs for users (i.e. not bare domain DIDs), but that is likely not the common scenario for many issuing users of the Onyx library.

The "middle" path, that minimized disruptions to the DIDMethod interface, was to add a DIDWebStore configuration to the WebDIDMethod. This receives notifications on modifications and deletions. This allows flexibility to accommodate the 2 different options. For example, a DIDWebStore implementation could receive notifications that alerts to the need to update a DID Document as a separate process, or in the case that it's capable of making updates, it can perform those directly.

Lastly, DIDWebMethod accepts a defaultDid setting in its constructor to allow reasonable behavior for create(). However, overloads with a specific did are available in case needed.

This decision, including the specific design of `DIDWebStore`, should be revisited as requirements evolve. 

### Other Simplifications and Assumptions
- **Limited Key/Capability Support**: For `did:web`, only Ed25519 key pairs and the `Ed25519VerificationKey2018` verification method are supported, though `did:web` supports a variety of verification methods and key types. As described above, for `did:pkh`, only eip1555 / Ethereum support is build in. See mapping below.
- **Minimal Implementation**: The implementation doesn’t overburden the `DIDMethod` contract and retains some key/verification method coupling.
- **Configuration Over Overloads**: Relies on constructor configuration instead of introducing numerous overloads.


### Summary of Key and Verification Method Mapping

Provided for future reference. 

With the addition of these `did:web` and `did:pkh` implementations, the current state of key / verification method support in the Onyx library is as follows. Asterisks (`*`) are next to did-methods that support flexible key / verification method options.  

| method   | lib               | key pair   | alg    | verification method              |
|----------|-------------------|------------|--------|----------------------------------|
| did:key  | key-did-resolver  | Ed25519*   | EdDSA  | Ed25519VerificationMethod2018    |
| did:ethr | ethr-did-resolver | secp256k1  | ES256K | EcdsaSecp256k1RecoveryMethod2020 |
| did:web  | web-did-resolver  | Ed25519*   | EdDSA  | Ed25519VerificationMethod2018    |
| did:pkh  | pkh-did-resolver  | secp256k1* | ES256K | EcdsaSecp256k1RecoveryMethod2020 |


## Future Opportunities

### did-pkh

- **Support for Additional Networks**: Future implementations may extend support to networks beyond Ethereum. This could require a combination of different configuration options in the constructor and/or overloads to `DIDMethod`.
- **Demonstration of more did-pkh use cases**: `did-pkh` has been used in a range of scenarios like session management, which could be a useful capability to add to the Onyx tool set.

### did:web
- **Support for more Cryptographic Methods and Capabilities**: Allow the creation of different key types. This could require a combination of different configuration options in the constructor and/or overloads to `DIDMethod`.
- **Revisit the DIDWebMethod configuration design**: As requirements (and possibly the `DIDMethod` interface) evolve, the DIDWebMethod configuration-related design decisions should be revisited.

### General
- **Extended Key and Verification Method Support**: In general, future versions of most of the existing DID methods could additional key types and capabilities. To some extent this could be addressed by configuration options or new overloads. Over time, this might require some minor changes to the `DIDMethod` abstraction to retain simplicity.


## References
- [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/)
- [did:pkh Method Specification](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md)
- [Upgradeable Decentralized Identity](https://blog.spruceid.com/upgradeable-decentralized-identity/)
- Chain Agnostic Improvement Proposals
    - [CAIP-2](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md)
    - [CAIP-10](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md)



