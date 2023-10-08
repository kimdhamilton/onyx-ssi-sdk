# Add more DID methods

DIDs are how Entities identify themselves in an SSI Ecosystem. The SSI Ecosystem determines which DID methods the Entities will use. There are many implementations of DID methods, and depending on the use case, some may be preferred over others. The goal of the Onyx SDK is to be compatible with different SSI ecosystems as well as enable Onyx to create new SSI Ecosystems for our use cases.

**Goal:** provide support for another DID method or the [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver)

## Spec

### DID method spec

* [DID spec](https://www.w3.org/TR/did-core/) outlines the requirements of a DID
* [DID method spec](https://www.w3.org/TR/did-core/#methods) outlines requirements of a DID method
* [DID method list](https://www.w3.org/TR/did-spec-registries/#did-methods) lists the documented DID methods


### Functionality to Implement
DID methods of interest: [did:web](https://w3c-ccg.github.io/did-method-web/), [Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
* implement the CRUD functions of a new DID method
* resolution of DID should be compatible with [did-resolver](https://github.com/decentralized-identity/did-resolver)

## Where to Start/Implementation Details

### DID Method Support
* Create a new file `did-{name of did method}.ts` that implements the `DIDMethod` Interface in `did.ts`
* If there is not already an existing resolver for the new did method, you will need to write one to support `resolve` that is compatible with `did-resolver`
* If the did method uses a new Keypair algorithm, you will need to add it to the `KEY_ALG` enum in `utils/KeyUtils.ts`

### Universal Resolver Support
The Universal Resolver is a separate service that can resolve Decentralized Identifiers (DIDs) across many different DID methods. It can be run locally via Docker.

* Implement an adapter to a universal resolver Instance: given the URL of the running Resolver instance, implement a `resolve` function
* Solution should implement the [`Resolvable`](https://github.com/decentralized-identity/did-resolver/blob/master/src/resolver.ts#L330) interface

## Testing
The functionality added for this challenge should be unit tested. Tests can be added [here](../../../../tests/unit/did)

## Criteria for Completion
* All [functionality](#Functionality-to-Implement) has been implemented
* Code written has corresponding unit tests (90% coverage)
* Code is well documented
* Code passes CI github action (building, linting, and testing of SDK)

## Design Decisions

### did:web

/*
* A did:web DID is creating by hosting a DID document at a defined URL. 
* @see {@link formatDidDocument} for details.
*/

Because modifications to did:web DIDs require creatng, upating, or removing a did.json file at the appropriate URL, a few simplifications and assumptions were made to conform to the `DIDMethod` while keeping the semantics clean.

1. Implemented support for only Ed25519 key pairs and `Ed25519VerificationKey2018` verification method: Note that did:web supports a range of verification methods and key type
2. and this minimal implemenetation that doesn't overburden the `DIDMethod` contract.
    * The DIDMethod contract assumes DID method / keypair coupling.
    * 
    * In the future, we could use config to specify defaults and provide new overloads, e.g. for did methods
    * that support more key types and capabilities (services) 


relies on ctor config rather than introducing too many overloads
still retains key / verification method coupling

```
    // Examples from web-did-resolver
    const ETH_IDENTITY = '0x2Cc31912B2b0f3075A87b3640923D45A26cef3Ee'
    const ethDidDocument: DIDDocument = {
        '@context': DID_CONTEXT,
        id: EXAMPLE_DID,
        publicKey: [
            {
                id: `${EXAMPLE_DID}#owner`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: EXAMPLE_DID,
                ethereumAddress: ETH_IDENTITY,
            },
        ],
        authentication: [`${EXAMPLE_DID}#owner`],
    }

```
### did:pkh