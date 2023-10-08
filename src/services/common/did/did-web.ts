import { DIDDocument, DIDResolutionResult, DIDResolver, Resolver, parse } from "did-resolver"
import { DID, DIDMethod, DIDWithKeys } from "./did"
import { getResolver } from "web-did-resolver"
import { DIDMethodFailureError } from "../../../errors"
import { BytesLike, base58 } from "ethers/lib/utils"
import { DID_CONTEXT, ED25519_2018_CONTEXT } from "../schemas"
import { KEY_ALG, KeyPair, KeyUtils } from "../../../utils"

export class WebDIDMethod implements DIDMethod {
    name = 'web';
    providerConfigs: WebProviderConfigs
    didWebStore: DIDWebStore
    keyAlg: KEY_ALG


    /**
     * Constructor for the did:web DID Method
     * 
     * @param providerConfigs - configuration for the did:web DID Method 
     * @see {@link WebProviderConfigs}
     * @throws {@link DIDMethodFailureError} if the base did is not a valid did:web DID
     */
    constructor(providerConfigs: WebProviderConfigs) {
        this.providerConfigs = providerConfigs
        this.didWebStore = providerConfigs.didWebStore
        this.keyAlg = providerConfigs.defaultKeyAlg
        // Avoid complications later in case this is misconfigured
        if (!this.checkFormat(this.didWebStore.defaultDid)) {
            throw new DIDMethodFailureError('Not a well-formed did:web DID');
        }
    }

    /**
      * Create a did:web for the DID specified in the provider configs.
      * Sends a notification to the didWebStore configured in the constructor.
      * 
      * The didWebStore is responsible for ensuring the DID document is hosted at the
      * corresponding URL. This may happen asynchronously, which is especially likely
      * if the did:web DID corresponds to the bare domain (as is the case here).
      * 
      * @returns a `Promise` that resolves to {@link DIDWithKeys}
      * @throws {@link DIDMethodFailureError} if the backing store fails to handle
      */
    async create(): Promise<DIDWithKeys> {
        return this.createWithDid(this.didWebStore.defaultDid)
    }

    /**
     * Create a did:web for the specified did. 
     * This doesn't make assumptions about whether the caller is capable of making
     * updates to the domain corresponding to the did. It simply creates the keys 
     * and DID document, and sends a notification to the didWebStore configured 
     * in the constructor, which is resonsible for handling any updates.
     * 
     * @param {string} did
     * @return {*}  {Promise<DIDWithKeys>}
     * @throws {@link DIDMethodFailureError} if not a valid did:web DID or if the backing 
     * store fails to handle
     */
    async createWithDid(did: string): Promise<DIDWithKeys> {
        if (!this.checkFormat(did)) {
            throw new DIDMethodFailureError('Not a well-formed did:web DID');
        }
        const keyPair = await KeyUtils.createEd25519KeyPair()
        const didWithKeys = {
            did,
            keyPair
        }

        await this.updateDid(didWithKeys)
        return didWithKeys

    }

    /**
     * Creates a did:web document given a private key.
     * Used when an EdDSA keypair has already been generated and is going to be used as a DID. 
     * 
     * This notifies the didWebStore configured in the constructor for subsequent handling, 
     * as described in {@link create}.
     * 
     * @throws {@link DIDMethodFailureError} if the private key is not valid or if the
     * backing store fails to handle 
     */
    async generateFromPrivateKey(privateKey: string | Uint8Array): Promise<DIDWithKeys> {
        return this.generateFromPrivateKeyWithDid(privateKey, this.didWebStore.defaultDid)
    }

    /**
     * Creates a DID given a private key and a DID.
     * Used when an EdDSA keypair has already been generated and is going to be used as a DID. 
     * 
     * This notifies the didWebStore configured in the constructor for subsequent handling, 
     * as described in {@link create}.
     * 
     * @throws {@link DIDMethodFailureError} if the private key is not valid, the
     * backing store fails to handle, or if the DID is not a valid did:web DID
     */
    async generateFromPrivateKeyWithDid(privateKey: string | Uint8Array, did: string): Promise<DIDWithKeys> {
        if (!KeyUtils.isBytesPrivateKey(privateKey)) {
            throw new DIDMethodFailureError('private key not in correct byte format')
        }
        if (!this.checkFormat(did)) {
            throw new DIDMethodFailureError('Not a well-formed did:web DID');
        }
  
        const key = await KeyUtils.createEd25519KeyPair(privateKey)
        const didWithKeys = {
            did: did,
            keyPair: {
                algorithm: this.keyAlg,
                publicKey: key.publicKey,
                privateKey: key.privateKey as Uint8Array,
            }
        }
        await this.updateDid(didWithKeys)
        return didWithKeys
  
    }

    /**
     * Resolves a DID using web-did-resolver to a {@link DIDResolutionResult} 
     * that contains the DIDDocument and associated Metadata.
     * 
     * Uses web-did-resolver and did-resolver.
     * 
     * @param did - DID to be resolved to its {@link DIDResolutionResult}
     * @returns a `Promise` that resolves to {@link DIDResolutionResult}` defined in did-resolver
     * @throws {@link DIDMethodFailureError} if resolution failed
     */
    async resolve(did: DID): Promise<DIDResolutionResult> {
        const keyDidResolver = new Resolver(getResolver());
        const result = await keyDidResolver.resolve(did);
        if (result.didResolutionMetadata.error) {
            throw new DIDMethodFailureError(`DID Resolution failed for ${did}, ${result.didResolutionMetadata.error}`)
        }
        return result;
    }

    /**
     * Updates the did with the new public key.
     * This notifies the didWebStore configured in the constructor for subsequent handling, 
     * as described in {@link create}.
     * 
     * @throws {@link DIDMethodFailureError} if the DID is not a valid did:web DID or if the
     * backing store fails to handle
     */
    async update(did: DIDWithKeys, publicKey: string | Uint8Array): Promise<boolean> {
        const newDidWithKey = {
            did: did.did,
            keyPair: {
                algorithm: this.keyAlg,
                publicKey: publicKey as Uint8Array,
            }
        }
        return this.updateDid(newDidWithKey)

    }

    /**
     * To deactivate a did:web DID, ensure the corresponding did.json file is no longer publicly available.
     * 
     * @throws {@link DIDMethodFailureError} with information about deactivating a did:web DID
     */
    async deactivate(did: DIDWithKeys): Promise<boolean> {
        const result = await this.didWebStore.delete(did.did)

        if (!result) {
            throw new DIDMethodFailureError('Failed to deactivate the did:web DID')
        }
        return result
    }

    /**
     * did:web is active if the URL is resolvable and not deactivated; inactive otherwise
     * 
     * @param did - DID to check status of
     * @returns a `Promise` that resolves to true if DID is active
     */
    async isActive(did: DID): Promise<boolean> {
        if (!this.checkFormat(did)) {
            return false
        }
        const didResult = await this.resolve(did)
        return !didResult.didDocumentMetadata.deactivated
    }

    /**
     * Get the identifier part of a did:web DID 
     * 
     * @param did - DID string
     * @returns the Identifier section of the DID
     * @throws {@link DIDMethodFailureError} if it's not a valid did:web DID
     */
    getIdentifier(did: DID): string {
        const parsed = parse(did)
        if (parsed !== null && parsed.method === this.name) {
            return parsed.id
        } else {
            throw new DIDMethodFailureError('Not a well-formed did:web DID');
        }

    }

    /**
     * Getter method for did:web Resolver from key-did-resolver
     * 
     * @returns type that is input to new {@link Resolver} from did-resolver
     */
    getDIDResolver(): Record<string, DIDResolver> {
        return getResolver()
    }

    /**
     * Helper function to check the format of a did:web DID, which uses the did-resolver parse function
     * 
     * Valid format is did:web:{identifier}, where identifier is a fully qualified domain name 
     * with an optional path to the DID document. Paths are delimited by colons rather than slashes.
     * 
     * @param did - DID string
     * @returns true if DID is in a valid did:web format
     */
    checkFormat(did: DID): boolean {
        const parsed = parse(did)
        return parsed !== null && parsed.method === this.name
    }

    /**
     * Convert a did:web DID to its corresponding URL, replacing the `did:web` prefix with `https://`
     * and replacing colons with slashes.
     * 
     * @param did the did:web DID
     * @returns the URL corresponding to the did:web DID
     * @throws {@link DIDMethodFailureError} if the DID's format is not valid per the did:web spec
     */
    didWebToUrl(did: DID): string {
        if (!this.checkFormat(did)) {
            throw new DIDMethodFailureError('Not a well-formed did:web DID');
        }
        
        const stripped = did.substring('did:web:'.length)
        let url = stripped.replace(/:/g, '/');

        if (!stripped.includes(':')) {
            url = stripped + '/.well-known';
        }

        
        return `https://${url}/did.json`;
    }


    async updateDid(didWithKey: DIDWithPublicKeys): Promise<boolean> {
        const didDocument = this.formatDidDocument(didWithKey.did, didWithKey.keyPair.publicKey)
        const result = await this.didWebStore.write(didWithKey.did, didDocument)

        if (!result) {
            throw new DIDMethodFailureError('Failed to create did:web DID')
        }
        return result
    }

    /**
     * Utility method convert DIDWithKeys into a DID document that can be hosted at the did:web URL.
     * See `create` for information about hosting the did document.
     * 
     * This is a minimal implementation that only supports Ed25519. This and could be generalized to 
     * different key encodings, verification methods, etc
     * 
     * Also see comments above about generalizing to support multiple keys and capabilities.
     * @param didWithKeys 
     * @returns {@link DIDDocument} that can be hosted at the did:web URL
     * @throws {@link DIDMethodFailureError} if the DID's format is not valid per the did:web spec
     */
    formatDidDocument(did: string, publicKey: BytesLike): DIDDocument {
        if (!this.checkFormat(did)) {
            throw new DIDMethodFailureError('Not a well-formed did:web DID');
        }

        const publicKeyAsBase58 = base58.encode(publicKey)

        const didWebDocument = {
            "@context": [DID_CONTEXT, ED25519_2018_CONTEXT],
            id: did,
            verificationMethod: [
                {
                    id: `${did}#${publicKeyAsBase58}`,
                    type: "Ed25519VerificationKey2018",
                    controller: did,
                    publicKeyBase58: publicKeyAsBase58
                }
            ],
            authentication: [
                `${did}#${publicKeyAsBase58}`
            ],
            assertionMethod: [
                `${did}#${publicKeyAsBase58}`
            ]
        }

        return didWebDocument
    }
}

export interface DIDWithPublicKeys {
    did: DID
    keyPair: Omit<KeyPair, 'privateKey'>
}

/**
 * Interface for the did:web backing store, to be called when a did:web DID is modified. 
 * This includes create, update, and deactivate events.
 * 
 * This asusmes that the backing store is responsible for and capable of making updates 
 * to the did:web DID document at the corresponding URL.
 * 
 */
export interface DIDWebStore {
    /**
     * Default DID to use for the did:web DID Method
     */
    defaultDid: string

    /**
     * Called upon a write event to a did:web DID.
     * @param did - DID string
     * @param didDocument - the {@link DIDDocument}
     * @returns  a `Promise` that resolves to a boolean indicating whether the delete was handled
     */
    write: (did: string, didDocument: DIDDocument) => Promise<boolean>

    /**
     * Called upon a delete event to a did:web DID.
     * @param did - DID string
     * @returns a `Promise` that resolves to a boolean indicating whether the delete was handled
     */
    delete: (did: string) => Promise<boolean>

}

/**
 * Configuration for the did:web DID Method
 */
export interface WebProviderConfigs {
    /** The {@link DIDWebStore} receives update/delete notifications when a did:web DID is modified */
    didWebStore: DIDWebStore
    /** 
     * Default {@link KEY_ALG} to use for the did:web DID Method.
     * Currently only supports EdDSA keypairs.
     */
    defaultKeyAlg: KEY_ALG
}
