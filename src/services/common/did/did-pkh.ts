import { DIDResolutionResult, DIDResolver, Resolver } from "did-resolver"
import { getResolver } from "pkh-did-resolver"
import { DID, DIDMethod, DIDWithKeys } from "./did"
import { DIDMethodFailureError } from "../../../errors"
import { KeyUtils, KEY_ALG } from "../../../utils"
import { ethers } from 'ethers'
import { JsonRpcProvider, Provider } from "@ethersproject/providers" 
import { ProviderConfigs } from "./did-ethr"
import { Wallet } from "@ethersproject/wallet"



/**
 * Currently does not support arweave and solana
 * 
    // networks:
    // eip155: eth, celo, poly
    // tezos: tezos (tz1, tz2, tz3) 
    // bip122: btc, doge
 */
export class PkhDIDMethod implements DIDMethod {
    name = 'pkh'
    network = 'eip155'
    providerConfigs: ProviderConfigs
    web3Provider: Provider


    constructor(providerConfigs: ProviderConfigs) {
        this.providerConfigs = providerConfigs
        this.web3Provider = providerConfigs.provider ? providerConfigs.provider : new JsonRpcProvider(providerConfigs.rpcUrl)
    }

    /**
     * Formats address as a pkh did, relies on [CAIP10](https://chainagnostic.org/CAIPs/caip-10)
     * and [CAIP2](https://chainagnostic.org/CAIPs/caip-2).
     * @param address blockchain address
     * @returns the corresponding did:pkh DID
     */
    async addressToDid(address: string): Promise<string> {

        const chainId =  (await this.web3Provider.getNetwork()).chainId
        const did = `did:${this.name}:${this.network}:${chainId}:${address}`
        return did
    }

    async create(): Promise<DIDWithKeys> {
        const account = ethers.Wallet.createRandom()
        const privateKey = account.privateKey
        const publicKey = KeyUtils.privateKeyToPublicKey(privateKey)
        const did = await this.addressToDid(account.address)

        const identity: DIDWithKeys = {
            did,
            keyPair: {
                algorithm: KEY_ALG.ES256K,
                publicKey,
                privateKey
            }
        }

        return identity

    }

    /**
     * Creates a DID given a private key
     * Used when an ES256K keypair has already been generated and is going to be used as a DID
     * 
     * @param privateKey - private key to be used in creation of a did:pkh DID
     * @returns a `Promise` that resolves to {@link DIDWithKeys}
     * @throws `DIDMethodFailureError` if private key is not in hex format
     */
    async generateFromPrivateKey(privateKey: string | Uint8Array): Promise<DIDWithKeys> {
        if (!KeyUtils.isHexPrivateKey(privateKey)) {
            throw new DIDMethodFailureError('new public key not in hex format')
        }
        const publicKey = KeyUtils.privateKeyToPublicKey(privateKey as string)
        const address = new Wallet(privateKey as string, this.web3Provider).address
        const did = await this.addressToDid(address)
        const identity: DIDWithKeys = {
            did,
            keyPair: {
                algorithm: KEY_ALG.ES256K,
                publicKey,
                privateKey
            }
        }
        return identity;
    }

    /**
     * 
     * Resolves a DID using the resolver from pkh-did-resolver to a {@link DIDResolutionResult} 
     * that contains the DIDDocument and associated metadata 
     * 
     * Uses pkh-did-resolver and did-resolver
     * 
     * @param did - the DID to be resolved
     * @returns a `Promise` that resolves to `DIDResolutionResult` defined in did-resolver
     * @throws `DIDMethodFailureError` if resolution failed
     */
    async resolve(did: DID): Promise<DIDResolutionResult> {
        const pkhResolver = new Resolver(getResolver())
        const result = await pkhResolver.resolve(did)
        if (result.didResolutionMetadata.error) {
            throw new DIDMethodFailureError(`DID Resolution failed for ${did}, ${result.didResolutionMetadata.error}`)
        }
        return result
    }
    
    /**
     * did:pkh does not support update
     * @throws `DIDMethodFailureError`
     */
    async update(_did: DIDWithKeys, _publicKey: string | Uint8Array): Promise<boolean> {
        throw new DIDMethodFailureError('did:pkh does not support Update')
    }

    /**
     * did:pkh does not support deactivate
     * @throws `DIDMethodFailureError`
     */
    async deactivate(_did: DIDWithKeys): Promise<boolean> {
        throw new DIDMethodFailureError('did:pkh does not support Delete')
    }

    /**
     * Since did:pkh cannot be updated or deactivated, the status will always be active
     * 
     * @param did - DID to check status of
     * @returns a `Promise` that always resolves to true if DID is in correct format
     * @throws `DIDMethodFailureError` if format check fails
     */
    async isActive(did: DID): Promise<boolean> {
        return this.checkFormat(did)

    }

    /**
     * Helper function to return the Identifier from a did:PKH string
     *  TODO: SHOULD THIS CONTAIN NETWORK??
     * 
     * @param did - DID string
     * @returns the Identifier section of the DID
     * @throws `DIDMethodFailureError` if format check fails
     */
    getIdentifier(did: string): string {
        if(!this.checkFormat(did)) {
            throw new DIDMethodFailureError('DID format incorrect')
        }
        return `${did.substring(did.indexOf(':', did.indexOf(':') + 1) + 1)}`
        // TODO THIS ISN'T RIGHT
    }

    /**
     * Getter method for did:pkh Resolver from pkh-did-resolver
     * 
     * @returns type that is input to new {@link Resolver} from did-resolver
     */
    getDIDResolver(): Record<string, DIDResolver> {
        return getResolver()
    }

    /**
     * Helper function to check format of a did:pkh. 
     * 
     * Correct format is did:pkh:{account_id} where account_id is defined by 
     * [CAIP10](https://chainagnostic.org/CAIPs/caip-10) and
     * [CAIP2](https://chainagnostic.org/CAIPs/caip-2).
     * 
     * However, this is more restrictive to reduce to supported namespaces
     * 
     * @param did - DID string
     * @returns true if format check passes
     */
    checkFormat(did: DID): boolean {
        const keyMatcher = /^did:pkh:(bip122|eip155|tezos):[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/ 
        return keyMatcher.test(did as string)
    }
  
  
    
}