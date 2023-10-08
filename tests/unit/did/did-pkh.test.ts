import { randomBytes } from 'crypto'
import { DIDMethodFailureError } from '../../../src/errors'
import { PkhDIDMethod } from '../../../src/services/common/did'
import { KEY_ALG } from '../../../src/utils'
import { Resolver } from 'did-resolver'

describe('did:pkh utilities', () => {

    let pkhDIDMethod: PkhDIDMethod

    const validPkhDids = [ 'did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6', 
        'did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L', 
        'did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5',  
        'did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a', 
        'did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011', 
        'did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8', 
        'did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq', 
        'did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX']

    const expectedDidDocuments = [
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6","verificationMethod":[{"id":"did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6","blockchainAccountId":"bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6"}],"authentication":["did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6#blockchainAccountId"],"assertionMethod":["did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6#blockchainAccountId"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L","verificationMethod":[{"id":"did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L","blockchainAccountId":"bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"}],"authentication":["did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L#blockchainAccountId"],"assertionMethod":["did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L#blockchainAccountId"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5","verificationMethod":[{"id":"did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5","blockchainAccountId":"eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5"}],"authentication":["did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5#blockchainAccountId"],"assertionMethod":["did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5#blockchainAccountId"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a","verificationMethod":[{"id":"did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a","blockchainAccountId":"eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"}],"authentication":["did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a#blockchainAccountId"],"assertionMethod":["did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a#blockchainAccountId"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011","verificationMethod":[{"id":"did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011","blockchainAccountId":"eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011"}],"authentication":["did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011#blockchainAccountId"],"assertionMethod":["did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011#blockchainAccountId"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8","verificationMethod":[{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8","blockchainAccountId":"tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"},{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#TezosMethod2021","type":"TezosMethod2021","controller":"did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8","blockchainAccountId":"tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"}],"authentication":["did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId","did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#TezosMethod2021"],"assertionMethod":["did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId","did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#TezosMethod2021"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq","verificationMethod":[{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq","blockchainAccountId":"tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"},{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#TezosMethod2021","type":"TezosMethod2021","controller":"did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq","blockchainAccountId":"tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"}],"authentication":["did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId","did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#TezosMethod2021"],"assertionMethod":["did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId","did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#TezosMethod2021"]},"didDocumentMetadata":{}},
        {"didResolutionMetadata":{"contentType":"application/did+json"},"didDocument":{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX","verificationMethod":[{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX","blockchainAccountId":"tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"},{"id":"did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#TezosMethod2021","type":"TezosMethod2021","controller":"did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX","blockchainAccountId":"tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"}],"authentication":["did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId","did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#TezosMethod2021"],"assertionMethod":["did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId","did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#TezosMethod2021"]},"didDocumentMetadata":{}}
    ]

    beforeAll (async () => {
        pkhDIDMethod = new PkhDIDMethod({
            name: 'maticmum',
            rpcUrl: 'https://rpc-mumbai.maticvigil.com/', 
            registry: "0x41D788c9c5D335362D713152F407692c5EEAfAae"})
        
    })

    it('Successfully creates a new did:pkh', async () => {
        const didPkh = await pkhDIDMethod.create()

        expect(didPkh.did.startsWith(`did:${pkhDIDMethod.name}`)).toBe(true)
        expect(didPkh.keyPair.privateKey).toBeDefined()
        expect(didPkh.keyPair.publicKey).toBeDefined()
        expect(didPkh.keyPair.algorithm).toBeDefined()
        expect(didPkh.keyPair.algorithm).toEqual(KEY_ALG.ES256K)
    })

    it('Successfully generates a did:pkh from existing private key', async () => {
        const didPkh = await pkhDIDMethod.create()
        const privateKey = didPkh.keyPair.privateKey
        const didPkhDup = await pkhDIDMethod.generateFromPrivateKey(privateKey)

        expect(didPkhDup.did.startsWith(`did:${pkhDIDMethod.name}`)).toBe(true)
        expect(didPkhDup.keyPair.privateKey).toBeDefined()
        expect(didPkhDup.keyPair.publicKey).toBeDefined()
        expect(didPkhDup.keyPair.algorithm).toBeDefined()
        expect(didPkhDup.did).toEqual(didPkh.did)
        expect(didPkhDup.keyPair.algorithm).toEqual(didPkh.keyPair.algorithm)
        expect(didPkh.keyPair.privateKey).toEqual(didPkh.keyPair.privateKey)
        expect(didPkh.keyPair.publicKey).toEqual(didPkh.keyPair.publicKey)
    })

    it('Generation of did:pkh from existing private key in non-matching format fails', async () => {
        const privateKey = randomBytes(64)

        await expect(pkhDIDMethod.generateFromPrivateKey(privateKey))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Generation of did:pkh from private key with incorrect byte count fails', async () => {
        const privateKey = randomBytes(33)

        await expect(pkhDIDMethod.generateFromPrivateKey(privateKey))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Resolution of created did:pkh succeeds', async () => {
        const didPkh = await pkhDIDMethod.create()
        const result = await pkhDIDMethod.resolve(didPkh.did)

        expect(result).toBeTruthy()
        expect(result.didDocument).toBeDefined()
        expect(result.didDocument?.id).toEqual(didPkh.did)
    })

    validPkhDids.forEach((didPkh, i) => {
        it(`Resolution of valid did:pkh succeeds, index ${i}: ${didPkh}`, async () => {
            const expectedDidDocument = expectedDidDocuments[i]
            const didDocument = await pkhDIDMethod.resolve(didPkh)
            expect(didDocument).toMatchObject(expectedDidDocument)
        })
    })


    it('Resolution of incorrect did method fails', async () => {
        const wrongDid = 'did:fail:1234'
        await expect(pkhDIDMethod.resolve(wrongDid))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Resolution of invalid did fails', async () => {
        const wrongDid = 'did:pkh:1234'
        await expect(pkhDIDMethod.resolve(wrongDid))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Updating did:pkh not supported', async () => {
        const didPkh = await pkhDIDMethod.create()
        const publicKey = randomBytes(33)
        await expect(pkhDIDMethod.update(didPkh, publicKey))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Deleting did:pkh not supported', async () => {
        const didPkh = await pkhDIDMethod.create()
        await expect(pkhDIDMethod.deactivate(didPkh))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    validPkhDids.forEach((didPkh, i) => {
        it(`Active status for valid pkh is true, index ${i}: ${didPkh}`, async () => {
            const format = await pkhDIDMethod.isActive(didPkh)
            expect(format).toBeTruthy()
        })
    })

    it('Active status for invalid pkh is false', async () => {
        const didPkh = 'did:pkh:123'
        const active = await pkhDIDMethod.isActive(didPkh)
        expect(active).toBe(false)
    })

    describe('extraction of did:pkh identifiers succeeds', () => {

        it('extraction of did:pkh:bip122 identifier succeeds', async () => {
            const didPkh = 'did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6')
        })

        it('extraction of did:pkh:bip122 identifier succeeds', async () => {
            const didPkh = 'did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L')
        })

        it('extraction of did:pkh:eip155 identifier succeeds', async () => {
            const didPkh = 'did:pkh:eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('eip155:137:0x4e90e8a8191c1c23a24a598c3ab4fb47ce926ff5')
        })
        it('extraction of did:pkh:eip155 identifier succeeds', async () => {
            const didPkh = 'did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a')
        })
        it('extraction of did:pkh:eip155 identifier succeeds', async () => {
            const didPkh = 'did:pkh:eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('eip155:42220:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011')
        })

        it('extraction of did:pkh:tezos identifier succeeds', async () => {
            const didPkh = 'did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8')
        })
        it('extraction of did:pkh:tezos identifier succeeds', async () => {
            const didPkh = 'did:pkh:tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq')
        })
        it('extraction of did:pkh:tezos identifier succeeds', async () => {
            const didPkh = 'did:pkh:tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX'
            const active = pkhDIDMethod.getIdentifier(didPkh)

            expect(active).toBe('tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX')
        })
    })

    it('Getting the resolver returns a valid pkh resolver', async () => {
        const didResolver = pkhDIDMethod.getDIDResolver()
        expect(didResolver).toBeDefined()

        const resolverWrapper = new Resolver({
            ...didResolver
            //...other reoslvers
        })


        const res = await resolverWrapper.resolve("did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L")
        expect(res.didDocument).toBeDefined()

    })

    it('Extraction of did:pkh identifier incorrect format fails', async () => {
        const didPkh = 'did:pkh:123'

        expect(() => pkhDIDMethod.getIdentifier(didPkh))
            .toThrow(DIDMethodFailureError)
    })

    
    validPkhDids.forEach((didPkh, i) => {
        it(`check format of did:pkh identifier succeeds, index ${i}: ${didPkh}`, async () => {
            const format = pkhDIDMethod.checkFormat(didPkh)

            expect(format).toBeTruthy()
        })
    })

    it('check format of did:pkh identifier incorrect format fails', async () => {
        const didPkh = 'did:pkh:123'
        const format = pkhDIDMethod.checkFormat(didPkh)

        expect(format).toBeFalsy()
    })
})