import { randomBytes } from 'crypto'
import { DIDMethodFailureError } from '../../../src/errors'
import { DidWebStore, WebDIDMethod } from '../../../src/services/common/did'
import { KeyUtils, KEY_ALG } from '../../../src/utils'
import { DID_CONTEXT, ED25519_2018_CONTEXT } from '../../../src/services/common'
import { DIDDocument, Resolver } from 'did-resolver'
import fetch from 'cross-fetch'
jest.mock('cross-fetch')
const mockedFetch = jest.mocked(fetch)

describe('did:web utilities', () => {

    const EXAMPLE_DID = 'did:web:example.com'

    const mockWrite = jest.fn().mockResolvedValue(true)
    const mockDelete = jest.fn().mockResolvedValue(true)

    const noopDidWebStore =   {
        baseDid: EXAMPLE_DID,
        write: mockWrite,
        delete: mockDelete
    }

    class InMemoryDidWebStore implements DidWebStore {
        baseDid = EXAMPLE_DID
        didWebStore = new Map<string, DIDDocument>()
        write (did: string, didDocument: DIDDocument): Promise<boolean> {
            this.didWebStore.set(did, didDocument) 
            return Promise.resolve(true)
        }
        delete (did: string): Promise<boolean> {
            this.didWebStore.delete(did)
            return Promise.resolve(true)
        }
    }


    const webDIDMethod = new WebDIDMethod({didWebStore: noopDidWebStore, keyAlg: KEY_ALG.EdDSA})

    // TODO:
    const EXAMPLE_KEY_PAIR = {
        algorithm: KEY_ALG.EdDSA,
        publicKey: '0x02f034136f204a02045c17f977fa9ac36362fe5a86524b464a56a26cbfb0754e23',
        privateKey: '0xd42a4eacb5cf7758ae07e12f3b3971b643b6c78f18972eb5444ffd66e03bac15'
    };
    const EXAMPLE_DID_KEY_PAIR = {
        did: EXAMPLE_DID,
        keyPair: EXAMPLE_KEY_PAIR
    }

    const ED_25519_DID_DOC = {
        "@context": [DID_CONTEXT, ED25519_2018_CONTEXT],
        id: EXAMPLE_DID,
        verificationMethod: [
            {
                "id": "did:web:example.com#sdHeQWTwoA91yu2YMsBs9HruxAAe6ribkmBqXhpAKVeJ",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:web:example.com",
                "publicKeyBase58": "sdHeQWTwoA91yu2YMsBs9HruxAAe6ribkmBqXhpAKVeJ"
            }
        ],
        authentication: [
            "did:web:example.com#sdHeQWTwoA91yu2YMsBs9HruxAAe6ribkmBqXhpAKVeJ"
        ],
        assertionMethod: [
            "did:web:example.com#sdHeQWTwoA91yu2YMsBs9HruxAAe6ribkmBqXhpAKVeJ"]
    }

    // Examples from web-did-resolver
    const ETH_IDENTITY = '0x2Cc31912B2b0f3075A87b3640923D45A26cef3Ee'
    const ETH_DID_DOC: DIDDocument = {
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

    beforeEach(() => {
        mockedFetch.mockClear()
        mockWrite.mockClear()
        mockDelete.mockClear()
    })

    it('Successfully creates a new did:web', async () => {
        const didWeb = await webDIDMethod.create()

        expect(didWeb.did.startsWith(`did:${webDIDMethod.name}`)).toBe(true)
        expect(didWeb.did).toEqual(EXAMPLE_DID)
        expect(didWeb.keyPair.privateKey).toBeDefined()
        expect(didWeb.keyPair.publicKey).toBeDefined()
        expect(didWeb.keyPair.algorithm).toBeDefined()
        expect(didWeb.keyPair.algorithm).toEqual(KEY_ALG.EdDSA)
        expect(didWeb.keyPair.privateKey.length).toEqual(KeyUtils.PRIVATE_KEY_LENGTH)
        expect(didWeb.keyPair.publicKey.length).toEqual(KeyUtils.PUBLIC_KEY_LENGTH)
        expect(mockWrite).toBeCalledTimes(1)
    })

    it('Successfully creates a new did:web corresponding to the specified did', async () => {
        const didWeb = await webDIDMethod.createWithDid("did:web:example2.com")

        expect(didWeb.did.startsWith(`did:${webDIDMethod.name}`)).toBe(true)
        expect(didWeb.did).toEqual("did:web:example2.com")
        expect(didWeb.keyPair.privateKey).toBeDefined()
        expect(didWeb.keyPair.publicKey).toBeDefined()
        expect(didWeb.keyPair.algorithm).toBeDefined()
        expect(didWeb.keyPair.algorithm).toEqual(KEY_ALG.EdDSA)
        expect(didWeb.keyPair.privateKey.length).toEqual(KeyUtils.PRIVATE_KEY_LENGTH)
        expect(didWeb.keyPair.publicKey.length).toEqual(KeyUtils.PUBLIC_KEY_LENGTH)
        expect(mockWrite).toBeCalledTimes(1)
    })

    it('Fails to create a did:web for a different did method', async () => {
        await expect(webDIDMethod.createWithDid('did:btcr:xyv2-xzpq-q9wa-p7t'))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Fails to create a did:web for an invalid did:web did', async () => {
        await expect(webDIDMethod.createWithDid('did:web:gd&5'))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Successfully generates a did:web from existing private key', async () => {
        const keyPair = await KeyUtils.createEd25519KeyPair()
        const didWeb = await webDIDMethod.generateFromPrivateKey(keyPair.privateKey)

        expect(didWeb.did.startsWith(`did:${webDIDMethod.name}`)).toBe(true)
        expect(didWeb.did).toEqual(EXAMPLE_DID)
        expect(didWeb.keyPair.privateKey).toBeDefined()
        expect(didWeb.keyPair.publicKey).toBeDefined()
        expect(didWeb.keyPair.algorithm).toBeDefined()
        expect(didWeb.keyPair.algorithm).toEqual(keyPair.algorithm)
        expect(didWeb.keyPair.privateKey).toEqual(keyPair.privateKey)
        expect(didWeb.keyPair.publicKey).toEqual(keyPair.publicKey)
        expect(mockWrite).toBeCalledTimes(1)
    })

    it('Generation of did:web from private key with incorrect byte count fails', async () => {
        const privateKey = randomBytes(33)

        await expect(webDIDMethod.generateFromPrivateKey(privateKey))
            .rejects.toThrowError(DIDMethodFailureError)

        expect(mockWrite).toBeCalledTimes(0)
    })

    it('Generation of did:web from existing private key in hex format fails', async () => {
        const privateKey = '0x69af672c46812a314eacbd90d6ee24cf5c03c4f46205f0b9b6fa2a079295e838'

        await expect(webDIDMethod.generateFromPrivateKey(privateKey))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Successfully generates a did:web from existing private key and did', async () => {
        const keyPair = await KeyUtils.createEd25519KeyPair()

        const didWeb = await webDIDMethod.generateFromPrivateKeyWithDid(keyPair.privateKey, 'did:web:example.com:alice:1234')
        expect(didWeb.did.startsWith(`did:${webDIDMethod.name}`)).toBe(true)
        expect(didWeb.did).toEqual('did:web:example.com:alice:1234')
        expect(didWeb.keyPair.privateKey).toBeDefined()
        expect(didWeb.keyPair.publicKey).toBeDefined()
        expect(didWeb.keyPair.algorithm).toBeDefined()
        expect(didWeb.keyPair.algorithm).toEqual(keyPair.algorithm)
        expect(didWeb.keyPair.privateKey).toEqual(keyPair.privateKey)
        expect(didWeb.keyPair.publicKey).toEqual(keyPair.publicKey)
        expect(mockWrite).toBeCalledTimes(1)
    })

    it('Generation of did:web from existing private key in hex format fails', async () => {
        const privateKey = '0x69af672c46812a314eacbd90d6ee24cf5c03c4f46205f0b9b6fa2a079295e838'

        await expect(webDIDMethod.generateFromPrivateKeyWithDid(privateKey, 'did:web:example.com'))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Generation of did:web from existing private key and invalid did fails', async () => {
        const keyPair = await KeyUtils.createEd25519KeyPair()
        await expect(webDIDMethod.generateFromPrivateKeyWithDid(keyPair.privateKey, 'did:btcr:xyv2-xzpq-q9wa-p7t'))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Creating a did:web fails if didWebStore fails', async () => {
        const mockFailedWrite = jest.fn().mockResolvedValue(false)
        const mockDidWebStore = {
            baseDid: EXAMPLE_DID,
            write: mockFailedWrite,
            delete: mockWrite
        }
        const webDIDMethod = new WebDIDMethod({didWebStore: mockDidWebStore, keyAlg: KEY_ALG.EdDSA})

        await expect(webDIDMethod.create()).rejects.toThrowError(DIDMethodFailureError)
        expect(mockFailedWrite).toBeCalledTimes(1)
    })

    it('Resolution of did:web succeeds', async () => {
        mockedFetch.mockResolvedValueOnce({
            json: () => Promise.resolve(ETH_DID_DOC),
        } as Response)

        const res = await webDIDMethod.resolve("did:web:example.com")
        expect(res.didDocument).toBeDefined()
    })

    it('Resolution after creation of did:web succeeds', async () => {

        // configure with a DidWebStore that stores didDocuments in memory
        const inMemoryStore = new InMemoryDidWebStore()
        const webDIDMethodWithStore = new WebDIDMethod({didWebStore: inMemoryStore, keyAlg: KEY_ALG.EdDSA})
        const didWeb = await webDIDMethodWithStore.createWithDid("did:web:example.com:alice:1234")
        
        const didDoc = inMemoryStore.didWebStore.get(didWeb.did)
        // mock fetch to return the did document that was just created; this should be returned by the resolver
        mockedFetch.mockResolvedValueOnce({
            json: () => Promise.resolve(didDoc),
        } as Response)

        const res = await webDIDMethod.resolve("did:web:example.com:alice:1234")
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        expect(res.didDocument).toMatchObject(didDoc!)
    })

    it('Resolving an updated did:web succeeds', async () => {
        // configure with a DidWebStore that stores didDocuments in memory
        const inMemoryStore = new InMemoryDidWebStore()
        const webDIDMethodWithStore = new WebDIDMethod({didWebStore: inMemoryStore, keyAlg: KEY_ALG.EdDSA})
        const didWeb = await webDIDMethodWithStore.createWithDid("did:web:example.com:alice:1234")

        const newKey = await KeyUtils.createEd25519KeyPair()
        webDIDMethodWithStore.update(didWeb, newKey.publicKey)
        const updatedDidDoc = inMemoryStore.didWebStore.get(didWeb.did)
        mockedFetch.mockResolvedValue({
            json: () => Promise.resolve(updatedDidDoc),
        } as Response)

        const res = await webDIDMethod.resolve("did:web:example.com:alice:1234")
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        expect(res.didDocument).toMatchObject(updatedDidDoc!)

    })
    it('Resolving an invalid did:web did fails', async () => {
        const wrongDid = 'did:web:1234%'
        await expect(webDIDMethod.resolve(wrongDid))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Resolving an incorrect did method fails', async () => {
        const wrongDid = 'did:fail:1234'
        await expect(webDIDMethod.resolve(wrongDid))
            .rejects.toThrowError(DIDMethodFailureError)
    })



    it('Successfully updates a did:web', async () => {
        const didWeb = await webDIDMethod.create()
        const keyPair = await KeyUtils.createEd25519KeyPair()
        const result = await webDIDMethod.update(didWeb, keyPair.publicKey)

        expect(result).toBeTruthy()
        expect(mockWrite).toBeCalledTimes(2)

    })

    it('Updating a did:web from existing private key in hex format fails', async () => {
        const privateKey = '0x69af672c46812a314eacbd90d6ee24cf5c03c4f46205f0b9b6fa2a079295e838'

        await expect(webDIDMethod.generateFromPrivateKey(privateKey))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Updating a did:web from private key with incorrect byte count fails', async () => {
        const privateKey = randomBytes(33)

        await expect(webDIDMethod.generateFromPrivateKey(privateKey))
            .rejects.toThrowError(DIDMethodFailureError)
    })

    it('Updating a did:web fails if didWebStore fails', async () => {
        const mockFailedWrite = jest.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false)
        const mockDidWebStore = {
            baseDid: EXAMPLE_DID,
            write: mockFailedWrite,
            delete: mockWrite
        }
        const webDIDMethod = new WebDIDMethod({didWebStore: mockDidWebStore, keyAlg: KEY_ALG.EdDSA})
        const didWeb = await webDIDMethod.create()
        await expect(webDIDMethod.update(didWeb, EXAMPLE_KEY_PAIR.publicKey)).rejects.toThrowError(DIDMethodFailureError)
        expect(mockFailedWrite).toBeCalledTimes(2)
    })


    it('Deleting did:web succeeds', async () => {
        const didWeb = await webDIDMethod.create()
        const result = expect(webDIDMethod.deactivate(didWeb))
        expect(result).toBeTruthy()
        expect(mockDelete).toBeCalledTimes(1)
    })

    it('Deleting did:web fails if didWebStore fails', async () => {
        const mockFailedDelete = jest.fn().mockResolvedValue(false)
        const mockDidWebStore = {
            baseDid: EXAMPLE_DID,
            write: mockWrite,
            delete: mockFailedDelete
        }
        const webDIDMethod = new WebDIDMethod({didWebStore: mockDidWebStore, keyAlg: KEY_ALG.EdDSA})


        const didWeb = await webDIDMethod.create()
        expect(webDIDMethod.deactivate(didWeb)).rejects.toThrowError(DIDMethodFailureError)
        expect(mockFailedDelete).toBeCalledTimes(1)
    })


    it('did:web active status true', async () => {
        webDIDMethod.resolve = jest.fn().mockResolvedValueOnce({
            didDocumentMetadata: {},
            didResolutionMetadata: { contentType: 'application/did+ld+json' }, 
            didDocument: ED_25519_DID_DOC
        }
        )

        const res = await webDIDMethod.isActive(EXAMPLE_DID_KEY_PAIR.did)
        expect(res).toBe(true)
    })


    it('did:web active status false for invalid did', async () => {
        const didWeb = 'did:web:123$'
        const active = await webDIDMethod.isActive(didWeb)

        expect(active).toBe(false)
    })

    it('Extracting a did:web identifier succeeds', async () => {
        const didWeb = 'did:web:example.com'

        expect(webDIDMethod.getIdentifier(didWeb)).toEqual('example.com')
    })

    it('Extracting a did:web identifier for invalid format fails', async () => {
        const didWeb = 'did:web:123$'

        expect(() => webDIDMethod.getIdentifier(didWeb))
            .toThrow(DIDMethodFailureError)
    })


    it('Getting the resolver returns a valid web resolver', async () => {
        const webResolver = webDIDMethod.getDIDResolver()
        expect(webResolver).toBeDefined()

        const resolverWrapper = new Resolver({
            ...webResolver
            //...other reoslvers
        })

        mockedFetch.mockResolvedValueOnce({
            json: () => Promise.resolve(ETH_DID_DOC),
        } as Response)

        const res = await resolverWrapper.resolve("did:web:example.com")
        expect(res.didDocument).toMatchObject(ETH_DID_DOC)

    })

    it('Check format of a valid did:web did succeeds', () => {
        const didWeb = 'did:web:example.com'
        const format = webDIDMethod.checkFormat(didWeb)

        expect(format).toBeTruthy()
    })

    it('Check format of a valid did:web did succeeds (domain and path)', () => {
        const didWeb = 'did:web:example.com:user:alice'
        const format = webDIDMethod.checkFormat(didWeb)

        expect(format).toBeTruthy()
    })

    it('Check format of an invalid did:web did fails', async () => {
        const didWeb = 'did:web:badExample&'
        const format = webDIDMethod.checkFormat(didWeb)

        expect(format).toBeFalsy()
    })

    it('Check format of a different did method fails', async () => {
        const didWeb = 'did:btcr:xyv2-xzpq-q9wa-p7t'
        const format = webDIDMethod.checkFormat(didWeb)

        expect(format).toBeFalsy()
    })

    it('Check format of a non-did string', async () => {
        const didWeb = '12345678'
        const format = webDIDMethod.checkFormat(didWeb)

        expect(format).toBeFalsy()
    })

    it('Converts a did:web did to a url', async () => {
        const didWeb = 'did:web:example.com'
        const url = webDIDMethod.didWebToUrl(didWeb)

        expect(url).toEqual('https://example.com/.well-known/did.json')
    })

    it('Converts a did:web did with path to a url', async () => {
        const didWeb = 'did:web:example.com:alice:123'
        const url = webDIDMethod.didWebToUrl(didWeb)

        expect(url).toEqual('https://example.com/alice/123/did.json')
    })

    it('Converting a did:web did a url fails for an invalid did', async () => {
        const badDidWeb = 'did:pkh:xyv2-xzpq-q9wa-p7t'
        expect(() => webDIDMethod.didWebToUrl(badDidWeb))
            .toThrowError(DIDMethodFailureError)
    })


    it('Successfully formats a did:web did document from a KeyPair on formatDidDocument', () => {
        const didWebDocument = webDIDMethod.formatDidDocument(EXAMPLE_DID_KEY_PAIR.did, EXAMPLE_DID_KEY_PAIR.keyPair.publicKey)
        expect(didWebDocument).toMatchObject(ED_25519_DID_DOC)
    })

    it('Formatting a did:web did document for an invalid did fails', () => {
        expect(() => webDIDMethod.formatDidDocument('did:pkh:xyv2-xzpq-q9wa-p7t', EXAMPLE_DID_KEY_PAIR.keyPair.publicKey))
            .toThrowError(DIDMethodFailureError)
    })

    it('Creating did:web method fails if baseDid is invalid', async () => {
        const mockDidWebStore = {
            baseDid: 'did:web:dgef^',
            write: mockWrite,
            delete: mockDelete
        }
        expect(() => new WebDIDMethod({didWebStore: mockDidWebStore, keyAlg: KEY_ALG.EdDSA})).toThrowError(DIDMethodFailureError)
    })


})


