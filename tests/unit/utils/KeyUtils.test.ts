import { randomBytes } from "crypto"
import { KeyTypeError } from "../../../src/errors"
import { KeyDIDMethod } from "../../../src/services/common"
import { KEY_ALG, KeyUtils } from "../../../src/utils"

describe('key utilities', () => {

    const ethrKeys = {
        did: 'did:ethr:maticmum:0x076231A475b8F905f71f45580bD00642025c4e0D',
        keyPair: {
            algorithm: KEY_ALG.ES256K,
            publicKey: '02f034136f204a02045c17f977fa9ac36362fe5a86524b464a56a26cbfb0754e23',
            privateKey: '0xd42a4eacb5cf7758ae07e12f3b3971b643b6c78f18972eb5444ffd66e03bac15'
        }
    }

    it('Successfully converts ES256K private key to public key', async () => {
        const pubKey = KeyUtils.privateKeyToPublicKey(ethrKeys.keyPair.privateKey)
        expect(pubKey).toBeDefined()
        expect(pubKey).toEqual(ethrKeys.keyPair.publicKey)
    })

    it('Fails converting private key with wrong length to public key', async () => {
        expect(() => KeyUtils.privateKeyToPublicKey('0x1234'))
            .toThrowError(KeyTypeError)

    })

    it('Check for hex private key succeeds', async () => {
        const check = KeyUtils.isHexPrivateKey(ethrKeys.keyPair.privateKey)
        expect(check).toBeTruthy()
    })

    it('Check for hex private key fails', async () => {
        const check = KeyUtils.isHexPrivateKey('0x1234')
        expect(check).toBeFalsy()
    })

    it('Check for hex private key fails when given public key', async () => {
        const check = KeyUtils.isHexPrivateKey(ethrKeys.keyPair.publicKey)
        expect(check).toBeFalsy()
    })

    it('Check for hex private key fails when given uint8array', async () => {
        const keymethod = new KeyDIDMethod()
        const key = await keymethod.create()
        const check = KeyUtils.isHexPrivateKey(key.keyPair.privateKey)
        expect(check).toBeFalsy()
    })

    it('Check for hex public key succeeds', async () => {
        const check = KeyUtils.isHexPublicKey(ethrKeys.keyPair.publicKey)
        expect(check).toBeTruthy()
    })

    it('Check for hex public key fails', async () => {
        const check = KeyUtils.isHexPublicKey('0x1234')
        expect(check).toBeFalsy()
    })

    it('Check for hex public key fails when given public key', async () => {
        const check = KeyUtils.isHexPublicKey(ethrKeys.keyPair.privateKey)
        expect(check).toBeFalsy()
    })

    it('Check for hex public key fails when given uint8array', async () => {
        const keymethod = new KeyDIDMethod()
        const key = await keymethod.create()
        const check = KeyUtils.isHexPublicKey(key.keyPair.publicKey)
        expect(check).toBeFalsy()
    })

    it('Check for bytes private key succeeds', async () => {
        const keymethod = new KeyDIDMethod()
        const key = await keymethod.create()
        const check = KeyUtils.isBytesPrivateKey(key.keyPair.privateKey)
        expect(check).toBeTruthy()
    })

    it('Check for private key fails, wrong number of bytes', async () => {
        const bytes = randomBytes(22)
        const check = KeyUtils.isBytesPrivateKey(bytes)
        expect(check).toBeFalsy()
    })

    it('Check for bytes private key fails when given public key', async () => {
        const keymethod = new KeyDIDMethod()
        const key = await keymethod.create()
        const check = KeyUtils.isBytesPrivateKey(key.keyPair.publicKey)
        expect(check).toBeFalsy()
    })

    it('Check for bytes private key fails when given hex', async () => {
        const check = KeyUtils.isBytesPrivateKey(ethrKeys.keyPair.privateKey)
        expect(check).toBeFalsy()
    })

    it('Check for bytes public key succeeds', async () => {
        const keymethod = new KeyDIDMethod()
        const key = await keymethod.create()
        const check = KeyUtils.isBytesPublicKey(key.keyPair.publicKey)
        expect(check).toBeTruthy()
    })

    it('Check for public key fails, wrong number of bytes', async () => {
        const bytes = randomBytes(22)
        const check = KeyUtils.isBytesPublicKey(bytes)
        expect(check).toBeFalsy()
    })

    it('Check for bytes public key fails when given private key', async () => {
        const keymethod = new KeyDIDMethod()
        const key = await keymethod.create()
        const check = KeyUtils.isBytesPublicKey(key.keyPair.privateKey)
        expect(check).toBeFalsy()
    })

    it('Check for bytes public key fails when given hex string', async () => {
        const check = KeyUtils.isBytesPublicKey(ethrKeys.keyPair.publicKey)
        expect(check).toBeFalsy()
    })

    it('Creates Ed25519 key pair', async () => {
        const keyPair = await KeyUtils.createEd25519KeyPair()
        expect(keyPair).toBeDefined()
        expect(keyPair.algorithm).toEqual(KEY_ALG.EdDSA)
        expect(keyPair.publicKey).toBeDefined()
        expect(keyPair.privateKey).toBeDefined()
        expect(keyPair.publicKey.length).toEqual(32)
        expect(keyPair.privateKey.length).toEqual(64)
    })

    it('Creates Ed25519 key pair with private key', async () => {
        const keyPair = await KeyUtils.createEd25519KeyPair()
        const keyPairDupe = await KeyUtils.createEd25519KeyPair(keyPair.privateKey)
        expect(keyPairDupe).toBeDefined()
        expect(keyPairDupe.algorithm).toEqual(KEY_ALG.EdDSA)
        expect(keyPairDupe.publicKey).toEqual(keyPair.publicKey)
    })

    it('Generation of Ed25519 key pair from existing private key in hex format fails', async () => {
        const privateKey = '0x69af672c46812a314eacbd90d6ee24cf5c03c4f46205f0b9b6fa2a079295e838'

        await expect(KeyUtils.createEd25519KeyPair(privateKey))
            .rejects.toThrowError(KeyTypeError)
    })

    it('Generation of Ed25519 key pair from private key with incorrect byte count fails', async () => {
        const privateKey = randomBytes(33)

        await expect(KeyUtils.createEd25519KeyPair(privateKey))
            .rejects.toThrowError(KeyTypeError)
    })

})