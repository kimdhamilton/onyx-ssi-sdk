import { ES256KSigner } from 'did-jwt'
import { Resolvable } from 'did-resolver'
import {
    ObjectPropertyClaim,
    bytesToBase64url,
    createArrayElementDisclosable,
    createObjectPropertyDisclosable,
    createSalt,
    createSdJWT,
    decodeSdJWT,
    encodeBase64url,
    formSdJwt,
    fromString,
    hashDisclosure,
    parseDisclosure,
    sdJwtPayloadHelper,
    stringToBytes,
    verifySdJWT,
} from "../../../src/services/common/signatures/sdjwt"
import {
    OBJECT_PROPERTY_DISCLOSURE_TEST_CASES,
    HASH_DISCLOSURE_TEST_CASES,
    ARRAY_ELEMENT_DISCLOSURE_TEST_CASES,
    ADDRESS_DECODED,
    ADDRESS_OPTION_1,
    ADDRESS_OPTION_1_DISCLOSURE,
    ADDRESS_OPTION_1_SD_JWT,
    ADDRESS_OPTION_2,
    ADDRESS_OPTION_2_DISCLOSURES,
    ADDRESS_OPTION_2_JWT_ONLY,
    ADDRESS_OPTION_2_SD_JWT,
    ADDRESS_OPTION_3,
    ADDRESS_OPTION_3_DISCLOSURES,
    ADDRESS_OPTION_3_SD_JWT,
    ADDRESS_SUBSET_DECODED,
    EXAMPLE_1_DECODED,
    EXAMPLE_1_JWT,
    EXAMPLE_1_KB_DECODED,
    EXAMPLE_1_KB_JWT,
    SD_JWT_REPEATED_CLAIM,
} from "./data/sdjwt.vectors"

import {expect, jest, it} from '@jest/globals';

/**
 * If set to true, this uses a special stringify function that allows an
 * exact match for the SD-JWT spec examples.
 *
 * Matching the spec outputs also requires the use of a pre-defined salt,
 * which is provided in the test cases. (@link sd-jwt-vectors.js)
 *
 * Because the exact stringify formatting is not specified by the spec,
 * this is not the default behavior. If not enabled, the default
 * JSON.stringify() function, with no args, will be used.
 */
export const SPEC_COMPAT_OPTIONS = {
    specCompatStringify: true,
}

export const BASE64_URL_REGEX = new RegExp(/^[-A-Za-z0-9_/]*={0,3}$/)

/**
 * Included as a did-jwt workaround
 * @param s 
 * @param minLength 
 * @returns 
 */
export function hexToBytes(s: string, minLength?: number): Uint8Array {
    let input = s.startsWith('0x') ? s.substring(2) : s

    if (input.length % 2 !== 0) {
        input = `0${input}`
    }

    if (minLength) {
        const paddedLength = Math.max(input.length, minLength * 2)
        input = input.padStart(paddedLength, '00')
    }

    return fromString(input.toLowerCase(), 'hex')
}




describe('SD-JWT utilities tests', () => {

    describe('createSalt()', () => {
        it('returns a string that is base64url encoded', () => {
            const salt = createSalt()
            expect(BASE64_URL_REGEX.test(salt)).toBeTruthy()
        })

        it('returns a string that is base64url encoded (with pre-defined salt)', () => {
            const salt = createSalt(32)
            expect(BASE64_URL_REGEX.test(salt)).toBeTruthy()
        })
    })

    /* SD-JWT spec (5.3) tests */
    describe('hashDisclosure()', () => {
        it.each(HASH_DISCLOSURE_TEST_CASES)(
            'matches SD-JWT spec output (disclosure: %s, expectedHash: %s)',
            (disclosure, expectedHash) => {
                const hash = hashDisclosure(disclosure)
                expect(hash).toEqual(expectedHash)
            }
        )
    })

    describe('makeSdJWTPayload()', () => {
        it('passes basic test', () => {
            const { sdJwtPayload, disclosables } = sdJwtPayloadHelper(
                { hiddenValue1: 'value1', hiddenValue2: 'value2' },
                { clearValue1: 'value3' }
            )

            expect(sdJwtPayload!._sd!.length).toEqual(2)
            expect(sdJwtPayload!.clearValue1).toEqual('value3')

            expect(disclosables.length).toEqual(2)

            expect(
                disclosables.find((d) => {
                    return d.digest === sdJwtPayload!._sd![0]
                })
            ).toBeTruthy()
            expect(
                disclosables.find((d) => {
                    return d.digest === sdJwtPayload!._sd![1]
                })
            ).toBeTruthy()
        })

        it('roundtrips', () => {
            expect.assertions(2)
            const input = {
                given_name: 'John',
                family_name: 'Doe',
                email: 'johndoe@example.com',
                phone_number: '+1-202-555-0101',
                phone_number_verified: true,
                birthdate: '1940-01-01',
                updated_at: 1570000000,
                address: {
                    street_address: '123 Main St',
                    locality: 'Anytown',
                    region: 'Anystate',
                    country: 'US',
                },
            }

            const { sdJwtPayload, disclosables } = sdJwtPayloadHelper(input, {})

            expect(sdJwtPayload!._sd!.length).toEqual(8)

            let decoded = {}

            sdJwtPayload!._sd!.forEach((sd) => {
                const match = disclosables.find((d) => d.digest === sd)
                const claim = match?.claim as ObjectPropertyClaim
                decoded = { ...decoded, [claim.key]: claim.value }
            })

            expect(decoded).toMatchObject(input)
        })
    })

    /* Ensures disclosures roundtrip */
    describe('parseObjectPropertyDisclosure()', () => {
        it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
            'parses disclosures stringified with specCompatStringify (specDisclosure: $specDisclosure)',
            ({ specDisclosure, key, value, salt }) => {
                const decoded = parseDisclosure(specDisclosure)
                expect(decoded.claim).toMatchObject({ key, value, salt })
            }
        )

        it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
            'parses disclosures stringified with default JSON.stringify() (defaultDisclosure: $defaultDisclosure)',
            ({ defaultDisclosure, key, value, salt }) => {
                const decoded = parseDisclosure(defaultDisclosure)
                expect(decoded.claim).toMatchObject({ key, value, salt })
            }
        )

        it('rejects an ill-formed disclosure', async () => {
            const salt = createSalt()

            const badDisclosure = [salt, 'address', 'Schulstr. 12', 'extraneous input']
            const stringified = JSON.stringify(badDisclosure)
            const asBytes = stringToBytes(stringified)
            const encdoedDisclosure = bytesToBase64url(asBytes)

            expect(() => parseDisclosure(encdoedDisclosure)).toThrow()
        })
    })

})


describe('SD-JWT core functionality', () => {
    const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
    const did = `did:ethr:${address}`

    const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
    const signer = ES256KSigner(hexToBytes(privateKey))

    const didDoc = {
        didDocument: {
            '@context': 'https://w3id.org/did/v1',
            id: did,
            verificationMethod: [
                {
                    id: `${did}#keys-1`,
                    type: 'JsonWebKey2020',
                    controller: did,
                    publicKeyHex: publicKey,
                },
            ],
            authentication: [`${did}#keys-1`],
            assertionMethod: [`${did}#keys-1`],
            capabilityInvocation: [`${did}#keys-1`],
            capabilityDelegation: [`${did}#some-key-that-does-not-exist`],
        },
    }

    const resolver = {
        resolve: jest.fn(async (didUrl: string) => {
            if (didUrl.includes(did)) {
                return {
                    didDocument: didDoc.didDocument,
                    didDocumentMetadata: {},
                    didResolutionMetadata: { contentType: 'application/did+ld+json' },
                }
            }

            return {
                didDocument: null,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    error: 'notFound',
                    message: 'resolver_error: DID document not found',
                },
            }
        }),
    } as Resolvable

    describe('createSdJWT()', () => {
        it('creates an SD-JWT (without key binding)', async () => {
            const expected = {
                header: {
                    alg: 'ES256K',
                    typ: 'JWT',
                },
                payload: {
                    given_name: 'John',
                    family_name: 'Doe',
                    email: 'johndoe@example.com',
                    phone_number: '+1-202-555-0101',
                    phone_number_verified: true,
                    birthdate: '1940-01-01',
                },
            }

            const { sdJwtPayload, disclosables } = sdJwtPayloadHelper(
                {
                    email: 'johndoe@example.com',
                    phone_number: '+1-202-555-0101',
                    phone_number_verified: true,
                    birthdate: '1940-01-01',
                },
                {
                    given_name: 'John',
                    family_name: 'Doe',
                    updated_at: 1570000000,
                },
                { sd_alg: 'sha-256' }
            )

            const disclosures = disclosables.map((d) => d.disclosure)

            const sdJwt = await createSdJWT(sdJwtPayload, {
                issuer: did,
                signer,
                disclosures: disclosures,
            })

            // verify result by decoding
            const decoded = decodeSdJWT(sdJwt, true)
            expect(decoded).toMatchObject(expected)
            const result = await verifySdJWT(sdJwt, { resolver })
            expect(result.verified).toBeTruthy()
        })

        it('creates SD-JWT spec address example (OPTION 1: Flat SD-JWT)', async () => {
            const sdJwt = await createSdJWT(ADDRESS_OPTION_1, {
                issuer: did,
                signer,
                disclosures: [ADDRESS_OPTION_1_DISCLOSURE],
            })

            const result = await verifySdJWT(sdJwt, { resolver })
            expect(result.verified).toBeTruthy()
        })

        it('creates SD-JWT spec address example (OPTION 2: Structured SD-JWT)', async () => {
            const sdJwt = await createSdJWT(ADDRESS_OPTION_2, {
                issuer: did,
                signer,
                disclosures: ADDRESS_OPTION_2_DISCLOSURES,
            })

            const result = await verifySdJWT(sdJwt, { resolver })
            expect(result.verified).toBeTruthy()
        })

        it('creates SD-JWT spec address example (OPTION 3: Recursive Disclosures)', async () => {
            const sdJwt = await createSdJWT(ADDRESS_OPTION_3, {
                issuer: did,
                signer,
                disclosures: ADDRESS_OPTION_3_DISCLOSURES,
            })

            const result = await verifySdJWT(sdJwt, { resolver })
            expect(result.verified).toBeTruthy()
        })

        it('rejects unsupported sd_alg', async () => {
            // TODO: share error example
            const { sdJwtPayload, disclosables } = sdJwtPayloadHelper(
                { hiddenValue1: 'value1', hiddenValue2: 'value2' },
                { clearValue1: 'value3' }
            )

            const disclosures = disclosables.map((d) => {
                return d.disclosure
            })

            sdJwtPayload._sd_alg = 'unsupported'

            await expect(
                createSdJWT(sdJwtPayload, {
                    issuer: did,
                    signer,
                    disclosures: disclosures,
                })
            ).rejects.toThrow()
        })

        it('fails when a repeated claim seen', async () => {
            // TODO: share error examples
            /*  let { sdJwtPayload, disclosables } = sdJwtPayloadHelper(
        { hiddenValue1: 'value1', hiddenValue2: 'value2' },
        { clearValue1: 'value3' }
      )

      sdJwtPayload = {
        hiddenValue1: 'value1',
        ...sdJwtPayload,
      }

      const disclosures = disclosables.map((d) => {
        return d.disclosure
      })

      expect(
        createSdJWT(sdJwtPayload, {
          issuer: did,
          signer,
          disclosures: disclosures,
        })
      ).rejects.toThrowError()
    })*/
        })
    })

    describe('decodeSdJWT()', () => {
        it('decodes SD-JWT spec example (without key binding)', () => {
            const decoded = decodeSdJWT(EXAMPLE_1_JWT, true)
            expect(decoded).toMatchObject(EXAMPLE_1_DECODED)
        })

        it('decodes SD-JWT spec example (with key binding)', () => {
            const decoded = decodeSdJWT(EXAMPLE_1_KB_JWT, true)
            expect(decoded).toMatchObject(EXAMPLE_1_KB_DECODED)
        })

        it('decodes SD-JWT spec address example (OPTION 1: Flat SD-JWT)', () => {
            const decoded = decodeSdJWT(ADDRESS_OPTION_1_SD_JWT, false)
            expect(decoded).toMatchObject(ADDRESS_DECODED)
        })

        it('decodes SD-JWT spec address example (OPTION 2: Structured SD-JWT)', () => {
            const decoded = decodeSdJWT(ADDRESS_OPTION_2_SD_JWT, true)
            expect(decoded).toMatchObject(ADDRESS_DECODED)
        })

        it('decodes SD-JWT spec address example (OPTION 3: Recursive Disclosures)', () => {
            const decoded = decodeSdJWT(ADDRESS_OPTION_3_SD_JWT, true)
            expect(decoded).toMatchObject(ADDRESS_DECODED)
        })

        /* Disclose only 1 of the 4 disclosures (street address) on example ADDRESS_OPTION_2.
    This test simulates a holder revealing only a subset of disclosures. */
        it('ignores undisclosed digests', () => {
            const sdJwt = formSdJwt(ADDRESS_OPTION_2_JWT_ONLY, ADDRESS_OPTION_2_DISCLOSURES.slice(0, 1))
            const decoded = decodeSdJWT(sdJwt, true)
            expect(decoded).toMatchObject(ADDRESS_SUBSET_DECODED)
        })

        it('fails when a repeated claim seen', async () => {
            expect(() => decodeSdJWT(SD_JWT_REPEATED_CLAIM, true)).toThrow()
        })
    })

    describe('verifySdJWT()', () => {
        it('rejects an ill-formed SD-JWT', async () => {
            const disclosures = ADDRESS_OPTION_2_DISCLOSURES.join('~~')
            const badEx1 = ADDRESS_OPTION_2_SD_JWT + '~' + disclosures
            await expect(verifySdJWT(badEx1, { resolver })).rejects.toThrow()
        })

        it('rejects an SD-JWT with an invalid signature', () => {})

        it('rejects an SD-JWT with unsupported sd_alg', async () => {
            const unsupportedSdAlgExample =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2OTY1MzA2MDUsIl9zZF9hbGciOiJ1bnN1cHBvcnRlZCIsIl9zZCI6WyI3bm01MkR5eVNJQUlRUXA2bjlfLV80M3o3eTR1MnFqV2ZBUmdpWl93TmNNIiwiNUdmMG4tWlpNdXZONng1bEkxTG1LckNMWDdVMWtYUmpQN2RFMlBvemh1RSJdLCJjbGVhclZhbHVlMSI6InZhbHVlMyIsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.dLP8epxmB5sBmVkkPy-SstzBpnRXXWqQDKtcbL9ZDo5J1FapbX9ZArZ1ZPKwIf2j74s60Vukg8IAg0ys-sezyg'

            const { sdJwtPayload, disclosables } = sdJwtPayloadHelper(
                { hiddenValue1: 'value1', hiddenValue2: 'value2' },
                { clearValue1: 'value3' }
            )

            const disclosures = disclosables.map((d) => d.disclosure)

            const sdJwt = formSdJwt(unsupportedSdAlgExample, disclosures)
            await expect(verifySdJWT(sdJwt, { resolver })).rejects.toThrow()
        })

        it('rejects an SD-JWT with an ill-formed array disclosure', () => {})
        it('rejects an SD-JWT with an ill-formed object disclosure', async () => {
            const salt = createSalt()

            const badDisclosure = [salt, 'address', 'Schulstr. 12', 'extraneous input']
            const stringified = JSON.stringify(badDisclosure)
            const asBytes = stringToBytes(stringified)
            const encodedDisclosure = bytesToBase64url(asBytes)

            const sdJwt = formSdJwt(ADDRESS_OPTION_2_JWT_ONLY, [encodedDisclosure])

            await expect(verifySdJWT(sdJwt, { resolver })).rejects.toThrow()
        })

        it('rejects an SD-JWT with a repeated claim', async () => {
            // TODO  expect(verifySdJWT(SD_JWT_REPEATED_CLAIM, { resolver })).rejects.toThrowError()
        })

        it('rejects an SD-JWT with digests found more than once', () => {})
    })
})

describe('SD-JWT creation helpers', () => {

    /* SD-JWT spec (5.2.1) tests  */
    describe('createObjectPropertyDisclosure()', () => {
        it('returns a string that is base64url encoded', () => {
            const key = 'someKey'
            const value = 'someValue'
            const disclosable = createObjectPropertyDisclosable(key, value)

            expect(BASE64_URL_REGEX.test(disclosable.disclosure)).toBeTruthy()
        })

        it('returns a string that is base64url encoded (given a pre-defined salt)', () => {
            const salt = createSalt()
            const key = 'someKey'
            const value = 'someValue'
            const disclosable = createObjectPropertyDisclosable(key, value, salt)

            expect(BASE64_URL_REGEX.test(disclosable.disclosure)).toBeTruthy()
        })

        it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
            'matches SD-JWT spec output with specCompatStringify (key: $key, value: $value, salt: $salt)',
            ({ key, value, salt, specDisclosure }) => {
                const actual = createObjectPropertyDisclosable(key, value, salt, {
                    ...SPEC_COMPAT_OPTIONS,
                })
                expect(actual.disclosure).toEqual(specDisclosure)
            }
        )

        it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
            'matches expected output with default JSON.stringify() (key: $key, value: $value, salt: $salt)',
            ({ key, value, salt, defaultDisclosure }) => {
                const actual = createObjectPropertyDisclosable(key, value, salt)
                expect(actual.disclosure).toEqual(defaultDisclosure)
            }
        )
    })

    /* SD-JWT spec (5.2.2) tests */
    describe('createArrayElementDisclosable()', () => {
        it('returns a string that is base64url encoded', () => {
            const arrayElement = 'someValue'
            const disclosable = createArrayElementDisclosable(arrayElement)

            expect(BASE64_URL_REGEX.test(disclosable.digest)).toBeTruthy()
        })

        it('returns a string that is base64url encoded (given a pre-defined salt)', () => {
            const salt = createSalt()
            const arrayElement = 'someValue'
            const disclosable = createArrayElementDisclosable(arrayElement, salt)

            expect(BASE64_URL_REGEX.test(disclosable.digest)).toBeTruthy()
        })

        it.each(ARRAY_ELEMENT_DISCLOSURE_TEST_CASES)(
            'matches SD-JWT spec output with specCompatStringify (arrayElement: $arrayElement, salt: $salt)',
            ({ arrayElement, salt, specDisclosure }) => {
                const actual = createArrayElementDisclosable(arrayElement, salt, {
                    ...SPEC_COMPAT_OPTIONS,
                })
                expect(actual.disclosure).toEqual(specDisclosure)
            }
        )

        it.each(ARRAY_ELEMENT_DISCLOSURE_TEST_CASES)(
            'matches expected output with default JSON.stringify() (arrayElement: $arrayElement, salt: $salt)',
            ({ arrayElement, salt, defaultDisclosure }) => {
                const actual = createArrayElementDisclosable(arrayElement, salt)
                expect(actual.disclosure).toEqual(defaultDisclosure)
            }
        )
    })

    describe('did-jwt workaround tests', () => {
        it('encodeBase64url() works', () => {
            const encoded = encodeBase64url('Alice')
            expect(encoded).toEqual('QWxpY2U')
        })

    })

})