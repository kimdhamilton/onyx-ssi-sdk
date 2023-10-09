import { JWTHeader, JWTPayload, JWTOptions, JWTVerifyOptions, JWTVerified,  createJWT, decodeJWT, verifyJWT, base64ToBytes } from 'did-jwt'
import { randomBytes } from '@noble/hashes/utils'
import { sha256 } from '@noble/hashes/sha256'

/**
 * Minimum salt length per SD-JWT spec
 */
const MINIMUM_SALT_LENGTH = 16
/**
 * Default hash algorithm for computing digests.
 */
export const DEFAULT_SD_ALG = 'sha-256'

/*** 
 * SD-JWT types
 */

export type JSONPrimitive = string | number | boolean | null
export type JSONObject = { [key: string]: JSONValue }
export type JSONArray = JSONValue[]

/**
 * Used to ensure values are JSON type; see 5.2.1 SD-JWT
 */
export type JSONValue = JSONPrimitive | JSONObject | JSONArray

/**
 * Extends {@link JWTPayload} to include the SD-JWT-specific fields
 */
export interface SdJWTPayload extends JWTPayload {
    /** Hash algorithm used for disclosures */
    _sd_alg: string
    /** Contains digests of disclosures */
    _sd?: string[]
}

/**
 * Extends {@link JWTDecoded} to include SD-JWT extensions
 * 
 */
export interface SdJWTDecoded extends JWTDecoded {
    /**
     * Note the type is {@link SdJWTPayload} and not {@link JWTPayload}.
     * This is because SD-JWT decoding involves removing the _sd_alg and _sd fields,
     * This is described in SD-JWT section 6. Verification and Processing 
     */
    payload: JWTPayload
    /**
     * base64url-encoded disclosures that issuers send to holders or 
     * holders share with verifiers. These hash to the digests in the payload
     */
    disclosures: string[]
    /**
     * Optional key binding JWT -- not yet implemented
     */
    kb_jwt?: string
}

/**
 * Extends {@link JWTVerified} to include SD-JWT extensions
 */
export interface SdJWTVerified extends JWTVerified {
    payload: Partial<SdJWTPayload>
}

/**
 * Extends {@link JWTOptions} to include SD-JWT-specific fields
 */
export interface SdJWTOptions extends JWTOptions {
    /**
     * base64url-encoded disclosures that issuers send to holders or holders share with verifiers.
     * These hash to the digests in the payload.
     */
    disclosures: string[]
    /**
     * Optional key binding JWT -- not yet implemented
     */
    kb_jwt?: string
}

/**
 * Abstraction to help issuers and holders (wallets) manage disclosures and digest mappings
 */
export interface Disclosable {
    disclosure: string
    digest: string
    decodedDisclosure: JSONValue[]
    claim: SDClaim
}

export interface SplitSdJWT {
    jwt: string
    disclosures: string[]
    kbJwt?: string
}

export interface DisclosureOptions {
    sd_alg?: string
}

/**
 * Compatibility option to enable exact mmtching SD-JWT stringify examples
 */
export interface CreateDisclosureOptions extends DisclosureOptions {
    specCompatStringify?: boolean
}

/**
 * Clear text / decoded disclosure inputs
 */
export interface SDClaim {
    salt: string
    value: JSONValue
}

export type ArrayElementClaim = SDClaim

export interface ObjectPropertyClaim extends SDClaim {
    key: string
}

/**
 * Helper object for creating SD-JWT payloads
 */
export interface SDJWTHelper {
    sdJwtPayload: Partial<SdJWTPayload>
    disclosables: Disclosable[]
}


/**
 * Issue an SD-JWT payload, appending the `disclosures` from {@link SdJWTOptions}.
 * 
 * Key binding is not yet implemented.
 *
 * @export
 * @param {Partial<SdJWTPayload>} payload
 * @param {SdJWTOptions} { issuer, signer, alg, expiresIn, canonicalize, disclosures, kb_jwt }
 * @param {Partial<JWTHeader>} [header={}]
 * @return {*}  {Promise<string>}
 */
export async function createSdJWT(
    payload: Partial<SdJWTPayload>,
    { issuer, signer, alg, expiresIn, canonicalize, disclosures, kb_jwt }: SdJWTOptions,
    header: Partial<JWTHeader> = {}
): Promise<string> {
    if (payload._sd_alg !== DEFAULT_SD_ALG) {
        throw new Error(`Unsupported sd_alg: ${payload._sd_alg}`)
    }

    const jwt = await createJWT(payload, { issuer, signer, alg, expiresIn, canonicalize }, header)
    return formSdJwt(jwt, disclosures, kb_jwt)
}

/**
 * Decodes an SD-JWT and returns an object representing the payload
 *
 * This performs the following checks required by SD-JWT 6.1.2-7:
 * - Ensure the _sd_alg header parameter is supported
 * - Ensure the disclosures are well-formed:
 *     - Object property disclosures are arrays of length 3
 *     - Array disclosures are arrays of length 2
 * - Claim names do not exist more than once (i.e. a disclosure does not overwrite a clear text claim)
 * - FIXME: need to add check that digests are not found more than once in the payload
 * - FIXME: Ensure nbf, iat, and exp clains, if present, are not selectively disclosed
 *
 * Per 6.1.6 and 7, this ensures _sd and _sd_alg are removed from the payload. Because _sd may appear
 * these are removed in the (optionally) recursive expandDisclosures method (to avoid duplicate
 * recursive processing).
 *
 *  @example
 *  decodeSdJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1...~<Disclosure 1>~...<optional KB-JWT>')
 *
 * @export
 * @param {string} sdJwt                an SD-JWT to verify
 * @param {boolean} [recurse=true]      whether to recurse into the payload to decode any nested SD-JWTs
 * @return {*}  {SDJWTDecoded}          the decoded SD-JWT
 */
export function decodeSdJWT(sdJwt: string, recurse = true): SdJWTDecoded {
    const { jwt, disclosures, kbJwt } = splitSdJwt(sdJwt)

    const decodedJwt = decodeJWT(jwt)

    const sdAlg = decodedJwt.payload._sd_alg || DEFAULT_SD_ALG
    const digestDisclosableMap = buildDigestDisclosableMap(disclosures, sdAlg)
    const converted = expandDisclosures(decodedJwt.payload, digestDisclosableMap, recurse) as JWTPayload
    delete converted['_sd_alg']

    const decodedSdJwt: SdJWTDecoded = {
        ...decodedJwt,
        payload: {
            ...converted,
        },
        disclosures: disclosures,
    }

    if (kbJwt) {
        decodedSdJwt.kb_jwt = kbJwt
    }

    return decodedSdJwt
}
/**
 *
 * Verify an SD-JWT and return the payload, performing SD-JWT-specific checks via {@link decodeSdJWT}.
 * 
 * @see {@link verifyJWT} for additional details about {@link JWTVerifyOptions}
 *
 * @export
 * @param {string} sdJwt
 * @param {JWTVerifyOptions} [options]
 * @return {*}  {Promise<JWTVerified>}
 */
export async function verifySdJWT(
    sdJwt: string,
    options: JWTVerifyOptions = {
        resolver: undefined,
        auth: undefined,
        audience: undefined,
        callbackUrl: undefined,
        skewTime: undefined,
        proofPurpose: undefined,
        policies: {},
    }
): Promise<SdJWTVerified> {
    const { jwt } = splitSdJwt(sdJwt)
    const verified = await verifyJWT(jwt, options)
    const decoded = decodeSdJWT(sdJwt, false)
    verified.payload = decoded.payload
    return verified
}

/**
 * Search for disclosure digests in the payload and replace with the parsed disclosures,
 * with optional recursion into the payload, as described in 6.1.3.
 *
 * To avoid duplicate recursive processing, this expands the disclosures and deletes the
 * digests, per 6.1 Verification
 * 
 * Future improvement: we can stop processing once we've seen disclosures. 
 * 
 * @export
 * @param {object} jwtPayload
 * @param {Map<string, Disclosable>} disclosableMap
 * @param {boolean} [recurse=true]
 * @return {*}  {object}
 */
export function expandDisclosures(
    jwtPayload: object,
    disclosableMap: Map<string, Disclosable>,
    recurse = true
): object {
    // clone the input
    const wip = JSON.parse(JSON.stringify(jwtPayload))

    const entries = Object.entries(jwtPayload)

    for (const [key, value] of entries) {
        if (key === '_sd') {
            const sdValues = value as string[]
            const asObjectDisclosures: ObjectPropertyClaim[] = sdValues
                .filter((digest: string) => disclosableMap.has(digest))
                .map((digest: string) => {
                    const disclosable = disclosableMap.get(digest)
                    const claim = disclosable?.claim as ObjectPropertyClaim
                    return claim
                })
            asObjectDisclosures.forEach((d) => {
                if (d.key in wip) {
                    throw new Error('Duplicate key in disclosure')
                } else {
                    let value = d.value
                    if (recurse) {
                        if (Array.isArray(value)) {
                            value = expandArrayElements(value, disclosableMap, recurse)
                        } else if (typeof value === 'object' && value !== null) {
                            value = expandDisclosures(value, disclosableMap, recurse) as JSONValue
                        }
                    }
                    wip[d.key] = value
                    // TODO: here and elsewhere -- object.assign?
                }
            })

            delete wip['_sd']
        } else if (Array.isArray(value)) {
            const mapped = expandArrayElements(value, disclosableMap, recurse)
            wip[key] = mapped
        } else if (recurse && typeof value === 'object') {
            const mapped = expandDisclosures(value, disclosableMap, recurse)
            wip[key] = mapped
        }
    }
    return wip
}

/**
 * Expands SD array elements into the payload
 *
 * @param {any[]} arrayElements
 * @param {Map<string, Disclosable>} disclosableMap
 * @param {boolean} recurse
 * @return {*}  {any[]}
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function expandArrayElements(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    arrayElements: any[],
    disclosableMap: Map<string, Disclosable>,
    recurse: boolean
): JSONValue[] {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mappedArray = [] as any[]
    for (const element of arrayElements) {
        if (typeof element === 'object') {
            if ('...' in element) {
                const disclosable = disclosableMap.get(element['...'])
                // skip if not revealed in disclosures
                if (!disclosable) {
                    continue
                }
                mappedArray.push(disclosable.claim.value)
            } else {
                // else recurse into object if recurse is true; if not, just add the
                // object back to the array
                let el = element
                if (recurse) {
                    el = expandDisclosures(element, disclosableMap, recurse)
                }
                mappedArray.push(el)
            }
        } else {
            // else its a primitive; add it to the array
            mappedArray.push(element)
        }
    }
    return mappedArray
}


/**
 * Build a map of digests to Disclosables, which is used to reconstruct the payload
 * @param {string[]} disclosures
 * @param {string} [sd_alg=DEFAULT_SD_ALG]
 * @return {*}  {Map<string, Disclosable>}
 */
export function buildDigestDisclosableMap(disclosures: string[], sd_alg: string = DEFAULT_SD_ALG): Map<string, Disclosable> {
    const mapEntries = disclosures
        .map((disclosures) => {
            return parseDisclosure(disclosures, sd_alg)
        })
        .map((d) => {
            return { digest: d.digest, disclosable: d }
        })

    return new Map(mapEntries.map((obj) => [obj.digest, obj.disclosable]))
}


/*** SD-JWT Utilities */


/**
 *  Creates the serialized SD-JWT with disclosures, which looks like the following:
 *  <JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>
 *
 * This format is used when issuers send an SD-JWT to a holder, and when a holder
 * sends an SD=JWT to a verifier, with the important distinction that the holder may choose to
 * reveal a subset of the disclosures provided by the issuer.
 *
 * @export
 * @param {string} jwt
 * @param {string[]} disclosures
 * @param {string} [kbJwt]
 * @return {*}  {string}
 */
export function formSdJwt(jwt: string, encodedDisclosures: string[], kbJwt?: string): string {
    return `${jwt}~${encodedDisclosures.join('~')}~${kbJwt ? kbJwt : ''}`
}

/* Utilites for SD-JWT Creation */

export function createSalt(length = MINIMUM_SALT_LENGTH): string {
    return bytesToBase64url(randomBytes(length))
}

/**
 * Hash a disclosure using the specified hash algorithm.
 *
 * @export
 * @param {string} disclosure           base64url-encoded disclosure
 * @param {string} [sd_alg=DEFAULT_SD_ALG]     hash algorithm to use for disclosures
 * @return {*}  {string}                hashed disclosure
 */
export function hashDisclosure(disclosure: string, sd_alg: string = DEFAULT_SD_ALG): string {
    if (sd_alg === DEFAULT_SD_ALG) {
        const digest = sha256.create().update(stringToBytes(disclosure)).digest()
        return bytesToBase64url(digest)
    }
    throw new Error(`Unsupported sd_alg: ${sd_alg}`)
}

export function splitSdJwt(sdJwt: string): SplitSdJWT {
    const parts = sdJwt.split('~')
    const kbJwt = parts.pop() || ''
    const [jwt, ...disclosures] = parts
    return { jwt, disclosures, kbJwt }
}

export function parseDisclosure(disclosure: string, sd_alg = DEFAULT_SD_ALG): Disclosable {
    return new ConcreteDisclosable(disclosure, sd_alg)
}

function decodeDisclosure(disclosure: string): JSONValue[] {
    let parsed: JSONValue[]

    try {
        const decoded = decodeBase64url(disclosure)
        parsed = JSON.parse(decoded)
    } catch (e) {
        throw new Error('Could not decode disclosure')
    }

    if (!Array.isArray(parsed)) {
        throw new Error(`Invalid disclosure format: ${parsed}`)
    }
    const decodedDisclosure = parsed as JSONValue[]

    if (decodedDisclosure.length < 2 || decodedDisclosure.length > 3) {
        throw new Error(`Decoded disclosure array length is not supported`)
    }

    return decodedDisclosure
}

export class ConcreteDisclosable implements Disclosable {
    disclosure: string
    digest: string
    decodedDisclosure: JSONValue[]
    claim: SDClaim

    constructor(disclosure: string, sd_alg = DEFAULT_SD_ALG) {
        this.disclosure = disclosure
        this.digest = hashDisclosure(disclosure, sd_alg)
        this.decodedDisclosure = decodeDisclosure(disclosure)

        if (this.decodedDisclosure.length === 2) {
            this.claim = {
                salt: this.decodedDisclosure[0] as string,
                value: this.decodedDisclosure[1] as JSONValue,
            }
        } else if (this.decodedDisclosure.length === 3) {
            const opClaim = {
                salt: this.decodedDisclosure[0] as string,
                key: this.decodedDisclosure[1] as string,
                value: this.decodedDisclosure[2] as JSONValue,
            } as ObjectPropertyClaim
            this.claim = opClaim
        } else {
            throw new Error(`Invalid disclosure format: ${disclosure}`)
        }
    }
}



/*** 
 * Optional helper functions for building SD-JWTs
 */

/**
 * Create an object property Disclosable as described in SD-JWT spec 5.2.1. Disclosures for Object Properties.
 *
 * Optionally pass in a salt, which is useful for testing against SD-JWT test vectors. Otherwise one will be generated.
 *
 * @export
 * @param {string} key
 * @param {JSONValue} value
 * @param {string} [salt=createSalt()]
 * @param {CreateDisclosureOptions} [options={ sd_alg: DEFAULT_SD_ALG }]
 * @return {*}  {Disclosable}
 */
export function createObjectPropertyDisclosable(
    key: string,
    value: JSONValue,
    salt: string = createSalt(),
    options: CreateDisclosureOptions = { sd_alg: DEFAULT_SD_ALG }
): Disclosable {
    const specStringify = options?.specCompatStringify || false
    const disclosureInput = [salt, key, value]
    const disclosure = toDisclosure(disclosureInput, specStringify)
    return new ConcreteDisclosable(disclosure, options?.sd_alg)
}

/**
 * Create an array element Disclosable as described in SD-JWT spec 5.2.2. Disclosures for Array Elements.
 *
 * Optionally pass in a salt, which is useful for testing against SD-JWT test vectors. Otherwise one will be generated.
 *
 * @export
 * @param {JSONValue} arrayElement
 * @param {string} [salt=createSalt()]
 * @param {CreateDisclosureOptions} [options={ sd_alg: DEFAULT_SD_ALG }]
 * @return {*}  {Disclosable}
 */
export function createArrayElementDisclosable(
    arrayElement: JSONValue,
    salt: string = createSalt(),
    options: CreateDisclosureOptions = { sd_alg: DEFAULT_SD_ALG }
): Disclosable {
    const specStringify = options?.specCompatStringify || false
    const disclosureInput = [salt, arrayElement]
    const disclosure = toDisclosure(disclosureInput, specStringify)
    return new ConcreteDisclosable(disclosure, options?.sd_alg)
}

/**
 * Encode an SD-JWT spec 5.2.1. Disclosures for Object Properties. Optional specCompatStringify
 * argument allows demonstration of compatibility with the SD-JWT spec examples.
 *
 * @param {Disclosure} disclosure
 * @param {boolean} [specCompatStringify=false]
 * @return {string}
 */
function toDisclosure(disclosureArray: JSONValue[], specCompatStringify = false): string {
    let stringified: string
    if (specCompatStringify) {
        stringified = doSpecStringify(disclosureArray)
    } else {
        stringified = JSON.stringify(disclosureArray)
    }
    const asBytes = stringToBytes(stringified)
    return bytesToBase64url(asBytes)
}

/**
 * JSON.stringify workaround for arrays, in order to match SD-JWT spec.
 *
 * Stringify element-wise and join with commas, space-separated.
 *
 * @param {Disclosure} disclosure
 * @return {*}  {string}
 */
function doSpecStringify(disclosure: JSONValue[]): string {
    const elements = disclosure.map((element) => {
        return JSON.stringify(element)
    })

    return `[${elements.join(', ')}]`
}

/**
 * Utility that demonstrates how issuers can construct an SD-JWT payload. This makes
 * a lot of shortcuts and assumptions and doesn't support arbitrary nesting of
 * SD objects out of the box. Such payloads can be constructed with other functions
 * like createObjectPropertyDisclosure and createArrayElementDisclosure.
 *
 * @export
 * @param {Partial<JWTPayload>} clearClaims
 * @param {Partial<JWTPayload>} sdClaims
 * @param {CreateDisclosureOptions} createOptions
 * @return {*}  {SDJWTHelper}
 */
export function sdJwtPayloadHelper(
    sdClaims: Partial<SdJWTPayload>,
    clearClaims: Partial<JWTPayload>,
    createOptions: CreateDisclosureOptions = { sd_alg: DEFAULT_SD_ALG }
): SDJWTHelper {
    // this will store the SD object property disclosures
    const sdArray = [] as string[]

    // We'll assume that if an sdClaim value is array, then all the elements should be SD.
    // These get stored back on the object as an array of digests
    const sdArrayElementWrapper = {} as Partial<JWTPayload>

    // This allows us to look up the disclosure from the digest
    const disclosables: Disclosable[] = []

    Object.entries(sdClaims).forEach(([key, value]) => {
        if (Array.isArray(value)) {
            const arrayElements = value as JSONValue[]
            const disclosables = arrayElements.map((arg) => {
                return createArrayElementDisclosable(arg, createSalt(), createOptions)
            })
            const _array = disclosables.map((d) => {
                return { '...': d.digest }
            })
            sdArrayElementWrapper[key] = _array
        } else {
            const disclosable = createObjectPropertyDisclosable(key, value, createSalt(), createOptions)
            disclosables.push(disclosable)
            sdArray.push(disclosable.digest)
        }
    })

    const sdJwtInput = {
        _sd_alg: createOptions.sd_alg,
        _sd: sdArray,
        ...clearClaims,
        ...sdArrayElementWrapper,
    }

    const result = {
        sdJwtPayload: sdJwtInput,
        disclosables: disclosables,
    }

    return result
}



/*** 
 * DID-JWT Workarounds
 * 
 * This section includes patches to did-jwt, including unexported functions and types, and a workaround
 * for issues caused by its use of uint8array. This may be removed once the issues are resolved.
 * {@link https://github.com/achingbrain/uint8arrays/issues/53#issuecomment-1749322614}
 */

export interface JWTDecoded {
    header: JWTHeader
    payload: JWTPayload
    signature: string
    data: string
}

export function toString(buffer: Uint8Array, encoding: BufferEncoding = 'utf-8'): string {
    return Buffer.from(buffer).toString(encoding)
}

export function fromString(str: string, encoding: BufferEncoding = 'utf-8'): Uint8Array {
    return Buffer.from(str, encoding)
}
export function bytesToBase64url(b: Uint8Array): string {
    return toString(b, 'base64url')
}

export function encodeBase64url(s: string): string {
    return bytesToBase64url(fromString(s))
}

export function decodeBase64url(s: string): string {
    return toString(base64ToBytes(s))
}

export function stringToBytes(s: string): Uint8Array {
    return fromString(s)
}
