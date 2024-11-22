import type { JWK } from 'jose'
import type { MdocContext } from '../../c-mdoc.js'
import { DataItem, DateOnly, cborDecode, cborEncode } from '../../cbor/index.js'
import { Algorithms, Headers, ProtectedHeaders, UnprotectedHeaders } from '../../cose/headers.js'
import { COSEKey } from '../../cose/key/cose-key.js'
import { stringToUint8Array } from '../../u-uint8-array.js'
import { IssuerSignedItem } from '../issuer-signed-item.js'
import { fromPEM } from '../utils.js'
import IssuerAuth from './issuer-auth.js'
import { IssuerSignedDocument } from './issuer-signed-document.js'
import type {
  DeviceKeyInfo,
  DigestAlgorithm,
  DocType,
  IssuerNameSpaces,
  MSO,
  SupportedAlgs,
  ValidityInfo,
} from './types.js'
function isObjectLike(value: unknown) {
  return typeof value === 'object' && value !== null
}

export default function isObject(input: unknown): input is Record<string, unknown> {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
    return false
  }
  if (Object.getPrototypeOf(input) === null) {
    return true
  }
  let proto = input
  while (Object.getPrototypeOf(proto) !== null) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    proto = Object.getPrototypeOf(proto)
  }
  return Object.getPrototypeOf(input) === proto
}

const DEFAULT_NS = 'org.iso.18013.5.1'

const getAgeInYears = (birth: string): number => {
  const birthDate = new Date(birth)
  birthDate.setHours(0, 0, 0, 0)
  // @ts-expect-error this works
  const ageDifMs = Date.now() - birthDate
  const ageDate = new Date(ageDifMs)
  return Math.abs(ageDate.getUTCFullYear() - 1970)
}

const addYears = (date: Date, years: number): Date => {
  const r = new Date(date.getTime())
  r.setFullYear(date.getFullYear() + years)
  return r
}

/**
 * Use this class when building new documents.
 *
 * This class allow you to build a document and sign it with the issuer's private key.
 */
export class Document {
  readonly docType: DocType
  #issuerNameSpaces: IssuerNameSpaces = new Map()
  #deviceKeyInfo?: DeviceKeyInfo
  #validityInfo: ValidityInfo = {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: addYears(new Date(), 1),
    expectedUpdate: undefined,
  }
  #digestAlgorithm: DigestAlgorithm = 'SHA-256'
  ctx: { crypto: MdocContext['crypto'] }

  constructor(doc: DocType, ctx: { crypto: MdocContext['crypto'] }) {
    this.docType = doc
    this.ctx = ctx
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private validateValues(values: Record<string, unknown>) {
    // TODO
    // validate required fields, no extra fields, data types, etc...
  }

  /**
   * Add a namespace to an unsigned document.
   *
   * @param {string} namespace - The namespace to add.
   * @param {Record<string, any>} values - The values to add to the namespace.
   * @returns {Document} - The document
   */
  addIssuerNameSpace(namespace: 'org.iso.18013.5.1' | (string & {}), values: Record<string, unknown>): Document {
    if (namespace === DEFAULT_NS) {
      this.validateValues(values)
    }

    const namespaceRecord = this.#issuerNameSpaces.get(namespace) ?? []

    const addAttribute = (key: string, value: unknown) => {
      let elementValue = value
      if (namespace === DEFAULT_NS) {
        // the following namespace attributes must be a full-date as specified in RFC 3339
        if (['birth_date', 'issue_date', 'expiry_date'].includes(key) && typeof elementValue === 'string') {
          elementValue = new DateOnly(elementValue)
        }

        if (key === 'driving_privileges' && Array.isArray(elementValue)) {
          elementValue.forEach((v, i) => {
            if (isObject(v) && typeof v.issue_date === 'string') {
              // @ts-expect-error this works
              // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
              elementValue[i].issue_date = new DateOnly(v.issue_date)
            }
            if (isObject(v) && typeof v.expiry_date === 'string') {
              // @ts-expect-error this works
              // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
              elementValue[i].expiry_date = new DateOnly(v.expiry_date)
            }
          })
        }
      }

      const digestID = namespaceRecord.length
      const issuerSignedItem = IssuerSignedItem.create(digestID, key, value, this.ctx)
      namespaceRecord.push(issuerSignedItem)
    }

    for (const [key, value] of Object.entries(values)) {
      addAttribute(key, value)
      if (this.docType === 'org.iso.18013.5.1.mDL' && key === 'birth_date') {
        if (typeof value !== 'string') {
          throw new Error(`Invalid type for 'birth_date'. Expected 'string', received '${typeof value}'`)
        }
        const ageInYears = getAgeInYears(value)
        addAttribute('age_over_21', ageInYears >= 21)
        addAttribute(`age_over_${Math.floor(ageInYears)}`, true)
      }
    }

    this.#issuerNameSpaces.set(namespace, namespaceRecord)

    return this
  }

  /**
   * Get the values in a namespace.
   *
   * @param {string} namespace - The namespace to add.
   * @returns {Record<string, any>} - The values in the namespace as an object
   */
  getIssuerNameSpace(namespace: string): Record<string, unknown> | undefined {
    const nameSpace = this.#issuerNameSpaces.get(namespace)
    if (!nameSpace) return undefined
    return Object.fromEntries(nameSpace.map((item) => [item.elementIdentifier, item.elementValue]))
  }

  /**
   * Add the device public key which will be include in the issuer signature.
   * The device public key could be in JWK format or as COSE_Key format.
   *
   * @param params
   * @param {JWK | Uint8Array} params.devicePublicKey - The device public key.
   */
  addDeviceKeyInfo({ deviceKey }: { deviceKey: JWK | Uint8Array }): Document {
    const deviceKeyCOSEKey = deviceKey instanceof Uint8Array ? deviceKey : COSEKey.fromJWK(deviceKey).encode()
    const decodedCoseKey = cborDecode(deviceKeyCOSEKey)

    this.#deviceKeyInfo = {
      deviceKey: decodedCoseKey,
    }

    return this
  }

  /**
   * Add validity info to the document that will be used in the issuer signature.
   *
   * @param info - the validity info
   * @param {Date} [info.signed] - The date the document is signed. default: now
   * @param {Date} [info.validFrom] - The date the document is valid from. default: signed
   * @param {Date} [info.validUntil] - The date the document is valid until. default: signed + 1 year
   * @param {Date} [info.expectedUpdate] - The date the document is expected to be updated. default: null
   * @returns
   */
  addValidityInfo(info: Partial<ValidityInfo> = {}): Document {
    const signed = info.signed ?? new Date()
    const validFrom = info.validFrom ?? signed
    const validUntil = info.validUntil ?? addYears(signed, 1)
    this.#validityInfo = {
      signed,
      validFrom,
      validUntil,
      expectedUpdate: info.expectedUpdate,
    }
    return this
  }

  /**
   * Set the digest algorithm used for the value digests in the issuer signature.
   *
   * The default is SHA-256.
   *
   * @param {DigestAlgorithm} digestAlgorithm - The digest algorithm to use.
   * @returns
   */
  useDigestAlgorithm(digestAlgorithm: DigestAlgorithm): Document {
    this.#digestAlgorithm = digestAlgorithm
    return this
  }

  /**
   * Generate the issuer signature for the document.
   *
   * @param {Object} params - The parameters object
   * @param {JWK | Uint8Array} params.issuerPrivateKey - The issuer's private key either in JWK format or COSE_KEY format as buffer.
   * @param {string | Uint8Array} params.issuerCertificate - The issuer's certificate in pem format or as a buffer.
   * @param {SupportedAlgs} params.alg - The algorhitm used for the MSO signature.
   * @param {string | Uint8Array} [params.kid] - The key id of the issuer's private key. default: issuerPrivateKey.kid
   * @returns {Promise<IssuerSignedDoc>} - The signed document
   */
  async sign(
    params: {
      issuerPrivateKey: JWK
      issuerCertificate: string | Uint8Array
      alg: SupportedAlgs
      kid?: string | Uint8Array
    },
    ctx: {
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<IssuerSignedDocument> {
    if (!this.#issuerNameSpaces) {
      throw new Error('No namespaces added')
    }

    const issuerPublicKeyBuffer =
      typeof params.issuerCertificate === 'string' ? fromPEM(params.issuerCertificate) : params.issuerCertificate

    const issuerPrivateKeyJWK =
      params.issuerPrivateKey instanceof Uint8Array
        ? COSEKey.import(params.issuerPrivateKey).toJWK()
        : params.issuerPrivateKey

    const valueDigests = new Map(
      await Promise.all(
        Array.from(this.#issuerNameSpaces.entries()).map(async ([namespace, items]) => {
          const digestMap = new Map<number, Uint8Array>()
          await Promise.all(
            items.map(async (item, index) => {
              const hash = await item.calculateDigest(this.#digestAlgorithm, ctx)
              digestMap.set(index, new Uint8Array(hash))
            })
          )
          return [namespace, digestMap] as [string, Map<number, Uint8Array>]
        })
      )
    )

    const mso: MSO = {
      version: '1.0',
      digestAlgorithm: this.#digestAlgorithm,
      valueDigests,
      deviceKeyInfo: this.#deviceKeyInfo,
      docType: this.docType,
      validityInfo: this.#validityInfo,
    }

    const payload = cborEncode(DataItem.fromData(mso))
    const protectedHeader: ProtectedHeaders = ProtectedHeaders.from([[Headers.Algorithm, Algorithms[params.alg]]])

    const _kid = params.kid ?? issuerPrivateKeyJWK.kid
    const kid = typeof _kid === 'string' ? stringToUint8Array(_kid) : _kid
    const headers: ConstructorParameters<typeof UnprotectedHeaders>[0] = kid
      ? [
          [Headers.KeyID, kid],
          [Headers.X5Chain, [issuerPublicKeyBuffer]],
        ]
      : [[Headers.X5Chain, [issuerPublicKeyBuffer]]]

    const unprotectedHeader = UnprotectedHeaders.from(headers)

    const issuerAuth = IssuerAuth.create(protectedHeader, unprotectedHeader, payload)

    const signature = await ctx.cose.sign1.sign({
      sign1: issuerAuth,
      jwk: issuerPrivateKeyJWK,
    })
    issuerAuth.signature = signature

    const issuerSigned = {
      issuerAuth,
      nameSpaces: this.#issuerNameSpaces,
    }

    return new IssuerSignedDocument(this.docType, issuerSigned)
  }
}
