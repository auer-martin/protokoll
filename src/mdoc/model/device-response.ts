import type { JWK } from 'jose'
import type { MdocContext } from '../../c-mdoc.js'
import { DataItem, cborEncode } from '../../cbor/index.js'
import {
  Algorithms,
  Headers,
  MacAlgorithms,
  MacProtectedHeaders,
  ProtectedHeaders,
  UnprotectedHeaders,
} from '../../cose/headers.js'
import { COSEKey, COSEKeyToRAW } from '../../cose/key/cose-key.js'
import { Mac0 } from '../../cose/mac0.js'
import { Sign1 } from '../../cose/sign1.js'
import { stringToUint8Array } from '../../u-uint8-array.js'
import type { IssuerSignedItem } from '../issuer-signed-item.js'
import { parseDeviceResponse } from '../parser.js'
import { calculateDeviceAutenticationBytes } from '../utils.js'
import type { DeviceRequest, DocRequest } from './device-request.js'
import { DeviceSignedDocument } from './device-signed-document.js'
import type { IssuerSignedDocument } from './issuer-signed-document.js'
import { MDoc } from './mdoc.js'
import {
  findMdocMatchingDocType,
  limitDisclosureToDeviceRequestNameSpaces,
  limitDisclosureToInputDescriptor,
} from './pex-limit-disclosure.js'
import type { InputDescriptor, PresentationDefinition } from './presentation-definition.js'
import type { DeviceAuth, DeviceSigned, MacSupportedAlgs, SupportedAlgs } from './types.js'

/**
 * A builder class for creating a device response.
 */
export class DeviceResponse {
  private mdoc: MDoc
  private pd?: PresentationDefinition
  private deviceRequest?: DeviceRequest
  private sessionTranscriptBytes?: Uint8Array
  private useMac = true
  private devicePrivateKey?: JWK
  public nameSpaces: Map<string, Map<string, unknown>> = new Map()
  private alg?: SupportedAlgs
  private macAlg?: MacSupportedAlgs
  private ephemeralPublicKey?: JWK

  /**
   * Create a DeviceResponse builder.
   *
   * @param {MDoc | Uint8Array} mdoc - The mdoc to use as a base for the device response.
   *                                   It can be either a parsed MDoc or a CBOR encoded MDoc.
   * @returns {DeviceResponse} - A DeviceResponse builder.
   */
  public static from(mdoc: MDoc | Uint8Array): DeviceResponse {
    if (mdoc instanceof Uint8Array) {
      return new DeviceResponse(parseDeviceResponse(mdoc))
    }
    return new DeviceResponse(mdoc)
  }

  constructor(mdoc: MDoc) {
    this.mdoc = mdoc
  }

  /**
   *
   * @param pd - The presentation definition to use for the device response.
   * @returns {DeviceResponse}
   */
  public usingPresentationDefinition(pd: PresentationDefinition): DeviceResponse {
    if (!pd.input_descriptors.length) {
      throw new Error('The Presentation Definition must have at least one Input Descriptor object.')
    }

    const hasDuplicates = pd.input_descriptors.some(
      (id1, idx) => pd.input_descriptors.findIndex((id2) => id2.id === id1.id) !== idx
    )
    if (hasDuplicates) {
      throw new Error('Each Input Descriptor object must have a unique id property.')
    }

    this.pd = pd
    return this
  }

  /**
   *
   * @param deviceRequest - The device request
   * @returns {DeviceResponse}
   */
  public usingDeviceRequest(deviceRequest: DeviceRequest): DeviceResponse {
    if (!deviceRequest.docRequests.length) {
      throw new Error('The deviceRequest must have at least one docRequest object.')
    }

    this.deviceRequest = deviceRequest
    return this
  }

  /**
   * Set the session transcript data to use for the device response.
   *
   * This is arbitrary and should match the session transcript as it will be calculated by the verifier.
   * The transcript must be a CBOR encoded DataItem of an array, there is no further requirement.
   *
   * Example: `usingSessionTranscriptBytes(cborEncode(DataItem.fromData([a,b,c])))` where `a`, `b` and `c` can be anything including `null`.
   *
   * It is preferable to use {@link usingSessionTranscriptForOID4VP} or {@link usingSessionTranscriptForWebAPI} when possible.
   *
   * @param {Uint8Array} sessionTranscriptBytes - The sessionTranscriptBytes data to use in the session transcript.
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptBytes(sessionTranscriptBytes: Uint8Array): DeviceResponse {
    if (this.sessionTranscriptBytes) {
      throw new Error(
        'A session transcript has already been set, either with .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      )
    }
    this.sessionTranscriptBytes = sessionTranscriptBytes
    return this
  }

  /**
   * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex B (OID4VP), 2023 draft.
   *
   * This should match the session transcript as it will be calculated by the verifier.
   *
   * @param {string} mdocGeneratedNonce - A cryptographically random number with sufficient entropy.
   * @param {string} clientId - The client_id Authorization Request parameter from the Authorization Request Object.
   * @param {string} responseUri - The response_uri Authorization Request parameter from the Authorization Request Object.
   * @param {string} verifierGeneratedNonce - The nonce Authorization Request parameter from the Authorization Request Object.
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptForOID4VP(input: {
    mdocGeneratedNonce: string
    clientId: string
    responseUri: string
    verifierGeneratedNonce: string
  }): DeviceResponse {
    const bytes = DeviceResponse.calculateSessionTranscriptForOID4VP(input)
    this.usingSessionTranscriptBytes(bytes)
    return this
  }

  public static calculateSessionTranscriptForOID4VP(input: {
    mdocGeneratedNonce: string
    clientId: string
    responseUri: string
    verifierGeneratedNonce: string
  }) {
    const { mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce } = input

    return cborEncode(
      DataItem.fromData([
        null, // deviceEngagementBytes
        null, // eReaderKeyBytes
        [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce],
      ])
    )
  }

  /**
   * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex A (Web API), 2023 draft.
   *
   * This should match the session transcript as it will be calculated by the verifier.
   *
   * @param {Uint8Array} deviceEngagementBytes - The device engagement, encoded as a Tagged 24 cbor
   * @param {Uint8Array} readerEngagementBytes - The reader engagement, encoded as a Tagged 24 cbor
   * @param {Uint8Array} eReaderKeyBytes - The reader ephemeral public key as a COSE Key, encoded as a Tagged 24 cbor
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptForWebAPI(input: {
    deviceEngagementBytes: Uint8Array
    readerEngagementBytes: Uint8Array
    eReaderKeyBytes: Uint8Array
  }): DeviceResponse {
    const bytes = DeviceResponse.calculateSessionTranscriptForWebApi(input)
    this.usingSessionTranscriptBytes(bytes)
    return this
  }

  public static calculateSessionTranscriptForWebApi(input: {
    deviceEngagementBytes: Uint8Array
    readerEngagementBytes: Uint8Array
    eReaderKeyBytes: Uint8Array
  }) {
    const { deviceEngagementBytes, eReaderKeyBytes, readerEngagementBytes } = input

    return cborEncode(
      DataItem.fromData([
        new DataItem({ buffer: deviceEngagementBytes }),
        new DataItem({ buffer: eReaderKeyBytes }),
        readerEngagementBytes,
      ])
    )
  }

  /**
   * Add a namespace to the device response.
   *
   * @param {string} nameSpace - The name space to add to the device response.
   * @param {Record<string, any> | Map<string, unknown>} data - The data to add to the name space.
   * @returns {DeviceResponse}
   */
  public addDeviceNameSpace(nameSpace: string, data: Map<string, unknown> | Record<string, unknown>): DeviceResponse {
    this.nameSpaces.set(nameSpace, data instanceof Map ? data : new Map(Object.entries(data)))
    return this
  }

  /**
   * Set the device's private key to be used for signing the device response.
   *
   * @param  {JWK} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithSignature(devicePrivateKey: JWK, alg: SupportedAlgs): DeviceResponse {
    this.devicePrivateKey = devicePrivateKey
    this.alg = alg
    this.useMac = false
    return this
  }

  /**
   * Set the reader shared key to be used for signing the device response with MAC.
   *
   * @param  {JWK} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {JWK} ephemeralPublicKey - The public part of the ephemeral key generated by the MDOC.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithMAC(devicePrivateKey: JWK, ephemeralPublicKey: JWK, alg: MacSupportedAlgs): DeviceResponse {
    this.devicePrivateKey = devicePrivateKey
    this.ephemeralPublicKey = ephemeralPublicKey
    this.macAlg = alg
    this.useMac = true
    return this
  }

  /**
   * Sign the device response and return the MDoc.
   *
   * @returns {Promise<MDoc>} - The device response as an MDoc.
   */
  public async sign(ctx: {
    crypto: MdocContext['crypto']
    cose: MdocContext['cose']
  }): Promise<MDoc> {
    const requests = this.pd?.input_descriptors ?? this.deviceRequest?.docRequests
    if (!requests) {
      throw new Error(
        'Must provide a presentation definition or device request with .usingPresentationDefinition() or .usingDeviceRequest()'
      )
    }

    if (!this.sessionTranscriptBytes) {
      throw new Error(
        'Must provide the session transcript with either .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      )
    }

    const limitedDeviceSignedDocuments = await Promise.all(
      requests.map(async (request) => {
        const isDeviceRequest = (r: InputDescriptor | DocRequest): r is DocRequest => 'itemsRequest' in request

        let mdoc: IssuerSignedDocument
        let disclosedNameSpaces: Map<string, IssuerSignedItem[]>
        if (isDeviceRequest(request)) {
          const docType = request.itemsRequest.data.docType
          mdoc = findMdocMatchingDocType(this.mdoc, docType)
          disclosedNameSpaces = limitDisclosureToDeviceRequestNameSpaces(mdoc, request.itemsRequest.data.nameSpaces)
        } else {
          mdoc = findMdocMatchingDocType(this.mdoc, request.id)
          disclosedNameSpaces = limitDisclosureToInputDescriptor(mdoc, request)
        }

        return new DeviceSignedDocument(
          mdoc.docType,
          {
            nameSpaces: disclosedNameSpaces,
            issuerAuth: mdoc.issuerSigned.issuerAuth,
          },
          await this.getDeviceSigned(mdoc.docType, ctx)
        )
      })
    )

    return new MDoc(limitedDeviceSignedDocuments)
  }

  private async getDeviceSigned(
    docType: string,
    ctx: {
      cose: MdocContext['cose']
      crypto: MdocContext['crypto']
    }
  ): Promise<DeviceSigned> {
    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      this.sessionTranscriptBytes,
      docType,
      this.nameSpaces
    )

    let deviceAuth: DeviceAuth
    if (this.useMac) {
      if (!this.sessionTranscriptBytes) {
        throw new Error('Missing sessionTranscriptBytes for getDeviceSigned')
      }

      deviceAuth = await this.getDeviceAuthMac(deviceAuthenticationBytes, this.sessionTranscriptBytes, ctx)
    } else {
      deviceAuth = await this.getDeviceAuthSign(deviceAuthenticationBytes, ctx)
    }

    const deviceSigned: DeviceSigned = {
      nameSpaces: this.nameSpaces,
      deviceAuth,
    }

    return deviceSigned
  }

  private async getDeviceAuthMac(
    deviceAuthenticationBytes: Uint8Array,
    sessionTranscriptBytes: Uint8Array,
    ctx: {
      cose: Pick<MdocContext['cose'], 'mac0'>
      crypto: MdocContext['crypto']
    }
  ): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) {
      throw new Error('Missing devicePrivateKey for getDeviceAuthMac')
    }

    if (!this.ephemeralPublicKey) {
      throw new Error('Missing ephemeralPublicKey for getDeviceAuthMac')
    }

    const { kid } = this.devicePrivateKey
    const ephemeralMacKeyJwk = await ctx.crypto.calculateEphemeralMacKeyJwk({
      privateKey: COSEKeyToRAW(COSEKey.fromJWK(this.devicePrivateKey).encode()),
      publicKey: COSEKeyToRAW(COSEKey.fromJWK(this.ephemeralPublicKey).encode()),

      sessionTranscriptBytes: sessionTranscriptBytes,
    })

    if (!this.macAlg) throw new Error('Missing macAlg')

    const protectedHeaders = MacProtectedHeaders.from([[Headers.Algorithm, MacAlgorithms[this.macAlg]]])

    const unprotectedHeaders = kid ? UnprotectedHeaders.from([[Headers.KeyID, stringToUint8Array(kid)]]) : undefined

    const mac0 = Mac0.create(protectedHeaders, unprotectedHeaders, deviceAuthenticationBytes, undefined)

    const tag = await ctx.cose.mac0.sign({ mac0, jwk: ephemeralMacKeyJwk })
    mac0.tag = tag
    return { deviceMac: mac0 }
  }

  private async getDeviceAuthSign(
    cborData: Uint8Array,
    ctx: {
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey')

    if (!this.alg) {
      throw new Error('The alg header must be set.')
    }

    const { kid } = this.devicePrivateKey
    const unprotectedHeaders = kid ? UnprotectedHeaders.from([[Headers.KeyID, stringToUint8Array(kid)]]) : undefined

    const sign1 = Sign1.create(
      ProtectedHeaders.from([[Headers.Algorithm, Algorithms[this.alg]]]),
      unprotectedHeaders,
      cborData
    )

    const signature = await ctx.cose.sign1.sign({
      sign1,
      jwk: this.devicePrivateKey,
    })
    sign1.signature = signature

    return { deviceSignature: sign1 }
  }
}
