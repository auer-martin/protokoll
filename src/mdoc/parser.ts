import { compareVersions } from 'compare-versions'
import { cborDecode } from '../cbor/index.js'
import { Mac0 } from '../cose/mac0.js'
import { Sign1 } from '../cose/sign1.js'
import { MDLParseError } from './errors.js'
import { IssuerSignedItem } from './issuer-signed-item.js'
import { DeviceSignedDocument } from './model/device-signed-document.js'
import IssuerAuth from './model/issuer-auth.js'
import { IssuerSignedDocument } from './model/issuer-signed-document.js'
import { MDoc } from './model/mdoc.js'
import type {
  DeviceAuth,
  DeviceSigned,
  IssuerNameSpaces,
  IssuerSigned,
  RawDeviceAuth,
  RawIndexedDataItem,
  RawIssuerAuth,
  RawNameSpaces,
} from './model/types.js'

const parseIssuerAuthElement = (rawIssuerAuth: RawIssuerAuth, expectedDocType?: string): IssuerAuth => {
  const issuerAuth = new IssuerAuth(...rawIssuerAuth)
  const { decodedPayload } = issuerAuth
  const { docType, version } = decodedPayload

  if (expectedDocType && docType !== expectedDocType) {
    throw new MDLParseError(`The issuerAuth docType must be ${expectedDocType}`)
  }

  if (!version || compareVersions(version, '1.0') !== 0) {
    throw new MDLParseError("The issuerAuth version must be '1.0'")
  }

  return issuerAuth
}

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuth => {
  const { deviceSignature, deviceMac } = Object.fromEntries(rawDeviceAuth)
  if (deviceSignature) {
    return { deviceSignature: new Sign1(...deviceSignature) }
  }
  if (deviceMac) {
    return { deviceMac: new Mac0(...deviceMac) }
  }

  throw new MDLParseError(`Invalid deviceAuth element. Missing 'deviceSignature' and 'deviceMac'`)
}

const namespaceToArray = (entries: RawIndexedDataItem): IssuerSignedItem[] => {
  return entries.map((di) => new IssuerSignedItem(di))
}

const mapIssuerNameSpaces = (namespace: RawNameSpaces): IssuerNameSpaces => {
  return new Map(Array.from(namespace.entries()).map(([nameSpace, entries]) => [nameSpace, namespaceToArray(entries)]))
}

/**
 * Parse a IssuerSignedDocument
 *
 * @param issuerSigned - The cbor encoded or decoded IssuerSigned Structure
 * @returns {Promise<IssuerSignedDocument>} - The parsed IssuerSigned document
 */
export const parseIssuerSigned = (
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  issuerSigned: Uint8Array | Map<string, any>,
  expectedDocType?: string
): IssuerSignedDocument => {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  let issuerSignedDecoded: Map<string, any>
  try {
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    issuerSignedDecoded = issuerSigned instanceof Map ? issuerSigned : (cborDecode(issuerSigned) as Map<string, any>)
  } catch (err) {
    throw new MDLParseError(
      `Unable to decode issuer signed document: ${err instanceof Error ? err.message : 'Unknown error'}`
    )
  }

  const issuerAuth = parseIssuerAuthElement(issuerSignedDecoded.get('issuerAuth'), expectedDocType)

  const parsedIssuerSigned: IssuerSigned = {
    ...issuerSignedDecoded,
    nameSpaces: mapIssuerNameSpaces(issuerSignedDecoded.get('nameSpaces')),
    issuerAuth,
  }

  return new IssuerSignedDocument(issuerAuth.decodedPayload.docType, parsedIssuerSigned)
}

/**
 * Parse a DeviceSignedDocument
 *
 * @param deviceSigned - The cbor encoded or decoded DeviceSigned Structure
 * @param issuerSigned - The cbor encoded or decoded IssuerSigned Structure
 * @returns {Promise<DeviceSignedDocument>} - The parsed DeviceSigned document
 */
export const parseDeviceSigned = (
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  deviceSigned: Uint8Array | Map<string, any>,
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  issuerSigned: Uint8Array | Map<string, any>,
  expectedDocType?: string
): DeviceSignedDocument => {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  let deviceSignedDecoded: Map<string, any>
  try {
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    deviceSignedDecoded = deviceSigned instanceof Map ? deviceSigned : (cborDecode(deviceSigned) as Map<string, any>)
  } catch (err) {
    throw new MDLParseError(
      `Unable to decode device signed document : ${err instanceof Error ? err.message : 'Unknown error'}`
    )
  }

  const deviceSignedParsed: DeviceSigned = {
    ...deviceSignedDecoded,
    nameSpaces: deviceSignedDecoded.get('nameSpaces').data,
    deviceAuth: parseDeviceAuthElement(deviceSignedDecoded.get('deviceAuth')),
  }

  const issuerSignedDocument = parseIssuerSigned(issuerSigned, expectedDocType)

  return new DeviceSignedDocument(issuerSignedDocument.docType, issuerSignedDocument.issuerSigned, deviceSignedParsed)
}

/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
export const parseDeviceResponse = (encoded: Uint8Array): MDoc => {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  let deviceResponse: Map<string, any>
  try {
    deviceResponse = cborDecode(encoded) as Map<string, unknown>
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err instanceof Error ? err.message : 'Unknown error'}`)
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse)

  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  const parsedDocuments: IssuerSignedDocument[] = documents.map((doc: Map<string, any>): IssuerSignedDocument => {
    const docType = doc.get('docType')
    const issuerSigned = doc.get('issuerSigned')
    const deviceSigned = doc.get('deviceSigned')

    if (deviceSigned) {
      return parseDeviceSigned(deviceSigned, issuerSigned, docType)
    }
    return parseIssuerSigned(issuerSigned, docType)
  })

  return new MDoc(parsedDocuments, version, status)
}
