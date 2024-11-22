import type { IssuerSignedItem } from '../issuer-signed-item.js'
import type { DeviceRequestNameSpaces } from './device-request.js'
import type { IssuerSignedDocument } from './issuer-signed-document.js'
import type { MDoc } from './mdoc.js'
import type { InputDescriptor } from './presentation-definition.js'
import type { DocType, IssuerNameSpaces } from './types.js'

export const limitDisclosureToDeviceRequestNameSpaces = (
  mdoc: IssuerSignedDocument,
  deviceRequestNameSpaces: DeviceRequestNameSpaces
): Map<string, IssuerSignedItem[]> => {
  const nameSpaces: Map<string, IssuerSignedItem[]> = new Map()

  for (const [nameSpace, nameSpaceFields] of deviceRequestNameSpaces.entries()) {
    const nsAttrs = mdoc.issuerSigned.nameSpaces.get(nameSpace) ?? []
    const digests = Array.from(nameSpaceFields.entries()).map(([elementIdentifier, _]) => {
      const digest = prepareDigest(elementIdentifier, nsAttrs)
      if (!digest) {
        throw new Error(`No matching field found for '${elementIdentifier}'`)
      }
      return digest
    })

    nameSpaces.set(nameSpace, digests)
  }
  return nameSpaces
}

const prepareDigest = (elementIdentifier: string, nsAttrs: IssuerSignedItem[]): IssuerSignedItem | null => {
  if (elementIdentifier.startsWith('age_over_')) {
    const digest = handleAgeOverNN(elementIdentifier, nsAttrs)
    return digest
  }

  const digest = nsAttrs.find((d) => d.elementIdentifier === elementIdentifier)
  return digest ?? null
}

const prepareDigestForInputDescriptor = (
  paths: string[],
  issuerNameSpaces: IssuerNameSpaces
): { nameSpace: string; digest: IssuerSignedItem } | null => {
  for (const path of paths) {
    const { nameSpace, elementIdentifier } = parsePath(path)
    const nsAttrs = issuerNameSpaces.get(nameSpace) ?? []

    const digest = prepareDigest(elementIdentifier, nsAttrs)
    if (digest) return { nameSpace, digest }
  }
  return null
}

const parsePath = (
  path: string
): {
  nameSpace: string
  elementIdentifier: string
} => {
  /**
   * path looks like this: "$['org.iso.18013.5.1']['family_name']"
   * the regex creates two groups with contents between "['" and "']"
   * the second entry in each group contains the result without the "'[" or "']"
   *
   * @example org.iso.18013.5.1 family_name
   */
  const matches = [...path.matchAll(/\['(.*?)'\]/g)]
  if (matches.length !== 2) {
    throw new Error(`Invalid path format: "${path}"`)
  }

  const [nameSpaceMatch, elementIdentifierMatch] = matches
  const nameSpace = nameSpaceMatch?.[1]
  const elementIdentifier = elementIdentifierMatch?.[1]

  if (!nameSpace || !elementIdentifier) {
    throw new Error(`Failed to parse path: "${path}"`)
  }

  return { nameSpace, elementIdentifier }
}

const handleAgeOverNN = (request: string, attributes: IssuerSignedItem[]): IssuerSignedItem | null => {
  const ageOverList = attributes
    .map((a, i) => {
      const { elementIdentifier: key, elementValue: value } = a
      return { key, value, index: i }
    })
    .filter((i) => i.key.startsWith('age_over_'))
    .map((i) => ({
      nn: Number.parseInt(i.key.replace('age_over_', ''), 10),
      ...i,
    }))
    .sort((a, b) => a.nn - b.nn)

  const reqNN = Number.parseInt(request.replace('age_over_', ''), 10)

  let item: (typeof ageOverList)[number] | undefined
  // Find nearest TRUE
  item = ageOverList.find((i) => i.value === true && i.nn >= reqNN)

  if (!item) {
    // Find the nearest False
    item = ageOverList.sort((a, b) => b.nn - a.nn).find((i) => i.value === false && i.nn <= reqNN)
  }

  if (!item) {
    return null
  }

  return attributes[item.index]
}

export const findMdocMatchingDocType = (mdoc: MDoc, docType: DocType) => {
  const matchingMdoc = mdoc.documents.filter((document) => document.docType === docType)

  if (!matchingMdoc[0]) {
    throw new Error(`Cannot limit the disclosure. No credential is matching the requested DocType '${docType}'`)
  }

  if (matchingMdoc.length > 1) {
    throw new Error(`Cannot limit the disclosure. Multiple credentials are matching the requested DocType '${docType}'`)
  }

  return matchingMdoc[0]
}

export const limitDisclosureToInputDescriptor = (
  mdoc: IssuerSignedDocument,
  inputDescriptor: InputDescriptor
): Map<string, IssuerSignedItem[]> => {
  const nameSpaces: Map<string, IssuerSignedItem[]> = new Map()

  for (const field of inputDescriptor.constraints.fields) {
    const result = prepareDigestForInputDescriptor(field.path, mdoc.issuerSigned.nameSpaces)
    if (!result) {
      throw new Error(
        `Cannot limit the disclosure to the input descriptor. No matching field found for '${field.path.join('.')}'`
      )
    }

    const { nameSpace, digest } = result
    const entry = nameSpaces.get(nameSpace)
    if (!entry) nameSpaces.set(nameSpace, [digest])
    else entry.push(digest)
  }

  return nameSpaces
}
