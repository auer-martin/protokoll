import type { DocType, IssuerSigned, MdocNameSpaces } from './types.js'

/**
 * Represents an issuer signed document.
 *
 * Note: You don't need instantiate this class.
 * This is the return type of the parser and the document.sign() method.
 */
export class IssuerSignedDocument {
  constructor(
    public readonly docType: DocType,
    public readonly issuerSigned: IssuerSigned
  ) {}

  /**
   * Create the structure for encoding a document.
   *
   * @returns {Map<string, unknown>} - The document as a map
   */
  public prepare(): Map<string, unknown> {
    const nameSpaces = new Map(
      Array.from(this.issuerSigned.nameSpaces.entries()).map(([nameSpace, items]) => {
        return [nameSpace, items.map((item) => item.dataItem)] as const
      })
    )

    // TODO: ERRORS MISSING
    const docMap = new Map(
      Object.entries({
        docType: this.docType,
        issuerSigned: {
          nameSpaces,
          issuerAuth: this.issuerSigned.issuerAuth.getContentForEncoding(),
        },
      })
    )
    return docMap
  }

  /**
   * Helper method to get the values in a namespace as a JS object.
   *
   * @param {string} namespace - The namespace to add.
   * @returns {Map<string, unknown>} - The values in the namespace as an object
   */
  getIssuerNameSpace(namespace: string): Map<string, unknown> | undefined {
    const nameSpace = this.issuerSigned.nameSpaces.get(namespace)
    if (!nameSpace) return undefined

    return new Map(nameSpace.map((item) => [item.elementIdentifier, item.elementValue]))
  }

  /**
   * List of namespaces in the document.
   */
  get issuerSignedNameSpaces(): string[] {
    return Array.from(this.issuerSigned.nameSpaces.keys())
  }

  public get allIssuerSignedNamespaces(): MdocNameSpaces {
    const namespaces = this.issuerSignedNameSpaces

    return new Map(
      namespaces.map((namespace) => {
        const namespaceValues = this.getIssuerNameSpace(namespace)
        if (!namespaceValues) {
          throw new Error(`Cannot extract the namespace '${namespace}' from the mdoc.`)
        }
        return [namespace, namespaceValues]
      })
    )
  }
}
