import { cborDecode, cborEncode } from '../../cbor'
import type { ItemsRequestData } from '../items-request'
import { ItemsRequest } from '../items-request'

export interface DocRequest {
  itemsRequest: ItemsRequest
  readerAuth?: ReaderAuth
}

export type ReaderAuth = [
  Uint8Array | undefined,
  Uint8Array | undefined,
  Uint8Array | undefined,
  Uint8Array | undefined,
]

export type DeviceRequestNameSpaces = Map<string, Map<string, boolean>>

export class DeviceRequest {
  constructor(
    public version: string,
    public docRequests: DocRequest[]
  ) {}

  public static from(
    version: string,
    docRequests: {
      itemsRequestData: ItemsRequestData
      readerAuth?: ReaderAuth
    }[]
  ) {
    return new DeviceRequest(
      version,
      docRequests.map((docRequest) => {
        return {
          ...docRequest,
          itemsRequest: ItemsRequest.create(
            docRequest.itemsRequestData.docType,
            docRequest.itemsRequestData.nameSpaces,
            docRequest.itemsRequestData.requestInfo
          ),
        }
      })
    )
  }

  public static parse(cbor: Uint8Array) {
    const res = cborDecode(cbor, {
      tagUint8Array: false,
      useRecords: true,
      mapsAsObjects: true,
      // biome-ignore lint/suspicious/noExplicitAny:
    }) as { version: string; docRequests: any[] }

    const { version, docRequests } = res

    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const parsedDocRequests: DocRequest[] = docRequests.map((docRequest) => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      const itemsRequest = new ItemsRequest(docRequest.itemsRequest)

      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return {
        ...docRequest,
        itemsRequest,
      }
    })

    return new DeviceRequest(version, parsedDocRequests)
  }

  public static encodeDocRequest(r: DocRequest) {
    // biome-ignore lint/suspicious/noExplicitAny:
    return new Map<string, any>([
      ['itemsRequest', r.itemsRequest.dataItem],
      ['readerAuth', r.readerAuth],
    ])
  }

  encode() {
    return cborEncode({
      version: this.version,
      // eslint-disable-next-line @typescript-eslint/unbound-method
      docRequests: this.docRequests.map(DeviceRequest.encodeDocRequest),
    })
  }
}
