import type * as jose from 'jose';
import type { MdocContext } from '../../c-mdoc.js';
import { DataItem, cborEncode } from '../../cbor/index.js';
import {
  Algorithms,
  Headers,
  MacAlgorithms,
  MacProtectedHeaders,
  ProtectedHeaders,
  UnprotectedHeaders,
} from '../../cose/headers.js';
import { COSEKey, COSEKeyToRAW } from '../../cose/key/cose-key.js';
import { Mac0 } from '../../cose/mac0.js';
import { Sign1 } from '../../cose/sign1.js';
import { stringToUint8Array } from '../../u-buffer.js';
import type { IssuerSignedItem } from '../issuer-signed-item.js';
import { parse } from '../parser.js';
import { calculateDeviceAutenticationBytes } from '../utils.js';
import { DeviceSignedDocument } from './device-signed-document.js';
import type { IssuerSignedDocument } from './issuer-signed-document.js';
import { MDoc } from './mdoc.js';
import type {
  InputDescriptor,
  PresentationDefinition,
} from './presentation-definition.js';
import type {
  DeviceAuth,
  DeviceSigned,
  MacSupportedAlgs,
  SupportedAlgs,
} from './types.js';

/**
 * A builder class for creating a device response.
 */
export class DeviceResponse {
  private mdoc: MDoc;
  private pd?: PresentationDefinition;
  private handover?: string[];
  private useMac = true;
  private devicePrivateKey?: Uint8Array;
  public deviceResponseCbor?: Uint8Array;
  public nameSpaces: Record<string, Record<string, any>> = {};
  private alg?: SupportedAlgs;
  private macAlg?: MacSupportedAlgs;
  private ephemeralPublicKey?: Uint8Array;

  /**
   * Create a DeviceResponse builder.
   *
   * @param {MDoc | Uint8Array} mdoc - The mdoc to use as a base for the device response.
   *                                   It can be either a parsed MDoc or a CBOR encoded MDoc.
   * @returns {DeviceResponse} - A DeviceResponse builder.
   */
  public static from(mdoc: MDoc | Uint8Array): DeviceResponse {
    if (mdoc instanceof Uint8Array) {
      return new DeviceResponse(parse(mdoc));
    }
    return new DeviceResponse(mdoc);
  }

  constructor(mdoc: MDoc) {
    this.mdoc = mdoc;
  }

  /**
   *
   * @param pd - The presentation definition to use for the device response.
   * @returns {DeviceResponse}
   */
  public usingPresentationDefinition(
    pd: PresentationDefinition
  ): DeviceResponse {
    if (!pd.input_descriptors.length) {
      throw new Error(
        'The Presentation Definition must have at least one Input Descriptor object.'
      );
    }

    const hasDuplicates = pd.input_descriptors.some(
      (id1, idx) =>
        pd.input_descriptors.findIndex(id2 => id2.id === id1.id) !== idx
    );
    if (hasDuplicates) {
      throw new Error(
        'Each Input Descriptor object must have a unique id property.'
      );
    }

    this.pd = pd;
    return this;
  }

  /**
   * Set the handover data to use for the device response.
   *
   * @param {string[]} handover - The handover data to use for the device response.
   * @returns {DeviceResponse}
   */
  public usingHandover(handover: string[]): DeviceResponse {
    this.handover = handover;
    return this;
  }

  /**
   * Add a namespace to the device response.
   *
   * @param {string} nameSpace - The name space to add to the device response.
   * @param {Record<string, any>} data - The data to add to the name space.
   * @returns {DeviceResponse}
   */
  public addDeviceNameSpace(
    nameSpace: string,
    data: Record<string, any>
  ): DeviceResponse {
    this.nameSpaces[nameSpace] = data;
    return this;
  }

  /**
   * Set the device's private key to be used for signing the device response.
   *
   * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithSignature(
    devicePrivateKey: jose.JWK | Uint8Array,
    alg: SupportedAlgs
  ): DeviceResponse {
    if (devicePrivateKey instanceof Uint8Array) {
      this.devicePrivateKey = devicePrivateKey;
    } else {
      this.devicePrivateKey = COSEKey.fromJWK(devicePrivateKey).encode();
    }
    this.alg = alg;
    this.useMac = false;
    return this;
  }

  /**
   * Set the reader shared key to be used for signing the device response with MAC.
   *
   * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {Uint8Array} ephemeralPublicKey - The public part of the ephemeral key generated by the MDOC.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithMAC(
    devicePrivateKey: jose.JWK | Uint8Array,
    ephemeralPublicKey: Uint8Array,
    alg: MacSupportedAlgs
  ): DeviceResponse {
    if (devicePrivateKey instanceof Uint8Array) {
      this.devicePrivateKey = devicePrivateKey;
    } else {
      this.devicePrivateKey = COSEKey.fromJWK(devicePrivateKey).encode();
    }
    this.ephemeralPublicKey = ephemeralPublicKey;
    this.macAlg = alg;
    this.useMac = true;
    return this;
  }

  /**
   * Sign the device response and return the MDoc.
   *
   * @returns {Promise<MDoc>} - The device response as an MDoc.
   */
  public async sign(ctx: {
    crypto: MdocContext['crypto'];
    cose: MdocContext['cose'];
    jose: MdocContext['jose'];
  }): Promise<MDoc> {
    if (!this.pd)
      throw new Error(
        'Must provide a presentation definition with .usingPresentationDefinition()'
      );
    if (!this.handover)
      throw new Error('Must provide handover data with .usingHandover()');

    const docs = await Promise.all(
      this.pd.input_descriptors.map(id => this.handleInputDescriptor(id, ctx))
    );
    return new MDoc(docs);
  }

  private async handleInputDescriptor(
    id: InputDescriptor,
    ctx: {
      cose: MdocContext['cose'];
      crypto: MdocContext['crypto'];
      jose: MdocContext['jose'];
    }
  ): Promise<DeviceSignedDocument> {
    const document = (this.mdoc.documents || []).find(d => d.docType === id.id);
    if (!document) {
      // TODO; probl need to create a DocumentError here, but let's just throw for now
      throw new Error(
        `The mdoc does not have a document with DocType "${id.id}"`
      );
    }

    const nameSpaces = await this.prepareNamespaces(id, document);

    return new DeviceSignedDocument(
      document.docType,
      {
        nameSpaces,
        issuerAuth: document.issuerSigned.issuerAuth,
      },
      await this.getDeviceSigned(document.docType, ctx)
    );
  }

  private async getDeviceSigned(
    docType: string,
    ctx: {
      cose: MdocContext['cose'];
      crypto: MdocContext['crypto'];
      jose: MdocContext['jose'];
    }
  ): Promise<DeviceSigned> {
    const sessionTranscript = [
      null, // deviceEngagementBytes
      null, // eReaderKeyBytes,
      this.handover,
    ];

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      sessionTranscript,
      docType,
      this.nameSpaces
    );

    const deviceSigned: DeviceSigned = {
      nameSpaces: this.nameSpaces,
      deviceAuth: this.useMac
        ? await this.getDeviceAuthMac(
            deviceAuthenticationBytes,
            sessionTranscript,
            ctx
          )
        : await this.getDeviceAuthSign(deviceAuthenticationBytes, ctx),
    };

    return deviceSigned;
  }

  private async getDeviceAuthMac(
    deviceAuthenticationBytes: Uint8Array,
    sessionTranscript: any,
    ctx: {
      cose: Pick<MdocContext['cose'], 'mac0'>;
      crypto: MdocContext['crypto'];
    }
  ): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) {
      throw new Error('Missing devicePrivateKey for getDeviceAuthMac');
    }

    if (!this.ephemeralPublicKey) {
      throw new Error('Missing ephemeralPublicKey for getDeviceAuthMac');
    }

    const key = COSEKeyToRAW(this.devicePrivateKey);
    const { kid } = COSEKey.import(this.devicePrivateKey).toJWK();

    const ephemeralMacKey = await ctx.crypto.calculateEphemeralMacKey({
      privateKey: key,
      publicKey: this.ephemeralPublicKey,
      sessionTranscriptBytes: cborEncode(DataItem.fromData(sessionTranscript)),
    });

    if (!this.macAlg) throw new Error('Missing macAlg');

    const protectedHeaders = MacProtectedHeaders.from([
      [Headers.Algorithm, MacAlgorithms[this.macAlg]],
    ]);

    const unprotectedHeaders = kid
      ? UnprotectedHeaders.from([[Headers.KeyID, stringToUint8Array(kid)]])
      : undefined;

    const mac = await Mac0.create(
      protectedHeaders,
      unprotectedHeaders,
      deviceAuthenticationBytes,
      ephemeralMacKey,
      ctx
    );

    return { deviceMac: mac };
  }

  private async getDeviceAuthSign(
    cborData: Uint8Array,
    ctx: {
      crypto: MdocContext['crypto'];
      cose: MdocContext['cose'];
      jose: MdocContext['jose'];
    }
  ): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey');

    if (!this.alg) {
      throw new Error('The alg header must be set.');
    }

    const { kid } = COSEKey.import(this.devicePrivateKey).toJWK();
    const unprotectedHeaders = kid
      ? UnprotectedHeaders.from([[Headers.KeyID, stringToUint8Array(kid)]])
      : undefined;

    const deviceSignature = await Sign1.sign(
      ProtectedHeaders.from([[Headers.Algorithm, Algorithms[this.alg]]]),
      unprotectedHeaders,
      cborData,
      await ctx.jose.importJwk(COSEKey.import(this.devicePrivateKey).toJWK()),
      ctx
    );
    return { deviceSignature };
  }

  private async prepareNamespaces(
    id: InputDescriptor,
    document: IssuerSignedDocument
  ) {
    const requestedFields = id.constraints.fields;
    const nameSpaces: Record<string, any> = {};
    for await (const field of requestedFields) {
      const result = await this.prepareDigest(field.path, document);
      if (!result) {
        // TODO: Do we add an entry to DocumentErrors if not found?
        console.log(`No matching field found for ${field.path}`);
        continue;
      }

      const { nameSpace, digest } = result;
      if (!nameSpaces[nameSpace]) nameSpaces[nameSpace] = [];
      nameSpaces[nameSpace].push(digest);
    }

    return nameSpaces;
  }

  private async prepareDigest(
    paths: string[],
    document: IssuerSignedDocument
  ): Promise<{ nameSpace: string; digest: IssuerSignedItem } | null> {
    /**
     * path looks like this: "$['org.iso.18013.5.1']['family_name']"
     * the regex creates two groups with contents between "['" and "']"
     * the second entry in each group contains the result without the "'[" or "']"
     */
    for (const path of paths) {
      // @ts-expect-error this is hacky
      const [[_1, nameSpace], [_2, elementIdentifier]] = [
        ...path.matchAll(/\['(.*?)'\]/g),
      ];
      if (!nameSpace)
        throw new Error(`Failed to parse namespace from path "${path}"`);
      if (!elementIdentifier)
        throw new Error(
          `Failed to parse elementIdentifier from path "${path}"`
        );

      const nsAttrs: IssuerSignedItem[] =
        document.issuerSigned.nameSpaces[nameSpace] || [];
      const digest = nsAttrs.find(
        d => d.elementIdentifier === elementIdentifier
      );

      if (elementIdentifier.startsWith('age_over_')) {
        return this.handleAgeOverNN(elementIdentifier, nameSpace, nsAttrs);
      }

      if (digest) {
        return {
          nameSpace,
          digest,
        };
      }
    }

    return null;
  }

  private handleAgeOverNN(
    request: string,
    nameSpace: string,
    attributes: IssuerSignedItem[]
  ): { nameSpace: string; digest: IssuerSignedItem } | null {
    const ageOverList = attributes
      .map((a, i) => {
        const { elementIdentifier: key, elementValue: value } = a;
        return { key, value, index: i };
      })
      .filter(i => i.key.startsWith('age_over_'))
      .map(i => ({
        nn: parseInt(i.key.replace('age_over_', ''), 10),
        ...i,
      }))
      .sort((a, b) => a.nn - b.nn);

    const reqNN = parseInt(request.replace('age_over_', ''), 10);

    let item;
    // Find nearest TRUE
    item = ageOverList.find(i => i.value === true && i.nn >= reqNN);

    if (!item) {
      // Find the nearest False
      item = ageOverList
        .sort((a, b) => b.nn - a.nn)
        .find(i => i.value === false && i.nn <= reqNN);
    }

    if (!item) {
      return null;
    }

    return {
      nameSpace,
      digest: attributes[item.index]!,
    };
  }
}