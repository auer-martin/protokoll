import {
  COSEKey,
  DeviceSignedDocument,
  Document,
  IssuerSignedDocument,
  MDoc,
  Verifier,
  parse,
} from '@protokoll/mdoc-client';
import * as jose from 'jose';
import { mdocContext } from '../mdoc-test-context.js';
import {
  DEVICE_JWK,
  ISSUER_CERTIFICATE,
  ISSUER_PRIVATE_KEY_JWK,
} from './config.js';

const { d, ...publicKeyJWK } = DEVICE_JWK as jose.JWK;

describe('issuing an MDOC', () => {
  let encoded: Uint8Array;
  let parsedDocument: IssuerSignedDocument;

  beforeAll(async () => {
    const issuerPrivateKey = ISSUER_PRIVATE_KEY_JWK;

    const document = await new Document('org.iso.18013.5.1.mDL', mdocContext)
      .addIssuerNameSpace('org.iso.18013.5.1', {
        family_name: 'Jones',
        given_name: 'Ava',
        birth_date: '2007-03-25',
      })
      .useDigestAlgorithm('SHA-512')
      .addValidityInfo({
        signed: new Date('2023-10-24'),
        validUntil: new Date('2050-10-24'),
      })
      .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
      .sign(
        {
          issuerPrivateKey,
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        },
        mdocContext
      );

    const mdoc = new MDoc([document]);
    encoded = mdoc.encode();

    const parsedMDOC = parse(encoded);
    parsedDocument = parsedMDOC.documents[0] as DeviceSignedDocument;
  });

  it('should be verifiable', async () => {
    const verifier = new Verifier([ISSUER_CERTIFICATE]);
    await verifier.verify(
      encoded,
      {
        onCheck: (verification, original) => {
          if (verification.category === 'DEVICE_AUTH') {
            return;
          }
          original(verification);
        },
      },
      mdocContext
    );
  });

  it('should contain the validity info', () => {
    const { validityInfo } =
      parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(validityInfo).toBeDefined();
    expect(validityInfo.signed).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validFrom).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validUntil).toEqual(new Date('2050-10-24'));
  });

  it('should use the correct digest alg', () => {
    const { digestAlgorithm } =
      parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(digestAlgorithm).toEqual('SHA-512');
  });

  it('should include the device public key', () => {
    const { deviceKeyInfo } =
      parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(deviceKeyInfo?.deviceKey).toBeDefined();
    const actual =
      typeof deviceKeyInfo !== 'undefined' &&
      COSEKey.import(deviceKeyInfo.deviceKey).toJWK();
    expect(actual).toEqual(publicKeyJWK);
  });

  it('should include the namespace and attributes', () => {
    const attrValues = parsedDocument.getIssuerNameSpace('org.iso.18013.5.1');
    // @ts-ignore
    const currentAge =
      new Date(Date.now() - new Date('2007-03-25').getTime()).getFullYear() -
      1970;
    expect(attrValues).toMatchInlineSnapshot(`
{
  "age_over_${currentAge}": true,
  "age_over_21": ${currentAge >= 21},
  "birth_date": "2007-03-25",
  "family_name": "Jones",
  "given_name": "Ava",
}
`);
  });
});