import type { MaybePromise } from '@protokoll/core';
import { base64ToUint8Array, uint8ArrayToBase64 } from '@protokoll/core';
import type { CryptoContext } from './c-crypto.js';
import { withCryptoContext } from './c-crypto.js';
import formatPEM from './format-pem.js';
import invalidKeyInput from './invalid-key-input.js';
import type { PEMImportOptions } from './key/import.js';
import { isCryptoKey } from './webcrypto.js';

export type PEMImportFunction = (
  input: {
    pem: string;
    alg: string;
  } & PEMImportOptions,
  ctx?: CryptoContext
) => MaybePromise<CryptoKey>;

const genericExport = async (
  input: {
    keyType: 'private' | 'public';
    keyFormat: 'spki' | 'pkcs8';
    key: CryptoKey;
  },
  _ctx?: CryptoContext
) => {
  const { keyType, keyFormat, key } = input;

  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, ...['CryptoKey']));
  }

  if (!key.extractable) {
    throw new TypeError('CryptoKey is not extractable');
  }

  if (key.type !== keyType) {
    throw new TypeError(`key is not a ${keyType} key`);
  }

  const ctx = withCryptoContext(_ctx ?? {});
  return formatPEM(
    uint8ArrayToBase64(
      new Uint8Array(await ctx.crypto.subtle.exportKey(keyFormat, key))
    ),
    `${keyType.toUpperCase()} KEY`
  );
};

export const toSPKI = (
  input: {
    key: CryptoKey;
  },
  ctx?: CryptoContext
) => {
  const { key } = input;
  return genericExport({ keyType: 'public', keyFormat: 'spki', key }, ctx);
};

export const toPKCS8 = (
  input: {
    key: CryptoKey;
  },
  ctx?: CryptoContext
) => {
  const { key } = input;
  return genericExport({ keyType: 'public', keyFormat: 'pkcs8', key }, ctx);
};

const findOid = (keyData: Uint8Array, oid: number[], from = 0): boolean => {
  if (from === 0) {
    oid.unshift(oid.length);
    oid.unshift(0x06);
  }
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const i = keyData.indexOf(oid[0]!, from);
  if (i === -1) return false;
  const sub = keyData.subarray(i, i + oid.length);
  if (sub.length !== oid.length) return false;
  return (
    sub.every((value, index) => value === oid[index]) ||
    findOid(keyData, oid, i + 1)
  );
};

const getNamedCurve = (keyData: Uint8Array): string => {
  switch (true) {
    case findOid(keyData, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]):
      return 'P-256';
    case findOid(keyData, [0x2b, 0x81, 0x04, 0x00, 0x22]):
      return 'P-384';
    case findOid(keyData, [0x2b, 0x81, 0x04, 0x00, 0x23]):
      return 'P-521';
    case findOid(keyData, [0x2b, 0x65, 0x6e]):
      return 'X25519';
    case findOid(keyData, [0x2b, 0x65, 0x6f]):
      return 'X448';
    case findOid(keyData, [0x2b, 0x65, 0x70]):
      return 'Ed25519';
    case findOid(keyData, [0x2b, 0x65, 0x71]):
      return 'Ed448';
    default:
      throw new Error(
        'Invalid or unsupported EC Key Curve or OKP Key Sub Type'
      );
  }
};

const genericImport = async (
  input: {
    pem: string;
    alg: string;
    replace: RegExp;
    keyFormat: 'spki' | 'pkcs8';
  } & PEMImportOptions,
  _ctx?: CryptoContext
) => {
  const { pem, alg, keyFormat, replace, extractable } = input;
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  let keyUsages: KeyUsage[];

  const keyData = new Uint8Array(
    atob(pem.replace(replace, ''))
      .split('')
      .map(c => c.charCodeAt(0))
  );

  const isPublic = keyFormat === 'spki';

  switch (alg) {
    case 'PS256':
    case 'PS384':
    case 'PS512':
      algorithm = { name: 'RSA-PSS', hash: `SHA-${alg.slice(-3)}` };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;
    case 'RS256':
    case 'RS384':
    case 'RS512':
      algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${alg.slice(-3)}` };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      algorithm = {
        name: 'RSA-OAEP',
        hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`,
      };
      keyUsages = isPublic ? ['encrypt', 'wrapKey'] : ['decrypt', 'unwrapKey'];
      break;
    case 'ES256':
      algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;
    case 'ES384':
      algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;
    case 'ES512':
      algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;
    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW': {
      const namedCurve = getNamedCurve(keyData);
      algorithm = namedCurve.startsWith('P-')
        ? { name: 'ECDH', namedCurve }
        : { name: namedCurve };
      keyUsages = isPublic ? [] : ['deriveBits'];
      break;
    }
    case 'EdDSA':
      algorithm = { name: getNamedCurve(keyData) };
      keyUsages = isPublic ? ['verify'] : ['sign'];
      break;
    default:
      throw new Error('Invalid or unsupported "alg" (Algorithm) value');
  }

  const ctx = withCryptoContext(_ctx ?? {});
  return ctx.crypto.subtle.importKey(
    keyFormat,
    keyData,
    algorithm,
    extractable ?? false,
    keyUsages
  );
};

export const fromPKCS8: PEMImportFunction = (input, ctx) => {
  return genericImport(
    {
      ...input,
      keyFormat: 'pkcs8',
      replace: /(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g,
    },
    ctx
  );
};

export const fromSPKI: PEMImportFunction = (input, ctx) => {
  return genericImport(
    {
      ...input,
      keyFormat: 'spki',
      replace: /(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g,
    },
    ctx
  );
};

function getElement(seq: Uint8Array) {
  const result = [];
  let next = 0;

  while (next < seq.length) {
    const nextPart = parseElement(seq.subarray(next));
    result.push(nextPart);
    next += nextPart.byteLength;
  }
  return result;
}

function parseElement(bytes: Uint8Array) {
  let position = 0;

  // tag
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  let tag = bytes[0]! & 0x1f;
  position++;
  if (tag === 0x1f) {
    tag = 0;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    while (bytes[position]! >= 0x80) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      tag = tag * 128 + bytes[position]! - 0x80;
      position++;
    }
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    tag = tag * 128 + bytes[position]! - 0x80;
    position++;
  }

  // length
  let length = 0;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  if (bytes[position]! < 0x80) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    length = bytes[position]!;
    position++;
  } else if (length === 0x80) {
    length = 0;

    while (
      bytes[position + length] !== 0 ||
      bytes[position + length + 1] !== 0
    ) {
      if (length > bytes.byteLength) {
        throw new TypeError('invalid indefinite form length');
      }
      length++;
    }

    const byteLength = position + length + 2;
    return {
      byteLength,
      contents: bytes.subarray(position, position + length),
      raw: bytes.subarray(0, byteLength),
    };
  } else {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const numberOfDigits = bytes[position]! & 0x7f;
    position++;
    length = 0;
    for (let i = 0; i < numberOfDigits; i++) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      length = length * 256 + bytes[position]!;
      position++;
    }
  }

  const byteLength = position + length;
  return {
    byteLength,
    contents: bytes.subarray(position, byteLength),
    raw: bytes.subarray(0, byteLength),
  };
}

function spkiFromX509(buf: Uint8Array) {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const element = getElement(parseElement(buf).contents)[0]!;
  const tbsCertificate = getElement(element.contents);
  return uint8ArrayToBase64(
    // @ts-expect-error this is correct
    tbsCertificate[tbsCertificate[0].raw[0] === 0xa0 ? 6 : 5].raw
  );
}

function getSPKI(x509: string): string {
  const pem = x509.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, '');
  const raw = base64ToUint8Array(pem);
  return formatPEM(spkiFromX509(raw), 'PUBLIC KEY');
}

export const fromX509: PEMImportFunction = (input, ctx) => {
  const { pem } = input;
  let spki: string;
  try {
    spki = getSPKI(pem);
  } catch (cause) {
    throw new Error('Failed to parse the X.509 certificate', { cause });
  }
  return fromSPKI({ ...input, pem: spki }, ctx);
};
