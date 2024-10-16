import type { CryptoContext } from './c-crypto.js';
import { withCryptoContext } from './c-crypto.js';
import type { GenerateKeyPairOptions } from './key/generate-key-pair.js';
import type { GenerateSecretOptions } from './key/generate-secret.js';

export async function generateSecret(
  input: {
    alg: string;
  } & GenerateSecretOptions,
  ctx: CryptoContext
) {
  const { alg, extractable } = input;
  let length: number;
  let algorithm: AesKeyGenParams | HmacKeyGenParams;
  let keyUsages: KeyUsage[];
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      length = parseInt(alg.slice(-3), 10);
      algorithm = { name: 'HMAC', hash: `SHA-${length}`, length };
      keyUsages = ['sign', 'verify'];
      break;
    case 'A128CBC-HS256':
    case 'A192CBC-HS384':
    case 'A256CBC-HS512':
      length = parseInt(alg.slice(-3), 10);
      return crypto.getRandomValues(new Uint8Array(length >> 3));
    case 'A128KW':
    case 'A192KW':
    case 'A256KW':
      length = parseInt(alg.slice(1, 4), 10);
      algorithm = { name: 'AES-KW', length };
      keyUsages = ['wrapKey', 'unwrapKey'];
      break;
    case 'A128GCMKW':
    case 'A192GCMKW':
    case 'A256GCMKW':
    case 'A128GCM':
    case 'A192GCM':
    case 'A256GCM':
      length = parseInt(alg.slice(1, 4), 10);
      algorithm = { name: 'AES-GCM', length };
      keyUsages = ['encrypt', 'decrypt'];
      break;
    default:
      throw new Error(
        'Invalid or unsupported JWK "alg" (Algorithm) Parameter value'
      );
  }

  return ctx.crypto.subtle.generateKey(
    algorithm,
    extractable ?? false,
    keyUsages
  ) as unknown as Promise<CryptoKey>;
}

function getModulusLengthOption(options?: GenerateKeyPairOptions) {
  const modulusLength = options?.modulusLength ?? 2048;
  if (typeof modulusLength !== 'number' || modulusLength < 2048) {
    throw new Error(
      'Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used'
    );
  }
  return modulusLength;
}

export async function generateKeyPair(
  input: {
    alg: string;
  } & GenerateKeyPairOptions,
  _ctx?: CryptoContext
) {
  const { alg, extractable } = input;
  let algorithm: RsaHashedKeyGenParams | EcKeyGenParams | KeyAlgorithm;
  let keyUsages: KeyUsage[];

  switch (alg) {
    case 'PS256':
    case 'PS384':
    case 'PS512':
      algorithm = {
        name: 'RSA-PSS',
        hash: `SHA-${alg.slice(-3)}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLengthOption(input),
      };
      keyUsages = ['sign', 'verify'];
      break;
    case 'RS256':
    case 'RS384':
    case 'RS512':
      algorithm = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: `SHA-${alg.slice(-3)}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLengthOption(input),
      };
      keyUsages = ['sign', 'verify'];
      break;
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      algorithm = {
        name: 'RSA-OAEP',
        hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLengthOption(input),
      };
      keyUsages = ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey'];
      break;
    case 'ES256':
      algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
      keyUsages = ['sign', 'verify'];
      break;
    case 'ES384':
      algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
      keyUsages = ['sign', 'verify'];
      break;
    case 'ES512':
      algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
      keyUsages = ['sign', 'verify'];
      break;
    case 'EdDSA': {
      keyUsages = ['sign', 'verify'];
      const crv = input.crv ?? 'Ed25519';
      switch (crv) {
        case 'Ed25519':
        case 'Ed448':
          algorithm = { name: crv };
          break;
        default:
          throw new Error('Invalid or unsupported crv option provided');
      }
      break;
    }
    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW': {
      keyUsages = ['deriveKey', 'deriveBits'];
      const crv = input.crv ?? 'P-256';
      switch (crv) {
        case 'P-256':
        case 'P-384':
        case 'P-521': {
          algorithm = { name: 'ECDH', namedCurve: crv };
          break;
        }
        case 'X25519':
        case 'X448':
          algorithm = { name: crv };
          break;
        default:
          throw new Error(
            'Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, X25519, and X448'
          );
      }
      break;
    }
    default:
      throw new Error(
        'Invalid or unsupported JWK "alg" (Algorithm) Parameter value'
      );
  }

  const ctx = withCryptoContext(_ctx ?? {});
  return ctx.crypto.subtle.generateKey(
    algorithm,
    extractable ?? false,
    keyUsages
  ) as Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  }>;
}