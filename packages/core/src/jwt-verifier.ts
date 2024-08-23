import type {
  JWK,
  JWTPayload,
  ProtectedHeaderParameters,
} from '@protokoll/core';

export type JwtType = 'jarm-response';

export type JwtProtectionMethod =
  | 'did'
  | 'x5c'
  | 'jwk'
  | 'openid-federation'
  | 'unknown';

export interface JwtVerifierBase {
  type: JwtType;
  method: JwtProtectionMethod;
}

export interface DidJwtVerifier extends JwtVerifierBase {
  method: 'did';

  alg: string;
  didUrl: string;
}

export interface X5cJwtVerifier extends JwtVerifierBase {
  method: 'x5c';

  alg: string;

  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  x5c: string[];
}

export interface OpenIdFederationJwtVerifier extends JwtVerifierBase {
  method: 'openid-federation';

  /**
   * The OpenId federation Entity
   */
  entityId: string;
}

export interface JwkJwtVerifier extends JwtVerifierBase {
  method: 'jwk';
  alg: string;

  jwk: JWK;
}

export interface CustomJwtVerifier extends JwtVerifierBase {
  method: 'unknown';
}

export type JwsVerificationMethod =
  | DidJwtVerifier
  | X5cJwtVerifier
  | CustomJwtVerifier
  | JwkJwtVerifier
  | OpenIdFederationJwtVerifier;

export const getDidJwtVerifier = (
  jwt: { header: ProtectedHeaderParameters; payload: JWTPayload },
  options: { type: JwtType }
): DidJwtVerifier => {
  const { type } = options;
  if (!jwt.header.kid)
    throw new Error(`Received an invalid JWT. Missing kid header.`);
  if (!jwt.header.alg)
    throw new Error(`Received an invalid JWT. Missing alg header.`);

  if (!jwt.header.kid.includes('#')) {
    throw new Error(
      `Received an invalid JWT.. '${type}' contains an invalid kid header.`
    );
  }
  return {
    method: 'did',
    didUrl: jwt.header.kid,
    type: type,
    alg: jwt.header.alg,
  };
};

export const getX5cVerifier = (
  jwt: { header: ProtectedHeaderParameters; payload: JWTPayload },
  options: { type: JwtType }
): X5cJwtVerifier => {
  const { type } = options;
  if (!jwt.header.x5c)
    throw new Error(`Received an invalid JWT. Missing x5c header.`);
  if (!jwt.header.alg)
    throw new Error(`Received an invalid JWT. Missing alg header.`);

  if (
    !Array.isArray(jwt.header.x5c) ||
    jwt.header.x5c.length === 0 ||
    !jwt.header.x5c.every(cert => typeof cert === 'string')
  ) {
    throw new Error(
      `Received an invalid JWT.. '${type}' contains an invalid x5c header.`
    );
  }

  return {
    method: 'x5c',
    x5c: jwt.header.x5c,
    type: type,
    alg: jwt.header.alg,
  };
};

export const getJwkVerifier = (
  jwt: { header: ProtectedHeaderParameters; payload: JWTPayload },
  options: { type: JwtType }
): JwkJwtVerifier => {
  const { type } = options;
  if (!jwt.header.jwk)
    throw new Error(`Received an invalid JWT.  Missing jwk header.`);
  if (!jwt.header.alg)
    throw new Error(`Received an invalid JWT. Missing alg header.`);

  if (typeof jwt.header.jwk !== 'object') {
    throw new Error(
      `Received an invalid JWT. '${type}' contains an invalid jwk header.`
    );
  }

  return { method: 'jwk', type, jwk: jwt.header.jwk, alg: jwt.header.alg };
};

export const getJwsVerificationMethod = (
  jwt: { header: ProtectedHeaderParameters; payload: JWTPayload },
  options: { type: JwtType }
): JwsVerificationMethod => {
  const { header, payload } = jwt;

  if (header.kid?.startsWith('did:'))
    return getDidJwtVerifier({ header, payload }, options);
  else if (jwt.header.x5c) return getX5cVerifier({ header, payload }, options);
  else if (jwt.header.jwk) return getJwkVerifier({ header, payload }, options);

  return { method: 'unknown', type: options.type };
};
export type GetJwsVerificationMethod = typeof getJwsVerificationMethod;

export type VerifyJwtCallback<JwtV extends JwsVerificationMethod> = (
  jwtVerifier: JwtV,
  jwt: { header: ProtectedHeaderParameters; payload: JWTPayload; raw: string }
) => Promise<boolean>;
