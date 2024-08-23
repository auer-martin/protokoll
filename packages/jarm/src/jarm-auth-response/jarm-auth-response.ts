import * as v from 'valibot';

import type { JSONWebKeySet, JWK } from '@protokoll/core';
import {
  decodeJwt,
  decodeProtectedHeader,
  getJwsVerificationMethod,
  isJws,
} from '@protokoll/core';

import type { JarmDirectPostJwtAuthResponseValidationContext } from './c-jarm-auth-response.js';
import {
  jarmOpenid4vpAuthResponseValidateParams,
  vJarmOpenid4vpResponseParams,
} from '../index.js';

export interface ClientMetadata {
  jwks: JSONWebKeySet;
}

export interface JarmAuthResponseValidation {
  /**
   * The JARM response parameter conveyed either as url query param, fragment param, or application/x-www-form-urlencoded in the body of the post request
   *
   */
  response: string;

  /**
   * (OPTIONAL) The client decrypts the JWT using the key determined by the kid JWT header parameter.
   * The key might be a private key, where the corresponding public key is registered with the expected issuer of the response
   * ("use":"enc" via the client's metadata jwks or jwks_uri) or a key derived from its client secret (see section 4.2).
   */
  resolveDecryptionJwk: (input: { kid: string }) => { jwk: JWK };
}

/**
 * Validate a JARM compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export const jarmDirectPostJwtAuthResponseValidation = async (
  input: JarmAuthResponseValidation,
  ctx: JarmDirectPostJwtAuthResponseValidationContext
) => {
  const { response } = input;

  const responseProtectedHeader = decodeProtectedHeader(response);

  let responseParams: unknown;

  if (!responseProtectedHeader.enc) {
    responseParams = await jarmResponseVerifyJws(input, ctx);
  } else {
    if (!responseProtectedHeader.kid) {
      throw new Error(`JWE is missing required protected header field 'kid'`);
    }

    const { jwk } = input.resolveDecryptionJwk({
      kid: responseProtectedHeader.kid,
    });

    const { plaintext } = await ctx.jose.jwe.decrypt({ jwe: response, jwk });

    if (isJws(plaintext)) {
      responseParams = await jarmResponseVerifyJws(input, ctx);
    } else {
      responseParams = JSON.parse(plaintext);
    }
  }

  const authResponseParams = v.parse(
    vJarmOpenid4vpResponseParams,
    responseParams
  );

  const { authRequestParams } =
    await ctx.oAuth.authRequest.getParams(authResponseParams);

  // TODO: MATCH REQUEST TO RESPONSE
  // TODO: check if it is an actual error response with error, error_uri etc and handle that accordingly

  jarmOpenid4vpAuthResponseValidateParams({
    authRequestParams,
    authResponseParams,
  });

  return { authRequestParams, authResponseParams };
};

async function jarmResponseVerifyJws(
  input: Pick<JarmAuthResponseValidation, 'response'>,
  ctx: JarmDirectPostJwtAuthResponseValidationContext
) {
  const { response } = input;
  const jwsProtectedHeader = decodeProtectedHeader(response);
  const jwsPayload = decodeJwt(response);

  const jwsVerificationMethod = getJwsVerificationMethod(
    { header: jwsProtectedHeader, payload: jwsPayload },
    { type: 'jarm-response' }
  );

  await ctx.jose.jws.verify({ compact: response, jwsVerificationMethod });
  return jwsPayload;
}
