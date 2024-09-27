import { http, HttpResponse } from 'msw';
import assert from 'node:assert';
import { describe, it } from 'node:test';

import type { Jwk } from '@protokoll/jose';
import { joseContext } from '@protokoll/jose/dist/src/u-jose-test-context.js';
import { setupServer } from 'msw/node';
import type { JarmAuthResponseCreateContext } from '../jarm-auth-response-send/c-jarm-auth-response-send.js';
import {
  jarmAuthResponseCreate,
  jarmAuthResponseSend,
} from '../jarm-auth-response-send/jarm-auth-response-send.js';
import type { JarmDirectPostJwtAuthResponseValidationContext } from './c-jarm-auth-response.js';
import {
  EXAMPLE_RP_P256_PRIVATE_KEY_JWK,
  ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK,
  ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
  ISO_MDL_7_JAR_AUTH_REQUEST,
  ISO_MDL_7_JARM_AUTH_RESPONSE,
  ISO_MDL_7_JARM_AUTH_RESPONSE_JWT,
} from './jarm-auth-response.fixtures.js';
import { jarmAuthResponseDirectPostJwtValidate } from './jarm-auth-response.js';

const jarmAuthResponseCreateContext: JarmAuthResponseCreateContext = {
  jose: {
    jwe: {
      encryptJwt: joseContext.jose.jwe.encryptJwt,
      encryptCompact: joseContext.jose.jwe.encryptCompact,
    },
    jws: { signJwt: joseContext.jose.jws.signJwt },
  },
};

export const decryptCompact: typeof joseContext.jose.jwe.decryptCompact =
  async input => {
    const { jwe, jwk: jwkToResolve } = input;
    let jwk: Jwk;
    if (
      jwkToResolve.kty === 'auto' &&
      jwkToResolve.kid === ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK.kid
    ) {
      jwk = ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK;
    } else {
      throw new Error('Received an invalid jwk.');
    }
    return await joseContext.jose.jwe.decryptCompact({ jwe, jwk });
  };

export const verifyJwt: typeof joseContext.jose.jws.verifyJwt = async input => {
  const { jws, jwk: jwkToResolve } = input;
  let jwk: Jwk;
  if (
    jwkToResolve.kty === 'auto' &&
    jwkToResolve.kid === EXAMPLE_RP_P256_PRIVATE_KEY_JWK.kid
  ) {
    jwk = EXAMPLE_RP_P256_PRIVATE_KEY_JWK;
  } else {
    throw new Error('Received an invalid jwk.');
  }
  return await joseContext.jose.jws.verifyJwt({ jws, jwk });
};

const jarmAuthResponseDirectPostJwtValidationContext: JarmDirectPostJwtAuthResponseValidationContext =
  {
    openid4vp: {
      authRequest: {
        get: () => ({
          authRequest: ISO_MDL_7_JAR_AUTH_REQUEST,
        }),
      },
    },
    jose: { jwe: { decryptCompact }, jws: { verifyJwt } },
  };

void describe('Jarm Auth Response', () => {
  void it(`Create jarmAuthResponse, send JarmAuthRequest, validate JarmAuthResponse (encrypted)`, async () => {
    const authRequest = {
      response_type: 'vp_token',
      response_uri: 'https://example-relying-party.com',
      response_mode: 'direct_post.jwt',
    } as const;

    const { authResponse } = await jarmAuthResponseCreate(
      {
        type: 'encrypted',
        jweEncryptJwtInput: {
          jwk: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
          protectedHeader: {
            alg: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.alg,
            kid: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.kid,
            enc: 'A256GCM',
          },
        },
        authResponse: ISO_MDL_7_JARM_AUTH_RESPONSE,
      },
      jarmAuthResponseCreateContext
    );

    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        // we receive the response we sent
        const searchParams = new URLSearchParams(await request.text());
        const response = searchParams.get('response');
        assert(response);
        assert.equal(response, authResponse);

        const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
          { response },
          jarmAuthResponseDirectPostJwtValidationContext
        );

        assert.deepEqual(
          ISO_MDL_7_JARM_AUTH_RESPONSE,
          validatedResponse.authResponse
        );

        assert.deepEqual(validatedResponse.type, 'encrypted');
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authResponse,
      authRequest,
    });

    server.close();
    assert.ok(response.ok);
  });

  void it(`Create jarmAuthResponse, send JarmAuthRequest, validate JarmAuthResponse (signed)`, async () => {
    const authRequest = {
      response_type: 'vp_token',
      response_uri: 'https://example-relying-party.com',
      response_mode: 'direct_post.jwt',
    } as const;

    const { authResponse } = await jarmAuthResponseCreate(
      {
        type: 'signed',
        jwsSignJwtInput: {
          jwk: EXAMPLE_RP_P256_PRIVATE_KEY_JWK,
          protectedHeader: {
            alg: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.alg,
            kid: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.kid,
          },
        },
        authResponse: {
          iss: 'https://example-issuer.com',
          aud: 'https://example-relying-party.com',
          exp: 9999999999,
          ...ISO_MDL_7_JARM_AUTH_RESPONSE,
        },
      },
      jarmAuthResponseCreateContext
    );

    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        // we receive the response we sent
        const searchParams = new URLSearchParams(await request.text());
        const response = searchParams.get('response');
        assert(response);
        assert.equal(response, authResponse);

        const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
          { response },
          jarmAuthResponseDirectPostJwtValidationContext
        );

        assert.deepEqual(validatedResponse.type, 'signed');
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authResponse: authResponse,
      authRequest,
    });

    server.close();
    assert.ok(response.ok);
  });

  void it(`Create jarmAuthResponse, send JarmAuthRequest, validate JarmAuthResponse (signed and encrypted)`, async () => {
    const authRequest = {
      response_type: 'vp_token',
      response_uri: 'https://example-relying-party.com',
      response_mode: 'direct_post.jwt',
    } as const;

    const { authResponse } = await jarmAuthResponseCreate(
      {
        type: 'signed encrypted',
        jwsSignJwtInput: {
          jwk: EXAMPLE_RP_P256_PRIVATE_KEY_JWK,
          protectedHeader: {
            alg: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.alg,
            kid: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.kid,
          },
        },
        jweEncryptCompactInput: {
          jwk: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
          protectedHeader: {
            alg: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.alg,
            kid: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.kid,
            enc: 'A256GCM',
          },
        },
        authResponse: {
          iss: 'https://example-issuer.com',
          aud: 'https://example-relying-party.com',
          exp: 9999999999,
          ...ISO_MDL_7_JARM_AUTH_RESPONSE,
        },
      },
      jarmAuthResponseCreateContext
    );

    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        // we receive the response we sent
        const searchParams = new URLSearchParams(await request.text());
        const response = searchParams.get('response');
        assert(response);
        assert.equal(response, authResponse);

        const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
          { response },
          jarmAuthResponseDirectPostJwtValidationContext
        );
        assert.deepEqual(validatedResponse.type, 'signed encrypted');

        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authResponse: authResponse,
      authRequest: authRequest,
    });

    server.close();
    assert.ok(response.ok);
  });

  void it(`'ISO_MDL_7_JARM_AUTH_RESPONSE' can be validated`, async () => {
    const { authRequest, authResponse } =
      await jarmAuthResponseDirectPostJwtValidate(
        { response: ISO_MDL_7_JARM_AUTH_RESPONSE_JWT },
        jarmAuthResponseDirectPostJwtValidationContext
      );

    assert.deepEqual(ISO_MDL_7_JARM_AUTH_RESPONSE, authResponse);
    assert.deepEqual(authRequest, authRequest);
  });
});
