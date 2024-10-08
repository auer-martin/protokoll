import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import assert from 'node:assert';
import { describe, it } from 'node:test';

import { ISO_MDL_7_JARM_AUTH_RESPONSE_JWT } from '../jarm-auth-response/jarm-auth-response.fixtures.js';
import { jarmAuthResponseSend } from './jarm-auth-response-send.js';

void describe('Jarm Auth Request', async () => {
  await it(`response_type 'vp_token' response_mode 'direct_post.jwt'`, async () => {
    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        const searchParams = new URLSearchParams(await request.text());
        const response = searchParams.get('response');
        assert.equal(response, ISO_MDL_7_JARM_AUTH_RESPONSE_JWT);
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authRequest: {
        response_type: 'vp_token',
        response_uri: 'https://example-relying-party.com',
        response_mode: 'direct_post.jwt',
      },
      authResponse: ISO_MDL_7_JARM_AUTH_RESPONSE_JWT,
    });

    server.close();
    assert.ok(response.ok);
  });

  await it(`response_type 'vp_token' response_mode 'jwt'`, async () => {
    const handlers = [
      http.post('https://example-relying-party.com', ({ request }) => {
        assert.strictEqual(
          request.url,
          `https://example-relying-party.com/#response=${ISO_MDL_7_JARM_AUTH_RESPONSE_JWT}`
        );
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authRequest: {
        response_type: 'vp_token',
        response_uri: 'https://example-relying-party.com',
        response_mode: 'jwt',
      },
      authResponse: ISO_MDL_7_JARM_AUTH_RESPONSE_JWT,
    });

    server.close();
    assert.ok(response.ok);
  });

  await it(`response_type 'vp_token' response_mode 'query.jwt'`, async () => {
    const handlers = [
      http.post('https://example-relying-party.com', ({ request }) => {
        assert.strictEqual(
          request.url,
          `https://example-relying-party.com/?response=${ISO_MDL_7_JARM_AUTH_RESPONSE_JWT}`
        );
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authRequest: {
        response_type: 'vp_token',
        response_uri: 'https://example-relying-party.com',
        response_mode: 'query.jwt',
      },
      authResponse: ISO_MDL_7_JARM_AUTH_RESPONSE_JWT,
    });

    server.close();
    assert.ok(response.ok);
  });
});
