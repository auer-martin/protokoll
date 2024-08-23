import * as v from 'valibot';

import type {
  CompactJWEHeaderParameters,
  JWK,
  JwsVerificationMethod,
  JWTPayload,
  MaybePromise,
  ProtectedHeaderParameters,
} from '@protokoll/core';

import type { JarmAuthResponseParams } from './v-jarm-auth-response-params.js';
import type { JarmOpenId4VpResponseParams } from './v-jarm-openid4vp-response-params.js';
import {
  vJarmResponseMode,
  vOpenid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import { vResponseType } from '../v-response-type-registry.js';

export const vAuthRequestParams = v.looseObject({
  state: v.optional(v.string()),
  response_mode: v.optional(
    v.union([vJarmResponseMode, vOpenid4vpJarmResponseMode])
  ),
  client_id: v.string(),
  response_type: vResponseType,
});

export type AuthRequestParams = v.InferInput<typeof vAuthRequestParams>;

export const vGetAuthRequestParamsOut = v.object({
  authRequestParams: vAuthRequestParams,
});

export type GetAuthRequestParametersOut = v.InferOutput<
  typeof vGetAuthRequestParamsOut
>;

export interface JarmDirectPostJwtAuthResponseValidationContext {
  oAuth: {
    authRequest: {
      getParams: (
        input: JarmAuthResponseParams | JarmOpenId4VpResponseParams
      ) => MaybePromise<GetAuthRequestParametersOut>;
    };
  };
  jose: {
    jwe: {
      decrypt: (input: { jwe: string; jwk: JWK }) => MaybePromise<{
        plaintext: string;
        protectedHeader: CompactJWEHeaderParameters;
      }>;
    };
    jws: {
      verify: (input: {
        compact: string;
        jwsVerificationMethod: JwsVerificationMethod;
      }) => MaybePromise<{
        payload: JWTPayload;
        protectedHeader: ProtectedHeaderParameters;
      }>;
    };
  };
}
