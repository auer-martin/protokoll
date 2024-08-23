import * as v from 'valibot';

import { vJarmAuthResponseParams } from './v-jarm-auth-response-params.js';

export const vJarmOpenid4vpResponseParams = v.looseObject({
  ...v.omit(vJarmAuthResponseParams, ['iss', 'aud', 'exp']).entries,
  vp_token: v.string(),
  presentation_submission: v.unknown(),
});

export type JarmOpenId4VpResponseParams = v.InferInput<
  typeof vJarmOpenid4vpResponseParams
>;

export const jarmOpenid4vpAuthResponseValidateParams = (input: {
  authRequestParams: { state?: string };
  authResponseParams: JarmOpenId4VpResponseParams;
}) => {
  const { authRequestParams, authResponseParams } = input;

  // 2. The client obtains the state parameter from the JWT and checks its binding to the user agent. If the check fails, the client MUST abort processing and refuse the response.
  if (authResponseParams.state !== authRequestParams.state) {
    throw new Error(
      `State missmatch between auth request '${authRequestParams.state}' and the jarm-auth-response.`
    );
  }
};
