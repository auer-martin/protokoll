import * as v from 'valibot';

export const vJarmAuthResponseParams = v.looseObject({
  state: v.optional(v.string()),

  /**
   * The issuer URL of the authorization server that created the response
   */
  iss: v.string(),

  /**
   * The client_id of the client the response is intended for
   */
  exp: v.number(),

  /**
   * Expiration of the JWT
   */
  aud: v.string(),
});

export type JarmAuthResponseParams = v.InferInput<
  typeof vJarmAuthResponseParams
>;

export const jarmAuthResponseValidateParams = (input: {
  authRequestParams: { client_id: string; state: string };
  authResponseParams: JarmAuthResponseParams;
}) => {
  const { authRequestParams, authResponseParams } = input;
  // 2. The client obtains the state parameter from the JWT and checks its binding to the user agent. If the check fails, the client MUST abort processing and refuse the response.
  if (authResponseParams.state !== authRequestParams.state) {
    throw new Error(
      `State missmatch between auth request '${authRequestParams.state}' and the jarm-auth-response.`
    );
  }

  // 4. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (authResponseParams.aud !== authRequestParams.client_id) {
    throw new Error(
      `Invalid audience in jarm-auth-response. Expected '${authRequestParams.client_id}' received '${authResponseParams.aud}'.`
    );
  }

  // 5. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // 120 seconds clock skew
  if (authResponseParams.exp >= Math.floor(Date.now() / 1000) + 120) {
    throw new Error(
      `The '${authRequestParams.state}' and the jarm-auth-response.`
    );
  }
};
