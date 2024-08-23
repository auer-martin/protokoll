import type * as jose from 'jose';
import { jwtDecode } from 'jwt-decode';

export const isJws = (jws: string) => {
  return jws.split('.').length === 3;
};

export const decodeProtectedHeader = (
  jwt: string
): jose.ProtectedHeaderParameters => {
  return jwtDecode(jwt, { header: true });
};

export const decodeJwt = (jwt: string): jose.JWTPayload => {
  return jwtDecode(jwt, { header: false });
};

export type JSONWebKeySet = jose.JSONWebKeySet;
export type JWK = jose.JWK;
export type JWTPayload = jose.JWTPayload;
export type CompactJWEHeaderParameters = jose.CompactJWEHeaderParameters;
export type ProtectedHeaderParameters = jose.ProtectedHeaderParameters;
