import { decodeBase64Flexible } from "./crypto.ts";

export interface JWK {
  kty: string;
  crv: string;
  alg?: string;
  use?: string;
  kid: string;
  x: string;
}

export interface JWKS {
  keys: JWK[];
}

export interface AccessTokenClaims {
  user_id?: string;
  sub?: string;
  email?: string;
  roles?: string[];
  role?: string;
  mfa_verified?: boolean;
  exp?: number;
  nbf?: number;
  iat?: number;
}

interface JWTHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}

interface CachedJWKS {
  keysByKid: Map<string, CryptoKey>;
  fetchedAt: number;
}

const DEFAULT_CACHE_TTL_MS = 5 * 60_000;
const REFRESH_MIN_GAP_MS = 5_000;

const jwksCache = new Map<string, CachedJWKS>();

function decodeBase64UrlJSON<T>(segment: string): T {
  const bytes = decodeBase64Flexible(segment);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function fetchJWKSKeys(jwksUrl: string, force: boolean): Promise<Map<string, CryptoKey>> {
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);
  if (cached) {
    if (!force && now - cached.fetchedAt < DEFAULT_CACHE_TTL_MS) {
      return cached.keysByKid;
    }
    if (force && now - cached.fetchedAt < REFRESH_MIN_GAP_MS) {
      return cached.keysByKid;
    }
  }

  const resp = await fetch(jwksUrl, { headers: { Accept: "application/json" } });
  if (!resp.ok) {
    if (cached) return cached.keysByKid;
    throw new Error(`JWKS fetch failed: HTTP ${resp.status}`);
  }
  const body = (await resp.json()) as JWKS;
  const keysByKid = new Map<string, CryptoKey>();
  for (const jwk of body.keys ?? []) {
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.kid || !jwk.x) {
      continue;
    }
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x: jwk.x },
      "Ed25519",
      false,
      ["verify"],
    );
    keysByKid.set(jwk.kid, key);
  }
  jwksCache.set(jwksUrl, { keysByKid, fetchedAt: now });
  return keysByKid;
}

export async function verifyJWT(
  token: string,
  options: {
    jwksUrl?: string;
    hs256Secret?: string;
    staticEd25519Keys?: Map<string, CryptoKey>;
    nowSeconds?: number;
  },
): Promise<AccessTokenClaims> {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("malformed JWT");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeBase64UrlJSON<JWTHeader>(headerB64);
  const claims = decodeBase64UrlJSON<AccessTokenClaims>(payloadB64);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sigBytes = decodeBase64Flexible(sigB64);

  let verified = false;
  if (header.alg === "EdDSA") {
    const kid = (header.kid ?? "").trim();
    if (!kid) {
      throw new Error("EdDSA JWT missing kid header");
    }
    let pubKey = options.staticEd25519Keys?.get(kid);
    if (!pubKey && options.jwksUrl) {
      let keys = await fetchJWKSKeys(options.jwksUrl, false);
      pubKey = keys.get(kid);
      if (!pubKey) {
        keys = await fetchJWKSKeys(options.jwksUrl, true);
        pubKey = keys.get(kid);
      }
    }
    if (!pubKey) {
      throw new Error(`unknown EdDSA signing kid: ${kid}`);
    }
    verified = await crypto.subtle.verify("Ed25519", pubKey, sigBytes, signingInput);
  } else if (header.alg === "HS256") {
    const secret = (options.hs256Secret ?? "").trim();
    if (!secret) {
      throw new Error("HS256 verification not configured");
    }
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const expected = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, signingInput));
    verified = timingSafeEqual(expected, sigBytes);
  } else {
    throw new Error(`unsupported JWT alg: ${header.alg ?? "none"}`);
  }

  if (!verified) {
    throw new Error("invalid JWT signature");
  }

  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (typeof claims.exp === "number" && now >= claims.exp) {
    throw new Error("JWT expired");
  }
  if (typeof claims.nbf === "number" && now < claims.nbf) {
    throw new Error("JWT not active yet");
  }
  return claims;
}

export function extractUserId(claims: AccessTokenClaims): string {
  return (claims.user_id || claims.sub || "").trim();
}

export function clearJWKSCacheForTests(): void {
  jwksCache.clear();
}
