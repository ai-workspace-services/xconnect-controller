import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildSigningKeysList,
  canonicalPolicyJSON,
  clientSigningBytes,
  decodeBase64Flexible,
  encodeBase64Url,
  etagMatches,
  gatewaySigningBytes,
  importEd25519PrivateKey,
  importEd25519PublicKey,
  loadSigningContext,
  sha256Hex,
  signEd25519,
  verifyEd25519,
} from "../src/crypto.ts";
import { createApp } from "../src/index.ts";
import { clearJWKSCacheForTests, verifyJWT } from "../src/jwks.ts";
import type {
  GatewaySignedConfig,
  PolicyArtifact,
  SignedConfig,
  WorkerEnv,
} from "../src/types.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = resolve(__dirname, "../../../contracts/xconnect-overlay-v1/golden-vectors.json");

interface GoldenVectors {
  schema_version: number;
  key_id: string;
  seed_base64: string;
  public_key_base64: string;
  policy: {
    artifact: PolicyArtifact;
    canonical_json: string;
    sha256_digest: string;
  };
  client_v1: {
    config: SignedConfig;
    signing_bytes: string;
    signature_base64: string;
  };
  client_v2: {
    config: SignedConfig;
    signing_bytes: string;
    signature_base64: string;
  };
  gateway_v1: {
    config: GatewaySignedConfig;
    signing_bytes: string;
    signature_base64: string;
  };
  gateway_v2: {
    config: GatewaySignedConfig;
    signing_bytes: string;
    signature_base64: string;
  };
}

const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as GoldenVectors;

test("Golden Vectors: Ed25519 key derivation, canonical JSON, digests, and signatures match Go byte-for-byte", async () => {
  const imported = await importEd25519PrivateKey(golden.seed_base64);
  assert.equal(imported.publicKeyBase64, golden.public_key_base64);

  const pubKey = await importEd25519PublicKey(golden.public_key_base64);

  // Policy canonical JSON + SHA-256 digest
  const policyJSON = canonicalPolicyJSON(golden.policy.artifact);
  assert.equal(policyJSON, golden.policy.canonical_json);
  assert.equal(await sha256Hex(policyJSON), golden.policy.sha256_digest);

  // Client v1
  const c1Bytes = clientSigningBytes(golden.client_v1.config);
  assert.equal(c1Bytes, golden.client_v1.signing_bytes);
  const c1Sig = await signEd25519(imported.signingKey, c1Bytes);
  assert.equal(c1Sig, golden.client_v1.signature_base64);
  assert.equal(await verifyEd25519(pubKey, c1Bytes, golden.client_v1.signature_base64), true);

  // Client v2
  const c2Bytes = clientSigningBytes(golden.client_v2.config);
  assert.equal(c2Bytes, golden.client_v2.signing_bytes);
  const c2Sig = await signEd25519(imported.signingKey, c2Bytes);
  assert.equal(c2Sig, golden.client_v2.signature_base64);
  assert.equal(await verifyEd25519(pubKey, c2Bytes, golden.client_v2.signature_base64), true);

  // Gateway v1
  const g1Bytes = gatewaySigningBytes(golden.gateway_v1.config);
  assert.equal(g1Bytes, golden.gateway_v1.signing_bytes);
  const g1Sig = await signEd25519(imported.signingKey, g1Bytes);
  assert.equal(g1Sig, golden.gateway_v1.signature_base64);
  assert.equal(await verifyEd25519(pubKey, g1Bytes, golden.gateway_v1.signature_base64), true);

  // Gateway v2
  const g2Bytes = gatewaySigningBytes(golden.gateway_v2.config);
  assert.equal(g2Bytes, golden.gateway_v2.signing_bytes);
  const g2Sig = await signEd25519(imported.signingKey, g2Bytes);
  assert.equal(g2Sig, golden.gateway_v2.signature_base64);
  assert.equal(await verifyEd25519(pubKey, g2Bytes, golden.gateway_v2.signature_base64), true);
});

test("JWKS EdDSA JWT verification accepts valid token, rejects expired/tampered, and supports dual signing-key ring", async () => {
  clearJWKSCacheForTests();
  const imported = await importEd25519PrivateKey(golden.seed_base64);
  const pubKey = await importEd25519PublicKey(golden.public_key_base64);

  const encodeJSON = (v: unknown) => encodeBase64Url(new TextEncoder().encode(JSON.stringify(v)));
  const signJWT = async (header: Record<string, unknown>, payload: Record<string, unknown>) => {
    const input = `${encodeJSON(header)}.${encodeJSON(payload)}`;
    const sigRaw = await crypto.subtle.sign(
      "Ed25519",
      imported.signingKey,
      new TextEncoder().encode(input),
    );
    return `${input}.${encodeBase64Url(new Uint8Array(sigRaw))}`;
  };

  const nowSec = 1_800_000_000;
  const staticKeys = new Map<string, CryptoKey>([[golden.key_id, pubKey]]);
  const validToken = await signJWT(
    { alg: "EdDSA", typ: "JWT", kid: golden.key_id },
    { user_id: "usr_123", email: "user@svc.plus", roles: ["user"], exp: nowSec + 300 },
  );

  const claims = await verifyJWT(validToken, {
    staticEd25519Keys: staticKeys,
    nowSeconds: nowSec,
  });
  assert.equal(claims.user_id, "usr_123");

  await assert.rejects(
    () => verifyJWT(validToken, { staticEd25519Keys: staticKeys, nowSeconds: nowSec + 301 }),
    /JWT expired/,
  );

  const tampered = validToken.slice(0, -4) + "AAAA";
  await assert.rejects(
    () => verifyJWT(tampered, { staticEd25519Keys: staticKeys, nowSeconds: nowSec }),
    /invalid JWT signature/,
  );

  // Signing key ring with current + previous overlap
  const env: WorkerEnv = {
    HYPERDRIVE: { connectionString: "" } as unknown as Hyperdrive,
    XCONNECT_OVERLAY_SIGNING_KEY_ID: golden.key_id,
    XCONNECT_OVERLAY_SIGNING_PRIVATE_KEY: golden.seed_base64,
    XCONNECT_OVERLAY_PREVIOUS_SIGNING_KEY_ID: "zero-signing-prev",
    XCONNECT_OVERLAY_PREVIOUS_SIGNING_PUBLIC_KEY: "s5yiz7WTECJKgBSapXGM9WOdoud/76xZbmHGbdK4y7o=",
    XCONNECT_OVERLAY_PREVIOUS_SIGNING_NOT_AFTER: "2026-12-03T00:00:00Z",
  };
  const ctx = await loadSigningContext(env);
  const keys = buildSigningKeysList(ctx, new Date("2026-11-26T08:00:00Z"));
  assert.equal(keys.length, 2);
  assert.equal(keys[0].status, "current");
  assert.equal(keys[1].status, "previous");
  assert.equal(decodeBase64Flexible(keys[0].public_key).length, 32);
});

test("Hono worker /healthz and /api/overlay/v1/signing-keys ETag/304 behavior", async () => {
  const app = createApp();
  const env: WorkerEnv = {
    HYPERDRIVE: { connectionString: "" } as unknown as Hyperdrive,
    XCONNECT_OVERLAY_SIGNING_KEY_ID: golden.key_id,
    XCONNECT_OVERLAY_SIGNING_PRIVATE_KEY: golden.seed_base64,
  };

  const healthResp = await app.request("/healthz", {}, env);
  assert.equal(healthResp.status, 200);
  const healthBody = (await healthResp.json()) as { status: string; runtime: string };
  assert.equal(healthBody.status, "ok");
  assert.equal(healthBody.runtime, "cloudflare-worker");

  // Unauthenticated signing-keys must fail with 401
  const unauthResp = await app.request("/api/overlay/v1/signing-keys", {}, env);
  assert.equal(unauthResp.status, 401);

  assert.equal(etagMatches(`W/"abc", "def"`, `"abc"`), true);
  assert.equal(etagMatches(`"xyz"`, `"abc"`), false);
});
